use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
mod backup;
mod browse;
mod collaboration;
mod sharing;
mod upload;
mod webdav;

use std::io::{self, Write};
use uuid::Uuid;

use crate::{
    auth::{require_admin, require_admin_with_credential, DriveCredential},
    blob,
    error::{ApiError, ApiResult},
    model::{
        ContentWrite, CreateFileRequest, FileKind, RunTwinScenarioRequest, TwinAssertionResult,
        TwinScenarioCatalog, TwinScenarioDescriptor, TwinScenarioRunResponse,
    },
    server::AppState,
};

const WORKSPACE_ROUNDTRIP: &str = "workspace_roundtrip";
const PREVIEW_DOWNLOAD_ROUNDTRIP: &str = "preview_download_roundtrip";
const TRASH_BEFORE_ASSERTIONS: &str = "trash_before_assertions";
const REMOVE_BLOB_BEFORE_ASSERTIONS: &str = "remove_blob_before_assertions";
const TRUNCATE_BLOB_BEFORE_ASSERTIONS: &str = "truncate_blob_before_assertions";
const STALE_REVISION_BEFORE_ASSERTIONS: &str = "stale_revision_before_assertions";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/debug/twin/scenarios", get(twin_scenarios))
        .route("/debug/twin/run", post(run_twin_scenario))
}

async fn twin_scenarios(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<TwinScenarioCatalog>> {
    require_admin(&state, &headers)?;
    Ok(Json(catalog()))
}

async fn run_twin_scenario(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RunTwinScenarioRequest>,
) -> ApiResult<Json<TwinScenarioRunResponse>> {
    let (_, source_credential) = require_admin_with_credential(&state, &headers)?;
    if !matches!(source_credential, DriveCredential::Operator) {
        return Err(ApiError::Forbidden);
    }
    if !state.config.e2e_enabled {
        return Err(ApiError::Forbidden);
    }
    let response = match request.scenario.as_str() {
        WORKSPACE_ROUNDTRIP => {
            validate_faults(&request.faults, &[TRASH_BEFORE_ASSERTIONS])?;
            run_workspace_roundtrip(state, request.faults)?
        }
        PREVIEW_DOWNLOAD_ROUNDTRIP => {
            validate_faults(
                &request.faults,
                &[
                    REMOVE_BLOB_BEFORE_ASSERTIONS,
                    TRUNCATE_BLOB_BEFORE_ASSERTIONS,
                    STALE_REVISION_BEFORE_ASSERTIONS,
                ],
            )?;
            if request.faults.len() > 1 {
                return Err(ApiError::Validation(
                    "preview/download twin accepts one fault at a time".to_string(),
                ));
            }
            run_preview_download_roundtrip(state, request.faults)?
        }
        browse::BROWSE_SCALE_ROUNDTRIP => {
            validate_faults(&request.faults, &[browse::TRASH_NESTED_BEFORE_ASSERTIONS])?;
            browse::run_browse_scale_roundtrip(state, request.faults)?
        }
        upload::SCENARIO => {
            validate_faults(&request.faults, &[upload::STALE_OFFSET, upload::INTERRUPT])?;
            upload::run(state, request.faults).await?
        }
        sharing::SCENARIO => {
            validate_faults(
                &request.faults,
                &[sharing::EXPIRED, sharing::WRONG_PASSWORD],
            )?;
            sharing::run(state, request.faults).await?
        }
        collaboration::SCENARIO => {
            validate_faults(
                &request.faults,
                &[collaboration::STALE_REVISION, collaboration::VIEWER_COMMENT],
            )?;
            collaboration::run(state, request.faults)?
        }
        webdav::SCENARIO => {
            validate_faults(&request.faults, &[webdav::CONFLICTING_TOKEN])?;
            webdav::run(state, request.faults)?
        }
        backup::SCENARIO => {
            validate_faults(&request.faults, &[backup::INTERRUPT])?;
            backup::run(state, request.faults)?
        }
        _ => {
            return Err(ApiError::Validation(format!(
                "unknown twin scenario: {}",
                request.scenario
            )))
        }
    };
    Ok(Json(response))
}

fn validate_faults(faults: &[String], allowed: &[&str]) -> ApiResult<()> {
    for fault in faults {
        if !allowed.contains(&fault.as_str()) {
            return Err(ApiError::Validation(format!("unknown twin fault: {fault}")));
        }
    }
    Ok(())
}

fn catalog() -> TwinScenarioCatalog {
    let mut catalog = TwinScenarioCatalog {
        scenarios: vec![
            TwinScenarioDescriptor {
                id: WORKSPACE_ROUNDTRIP.to_string(),
                description: "Creates a workspace/file and validates sync, search, and jobs"
                    .to_string(),
            },
            TwinScenarioDescriptor {
                id: browse::BROWSE_SCALE_ROUNDTRIP.to_string(),
                description: "Creates a nested tree and validates recursive sizes plus bounded browse diagnostics"
                    .to_string(),
            },
            TwinScenarioDescriptor {
                id: PREVIEW_DOWNLOAD_ROUNDTRIP.to_string(),
                description:
                    "Creates image media and validates preview plus streamed download capabilities"
                        .to_string(),
            },
        ],
        faults: vec![
            TwinScenarioDescriptor {
                id: TRASH_BEFORE_ASSERTIONS.to_string(),
                description: "Trashes the workspace scenario file before assertions".to_string(),
            },
            TwinScenarioDescriptor {
                id: browse::TRASH_NESTED_BEFORE_ASSERTIONS.to_string(),
                description: "Trashes the nested browse file before size assertions".to_string(),
            },
            TwinScenarioDescriptor {
                id: REMOVE_BLOB_BEFORE_ASSERTIONS.to_string(),
                description: "Removes the preview scenario source blob before assertions"
                    .to_string(),
            },
            TwinScenarioDescriptor {
                id: TRUNCATE_BLOB_BEFORE_ASSERTIONS.to_string(),
                description: "Truncates the preview scenario source blob before assertions"
                    .to_string(),
            },
            TwinScenarioDescriptor {
                id: STALE_REVISION_BEFORE_ASSERTIONS.to_string(),
                description: "Attempts a stale content revision before preview assertions"
                    .to_string(),
            },
        ],
    };
    catalog.scenarios.extend([
        upload::descriptor(),
        sharing::descriptor(),
        collaboration::descriptor(),
        webdav::descriptor(),
        backup::descriptor(),
    ]);
    catalog.faults.extend(upload::fault_descriptors());
    catalog.faults.extend(sharing::fault_descriptors());
    catalog.faults.extend(collaboration::fault_descriptors());
    catalog.faults.extend(webdav::fault_descriptors());
    catalog.faults.extend(backup::fault_descriptors());
    catalog
}

fn run_preview_download_roundtrip(
    state: AppState,
    faults: Vec<String>,
) -> ApiResult<TwinScenarioRunResponse> {
    let (workspace, _, _) = state
        .storage
        .create_workspace("Twin Preview Workspace", "twin@example.test")?;
    let color_seed = Uuid::now_v7().as_u128();
    let mut cursor = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        2,
        2,
        image::Rgba([
            color_seed as u8,
            (color_seed >> 8) as u8,
            (color_seed >> 16) as u8,
            255,
        ]),
    ))
    .write_to(&mut cursor, image::ImageFormat::Png)
    .map_err(|error| ApiError::Io(io::Error::other(error)))?;
    let content = cursor.into_inner();
    let (content_hash, file) = {
        let _blob_lifecycle_lock = blob::BlobLifecycleLock::acquire_shared(&state.data_dir())?;
        let content_hash = blob::put_blob(&state.data_dir(), &content)?;
        let (file, _) = state.storage.create_file_with_content_bytes(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "twin-preview.png".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            Some(content_hash.clone()),
            content.len() as i64,
        )?;
        (content_hash, file)
    };
    state
        .storage
        .run_queued_background_jobs(&state.data_dir())?;
    let preview = state.storage.get_file_preview(&file.id)?;
    let source_path = blob::blob_file_path(&state.data_dir(), &content_hash)?;

    let source_removed = faults
        .iter()
        .any(|fault| fault == REMOVE_BLOB_BEFORE_ASSERTIONS);
    let source_truncated = faults
        .iter()
        .any(|fault| fault == TRUNCATE_BLOB_BEFORE_ASSERTIONS);
    let source_present = if source_removed || source_truncated {
        // This scenario intentionally corrupts a referenced object, so exclude
        // publishers until the exact original bytes have been restored.
        let _blob_lifecycle_lock = blob::BlobLifecycleLock::acquire_exclusive(&state.data_dir())?;
        if source_removed {
            blob::remove_blob(&state.data_dir(), &content_hash)?;
        } else {
            let mut source = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&source_path)?;
            source.write_all(&content[..content.len().saturating_sub(1)])?;
            source.sync_all()?;
        }

        let source_present = std::fs::metadata(&source_path)
            .is_ok_and(|metadata| metadata.len() == content.len() as u64);
        blob::remove_blob(&state.data_dir(), &content_hash)?;
        let restored_hash = blob::put_blob(&state.data_dir(), &content)?;
        if restored_hash != content_hash {
            return Err(ApiError::Io(io::Error::other(
                "service twin could not restore the injected source blob fault",
            )));
        }
        source_present
    } else {
        std::fs::metadata(&source_path).is_ok_and(|metadata| metadata.len() == content.len() as u64)
    };
    let stale_revision_faulted = faults
        .iter()
        .any(|fault| fault == STALE_REVISION_BEFORE_ASSERTIONS);
    let stale_revision_contained = if stale_revision_faulted {
        let _blob_lifecycle_lock = blob::BlobLifecycleLock::acquire_shared(&state.data_dir())?;
        let stale_content = b"stale service twin content";
        let stale_hash = blob::put_blob(&state.data_dir(), stale_content)?;
        matches!(
            state.storage.put_content(
                &file.id,
                0,
                &stale_hash,
                i64::try_from(stale_content.len()).unwrap_or(i64::MAX),
            )?,
            ContentWrite::Conflict(ref conflict)
                if conflict.error == "stale_revision"
                    && conflict.file_id == file.id
                    && conflict.current_revision == file.revision
        )
    } else {
        true
    };
    let download_capability_roundtrip = if source_present {
        let raw = state.file_download_tickets.issue(
            file.name.clone(),
            source_path.clone(),
            content.len() as u64,
        )?;
        state.file_download_tickets.redeem(&raw, None).is_ok()
            && state.file_download_tickets.redeem(&raw, None).is_err()
    } else {
        false
    };
    let preview_capability_reusable = if source_present {
        let raw = state.file_download_tickets.issue_preview(
            file.name.clone(),
            source_path,
            content.len() as u64,
        )?;
        state.file_download_tickets.redeem(&raw, None).is_ok()
            && state.file_download_tickets.redeem(&raw, None).is_ok()
    } else {
        false
    };
    let job_totals = state.storage.background_job_totals()?;
    let assertions = vec![
        assertion(
            "image_preview_ready",
            preview.as_ref().is_some_and(|record| {
                record.status == "ready"
                    && record.kind == "image_thumbnail"
                    && record.thumbnail_hash.is_some()
            }),
            "image preview and thumbnail are ready",
            "image preview or thumbnail is unavailable",
        ),
        assertion(
            "download_source_streamable",
            source_present,
            "immutable source metadata matches the stored blob",
            "download source blob is missing or has the wrong size",
        ),
        assertion(
            "download_capability_one_use",
            download_capability_roundtrip,
            "single-file download capability redeems exactly once",
            "single-file download capability did not enforce one-use redemption",
        ),
        assertion(
            "preview_capability_range_reusable",
            preview_capability_reusable,
            "preview capability supports repeated bounded range fetches",
            "preview capability could not support repeated media range fetches",
        ),
        assertion(
            "requested_revision_current",
            !stale_revision_faulted,
            "preview/download requested the current revision",
            "an injected stale revision request was isolated as a conflict",
        ),
        assertion(
            "stale_revision_conflict_contained",
            stale_revision_contained,
            "stale revision handling preserved the current file",
            "stale revision handling did not produce the expected conflict",
        ),
        assertion(
            "background_jobs_drained",
            job_totals.queued == 0,
            "background preview jobs drained",
            "background preview jobs remain queued",
        ),
    ];
    let passed = assertions.iter().all(|assertion| assertion.passed);
    let receipt = state
        .storage
        .insert_receipt("twin.run", "system", Some(&workspace.id))?;
    Ok(TwinScenarioRunResponse {
        scenario: PREVIEW_DOWNLOAD_ROUNDTRIP.to_string(),
        faults,
        passed,
        workspace_id: workspace.id,
        file_id: file.id,
        assertions,
        receipt,
    })
}

fn run_workspace_roundtrip(
    state: AppState,
    faults: Vec<String>,
) -> ApiResult<TwinScenarioRunResponse> {
    let unique = Uuid::now_v7().to_string();
    let content = format!("shellx service twin unique term {unique}");
    let (workspace, _, _) = state
        .storage
        .create_workspace("Twin Workspace", "twin@example.test")?;
    let _blob_lifecycle_lock = blob::BlobLifecycleLock::acquire_shared(&state.data_dir())?;
    let content_hash = blob::put_blob(&state.data_dir(), content.as_bytes())?;
    let (file, _) = state.storage.create_file_with_content_bytes(
        CreateFileRequest {
            workspace_id: workspace.id.clone(),
            parent_id: None,
            name: "twin.txt".to_string(),
            kind: FileKind::File,
            content: None,
            path: None,
        },
        Some(content_hash),
        content.len() as i64,
    )?;
    state.storage.index_file_text(&file, &content)?;
    state
        .storage
        .run_queued_background_jobs(&state.data_dir())?;

    if faults.iter().any(|fault| fault == TRASH_BEFORE_ASSERTIONS) {
        state.storage.set_trashed(&file.id, true)?;
    }

    let current_file = state
        .storage
        .get_file(&file.id)?
        .ok_or(ApiError::NotFound)?;
    let sync_health = state.storage.sync_health_for_workspaces(
        vec![workspace.clone()],
        Some("twin@example.test".to_string()),
    )?;
    let search_hits = state.storage.search_files(&unique)?;
    let job_totals = state.storage.background_job_totals()?;

    let assertions = vec![
        assertion(
            "workspace_created",
            workspace.storage_mode == "open",
            "workspace is open",
            "workspace was not created as open",
        ),
        assertion(
            "file_downloadable",
            !current_file.trashed
                && matches!(current_file.kind, FileKind::File)
                && current_file.content_hash.is_some(),
            "file is active and server-readable",
            "file is not active and server-readable",
        ),
        assertion(
            "search_finds_file",
            search_hits.iter().any(|hit| hit.id == file.id),
            "search returned the scenario file",
            "search did not return the scenario file",
        ),
        assertion(
            "sync_health_downloadable",
            sync_health.totals.downloadable_files >= 1,
            "sync health reports a downloadable file",
            "sync health reports no downloadable files",
        ),
        assertion(
            "background_jobs_drained",
            job_totals.queued == 0,
            "background jobs drained",
            "background jobs remain queued",
        ),
    ];
    let passed = assertions.iter().all(|assertion| assertion.passed);
    let receipt = state
        .storage
        .insert_receipt("twin.run", "system", Some(&workspace.id))?;

    Ok(TwinScenarioRunResponse {
        scenario: WORKSPACE_ROUNDTRIP.to_string(),
        faults,
        passed,
        workspace_id: workspace.id,
        file_id: file.id,
        assertions,
        receipt,
    })
}

fn assertion(
    name: &str,
    passed: bool,
    pass_message: &str,
    fail_message: &str,
) -> TwinAssertionResult {
    TwinAssertionResult {
        name: name.to_string(),
        passed,
        message: if passed { pass_message } else { fail_message }.to_string(),
    }
}
