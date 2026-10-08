use axum::{
    extract::{Path, State},
    http::{header, HeaderMap},
    response::Response,
    routing::get,
    Router,
};
use chrono::{DateTime, Utc};

use crate::{
    auth::constant_time_str_eq,
    download_subjects::FileContentSubject,
    download_tickets::{
        FileDownloadAuthorization, FileTicketDisposition, PublicShareFileAuthorization,
    },
    error::{ApiError, ApiResult},
    public_client_binding,
    routes::blob_response::{
        is_safe_inline_file_name, serve_blob_file_with_guard,
        serve_blob_file_with_guard_after_open, Disposition,
    },
    server::{request_client_fingerprint, AppState},
    storage::{FileAccessKind, Storage},
    streaming_zip,
};

mod revalidation;
use revalidation::{authenticated_archive_revalidator, public_archive_revalidator};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/downloads/{ticket}", get(download_archive))
        .route("/downloads/files/{ticket}", get(download_file))
}

/// Redeem a short-lived, one-use archive capability. Authorization and archive
/// scoping happen before ticket issue; this unauthenticated GET lets the
/// browser stream the attachment to disk without buffering it in JavaScript.
async fn download_archive(
    State(state): State<AppState>,
    Path(ticket): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let transport_fingerprint = request_client_fingerprint(&headers).to_string();
    let client_binding = public_client_binding::from_request(&state, &headers)?;
    let ticket =
        state
            .archive_tickets
            .redeem(&ticket, &transport_fingerprint, client_binding.as_deref())?;
    let admission_permit = state
        .archive_tickets
        .try_acquire_producer(&ticket, &transport_fingerprint)?;
    let current_subjects = ticket
        .entries
        .iter()
        .filter_map(|entry| entry.content_subject.clone())
        .collect::<Vec<_>>();
    let (authenticated_stream_permit, authenticated_revalidator) =
        if let Some(source) = ticket.authenticated_source.as_ref() {
            let content_subjects = current_subjects
                .iter()
                .cloned()
                .map(FileContentSubject::Current)
                .collect::<Vec<_>>();
            let storage = state.storage.clone();
            let workspace_id = source.workspace_id.clone();
            let source_file_ids = source.source_file_ids.clone();
            let actor = source.actor.clone();
            let source_credential = source.source_credential.clone();
            state
                .run_metadata_planning(&source.actor.email.clone(), move || {
                    storage.ensure_download_ticket_authorized(
                        &workspace_id,
                        &source_file_ids,
                        &content_subjects,
                        &actor,
                        &source_credential,
                    )
                })
                .await?;
            let revalidator = authenticated_archive_revalidator(
                state.storage.clone(),
                source.workspace_id.clone(),
                source.source_file_ids.clone(),
                source.actor.clone(),
                source.source_credential.clone(),
            );
            (
                Some(state.try_authenticated_body_stream(&source.actor.email)?),
                Some(revalidator),
            )
        } else {
            (None, None)
        };
    let (public_stream_permit, public_revalidator) = if let Some(share_id) =
        ticket.source_share_id.as_deref()
    {
        let expected_fingerprint = ticket
            .source_share_authorization_fingerprint
            .as_deref()
            .ok_or(ApiError::NotFound)?
            .to_string();
        let share_root_id = ticket
            .source_share_root_id
            .as_deref()
            .ok_or(ApiError::NotFound)?
            .to_string();
        let storage = state.storage.clone();
        let share_id = share_id.to_string();
        let source_file_ids = ticket.source_share_file_ids.clone();
        let current_subjects = current_subjects.clone();
        let initial_storage = storage.clone();
        let initial_share_id = share_id.clone();
        let initial_share_root_id = share_root_id.clone();
        let initial_fingerprint = expected_fingerprint.clone();
        state
            .run_metadata_planning(&format!("share:{share_id}"), move || {
                let share = initial_storage
                    .get_share(&initial_share_id)?
                    .ok_or(ApiError::NotFound)?;
                let expired = share.share.expires_at.as_deref().is_some_and(|value| {
                    DateTime::parse_from_rfc3339(value)
                        .map(|expires_at| expires_at.with_timezone(&Utc) <= Utc::now())
                        .unwrap_or(true)
                });
                if share.share.revoked
                    || expired
                    || !share.share.allow_download
                    || share.share.file_id != initial_share_root_id
                    || initial_storage.file_is_effectively_trashed(&initial_share_root_id)?
                {
                    return Err(ApiError::NotFound);
                }
                initial_storage.ensure_share_archive_ticket_authorized(
                    &initial_share_root_id,
                    &source_file_ids,
                    &current_subjects,
                )?;
                if !constant_time_str_eq(&initial_fingerprint, &share.authorization_fingerprint()) {
                    return Err(ApiError::NotFound);
                }
                Ok(())
            })
            .await?;
        let revalidator = public_archive_revalidator(
            storage,
            share_id.clone(),
            share_root_id,
            expected_fingerprint,
        );
        (
            Some(state.try_public_body_stream(&share_id, &transport_fingerprint)?),
            Some(revalidator),
        )
    } else {
        (None, None)
    };
    let statistics_targets = ticket
        .entries
        .iter()
        .filter_map(|entry| entry.statistics_target.clone())
        .collect::<Vec<_>>();
    let response = streaming_zip::response(
        ticket.entries,
        &ticket.download_name,
        admission_permit,
        (public_stream_permit, authenticated_stream_permit),
        public_revalidator.or(authenticated_revalidator),
    )
    .await?;
    state
        .storage
        .record_file_accesses_best_effort(&statistics_targets, FileAccessKind::Download);
    Ok(response)
}

/// Redeem a short-lived, one-use single-file capability. The blob remains on
/// disk and is streamed directly into the response; no JavaScript or server
/// buffer scales with the file size.
async fn download_file(
    State(state): State<AppState>,
    Path(ticket): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let client_fingerprint = request_client_fingerprint(&headers);
    let client_binding = public_client_binding::from_request(&state, &headers)?;
    let ticket = state
        .file_download_tickets
        .redeem(&ticket, client_binding.as_deref())?;
    let source_share_id = ticket
        .share_authorization
        .as_ref()
        .map(|authorization| authorization.share_id.clone());
    let stream_permit = if let Some(authorization) = ticket.share_authorization.as_ref() {
        revalidate_public_file_ticket(
            &state.storage,
            authorization,
            ticket.disposition,
            &ticket.file_name,
        )?;
        (
            Some(state.try_public_body_stream(&authorization.share_id, client_fingerprint)?),
            None,
        )
    } else if let Some(authorization) = ticket.authorization.as_ref() {
        revalidate_authenticated_file_ticket(&state.storage, authorization)?;
        (
            None,
            Some(state.try_authenticated_body_stream(&authorization.actor.email)?),
        )
    } else {
        (None, None)
    };
    let actual_size = tokio::fs::metadata(&ticket.blob_path).await?.len();
    if actual_size != ticket.expected_size {
        return Err(ApiError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stored blob size does not match download ticket",
        )));
    }
    let range_header = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let disposition = match ticket.disposition {
        crate::download_tickets::FileTicketDisposition::Inline => Disposition::Inline,
        crate::download_tickets::FileTicketDisposition::Attachment => Disposition::Attachment,
    };
    let terminal_share_authorization = ticket.share_authorization.clone();
    let terminal_authenticated_authorization = ticket.authorization.clone();
    let terminal_disposition = ticket.disposition;
    let terminal_file_name = ticket.file_name.clone();
    let response = if let Some(authorization) = terminal_share_authorization {
        let terminal_storage = state.storage.clone();
        serve_blob_file_with_guard_after_open(
            &ticket.file_name,
            &ticket.blob_path,
            range_header,
            disposition,
            stream_permit,
            move || {
                revalidate_public_file_ticket(
                    &terminal_storage,
                    &authorization,
                    terminal_disposition,
                    &terminal_file_name,
                )
            },
        )
        .await?
    } else if let Some(authorization) = terminal_authenticated_authorization {
        let terminal_storage = state.storage.clone();
        serve_blob_file_with_guard_after_open(
            &ticket.file_name,
            &ticket.blob_path,
            range_header,
            disposition,
            stream_permit,
            move || revalidate_authenticated_file_ticket(&terminal_storage, &authorization),
        )
        .await?
    } else {
        serve_blob_file_with_guard(
            &ticket.file_name,
            &ticket.blob_path,
            range_header,
            disposition,
            stream_permit,
        )
        .await?
    };
    if ticket.record_statistics {
        if let Some(target) = ticket.statistics_target {
            let kind = match ticket.disposition {
                crate::download_tickets::FileTicketDisposition::Inline => FileAccessKind::Access,
                crate::download_tickets::FileTicketDisposition::Attachment => {
                    FileAccessKind::Download
                }
            };
            state.storage.record_file_access_best_effort(
                &target.file_id,
                &target.workspace_id,
                kind,
            );
        }
        if let Some(share_id) = source_share_id {
            state.storage.record_unlimited_share_access(&share_id)?;
            state
                .storage
                .insert_receipt("share.access", "public", Some(&share_id))?;
        }
    }
    Ok(response)
}

fn revalidate_public_file_ticket(
    storage: &Storage,
    authorization: &PublicShareFileAuthorization,
    disposition: FileTicketDisposition,
    file_name: &str,
) -> ApiResult<()> {
    let share = storage
        .get_share(&authorization.share_id)?
        .ok_or(ApiError::NotFound)?;
    let expired = share.share.expires_at.as_deref().is_some_and(|value| {
        DateTime::parse_from_rfc3339(value)
            .map(|expires_at| expires_at.with_timezone(&Utc) <= Utc::now())
            .unwrap_or(true)
    });
    if share.share.revoked
        || expired
        || share.share.file_id != authorization.share_root_id
        || storage.file_is_effectively_trashed(&authorization.share_root_id)?
        || (disposition == FileTicketDisposition::Attachment && !share.share.allow_download)
        || (disposition == FileTicketDisposition::Inline
            && !share.share.allow_download
            && !is_safe_inline_file_name(file_name))
        || !constant_time_str_eq(
            &authorization.authorization_fingerprint,
            &share.authorization_fingerprint(),
        )
    {
        return Err(ApiError::NotFound);
    }
    storage.ensure_share_file_ticket_authorized(
        &authorization.share_root_id,
        &authorization.subject.file_id,
        &authorization.subject,
    )
}

fn revalidate_authenticated_file_ticket(
    storage: &Storage,
    authorization: &FileDownloadAuthorization,
) -> ApiResult<()> {
    let source_file_ids = [authorization.subject.file_id().to_string()];
    storage.ensure_download_ticket_authorized(
        &authorization.workspace_id,
        &source_file_ids,
        std::slice::from_ref(&authorization.subject),
        &authorization.actor,
        &authorization.source_credential,
    )
}
