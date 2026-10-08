use std::collections::{HashMap, HashSet};

use rusqlite::{params, Transaction};
use uuid::Uuid;

use crate::{
    error::{ApiError, ApiResult},
    model::{
        DriveFile, FileKind, RcloneFolderCollisionPolicy, RcloneImportPreviewAction,
        RcloneImportSummary,
    },
};

use super::super::super::{
    row_to_file, validate_file_name, MAX_FILE_TREE_DEPTH, MAX_FILE_TREE_NODES,
};
use super::{Mutation, PlannedRcloneImport, PreparedRcloneEntry};

#[derive(Clone)]
struct ResolvedNode {
    file: DriveFile,
    planned: bool,
    resolved_path: String,
    keep_both: bool,
}

impl ResolvedNode {
    fn file(&self) -> &DriveFile {
        &self.file
    }

    fn is_planned(&self) -> bool {
        self.planned
    }

    fn existing(file: DriveFile, resolved_path: String) -> Self {
        Self {
            file,
            planned: false,
            resolved_path,
            keep_both: false,
        }
    }

    fn planned(file: DriveFile, resolved_path: String, keep_both: bool) -> Self {
        Self {
            file,
            planned: true,
            resolved_path,
            keep_both,
        }
    }
}

pub(super) fn plan_rclone_import(
    tx: &Transaction<'_>,
    workspace_id: &str,
    entries: Vec<PreparedRcloneEntry>,
    folder_collision_policy: RcloneFolderCollisionPolicy,
    now: &str,
) -> ApiResult<PlannedRcloneImport> {
    let mut resolved = HashMap::<String, ResolvedNode>::new();
    let mut planned_destinations = HashMap::<(Option<String>, String), ResolvedNode>::new();
    let explicit_folder_paths = entries
        .iter()
        .filter(|entry| matches!(entry.kind, FileKind::Folder))
        .map(|entry| entry.parts.join("/"))
        .collect::<HashSet<_>>();
    let mut explicit_paths = HashSet::new();
    let mut mutations = Vec::<Mutation>::new();
    let mut imported_paths = Vec::with_capacity(entries.len());
    let mut summary = RcloneImportSummary::default();
    let mut actions = Vec::with_capacity(entries.len());

    for entry in entries {
        if entry.parts.len() > MAX_FILE_TREE_DEPTH + 1 {
            return Err(ApiError::Validation(
                "rclone import path exceeds the file-tree depth limit".to_string(),
            ));
        }
        for part in &entry.parts {
            if validate_file_name(part)? != *part {
                return Err(ApiError::Validation(
                    "rclone import path is not canonically normalized".to_string(),
                ));
            }
        }
        if let Some(content) = entry.content.as_ref() {
            let actual_bytes = i64::try_from(content.text.len()).map_err(|_| {
                ApiError::PayloadTooLarge(
                    "rclone import content length cannot be represented".to_string(),
                )
            })?;
            if content.bytes != actual_bytes
                || content.hash.len() != 64
                || !content
                    .hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(ApiError::Validation(
                    "rclone import content metadata is inconsistent".to_string(),
                ));
            }
        }
        let path = entry.parts.join("/");
        if entry.parts.is_empty() || !explicit_paths.insert(path.clone()) {
            return Err(ApiError::Validation(format!(
                "rclone import contains a duplicate or empty path: {path}"
            )));
        }
        let bytes = entry
            .content
            .as_ref()
            .map(|content| content.bytes)
            .unwrap_or(0);
        summary.entries = summary.entries.checked_add(1).ok_or_else(|| {
            ApiError::Validation("rclone import entry count overflow".to_string())
        })?;
        summary.estimated_bytes = summary
            .estimated_bytes
            .checked_add(bytes)
            .ok_or_else(|| ApiError::Validation("rclone import byte count overflow".to_string()))?;

        let mut parent_id: Option<String> = None;
        let mut parent_resolved_path: Option<String> = None;
        for depth in 0..entry.parts.len().saturating_sub(1) {
            let prefix = entry.parts[..=depth].join("/");
            let name = &entry.parts[depth];
            let node = resolve_or_plan_folder(
                tx,
                workspace_id,
                parent_id.as_deref(),
                parent_resolved_path.as_deref(),
                name,
                &prefix,
                explicit_folder_paths.contains(&prefix),
                folder_collision_policy,
                now,
                &mut resolved,
                &mut planned_destinations,
                &mut mutations,
            )?;
            parent_id = Some(node.file().id.clone());
            parent_resolved_path = Some(node.resolved_path.clone());
        }

        let name = entry.parts.last().expect("non-empty path was checked");
        let (final_node, action) = match entry.kind {
            FileKind::Folder => {
                let node = resolve_or_plan_folder(
                    tx,
                    workspace_id,
                    parent_id.as_deref(),
                    parent_resolved_path.as_deref(),
                    name,
                    &path,
                    true,
                    folder_collision_policy,
                    now,
                    &mut resolved,
                    &mut planned_destinations,
                    &mut mutations,
                )?;
                let action = if node.keep_both {
                    summary.created_folders += 1;
                    summary.collisions += 1;
                    "keep_both"
                } else if node.is_planned() {
                    summary.created_folders += 1;
                    "create_folder"
                } else {
                    summary.existing_folders += 1;
                    "exists"
                };
                (node, action)
            }
            FileKind::File => {
                let existing_node = if let Some(node) = resolved.get(&path) {
                    Some(node.clone())
                } else if let Some(node) =
                    planned_destinations.get(&destination_key(parent_id.as_deref(), name))
                {
                    Some(node.clone())
                } else {
                    query_child(tx, workspace_id, parent_id.as_deref(), name)?.map(|file| {
                        ResolvedNode::existing(
                            file,
                            join_resolved_path(parent_resolved_path.as_deref(), name),
                        )
                    })
                };
                match existing_node {
                    Some(node) => {
                        require_active_kind(node.file(), FileKind::File, &path)?;
                        if node.is_planned() {
                            return Err(ApiError::Validation(format!(
                                "rclone path changes a planned folder into a file: {path}"
                            )));
                        }
                        let mut file = node.file().clone();
                        if let Some(content) = entry.content {
                            file.revision = file.revision.checked_add(1).ok_or_else(|| {
                                ApiError::Validation("file revision overflow".to_string())
                            })?;
                            file.content_hash = Some(content.hash.clone());
                            file.size_bytes = Some(content.bytes);
                            file.updated_at = now.to_string();
                            mutations.push(Mutation::Update {
                                file: file.clone(),
                                content,
                            });
                        }
                        summary.updated_files += 1;
                        summary.collisions += 1;
                        (
                            ResolvedNode::existing(
                                file,
                                join_resolved_path(parent_resolved_path.as_deref(), name),
                            ),
                            "update",
                        )
                    }
                    None => {
                        let content_hash =
                            entry.content.as_ref().map(|content| content.hash.clone());
                        let content_bytes = entry
                            .content
                            .as_ref()
                            .map(|content| content.bytes)
                            .unwrap_or(0);
                        let destination = destination_key(parent_id.as_deref(), name);
                        let file = planned_file(
                            workspace_id,
                            parent_id,
                            name,
                            FileKind::File,
                            content_hash,
                            content_bytes,
                            now,
                        );
                        push_create_mutation(&mut mutations, file.clone())?;
                        let node = ResolvedNode::planned(
                            file,
                            join_resolved_path(parent_resolved_path.as_deref(), name),
                            false,
                        );
                        planned_destinations.insert(destination, node.clone());
                        summary.created_files += 1;
                        (node, "create")
                    }
                }
            }
        };
        actions.push(RcloneImportPreviewAction {
            path: path.clone(),
            resolved_path: final_node.resolved_path.clone(),
            file_id: final_node.file().id.clone(),
            kind: final_node.file().kind.clone(),
            action: action.to_string(),
            bytes,
            message: None,
        });
        resolved.insert(path.clone(), final_node);
        imported_paths.push(path);
    }

    let imported = imported_paths
        .iter()
        .map(|path| {
            resolved
                .get(path)
                .map(|node| node.file().clone())
                .ok_or_else(|| {
                    ApiError::Validation("rclone import result lost a planned path".to_string())
                })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(PlannedRcloneImport {
        mutations,
        imported,
        summary,
        actions,
    })
}

#[allow(clippy::too_many_arguments)]
fn resolve_or_plan_folder(
    tx: &Transaction<'_>,
    workspace_id: &str,
    parent_id: Option<&str>,
    parent_resolved_path: Option<&str>,
    name: &str,
    source_path: &str,
    explicit_folder: bool,
    folder_collision_policy: RcloneFolderCollisionPolicy,
    now: &str,
    resolved: &mut HashMap<String, ResolvedNode>,
    planned_destinations: &mut HashMap<(Option<String>, String), ResolvedNode>,
    mutations: &mut Vec<Mutation>,
) -> ApiResult<ResolvedNode> {
    if let Some(node) = resolved.get(source_path) {
        require_active_kind(node.file(), FileKind::Folder, source_path)?;
        return Ok(node.clone());
    }
    let destination = destination_key(parent_id, name);
    let planned = planned_destinations.get(&destination).cloned();
    let active = query_child(tx, workspace_id, parent_id, name)?;
    let destination_is_occupied = active.is_some() || planned.is_some();
    let node = if explicit_folder && destination_is_occupied {
        match folder_collision_policy {
            RcloneFolderCollisionPolicy::Cancel => return Err(ApiError::Conflict),
            RcloneFolderCollisionPolicy::KeepBoth => {
                let name = available_folder_copy_name(
                    tx,
                    workspace_id,
                    parent_id,
                    name,
                    planned_destinations,
                )?;
                let file = planned_file(
                    workspace_id,
                    parent_id.map(str::to_string),
                    &name,
                    FileKind::Folder,
                    None,
                    0,
                    now,
                );
                push_create_mutation(mutations, file.clone())?;
                let node = ResolvedNode::planned(
                    file,
                    join_resolved_path(parent_resolved_path, &name),
                    true,
                );
                planned_destinations.insert(destination_key(parent_id, &name), node.clone());
                node
            }
        }
    } else if let Some(file) = active {
        require_active_kind(&file, FileKind::Folder, source_path)?;
        ResolvedNode::existing(file, join_resolved_path(parent_resolved_path, name))
    } else if planned.is_some() {
        // A distinct incoming source path cannot be routed into a folder the
        // virtual planner already reserved for another path. That would merge
        // source trees before the transaction inserts either folder.
        return Err(ApiError::Conflict);
    } else {
        let file = planned_file(
            workspace_id,
            parent_id.map(str::to_string),
            name,
            FileKind::Folder,
            None,
            0,
            now,
        );
        push_create_mutation(mutations, file.clone())?;
        let node =
            ResolvedNode::planned(file, join_resolved_path(parent_resolved_path, name), false);
        planned_destinations.insert(destination, node.clone());
        node
    };
    resolved.insert(source_path.to_string(), node.clone());
    Ok(node)
}

fn destination_key(parent_id: Option<&str>, name: &str) -> (Option<String>, String) {
    (parent_id.map(str::to_string), name.to_string())
}

fn join_resolved_path(parent: Option<&str>, name: &str) -> String {
    parent
        .map(|parent| format!("{parent}/{name}"))
        .unwrap_or_else(|| name.to_string())
}

fn available_folder_copy_name(
    tx: &Transaction<'_>,
    workspace_id: &str,
    parent_id: Option<&str>,
    requested_name: &str,
    planned_destinations: &HashMap<(Option<String>, String), ResolvedNode>,
) -> ApiResult<String> {
    let first = crate::storage::file_destination::available_copy_name_in_tx(
        tx,
        workspace_id,
        parent_id,
        requested_name,
    )?;
    if !planned_destinations.contains_key(&destination_key(parent_id, &first)) {
        return Ok(first);
    }
    for sequence in 1..=10_001 {
        let candidate =
            crate::storage::derived_names::derive_copy_file_name(requested_name, sequence)?;
        if planned_destinations.contains_key(&destination_key(parent_id, &candidate)) {
            continue;
        }
        if query_child(tx, workspace_id, parent_id, &candidate)?.is_none() {
            return Ok(candidate);
        }
    }
    Err(ApiError::PayloadTooLarge(
        "destination has too many similarly named active files".to_string(),
    ))
}

fn push_create_mutation(mutations: &mut Vec<Mutation>, file: DriveFile) -> ApiResult<()> {
    let created = mutations
        .iter()
        .filter(|mutation| matches!(mutation, Mutation::Create { .. }))
        .count();
    if created >= MAX_FILE_TREE_NODES {
        return Err(ApiError::PayloadTooLarge(format!(
            "rclone import expands beyond the {MAX_FILE_TREE_NODES}-item workspace tree limit"
        )));
    }
    mutations.push(Mutation::Create { file });
    Ok(())
}

fn query_child(
    tx: &Transaction<'_>,
    workspace_id: &str,
    parent_id: Option<&str>,
    name: &str,
) -> ApiResult<Option<DriveFile>> {
    let sql = if parent_id.is_some() {
        "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                content_hash, created_at, updated_at, content_bytes, cover_hash
         FROM files
         WHERE workspace_id = ?1 AND parent_id = ?2 AND name = ?3 AND trashed = 0
         ORDER BY id ASC LIMIT 2"
    } else {
        "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                content_hash, created_at, updated_at, content_bytes, cover_hash
         FROM files
         WHERE workspace_id = ?1 AND parent_id IS NULL AND name = ?3 AND trashed = 0
         ORDER BY id ASC LIMIT 2"
    };
    let mut statement = tx.prepare(sql)?;
    let files = statement
        .query_map(params![workspace_id, parent_id, name], row_to_file)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    match files.as_slice() {
        [] => Ok(None),
        [file] => Ok(Some(file.clone())),
        _ => Err(ApiError::Conflict),
    }
}

fn require_active_kind(file: &DriveFile, expected: FileKind, path: &str) -> ApiResult<()> {
    let matches_kind = matches!(
        (&file.kind, expected),
        (FileKind::File, FileKind::File) | (FileKind::Folder, FileKind::Folder)
    );
    if !matches_kind {
        return Err(ApiError::Validation(format!(
            "rclone path collides with an incompatible entry: {path}"
        )));
    }
    Ok(())
}

fn planned_file(
    workspace_id: &str,
    parent_id: Option<String>,
    name: &str,
    kind: FileKind,
    content_hash: Option<String>,
    content_bytes: i64,
    now: &str,
) -> DriveFile {
    let size_bytes = matches!(kind, FileKind::File).then_some(content_bytes);
    DriveFile {
        id: Uuid::now_v7().to_string(),
        workspace_id: workspace_id.to_string(),
        parent_id,
        name: name.to_string(),
        kind,
        revision: 1,
        trashed: false,
        starred: false,
        content_hash,
        created_at: now.to_string(),
        updated_at: now.to_string(),
        size_bytes,
        folder_size_bytes: None,
        has_cover: false,
    }
}
