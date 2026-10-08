use serde::Serialize;

use crate::{
    auth::opaque_audit_ref,
    model::{
        AuthAttemptDebug, DropLink, FilePreview, FolderTemplate, Receipt, ShareLink, SyncChange,
    },
};

mod capability_relations;

pub(crate) use capability_relations::{
    emails, notifications, DebugEmailResponse, DebugNotificationsResponse,
};

#[derive(Serialize)]
pub(crate) struct DebugReceipt {
    receipt_ref: String,
    kind: String,
    actor_ref: String,
    target_ref: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
pub(crate) struct DebugFolderTemplateItem {
    item_ref: String,
    path: String,
    kind: crate::model::FileKind,
    content_present: bool,
    content_bytes: usize,
    created_at: String,
}

#[derive(Serialize)]
pub(crate) struct DebugFolderTemplate {
    template_ref: String,
    workspace_id: String,
    name: String,
    description_present: bool,
    created_by_ref: String,
    created_at: String,
    items: Vec<DebugFolderTemplateItem>,
}

#[derive(Serialize)]
pub(crate) struct DebugFilePreview {
    file_id: String,
    workspace_id: String,
    revision: i64,
    kind: String,
    content_present: bool,
    content_bytes: usize,
    thumbnail_present: bool,
    thumbnail_content_type: Option<String>,
    width: Option<i64>,
    height: Option<i64>,
    status: String,
    updated_at: String,
}

#[derive(Serialize)]
pub(crate) struct DebugShareLink {
    share_ref: String,
    file_id: String,
    kind: String,
    expires_at: Option<String>,
    expires_in_seconds: Option<i64>,
    revoked: bool,
    created_at: String,
    access_count: i64,
    last_accessed_at: Option<String>,
    allow_download: bool,
    recipient_note_present: bool,
    max_uses: Option<i64>,
    uses_remaining: Option<i64>,
}

#[derive(Serialize)]
pub(crate) struct DebugDropLink {
    drop_ref: String,
    workspace_id: String,
    name: String,
    expires_at: String,
    revoked: bool,
    created_at: String,
    upload_count: i64,
    last_uploaded_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct DebugSyncChange {
    id: i64,
    workspace_id: String,
    kind: String,
    entity_type: String,
    entity_ref: String,
    actor_ref: String,
    receipt_ref: String,
    created_at: String,
}

pub(crate) fn attempt_key_ref(key: &str, signing_key: &str) -> String {
    opaque_audit_ref(&format!("auth-attempt\0{key}"), signing_key).replacen(
        "target-v1-",
        "auth-attempt-v1-",
        1,
    )
}

pub(crate) fn drop_ref(drop_id: &str, signing_key: &str) -> String {
    opaque_audit_ref(&format!("drop\0{drop_id}"), signing_key).replacen("target-v1-", "drop-v1-", 1)
}

pub(crate) fn auth_attempts(
    attempts: Vec<AuthAttemptDebug>,
    signing_key: &str,
) -> Vec<AuthAttemptDebug> {
    attempts
        .into_iter()
        .map(|mut attempt| {
            if is_capability_attempt_scope(&attempt.scope) {
                attempt.key = attempt_key_ref(&attempt.key, signing_key);
                attempt.actor_email = attempt.actor_email.as_deref().map(|value| {
                    opaque_audit_ref(&format!("capability\0{value}"), signing_key).replacen(
                        "target-v1-",
                        "capability-v1-",
                        1,
                    )
                });
            }
            attempt
        })
        .collect()
}

/// Auth-attempt rows for all Share and Drop operations are indexed by their
/// raw capability identifier. Debug/admin views must expose only stable opaque
/// references, including passwordless content and download rate-limit rows.
pub(crate) fn is_capability_attempt_scope(scope: &str) -> bool {
    scope.starts_with("share_") || scope.starts_with("drop_")
}

pub(crate) fn receipts(receipts: Vec<Receipt>, signing_key: &str) -> Vec<DebugReceipt> {
    receipts
        .into_iter()
        .map(|receipt| DebugReceipt {
            receipt_ref: opaque_audit_ref(&format!("receipt\0{}", receipt.id), signing_key)
                .replacen("target-v1-", "receipt-v1-", 1),
            kind: receipt.kind,
            actor_ref: opaque_audit_ref(&format!("actor\0{}", receipt.actor), signing_key)
                .replacen("target-v1-", "actor-v1-", 1),
            target_ref: receipt
                .target_id
                .map(|target| opaque_audit_ref(&format!("receipt-target\0{target}"), signing_key)),
            created_at: receipt.created_at,
        })
        .collect()
}

pub(crate) fn folder_templates(
    templates: Vec<FolderTemplate>,
    signing_key: &str,
) -> Vec<DebugFolderTemplate> {
    templates
        .into_iter()
        .map(|template| DebugFolderTemplate {
            template_ref: opaque_audit_ref(
                &format!("folder-template\0{}", template.id),
                signing_key,
            )
            .replacen("target-v1-", "template-v1-", 1),
            workspace_id: template.workspace_id,
            name: template.name,
            description_present: template.description.is_some(),
            created_by_ref: opaque_audit_ref(
                &format!("template-actor\0{}", template.created_by),
                signing_key,
            )
            .replacen("target-v1-", "actor-v1-", 1),
            created_at: template.created_at,
            items: template
                .items
                .into_iter()
                .map(|item| {
                    let content_bytes = item.content.as_deref().map(str::len).unwrap_or(0);
                    DebugFolderTemplateItem {
                        item_ref: opaque_audit_ref(
                            &format!("folder-template-item\0{}", item.id),
                            signing_key,
                        )
                        .replacen("target-v1-", "template-item-v1-", 1),
                        path: item.path,
                        kind: item.kind,
                        content_present: content_bytes != 0,
                        content_bytes,
                        created_at: item.created_at,
                    }
                })
                .collect(),
        })
        .collect()
}

pub(crate) fn preview(preview: FilePreview) -> DebugFilePreview {
    DebugFilePreview {
        file_id: preview.file_id,
        workspace_id: preview.workspace_id,
        revision: preview.revision,
        kind: preview.kind,
        content_present: !preview.content.is_empty(),
        content_bytes: preview.content.len(),
        thumbnail_present: preview.thumbnail_hash.is_some(),
        thumbnail_content_type: preview.thumbnail_content_type,
        width: preview.width,
        height: preview.height,
        status: preview.status,
        updated_at: preview.updated_at,
    }
}

pub(crate) fn previews(previews: Vec<FilePreview>) -> Vec<DebugFilePreview> {
    previews.into_iter().map(preview).collect()
}

pub(crate) fn shares(shares: Vec<ShareLink>, signing_key: &str) -> Vec<DebugShareLink> {
    shares
        .into_iter()
        .map(|share| DebugShareLink {
            share_ref: opaque_audit_ref(&format!("share\0{}", share.id), signing_key).replacen(
                "target-v1-",
                "share-v1-",
                1,
            ),
            file_id: share.file_id,
            kind: share.kind,
            expires_at: share.expires_at,
            expires_in_seconds: share.expires_in_seconds,
            revoked: share.revoked,
            created_at: share.created_at,
            access_count: share.access_count,
            last_accessed_at: share.last_accessed_at,
            allow_download: share.allow_download,
            recipient_note_present: share.recipient_note.is_some(),
            max_uses: share.max_uses,
            uses_remaining: share.uses_remaining,
        })
        .collect()
}

pub(crate) fn drops(drops: Vec<DropLink>, signing_key: &str) -> Vec<DebugDropLink> {
    drops
        .into_iter()
        .map(|drop| DebugDropLink {
            drop_ref: drop_ref(&drop.id, signing_key),
            workspace_id: drop.workspace_id,
            name: drop.name,
            expires_at: drop.expires_at,
            revoked: drop.revoked,
            created_at: drop.created_at,
            upload_count: drop.upload_count,
            last_uploaded_at: drop.last_uploaded_at,
        })
        .collect()
}

pub(crate) fn sync_changes(changes: Vec<SyncChange>, signing_key: &str) -> Vec<DebugSyncChange> {
    changes
        .into_iter()
        .map(|change| DebugSyncChange {
            id: change.id,
            workspace_id: change.workspace_id,
            kind: change.kind,
            entity_type: change.entity_type,
            entity_ref: opaque_audit_ref(
                &format!("sync-entity\0{}", change.entity_id),
                signing_key,
            )
            .replacen("target-v1-", "entity-v1-", 1),
            actor_ref: opaque_audit_ref(&format!("sync-actor\0{}", change.actor), signing_key)
                .replacen("target-v1-", "actor-v1-", 1),
            receipt_ref: opaque_audit_ref(
                &format!("sync-receipt\0{}", change.receipt_id),
                signing_key,
            )
            .replacen("target-v1-", "receipt-v1-", 1),
            created_at: change.created_at,
        })
        .collect()
}
