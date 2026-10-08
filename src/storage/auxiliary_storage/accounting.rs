use crate::error::{ApiError, ApiResult};

use super::WorkspaceAuxiliaryStorageDelta;

impl WorkspaceAuxiliaryStorageDelta {
    pub(crate) fn checked_total(self) -> ApiResult<i64> {
        [
            self.file_metadata_bytes,
            self.metadata_fts_projection_bytes,
            self.comment_reply_body_bytes,
            self.notification_bytes,
            self.email_outbox_bytes,
        ]
        .into_iter()
        .try_fold(0_i64, |total, value| {
            total.checked_add(value).ok_or_else(|| {
                ApiError::Validation("workspace auxiliary storage delta overflow".to_string())
            })
        })
    }

    pub(crate) fn checked_difference(self, previous: Self) -> ApiResult<Self> {
        Ok(Self {
            file_metadata_bytes: checked_subtract(
                self.file_metadata_bytes,
                previous.file_metadata_bytes,
                "file metadata",
            )?,
            metadata_fts_projection_bytes: checked_subtract(
                self.metadata_fts_projection_bytes,
                previous.metadata_fts_projection_bytes,
                "metadata FTS projection",
            )?,
            comment_reply_body_bytes: checked_subtract(
                self.comment_reply_body_bytes,
                previous.comment_reply_body_bytes,
                "comment/reply bodies",
            )?,
            notification_bytes: checked_subtract(
                self.notification_bytes,
                previous.notification_bytes,
                "notifications",
            )?,
            email_outbox_bytes: checked_subtract(
                self.email_outbox_bytes,
                previous.email_outbox_bytes,
                "workspace email outbox",
            )?,
        })
    }
}

fn checked_subtract(next: i64, previous: i64, label: &str) -> ApiResult<i64> {
    next.checked_sub(previous)
        .ok_or_else(|| ApiError::Validation(format!("{label} delta overflow")))
}

pub(super) fn checked_usage_total(
    file_metadata_bytes: i64,
    metadata_fts_projection_bytes: i64,
    comment_reply_body_bytes: i64,
    notification_bytes: i64,
    email_outbox_bytes: i64,
) -> ApiResult<i64> {
    [
        file_metadata_bytes,
        metadata_fts_projection_bytes,
        comment_reply_body_bytes,
        notification_bytes,
        email_outbox_bytes,
    ]
    .into_iter()
    .try_fold(0_i64, |total, value| {
        if value < 0 {
            return Err(ApiError::Validation(
                "workspace auxiliary storage ledger contains a negative category".to_string(),
            ));
        }
        total.checked_add(value).ok_or_else(|| {
            ApiError::Validation("workspace auxiliary storage total overflow".to_string())
        })
    })
}
