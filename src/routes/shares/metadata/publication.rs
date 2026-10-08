use chrono::Utc;

use crate::{
    error::{ApiError, ApiResult},
    model::{DriveFile, PublicShareMetadata, ShareEntry},
    share_access_tokens,
    storage::ClaimedShareAccess,
};

use super::MAX_PUBLIC_SHARE_METADATA_BYTES;

pub(super) struct MetadataPublication {
    pub target: DriveFile,
    pub entries: Option<Vec<ShareEntry>>,
    pub folder_size_bytes: Option<i64>,
    pub requires_password: bool,
    pub share_id: String,
    pub authorization_fingerprint: String,
    pub client_fingerprint: String,
    pub signing_secret: String,
}

impl MetadataPublication {
    pub(super) fn encode(self, claimed: &ClaimedShareAccess) -> ApiResult<Vec<u8>> {
        let share = &claimed.share;
        let access_token = if share.max_uses.is_none() {
            Some(share_access_tokens::mint(
                &self.share_id,
                &self.authorization_fingerprint,
                &self.client_fingerprint,
                Utc::now()
                    .timestamp()
                    .saturating_add(share_access_tokens::TTL_SECONDS),
                &self.signing_secret,
            )?)
        } else {
            claimed.access_token.clone()
        };
        let metadata = PublicShareMetadata {
            kind: self.target.kind.as_db_str().to_string(),
            name: self.target.name,
            size_bytes: self.target.size_bytes,
            folder_size_bytes: self.folder_size_bytes,
            updated_at: self.target.updated_at,
            permission: "read".to_string(),
            expires_at: share.expires_at.clone(),
            allow_download: share.allow_download,
            recipient_note: share.recipient_note.clone(),
            max_uses: share.max_uses,
            access_count: share.access_count,
            uses_remaining: share.uses_remaining,
            access_token,
            requires_password: self.requires_password,
            entries: self.entries,
        };
        let bytes = serde_json::to_vec(&metadata).map_err(|error| {
            ApiError::Maintenance(format!("could not size public share metadata: {error}"))
        })?;
        if bytes.len() > MAX_PUBLIC_SHARE_METADATA_BYTES {
            return Err(ApiError::PayloadTooLarge(format!(
                "public share metadata exceeds its {MAX_PUBLIC_SHARE_METADATA_BYTES}-byte response limit"
            )));
        }
        Ok(bytes)
    }
}
