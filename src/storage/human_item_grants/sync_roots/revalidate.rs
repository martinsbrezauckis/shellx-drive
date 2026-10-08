//! Bounded authority refresh for roots already configured on one desktop.

use std::collections::BTreeSet;

use crate::model::SyncRootReplacement;

use super::*;

pub(super) fn ensure_full_root_publication_limit(count: usize) -> ApiResult<()> {
    if count > 2_000 {
        Err(ApiError::SyncRootDiscoveryOverflow)
    } else {
        Ok(())
    }
}

impl Storage {
    pub fn revalidate_configured_sync_roots(
        &self,
        root_ids: &[String],
        actor: &Actor,
        credential: &DriveCredential,
    ) -> ApiResult<(Vec<SyncRoot>, Vec<String>, Vec<SyncRootReplacement>)> {
        if root_ids.len() > 100
            || root_ids.iter().any(|id| id.is_empty() || id.len() > 4_096)
            || root_ids.iter().collect::<BTreeSet<_>>().len() != root_ids.len()
        {
            return Err(ApiError::Validation(
                "configured root IDs must be distinct and limited to 100".to_string(),
            ));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        authorization::ensure_source_credential_active(&tx, actor, credential)?;
        let actor = sync_actor(actor);
        let mut roots = Vec::with_capacity(root_ids.len());
        let mut revoked_ids = Vec::new();
        let mut replacements = Vec::new();
        for root_id in root_ids {
            if let Some(grant_id) = root_id.strip_prefix("item-grant:") {
                // The old grant row is only used to identify a requested file.
                // Publish a replacement only after current authorization and
                // canonicalization prove the same exact file subject.
                let file_id: Option<String> = tx
                    .query_row(
                        "SELECT root_file_id FROM human_item_grants WHERE id = ?1",
                        params![grant_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                let canonical = match file_id {
                    Some(file_id) => {
                        page::canonical_item_root_at_file_in_tx(&tx, &file_id, &actor)?
                    }
                    None => None,
                };
                match canonical {
                    Some(root) if root.id == *root_id => roots.push(root),
                    Some(root) => replacements.push(SyncRootReplacement {
                        requested_id: root_id.clone(),
                        root,
                    }),
                    None => revoked_ids.push(root_id.clone()),
                }
                continue;
            }
            match resolve_sync_root_in_tx(&tx, root_id, &actor) {
                Ok(root) => roots.push(root),
                Err(ApiError::NotFound | ApiError::Forbidden) => revoked_ids.push(root_id.clone()),
                Err(error) => return Err(error),
            }
        }
        tx.commit()?;
        Ok((roots, revoked_ids, replacements))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_root_publication_has_typed_two_thousand_root_bound() {
        assert!(ensure_full_root_publication_limit(2_000).is_ok());
        assert!(matches!(
            ensure_full_root_publication_limit(2_001),
            Err(ApiError::SyncRootDiscoveryOverflow)
        ));
    }
}
