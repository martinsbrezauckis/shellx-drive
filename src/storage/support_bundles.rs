use chrono::Utc;
use rusqlite::{params, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential},
    error::ApiResult,
    model::{Receipt, SupportBundleMetadata},
};

use super::{authorization, insert_receipt_rows, new_receipt, Storage};

impl Storage {
    /// Record a generated bundle only if its exact current administrator
    /// credential remains valid at the write transaction's linearization point.
    pub(crate) fn create_support_bundle_authorized(
        &self,
        debug_export_bytes: i64,
        logs_count: i64,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(SupportBundleMetadata, Receipt)> {
        let receipt = new_receipt("support_bundle.create", &actor.email, None);
        let metadata = SupportBundleMetadata {
            id: Uuid::now_v7().to_string(),
            receipt_id: receipt.id.clone(),
            generated_at: Utc::now().to_rfc3339(),
            debug_export_bytes,
            logs_count,
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        tx.execute(
            "INSERT INTO support_bundles (
                id, receipt_id, generated_at, debug_export_bytes, logs_count
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &metadata.id,
                &metadata.receipt_id,
                &metadata.generated_at,
                metadata.debug_export_bytes,
                metadata.logs_count,
            ],
        )?;
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((metadata, receipt))
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    use crate::{
        auth::{Actor, AuthMode, DriveCredential},
        error::ApiError,
        storage::Storage,
    };

    #[test]
    fn revoked_admin_session_cannot_record_bundle_or_receipt() {
        let data = tempfile::tempdir().unwrap();
        let storage = Storage::open(data.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let email = "support-revoked-admin@example.test";
        let (account, _) = storage
            .bootstrap_auth_account(email, "stored-password-hash")
            .unwrap();
        let session_id = Uuid::now_v7().to_string();
        storage
            .record_auth_session(
                &session_id,
                email,
                "local-password",
                &account.user_id,
                "support-revoked-session-hash",
                &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            )
            .unwrap();
        let actor = Actor {
            email: email.to_string(),
            is_admin: true,
            auth_mode: AuthMode::LocalAccount,
            allowed_workspace_ids: None,
        };
        let credential = DriveCredential::UserSession(session_id.clone());
        storage
            .ensure_admin_publication_authorized(&actor, &credential)
            .unwrap();
        storage.revoke_auth_session(&session_id, email).unwrap();

        assert!(matches!(
            storage.create_support_bundle_authorized(1, 1, &actor, &credential),
            Err(ApiError::Unauthenticated)
        ));
        let conn = storage.conn.lock().unwrap();
        let bundles: i64 = conn
            .query_row("SELECT COUNT(*) FROM support_bundles", [], |row| row.get(0))
            .unwrap();
        let receipts: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM receipts WHERE kind = 'support_bundle.create'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(bundles, 0);
        assert_eq!(receipts, 0);
    }
}
