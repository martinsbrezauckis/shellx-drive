use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{DriveGroup, GroupMember, Receipt},
};

use super::{authorization, insert_receipt_rows, new_receipt, validate_group_name, Storage};

impl Storage {
    pub(crate) fn create_group_authorized(
        &self,
        name: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(DriveGroup, Receipt)> {
        let group = DriveGroup {
            id: Uuid::now_v7().to_string(),
            name: validate_group_name(name)?,
            created_by: actor.email.clone(),
            created_at: Utc::now().to_rfc3339(),
        };
        let receipt = new_receipt("group.create", &actor.email, Some(&group.id));
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        tx.execute(
            r#"INSERT INTO "groups" (id, name, created_by, created_at)
               VALUES (?1, ?2, ?3, ?4)"#,
            params![group.id, group.name, group.created_by, group.created_at],
        )?;
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((group, receipt))
    }

    pub(crate) fn upsert_group_member_authorized(
        &self,
        group_id: &str,
        email: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(GroupMember, Receipt)> {
        let now = Utc::now().to_rfc3339();
        let user_id = Uuid::now_v7().to_string();
        let receipt = new_receipt("group.member.upsert", &actor.email, Some(group_id));
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
            tx.query_row(
                r#"SELECT 1 FROM "groups" WHERE id = ?1"#,
                params![group_id],
                |_| Ok(()),
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
            tx.execute(
                "INSERT INTO users (id, email, created_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(email) DO NOTHING",
                params![&user_id, email, &now],
            )?;
            let user_id: String = tx.query_row(
                "SELECT id FROM users WHERE email = ?1",
                params![email],
                |row| row.get(0),
            )?;
            tx.execute(
                "INSERT INTO group_members (group_id, user_id, created_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(group_id, user_id) DO NOTHING",
                params![group_id, user_id, now],
            )?;
            insert_receipt_rows(&tx, &receipt)?;
            tx.commit()?;
        }
        let member = self
            .group_member_by_email(group_id, email)?
            .ok_or(ApiError::NotFound)?;
        Ok((member, receipt))
    }

    pub(crate) fn remove_group_member_authorized(
        &self,
        group_id: &str,
        email: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        let receipt = new_receipt("group.member.remove", &actor.email, Some(group_id));
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        let user_id = tx
            .query_row(
                "SELECT users.id
                 FROM group_members JOIN users ON users.id = group_members.user_id
                 WHERE group_members.group_id = ?1 AND users.email = ?2",
                params![group_id, email],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        tx.execute(
            "DELETE FROM group_members WHERE group_id = ?1 AND user_id = ?2",
            params![group_id, user_id],
        )?;
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }
}
