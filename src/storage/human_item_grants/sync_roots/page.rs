//! Keyset discovery of effective roots. Candidate grant rows are never published:
//! each file is independently resolved against all applicable ancestor grants.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::model::SyncRootPageResponse;

use super::*;

const PAGE_ROOT_LIMIT: usize = 50;
const ITEM_SCAN_LIMIT: usize = 16;
const PAGE_JSON_LIMIT: usize = 1024 * 1024;
const CURSOR_LIMIT: usize = 2048;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
enum Phase {
    Private,
    Owner,
    Shared,
    Item,
}

impl Phase {
    fn next(self) -> Option<Self> {
        match self {
            Self::Private => Some(Self::Owner),
            Self::Owner => Some(Self::Shared),
            Self::Shared => Some(Self::Item),
            Self::Item => None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct PageCursor {
    phase: Phase,
    key: String,
}

fn invalid_cursor() -> ApiError {
    ApiError::Validation("invalid sync root page cursor".to_string())
}

fn cursor_mac(
    payload: &[u8],
    actor: &Actor,
    credential: &DriveCredential,
    signing_key: &str,
) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes()).expect("HMAC key");
    for part in [
        b"shellx-drive-sync-root-page-v1".as_slice(),
        payload,
        actor.email.as_bytes(),
        format!("{:?}", actor.auth_mode).as_bytes(),
    ] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    let (kind, identity) = match credential {
        DriveCredential::Operator => ("operator", ""),
        DriveCredential::AppToken(id) => ("app", id.as_str()),
        DriveCredential::UserSession(id) => ("session", id.as_str()),
        DriveCredential::DelegatedAgentToken(id) => ("delegated", id.as_str()),
    };
    for part in [kind.as_bytes(), identity.as_bytes()] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    match actor.allowed_workspace_ids.as_ref() {
        None => mac.update(b"unrestricted"),
        Some(ids) => {
            mac.update(b"scoped");
            let mut ids = ids.iter().collect::<Vec<_>>();
            ids.sort_unstable();
            for id in ids {
                mac.update(&(id.len() as u64).to_be_bytes());
                mac.update(id.as_bytes());
            }
        }
    }
    mac
}

fn encode_cursor(
    cursor: &PageCursor,
    actor: &Actor,
    credential: &DriveCredential,
    signing_key: &str,
) -> ApiResult<String> {
    let payload = serde_json::to_vec(cursor).map_err(|_| invalid_cursor())?;
    let tag = cursor_mac(&payload, actor, credential, signing_key)
        .finalize()
        .into_bytes();
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(tag)
    ))
}

fn decode_cursor(
    encoded: &str,
    actor: &Actor,
    credential: &DriveCredential,
    signing_key: &str,
) -> ApiResult<PageCursor> {
    if encoded.is_empty() || encoded.len() > CURSOR_LIMIT {
        return Err(invalid_cursor());
    }
    let (payload, tag) = encoded.split_once('.').ok_or_else(invalid_cursor)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| invalid_cursor())?;
    let tag = URL_SAFE_NO_PAD.decode(tag).map_err(|_| invalid_cursor())?;
    cursor_mac(&payload, actor, credential, signing_key)
        .verify_slice(&tag)
        .map_err(|_| invalid_cursor())?;
    let cursor: PageCursor = serde_json::from_slice(&payload).map_err(|_| invalid_cursor())?;
    if cursor.key.len() > 4096 {
        return Err(invalid_cursor());
    }
    Ok(cursor)
}

fn workspace_page_sql(phase: Phase) -> String {
    const NOT_PRIVATE: &str = "AND NOT EXISTS (SELECT 1 FROM account_private_workspaces p WHERE p.user_id = u.id AND p.workspace_id = wm.workspace_id)";
    let member_phase = match phase {
        Phase::Private => "AND EXISTS (SELECT 1 FROM account_private_workspaces p WHERE p.user_id = u.id AND p.workspace_id = wm.workspace_id)".to_string(),
        Phase::Owner => format!("AND wm.role = 'owner' {NOT_PRIVATE}"),
        Phase::Shared => format!("AND wm.role <> 'owner' {NOT_PRIVATE}"),
        Phase::Item => unreachable!(),
    };
    let member = format!(
        "SELECT wm.workspace_id AS id FROM users u
         CROSS JOIN workspace_members wm INDEXED BY idx_workspace_members_actor_access
         CROSS JOIN workspaces w
         WHERE u.email = ?1 AND wm.user_id = u.id
           AND w.id = wm.workspace_id AND w.archived_at IS NULL
           AND wm.workspace_id > ?2
           AND (wm.expires_at IS NULL OR julianday(wm.expires_at) > julianday('now'))
           AND (?4 IS NULL OR EXISTS (SELECT 1 FROM json_each(?4) scope WHERE scope.value = wm.workspace_id))
           {member_phase} ORDER BY wm.workspace_id LIMIT ?3"
    );
    if phase != Phase::Shared {
        return member;
    }
    let group =
        "SELECT DISTINCT wgg.workspace_id AS id FROM users u
         CROSS JOIN group_members gm INDEXED BY idx_group_members_actor_access
         CROSS JOIN workspace_group_grants wgg INDEXED BY idx_workspace_group_grants_access
         CROSS JOIN workspaces w
         WHERE u.email = ?1 AND gm.user_id = u.id AND wgg.group_id = gm.group_id
           AND w.id = wgg.workspace_id AND w.archived_at IS NULL
           AND wgg.workspace_id > ?2
           AND (?4 IS NULL OR EXISTS (SELECT 1 FROM json_each(?4) scope WHERE scope.value = wgg.workspace_id))
           AND NOT EXISTS (SELECT 1 FROM account_private_workspaces p WHERE p.user_id = u.id AND p.workspace_id = wgg.workspace_id)
           AND NOT EXISTS (SELECT 1 FROM workspace_members own WHERE own.user_id = u.id AND own.workspace_id = wgg.workspace_id AND own.role = 'owner' AND (own.expires_at IS NULL OR julianday(own.expires_at) > julianday('now')))
         ORDER BY wgg.workspace_id LIMIT ?3".to_string();
    format!(
        "WITH member_page AS ({member}), group_page AS ({group})
         SELECT id FROM member_page UNION SELECT id FROM group_page ORDER BY id LIMIT ?3"
    )
}

fn workspace_candidate_ids_in_tx(
    tx: &Transaction<'_>,
    actor: &Actor,
    phase: Phase,
    after: &str,
    page_limit: usize,
) -> ApiResult<Vec<String>> {
    let scope = scope_json(actor)?;
    let sql = workspace_page_sql(phase);
    let mut stmt = tx.prepare(&sql)?;
    let rows = stmt
        .query_map(
            params![actor.email, after, (page_limit + 1) as i64, scope],
            |row| row.get(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn scope_json(actor: &Actor) -> ApiResult<Option<String>> {
    actor
        .allowed_workspace_ids
        .as_ref()
        .map(|ids| {
            let mut sorted = ids.iter().collect::<Vec<_>>();
            sorted.sort_unstable();
            serde_json::to_string(&sorted)
        })
        .transpose()
        .map_err(|_| ApiError::Validation("invalid workspace scope".to_string()))
}

fn item_page_sql(scoped: bool) -> String {
    let (everyone_source, everyone_scope) = if scoped {
        (
            "json_each(?4) scope CROSS JOIN human_item_grants g INDEXED BY idx_human_item_grants_scoped_everyone_page",
            "AND g.workspace_id = scope.value",
        )
    } else {
        (
            "human_item_grants g INDEXED BY idx_human_item_grants_everyone_page",
            "AND ?4 IS NULL",
        )
    };
    format!(
        "WITH direct AS (
           SELECT g.root_file_id AS id FROM users u
           CROSS JOIN human_item_grants g INDEXED BY idx_human_item_grants_account_current
           CROSS JOIN files f
           WHERE u.email = ?1 AND g.principal_kind = 'account'
             AND g.principal_ref = u.id AND f.id = g.root_file_id AND f.trashed = 0
             AND EXISTS (SELECT 1 FROM auth_accounts a WHERE a.user_id = u.id AND a.disabled_at IS NULL)
             AND g.revoked_at IS NULL AND g.publication_pending = 0
             AND g.root_file_id > ?2
             AND (g.expires_at IS NULL OR julianday(g.expires_at) > julianday('now'))
             AND (?4 IS NULL OR EXISTS (SELECT 1 FROM json_each(?4) scope WHERE scope.value = g.workspace_id))
           ORDER BY g.root_file_id LIMIT ?3
         ), grouped AS (
           SELECT DISTINCT g.root_file_id AS id FROM users u
           CROSS JOIN group_members gm INDEXED BY idx_group_members_actor_access
           CROSS JOIN human_item_grants g INDEXED BY idx_human_item_grants_group_current
           CROSS JOIN files f
           WHERE u.email = ?1 AND g.principal_kind = 'group'
             AND gm.user_id = u.id AND g.principal_ref = gm.group_id
             AND f.id = g.root_file_id AND f.trashed = 0
             AND EXISTS (SELECT 1 FROM auth_accounts a WHERE a.user_id = u.id AND a.disabled_at IS NULL)
             AND g.revoked_at IS NULL AND g.publication_pending = 0
             AND g.root_file_id > ?2
             AND (g.expires_at IS NULL OR julianday(g.expires_at) > julianday('now'))
             AND (?4 IS NULL OR EXISTS (SELECT 1 FROM json_each(?4) scope WHERE scope.value = g.workspace_id))
           ORDER BY g.root_file_id LIMIT ?3
         ), everyone AS (
           SELECT g.root_file_id AS id FROM {everyone_source}
           CROSS JOIN files f
           WHERE g.principal_kind = 'everyone' AND g.revoked_at IS NULL
             AND f.id = g.root_file_id AND f.trashed = 0
             AND g.publication_pending = 0 AND g.root_file_id > ?2
             {everyone_scope}
             AND (g.expires_at IS NULL OR julianday(g.expires_at) > julianday('now'))
             AND EXISTS (SELECT 1 FROM auth_accounts a WHERE a.email = ?1 AND a.disabled_at IS NULL)
           ORDER BY g.root_file_id LIMIT ?3
         )
         SELECT id FROM direct UNION SELECT id FROM grouped UNION SELECT id FROM everyone
         ORDER BY id LIMIT ?3"
    )
}

fn item_candidate_ids_in_tx(
    tx: &Transaction<'_>,
    actor: &Actor,
    after: &str,
) -> ApiResult<Vec<String>> {
    let scope = scope_json(actor)?;
    let sql = item_page_sql(scope.is_some());
    let mut stmt = tx.prepare(&sql)?;
    let rows = stmt
        .query_map(
            params![actor.email, after, (ITEM_SCAN_LIMIT + 1) as i64, scope],
            |row| row.get(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub(super) fn canonical_item_root_at_file_in_tx(
    tx: &Transaction<'_>,
    file_id: &str,
    actor: &Actor,
) -> ApiResult<Option<SyncRoot>> {
    let ancestry = match live_ancestry_in_tx(tx, file_id) {
        Ok(ancestry) => ancestry,
        Err(ApiError::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(file) = ancestry.first() else {
        return Ok(None);
    };
    if actor
        .allowed_workspace_ids
        .as_ref()
        .is_some_and(|ids| !ids.contains(&file.workspace_id))
        || whole_workspace_role_in_tx(tx, &file.workspace_id, &actor.email)?.is_some()
    {
        return Ok(None);
    }
    let workspace_live: bool = tx
        .query_row(
            "SELECT archived_at IS NULL FROM workspaces WHERE id = ?1",
            [&file.workspace_id],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(false);
    if !workspace_live {
        return Ok(None);
    }
    for ancestor in ancestry.iter().rev() {
        let mut grants = matching_grants_at_root_in_tx(tx, &ancestor.id, &actor.email)?;
        if grants.is_empty() {
            continue;
        }
        if ancestor.id != file_id {
            return Ok(None);
        }
        grants.sort_by(|a, b| a.id.cmp(&b.id));
        let stable = grants.first().ok_or(ApiError::NotFound)?;
        let role = grants
            .iter()
            .map(|grant| grant.role)
            .max_by_key(|role| role_rank(*role))
            .ok_or(ApiError::NotFound)?;
        let label = tx.query_row("SELECT name FROM files WHERE id = ?1", [file_id], |row| {
            row.get(0)
        })?;
        return Ok(Some(SyncRoot {
            id: format!("item-grant:{}", stable.id),
            kind: "item_grant".to_string(),
            workspace_id: file.workspace_id.clone(),
            root_file_id: Some(file_id.to_string()),
            grant_id: Some(stable.id.clone()),
            owner_label: workspace_owner_label_in_tx(tx, &file.workspace_id)?,
            role: role.as_db_str().to_string(),
            expires_at: stable.expires_at.clone(),
            label,
            access_generation: access_generation_in_tx(tx)?,
            action_capabilities: item_action_capabilities_in_tx(tx, file_id, actor)?.1,
        }));
    }
    Ok(None)
}

fn push_bounded(roots: &mut Vec<SyncRoot>, root: SyncRoot, bytes: &mut usize) -> ApiResult<bool> {
    let size = serde_json::to_vec(&root)
        .map_err(|_| ApiError::PayloadTooLarge("sync root serialization failed".to_string()))?
        .len();
    if size > PAGE_JSON_LIMIT - 4096 {
        return Err(ApiError::PayloadTooLarge(
            "sync root exceeds page byte limit".to_string(),
        ));
    }
    if *bytes + size > PAGE_JSON_LIMIT - 4096 {
        return Ok(false);
    }
    *bytes += size;
    roots.push(root);
    Ok(true)
}

impl Storage {
    pub fn list_sync_root_page(
        &self,
        actor: &Actor,
        credential: &DriveCredential,
        encoded_cursor: Option<&str>,
        signing_key: &str,
    ) -> ApiResult<SyncRootPageResponse> {
        self.list_sync_root_page_limited(
            actor,
            credential,
            encoded_cursor,
            signing_key,
            PAGE_ROOT_LIMIT,
        )
    }

    pub fn list_sync_root_page_limited(
        &self,
        actor: &Actor,
        credential: &DriveCredential,
        encoded_cursor: Option<&str>,
        signing_key: &str,
        page_limit: usize,
    ) -> ApiResult<SyncRootPageResponse> {
        if !(1..=PAGE_ROOT_LIMIT).contains(&page_limit) {
            return Err(ApiError::Validation(
                "sync root page limit must be 1 through 50".to_string(),
            ));
        }
        let actor = sync_actor(actor);
        let mut cursor = match encoded_cursor {
            Some(value) => decode_cursor(value, &actor, credential, signing_key)?,
            None => PageCursor {
                phase: Phase::Private,
                key: String::new(),
            },
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        authorization::ensure_source_credential_active(&tx, &actor, credential)?;
        let mut roots = Vec::new();
        let mut bytes = 64;
        let mut has_more = true;
        loop {
            let candidates = if cursor.phase == Phase::Item {
                item_candidate_ids_in_tx(&tx, &actor, &cursor.key)?
            } else {
                workspace_candidate_ids_in_tx(&tx, &actor, cursor.phase, &cursor.key, page_limit)?
            };
            let scan_limit = if cursor.phase == Phase::Item {
                ITEM_SCAN_LIMIT
            } else {
                page_limit
            };
            let mut processed = 0;
            for candidate in candidates.iter().take(scan_limit) {
                let root = if cursor.phase == Phase::Item {
                    canonical_item_root_at_file_in_tx(&tx, candidate, &actor)?
                } else {
                    match resolve_sync_root_in_tx(&tx, &format!("workspace:{candidate}"), &actor) {
                        Ok(root) => Some(root),
                        Err(ApiError::NotFound) => None,
                        Err(error) => return Err(error),
                    }
                };
                if let Some(root) = root {
                    if !push_bounded(&mut roots, root, &mut bytes)? {
                        break;
                    }
                }
                cursor.key = candidate.clone();
                processed += 1;
                if roots.len() == page_limit {
                    break;
                }
            }
            if processed < candidates.len() || roots.len() == page_limit {
                break;
            }
            match cursor.phase.next() {
                Some(next) => {
                    cursor.phase = next;
                    cursor.key.clear();
                }
                None => {
                    has_more = false;
                    break;
                }
            }
        }
        // Each page is admitted under one current credential and transaction.
        // Selected roots are revalidated at pairing commit, so unrelated
        // account churn need not invalidate this keyset continuation.
        authorization::ensure_source_credential_active(&tx, &actor, credential)?;
        tx.commit()?;
        let next_cursor = if has_more {
            Some(encode_cursor(&cursor, &actor, credential, signing_key)?)
        } else {
            None
        };
        Ok(SyncRootPageResponse { roots, next_cursor })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthMode;
    use rusqlite::Connection;

    fn explain(conn: &Connection, sql: &str, scope: Option<&str>) -> Vec<String> {
        let mut statement = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        statement
            .query_map(params!["reader@example.test", "", 17, scope], |row| {
                row.get(3)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    #[test]
    fn page_plans_start_at_actor_and_seek_indexed_grants() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(directory.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let conn = storage.conn.lock().unwrap();
        for phase in [Phase::Private, Phase::Owner, Phase::Shared] {
            let plan = explain(&conn, &workspace_page_sql(phase), None);
            assert!(
                plan.iter()
                    .any(|step| step.contains("idx_workspace_members_actor_access")),
                "{phase:?}: {plan:?}"
            );
            assert!(
                !plan.iter().any(|step| step.starts_with("SCAN w ")),
                "{phase:?}: {plan:?}"
            );
            if phase == Phase::Shared {
                assert!(
                    plan.iter()
                        .any(|step| step.contains("idx_group_members_actor_access")),
                    "{plan:?}"
                );
                assert!(
                    plan.iter()
                        .any(|step| step.contains("idx_workspace_group_grants_access")),
                    "{plan:?}"
                );
            }
        }
        for scoped in [false, true] {
            let plan = explain(
                &conn,
                &item_page_sql(scoped),
                scoped.then_some("[\"workspace-a\"]"),
            );
            for index in [
                "idx_human_item_grants_account_current",
                "idx_human_item_grants_group_current",
                if scoped {
                    "idx_human_item_grants_scoped_everyone_page"
                } else {
                    "idx_human_item_grants_everyone_page"
                },
            ] {
                assert!(
                    plan.iter().any(|step| step.contains(index)),
                    "{index}: {plan:?}"
                );
            }
            assert!(
                !plan.iter().any(|step| step.starts_with("SCAN g ")),
                "{plan:?}"
            );
        }
    }

    #[test]
    fn cursor_rejects_actor_credential_scope_and_payload_changes() {
        let actor = Actor {
            email: "reader@example.test".to_string(),
            is_admin: false,
            auth_mode: AuthMode::LocalAccount,
            allowed_workspace_ids: None,
        };
        let credential = DriveCredential::UserSession("session-a".to_string());
        let page = PageCursor {
            phase: Phase::Item,
            key: "file-9".to_string(),
        };
        let encoded = encode_cursor(&page, &actor, &credential, "test-signing-key").unwrap();
        assert_eq!(
            decode_cursor(&encoded, &actor, &credential, "test-signing-key")
                .unwrap()
                .key,
            "file-9"
        );
        let other_credential = DriveCredential::UserSession("session-b".to_string());
        assert!(decode_cursor(&encoded, &actor, &other_credential, "test-signing-key").is_err());
        let mut other_actor = actor.clone();
        other_actor.email = "other@example.test".to_string();
        assert!(decode_cursor(&encoded, &other_actor, &credential, "test-signing-key").is_err());
        other_actor = actor.clone();
        other_actor.allowed_workspace_ids = Some(["workspace-1".to_string()].into());
        assert!(decode_cursor(&encoded, &other_actor, &credential, "test-signing-key").is_err());
        assert!(decode_cursor(
            &encoded.replace('a', "b"),
            &actor,
            &credential,
            "test-signing-key"
        )
        .is_err());
    }

    #[test]
    fn scoped_item_scan_never_selects_out_of_scope_candidate_ids() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE human_item_grants (
                root_file_id TEXT, workspace_id TEXT, revoked_at TEXT,
                publication_pending INTEGER, expires_at TEXT,
                principal_kind TEXT, principal_ref TEXT
            );
            CREATE TABLE files (id TEXT, trashed INTEGER);
            CREATE TABLE users (id TEXT, email TEXT);
            CREATE TABLE auth_accounts (user_id TEXT, email TEXT, disabled_at TEXT);
            CREATE TABLE group_members (group_id TEXT, user_id TEXT);
            CREATE INDEX idx_group_members_actor_access ON group_members(user_id, group_id);
            CREATE INDEX idx_human_item_grants_scoped_everyone_page
                ON human_item_grants(workspace_id, root_file_id)
                WHERE principal_kind = 'everyone' AND revoked_at IS NULL AND publication_pending = 0;
            CREATE INDEX idx_human_item_grants_everyone_page
                ON human_item_grants(root_file_id)
                WHERE principal_kind = 'everyone' AND revoked_at IS NULL AND publication_pending = 0;
            CREATE INDEX idx_human_item_grants_account_current
                ON human_item_grants(principal_ref, root_file_id)
                WHERE principal_kind = 'account' AND revoked_at IS NULL;
            CREATE INDEX idx_human_item_grants_group_current
                ON human_item_grants(principal_ref, root_file_id)
                WHERE principal_kind = 'group' AND revoked_at IS NULL;
            INSERT INTO users VALUES ('reader-id','reader@example.test');
            INSERT INTO auth_accounts VALUES ('reader-id','reader@example.test',NULL);
            INSERT INTO files VALUES ('a_out',0),('z_in',0);
            INSERT INTO human_item_grants VALUES
                ('a_out','other',NULL,0,NULL,'everyone',NULL),
                ('z_in','inside',NULL,0,NULL,'everyone',NULL);",
        )
        .unwrap();
        let actor = Actor {
            email: "reader@example.test".to_string(),
            is_admin: false,
            auth_mode: AuthMode::DelegatedAgent,
            allowed_workspace_ids: Some(["inside".to_string()].into()),
        };
        let tx = db.transaction().unwrap();
        assert_eq!(
            item_candidate_ids_in_tx(&tx, &actor, "").unwrap(),
            vec!["z_in"]
        );
        assert_eq!(
            item_candidate_ids_in_tx(&tx, &actor, "a_out").unwrap(),
            vec!["z_in"]
        );
        assert!(item_candidate_ids_in_tx(&tx, &actor, "z_in")
            .unwrap()
            .is_empty());
    }
}
