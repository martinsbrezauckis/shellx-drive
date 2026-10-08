//! Exact, fail-closed compatibility rules for older V2 backup table shapes.
//!
//! Archive validation and transactional restore use the same explicit allowlist.
mod delegated_agent;

const COMPATIBLE_OMISSIONS: &[(&str, &[&str])] = &[
    ("auth_accounts", &["totp_last_used_counter"]),
    ("auth_sessions", &["publication_pending"]),
    ("app_tokens", &["publication_pending"]),
    ("agent_tokens", &["publication_pending"]),
    ("agent_principals", &["creator_authority_kind"]),
    ("agent_principals", &["publication_pending"]),
    (
        "agent_principals",
        &["creator_authority_kind", "publication_pending"],
    ),
    ("agent_folder_grants", &["creator_authority_kind"]),
    ("agent_folder_grants", &["publication_pending"]),
    (
        "agent_folder_grants",
        &["creator_authority_kind", "publication_pending"],
    ),
    ("workspace_invitations", &["publication_pending"]),
    ("files", &["cover_bytes"]),
    ("files", &["drop_inbox_owner_id"]),
    ("files", &["cover_bytes", "drop_inbox_owner_id"]),
    ("email_outbox", &["workspace_id"]),
    ("office_edit_sessions", &["source_credential_generation"]),
    (
        "file_text_index",
        &["source_revision", "source_content_hash"],
    ),
    (
        "upload_sessions",
        &[
            "target_file_id",
            "base_revision",
            "completion_receipt_id",
            "completion_current_revision",
            "quota_reservation_bytes",
        ],
    ),
    (
        "upload_sessions",
        &[
            "target_file_id",
            "base_revision",
            "completion_receipt_id",
            "completion_current_revision",
            "quota_reservation_bytes",
            "duplicate_policy",
        ],
    ),
    ("share_access_grants", &["client_fingerprint"]),
    ("shares", &["publication_pending"]),
    ("drops", &["publication_pending"]),
    ("drops", &["inbox_file_id"]),
    ("drops", &["publication_pending", "inbox_file_id"]),
];

/// Archives written before item sharing joined the backup set omit this exact
/// pair.  It is a single bounded compatibility shape: accepting either table
/// alone could turn a truncated archive into an authority-bearing restore.
pub(crate) const HISTORICALLY_OMITTED_HUMAN_ITEM_SHARING_TABLES: [&str; 2] =
    ["human_item_grants", "human_item_access_generation"];

pub(crate) fn columns_are_compatible(
    table: &str,
    incoming: &[String],
    expected: &[String],
) -> bool {
    incoming == expected
        || delegated_agent::agent_principal_columns_are_compatible(table, incoming, expected)
        || COMPATIBLE_OMISSIONS
            .iter()
            .any(|(compatible_table, omitted_columns)| {
                matches_without(table, incoming, expected, compatible_table, omitted_columns)
            })
}

fn matches_without(
    table: &str,
    incoming: &[String],
    expected: &[String],
    compatible_table: &str,
    omitted_columns: &[&str],
) -> bool {
    table == compatible_table
        && incoming
            == expected
                .iter()
                .filter(|column| !omitted_columns.contains(&column.as_str()))
                .cloned()
                .collect::<Vec<_>>()
}

pub(crate) fn omits_historical_human_item_sharing_tables(
    incoming: &[&str],
    expected: &[&str],
) -> bool {
    incoming
        == expected
            .iter()
            .copied()
            .filter(|table| !HISTORICALLY_OMITTED_HUMAN_ITEM_SHARING_TABLES.contains(table))
            .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use super::{columns_are_compatible, omits_historical_human_item_sharing_tables};

    #[test]
    fn accepts_only_the_enumerated_exact_legacy_shape() {
        let expected = vec!["id".to_string(), "cover_bytes".to_string()];
        assert!(columns_are_compatible(
            "files",
            &["id".to_string()],
            &expected
        ));
        assert!(!columns_are_compatible("files", &[], &expected));
        assert!(!columns_are_compatible(
            "workspaces",
            &["id".to_string()],
            &expected
        ));
    }

    #[test]
    fn accepts_only_the_complete_pre_item_sharing_table_sequence() {
        let expected = [
            "files",
            "human_item_grants",
            "human_item_access_generation",
            "shares",
        ];
        assert!(omits_historical_human_item_sharing_tables(
            &["files", "shares"],
            &expected
        ));
        assert!(!omits_historical_human_item_sharing_tables(
            &["files", "human_item_grants", "shares"],
            &expected
        ));
        assert!(!omits_historical_human_item_sharing_tables(
            &["shares", "files"],
            &expected
        ));
    }
}
