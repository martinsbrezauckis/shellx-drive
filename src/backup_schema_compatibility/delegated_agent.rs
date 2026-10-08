const HISTORICAL_OMISSIONS: &[&[&str]] = &[
    &["delegation_parent_kind"],
    &["creator_authority_kind", "delegation_parent_kind"],
    &["publication_pending", "delegation_parent_kind"],
    &[
        "creator_authority_kind",
        "publication_pending",
        "delegation_parent_kind",
    ],
];

pub(super) fn agent_principal_columns_are_compatible(
    table: &str,
    incoming: &[String],
    expected: &[String],
) -> bool {
    table == "agent_principals"
        && HISTORICAL_OMISSIONS.iter().any(|omitted| {
            incoming
                == expected
                    .iter()
                    .filter(|column| !omitted.contains(&column.as_str()))
                    .cloned()
                    .collect::<Vec<_>>()
        })
}
