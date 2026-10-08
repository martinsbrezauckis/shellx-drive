use super::*;

#[test]
fn routine_eviction_uses_the_partial_retention_index() {
    let conn = connection();
    install_with_limit(&conn, 5).unwrap();
    let sql = format!(
        "EXPLAIN QUERY PLAN SELECT id FROM receipts WHERE NOT ({PROTECTED})
         ORDER BY created_at ASC, id ASC LIMIT 1"
    );
    let details: Vec<String> = conn
        .prepare(&sql)
        .unwrap()
        .query_map([], |row| row.get(3))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        details
            .iter()
            .any(|detail| detail.contains("idx_receipts_routine_retention")),
        "routine receipt eviction did not use its partial index: {details:?}"
    );
    assert!(details
        .iter()
        .all(|detail| !detail.contains("USE TEMP B-TREE")));
}
