use super::drop_expiry_from_ttl;
use chrono::{DateTime, Datelike, Utc};

#[test]
fn drop_expiry_rejects_values_that_cannot_be_stored_as_ordered_dates() {
    for ttl in [i64::MIN, -1, 0, 300_000_000_000, i64::MAX] {
        assert!(drop_expiry_from_ttl(ttl).is_err(), "ttl {ttl}");
    }
    let expiry = drop_expiry_from_ttl(3600).unwrap();
    let parsed = DateTime::parse_from_rfc3339(&expiry).unwrap();
    assert!(parsed.with_timezone(&Utc) > Utc::now());
    assert!(parsed.year() <= 9999);
    assert!(expiry.ends_with("+00:00"));
}
