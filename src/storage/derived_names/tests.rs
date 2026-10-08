use super::*;

#[test]
fn derived_names_reserve_suffix_bytes_without_splitting_utf8() {
    let name = derive_file_name(&"é".repeat(128), " copy").unwrap();

    assert_eq!(name, format!("{} copy", "é".repeat(125)));
    assert_eq!(name.len(), MAX_FILE_NAME_BYTES);
    assert_eq!(validate_file_name(&name).unwrap(), name);
}

#[test]
fn conflict_names_are_canonical_and_windows_safe() {
    let name = derive_conflict_file_name(
        &format!("{}x", "é".repeat(127)),
        "2026-08-26T12:34:56+00:00",
    )
    .unwrap();

    assert!(name.len() <= MAX_FILE_NAME_BYTES);
    assert!(!name.contains(':'));
    assert!(name.ends_with(" (conflict 2026-08-26T12-34-56+00-00)"));
    assert_eq!(validate_file_name(&name).unwrap(), name);
}

#[test]
fn copy_names_preserve_extensions_and_utf8_within_the_byte_limit() {
    assert_eq!(
        derive_copy_file_name("photo.png", 1).unwrap(),
        "photo (copy).png"
    );
    assert_eq!(
        derive_copy_file_name("photo.png", 2).unwrap(),
        "photo (copy2).png"
    );
    assert_eq!(derive_copy_file_name("folder", 1).unwrap(), "folder (copy)");

    let name = derive_copy_file_name(&format!("a{}.png", "é".repeat(125)), 3).unwrap();
    assert_eq!(name.len(), MAX_FILE_NAME_BYTES);
    assert!(name.ends_with(" (copy3).png"));
    assert_eq!(validate_file_name(&name).unwrap(), name);
}
