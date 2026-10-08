use serde_json::json;

use crate::error::ApiError;

use super::*;

#[test]
fn metadata_labels_bound_normalization_buffer_for_duplicate_heavy_input() {
    let labels = (0..4096)
        .flat_map(|_| [" Alpha ", "ALPHA", "  ", "K"])
        .map(str::to_string)
        .collect();
    let projection = project_file_metadata_storage(labels, &json!({})).unwrap();
    assert_eq!(projection.labels, ["alpha", "k"]);
    assert!(projection.labels.capacity() <= MAX_FILE_METADATA_LABELS);

    let projection = project_file_metadata_storage(vec!["K".repeat(64)], &json!({})).unwrap();
    assert_eq!(projection.labels, ["k".repeat(64)]);
}

#[test]
fn metadata_labels_limit_unique_normalized_values_and_preserve_error_order() {
    let labels: Vec<String> = (0..MAX_FILE_METADATA_LABELS)
        .rev()
        .map(|index| format!("LABEL-{index:02}"))
        .collect();
    let mut repeated = labels.clone();
    repeated.extend(
        labels
            .iter()
            .map(|label| format!("  {}  ", label.to_lowercase())),
    );
    let projection = project_file_metadata_storage(repeated, &json!({})).unwrap();
    let expected: Vec<String> = (0..MAX_FILE_METADATA_LABELS)
        .map(|index| format!("label-{index:02}"))
        .collect();
    assert_eq!(projection.labels, expected);
    assert!(projection.labels.capacity() <= MAX_FILE_METADATA_LABELS);

    let mut over_limit = labels;
    over_limit.push("one-more-label".to_string());
    let error = project_file_metadata_storage(over_limit.clone(), &json!({})).unwrap_err();
    assert!(
        matches!(&error, ApiError::PayloadTooLarge(message) if message.contains("at most 64 metadata labels"))
    );

    over_limit.push("İ".repeat(32));
    let error = project_file_metadata_storage(over_limit, &json!({})).unwrap_err();
    assert!(
        matches!(&error, ApiError::PayloadTooLarge(message) if message.contains("64 UTF-8 bytes"))
    );
}
