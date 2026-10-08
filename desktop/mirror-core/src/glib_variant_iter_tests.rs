use glib::{prelude::ToVariant, Variant};

fn string_array() -> Variant {
    let strings = ["zero", "one", "two", "three", "four", "five"];
    strings.as_slice().to_variant()
}

#[test]
fn variant_str_iter_is_safe_for_forward_and_backward_optimized_access() {
    let variant = string_array();
    let mut iter = variant.array_iter_str().expect("an array of strings");

    assert_eq!(iter.next(), Some("zero"));
    assert_eq!(iter.nth(1), Some("two"));
    assert_eq!(iter.next_back(), Some("five"));
    assert_eq!(iter.nth_back(1), Some("three"));
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next_back(), None);

    assert_eq!(
        string_array()
            .array_iter_str()
            .expect("an array of strings")
            .last(),
        Some("five")
    );
}
