use crate::error::{ApiError, ApiResult};

/// Turn Drive path components into an injective, extractor-portable ZIP path.
/// `%` is always escaped, so an encoded unsafe byte cannot collide with a
/// literal percent sequence from another Drive name.
pub(super) fn portable_archive_path(path: &str) -> ApiResult<String> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        return Err(unsafe_path());
    }
    path.split('/')
        .map(portable_component)
        .collect::<ApiResult<Vec<_>>>()
        .map(|components| components.join("/"))
}

pub(super) fn validate_portable_archive_path(path: &str) -> ApiResult<()> {
    if path.split('/').all(is_portable_component) {
        Ok(())
    } else {
        Err(unsafe_path())
    }
}

fn portable_component(component: &str) -> ApiResult<String> {
    if component.is_empty() || component == "." || component == ".." {
        return Err(unsafe_path());
    }
    let encode_all = is_windows_device_name(component);
    let trailing_start = component.trim_end_matches([' ', '.']).len();
    let mut encoded = String::with_capacity(component.len());
    for (index, character) in component.char_indices() {
        let unsafe_character = encode_all
            || character == '%'
            || character.is_control()
            || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
            || (index >= trailing_start && matches!(character, ' ' | '.'));
        if unsafe_character {
            for byte in character.to_string().bytes() {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        } else {
            encoded.push(character);
        }
    }
    Ok(encoded)
}

fn is_portable_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && !component.ends_with([' ', '.'])
        && !component.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
        })
        && !is_windows_device_name(component)
}

fn is_windows_device_name(component: &str) -> bool {
    let base = component
        .trim_end_matches([' ', '.'])
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || base
        .strip_prefix("COM")
        .or_else(|| base.strip_prefix("LPT"))
        .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

fn unsafe_path() -> ApiError {
    ApiError::Validation("archive contains an unsafe path".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn encodes_drive_ads_device_and_trailing_forms_portably() {
        for (input, expected) in [
            ("C:/payload.txt", "C%3A/payload.txt"),
            ("file.txt:stream", "file.txt%3Astream"),
            ("CON.txt", "%43%4F%4E%2E%74%78%74"),
            ("folder. ", "folder%2E%20"),
        ] {
            let encoded = portable_archive_path(input).unwrap();
            assert_eq!(encoded, expected);
            validate_portable_archive_path(&encoded).unwrap();
        }
    }

    #[test]
    fn percent_escaping_keeps_encoded_names_injective() {
        let inputs = ["a:b", "a%3Ab", "CON", "%43%4F%4E", "name.", "name%2E"];
        let encoded = inputs
            .into_iter()
            .map(|name| portable_archive_path(name).unwrap())
            .collect::<HashSet<_>>();
        assert_eq!(encoded.len(), inputs.len());
    }

    #[test]
    fn portable_unicode_names_are_preserved() {
        assert_eq!(
            portable_archive_path("Mārtiņš/文档.txt").unwrap(),
            "Mārtiņš/文档.txt"
        );
    }
}
