use std::collections::{HashMap, HashSet};

use crate::{DesktopError, RemoteFile, RemoteFileKind, Result};

/// The native picker is serialized through Tauri, so every human breadcrumb
/// has a strict independent ceiling. A deep valid Drive tree may be rendered
/// with a leading ellipsis, while the opaque folder id remains exact.
const MAX_FOLDER_CHOICE_LABEL_BYTES: usize = 1_024;
const ELLIPSIS: &str = "…";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FolderChoiceLabel {
    pub remote_root_id: Option<String>,
    pub label: String,
}

pub fn folder_choice_labels(
    workspace_name: &str,
    manifest: &[RemoteFile],
) -> Result<Vec<FolderChoiceLabel>> {
    let mut live = HashMap::new();
    for file in manifest.iter().filter(|file| !file.trashed) {
        if live.insert(file.id.as_str(), file).is_some() {
            return Err(DesktopError::InvalidState(format!(
                "remote manifest contains duplicate item id: {}",
                file.id
            )));
        }
    }

    let mut cache = HashMap::new();
    let mut choices = vec![FolderChoiceLabel {
        remote_root_id: None,
        label: append_bounded(workspace_name, " — ", "Workspace root"),
    }];
    for folder in manifest
        .iter()
        .filter(|file| !file.trashed && file.kind == RemoteFileKind::Folder)
    {
        let breadcrumb = folder_breadcrumb(folder, &live, &mut cache)?;
        choices.push(FolderChoiceLabel {
            remote_root_id: Some(folder.id.clone()),
            label: append_bounded(workspace_name, " — ", &breadcrumb),
        });
    }
    choices.sort_by(|left, right| left.label.cmp(&right.label));
    Ok(choices)
}

fn folder_breadcrumb<'a>(
    folder: &'a RemoteFile,
    live: &HashMap<&'a str, &'a RemoteFile>,
    cache: &mut HashMap<&'a str, String>,
) -> Result<String> {
    if let Some(cached) = cache.get(folder.id.as_str()) {
        return Ok(cached.clone());
    }

    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut current = Some(folder);
    let base = loop {
        let Some(node) = current else {
            break String::new();
        };
        if let Some(cached) = cache.get(node.id.as_str()) {
            break cached.clone();
        }
        if !seen.insert(node.id.as_str()) {
            return Err(DesktopError::RemoteParentCycle(node.id.clone()));
        }
        chain.push(node);
        current = node
            .parent_id
            .as_deref()
            .and_then(|parent| live.get(parent).copied());
    };

    let mut breadcrumb = base;
    while let Some(node) = chain.pop() {
        breadcrumb = if breadcrumb.is_empty() {
            bounded_suffix(&node.name, MAX_FOLDER_CHOICE_LABEL_BYTES)
        } else {
            append_bounded(&breadcrumb, " / ", &node.name)
        };
        cache.insert(node.id.as_str(), breadcrumb.clone());
    }
    Ok(breadcrumb)
}

fn append_bounded(prefix: &str, separator: &str, suffix: &str) -> String {
    let suffix = bounded_suffix(suffix, MAX_FOLDER_CHOICE_LABEL_BYTES);
    if prefix.is_empty() {
        return suffix;
    }
    let fixed = separator.len().saturating_add(suffix.len());
    if fixed >= MAX_FOLDER_CHOICE_LABEL_BYTES {
        return bounded_suffix(&suffix, MAX_FOLDER_CHOICE_LABEL_BYTES);
    }
    let prefix_budget = MAX_FOLDER_CHOICE_LABEL_BYTES - fixed;
    let prefix = bounded_suffix(prefix, prefix_budget);
    format!("{prefix}{separator}{suffix}")
}

fn bounded_suffix(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_string();
    }
    if limit <= ELLIPSIS.len() {
        return ".".repeat(limit);
    }
    let suffix_budget = limit - ELLIPSIS.len();
    let mut start = value.len().saturating_sub(suffix_budget);
    while start < value.len() && !value.is_char_boundary(start) {
        start += 1;
    }
    format!("{ELLIPSIS}{}", &value[start..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(id: &str, parent_id: Option<&str>, name: &str) -> RemoteFile {
        RemoteFile {
            id: id.to_string(),
            workspace_id: "workspace".to_string(),
            parent_id: parent_id.map(str::to_string),
            name: name.to_string(),
            kind: RemoteFileKind::Folder,
            revision: 1,
            trashed: false,
            content_hash: None,
            size_bytes: None,
        }
    }

    #[test]
    fn deep_folder_labels_are_memoized_and_bounded() {
        let mut manifest = Vec::new();
        let mut parent = None;
        for index in 0..512 {
            let id = format!("folder-{index}");
            manifest.push(folder(&id, parent.as_deref(), &"x".repeat(255)));
            parent = Some(id);
        }
        let choices = folder_choice_labels(&"workspace".repeat(1_000), &manifest).unwrap();
        assert_eq!(choices.len(), manifest.len() + 1);
        assert!(choices
            .iter()
            .all(|choice| choice.label.len() <= MAX_FOLDER_CHOICE_LABEL_BYTES));
        assert!(choices
            .iter()
            .any(|choice| choice.label.starts_with(ELLIPSIS)));
    }

    #[test]
    fn folder_cycles_fail_closed() {
        let manifest = vec![folder("a", Some("b"), "A"), folder("b", Some("a"), "B")];
        assert!(matches!(
            folder_choice_labels("Workspace", &manifest),
            Err(DesktopError::RemoteParentCycle(_))
        ));
    }
}
