use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::{
    is_supported_windows_name_character, windows_paths_compare_ignore_case, MAX_PATH_DEPTH,
    MAX_WINDOWS_COMPONENT_CHARS, MAX_WINDOWS_PATH_CHARS,
};
use crate::{error::Result, mirror::RemoteEntry, DesktopError};

const MAX_REMOTE_PARENT_WALK: usize = 256;
const MAX_REMOTE_PATH_OUTPUT_BYTES: usize = 12 * 1024 * 1024;

/// A remote-relative path Drive cannot safely represent in the selected
/// Windows mirror. Unlike a local filesystem error, this is manifest data:
/// callers retain it as a durable review and do not publish around it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RemotePathIssue {
    pub remote_id: String,
    pub path: PathBuf,
    pub reason: String,
    collision: bool,
}

/// Compatible paths plus stable review data for incompatible remote items.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct RemotePathMapping {
    pub paths: BTreeMap<String, PathBuf>,
    pub issues: Vec<RemotePathIssue>,
}

#[derive(Clone)]
enum RemoteProjection {
    OutsideSelection,
    Compatible {
        path: PathBuf,
        depth: usize,
        utf16_len: usize,
    },
    Incompatible {
        path: PathBuf,
        reason: String,
    },
}

/// Inspect every live descendant before local publication. Parent projections
/// are memoized, and retained paths/issues share one hard output budget.
pub fn inspect_remote_paths(
    entries: &[RemoteEntry],
    selected_root: Option<&str>,
) -> Result<RemotePathMapping> {
    let mut index = HashMap::new();
    for entry in entries {
        if index.insert(entry.id.as_str(), entry).is_some() {
            return Err(DesktopError::InvalidState(format!(
                "remote manifest contains duplicate item id: {}",
                entry.id
            )));
        }
    }
    if let Some(root) = selected_root {
        if !index.contains_key(root) {
            return Err(DesktopError::UnknownRemoteRoot(root.to_string()));
        }
    }

    let mut mapping = RemotePathMapping::default();
    let mut projections = HashMap::new();
    let mut candidates = Vec::new();
    let mut output_bytes = 0_usize;
    for entry in entries.iter().filter(|entry| !entry.trashed) {
        match project_remote_entry(entry, &index, selected_root, &mut projections)? {
            RemoteProjection::OutsideSelection => continue,
            RemoteProjection::Compatible { .. }
                if selected_root.is_some_and(|root| root == entry.id) =>
            {
                continue;
            }
            RemoteProjection::Compatible { path, .. } => {
                reserve_remote_output(&mut output_bytes, &entry.id, &path, "")?;
                candidates.push((entry.id.clone(), path));
            }
            RemoteProjection::Incompatible { path, reason } => {
                reserve_remote_output(&mut output_bytes, &entry.id, &path, &reason)?;
                mapping.issues.push(RemotePathIssue {
                    remote_id: entry.id.clone(),
                    path,
                    reason,
                    collision: false,
                });
            }
        }
    }

    let mut exact_counts: HashMap<PathBuf, usize> = HashMap::new();
    for (_, path) in &candidates {
        *exact_counts.entry(path.clone()).or_default() += 1;
    }
    let mut ordered = (0..candidates.len()).collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        windows_paths_compare_ignore_case(&candidates[*left].1, &candidates[*right].1)
            .then(left.cmp(right))
    });
    let mut colliding = HashSet::new();
    let mut group_start = 0;
    while group_start < ordered.len() {
        let mut group_end = group_start + 1;
        while group_end < ordered.len()
            && windows_paths_compare_ignore_case(
                &candidates[ordered[group_start]].1,
                &candidates[ordered[group_end]].1,
            )
            .is_eq()
        {
            group_end += 1;
        }
        if group_end - group_start > 1 {
            colliding.extend(ordered[group_start..group_end].iter().copied());
        }
        group_start = group_end;
    }
    for (index, (remote_id, path)) in candidates.into_iter().enumerate() {
        if colliding.contains(&index) {
            let exact_collision = exact_counts.get(&path).copied().unwrap_or(0) > 1;
            let reason = if exact_collision {
                "two Drive items map to this exact Windows path".to_string()
            } else {
                "Windows treats this Drive path as the same path when matching case-insensitively"
                    .to_string()
            };
            reserve_remote_output(&mut output_bytes, &remote_id, &path, &reason)?;
            mapping.issues.push(RemotePathIssue {
                remote_id,
                path,
                reason,
                collision: true,
            });
        } else {
            mapping.paths.insert(remote_id, path);
        }
    }
    mapping.issues.sort_by(|left, right| {
        (&left.path, &left.reason, &left.remote_id).cmp(&(
            &right.path,
            &right.reason,
            &right.remote_id,
        ))
    });
    Ok(mapping)
}

/// Strict callers retain the historical all-or-error surface.
pub fn map_remote_paths(
    entries: &[RemoteEntry],
    selected_root: Option<&str>,
) -> Result<BTreeMap<String, PathBuf>> {
    let mapping = inspect_remote_paths(entries, selected_root)?;
    let Some(issue) = mapping.issues.first() else {
        return Ok(mapping.paths);
    };
    Err(if issue.collision {
        DesktopError::CaseCollision(issue.path.display().to_string())
    } else {
        DesktopError::UnsafePath(format!("{}: {}", issue.path.display(), issue.reason))
    })
}

fn project_remote_entry<'a>(
    entry: &'a RemoteEntry,
    index: &HashMap<&'a str, &'a RemoteEntry>,
    selected_root: Option<&str>,
    cache: &mut HashMap<String, RemoteProjection>,
) -> Result<RemoteProjection> {
    if let Some(cached) = cache.get(&entry.id) {
        return Ok(cached.clone());
    }

    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut current = Some(entry);
    let base = loop {
        let Some(node) = current else {
            break if selected_root.is_some() {
                RemoteProjection::OutsideSelection
            } else {
                empty_remote_projection()
            };
        };
        if selected_root.is_some_and(|root| root == node.id) {
            break empty_remote_projection();
        }
        if let Some(cached) = cache.get(&node.id) {
            break cached.clone();
        }
        if !seen.insert(node.id.as_str()) {
            return Err(DesktopError::RemoteParentCycle(node.id.clone()));
        }
        if chain.len() >= MAX_REMOTE_PARENT_WALK {
            break RemoteProjection::Incompatible {
                path: PathBuf::new(),
                reason: format!(
                    "remote ancestry exceeds the {MAX_REMOTE_PARENT_WALK}-component inspection limit"
                ),
            };
        }
        chain.push(node);
        current = node
            .parent_id
            .as_deref()
            .and_then(|parent| index.get(parent).copied());
    };

    let mut projection = base;
    while let Some(node) = chain.pop() {
        projection = extend_remote_projection(projection, &node.name);
        cache.insert(node.id.clone(), projection.clone());
    }
    Ok(cache.get(&entry.id).cloned().unwrap_or(projection))
}

fn empty_remote_projection() -> RemoteProjection {
    RemoteProjection::Compatible {
        path: PathBuf::new(),
        depth: 0,
        utf16_len: 0,
    }
}

fn extend_remote_projection(parent: RemoteProjection, name: &str) -> RemoteProjection {
    let RemoteProjection::Compatible {
        mut path,
        depth,
        utf16_len,
    } = parent
    else {
        return parent;
    };
    if depth >= MAX_PATH_DEPTH {
        return RemoteProjection::Incompatible {
            path,
            reason: format!("path depth exceeds the {MAX_PATH_DEPTH}-component Windows limit"),
        };
    }
    let component_utf16_len = name
        .encode_utf16()
        .take(MAX_WINDOWS_COMPONENT_CHARS + 1)
        .count();
    if let Some(reason) = remote_component_issue(name, component_utf16_len) {
        let issue_path = if component_utf16_len <= MAX_WINDOWS_COMPONENT_CHARS
            && utf16_len
                .saturating_add(usize::from(depth > 0))
                .saturating_add(component_utf16_len)
                <= MAX_WINDOWS_PATH_CHARS
        {
            path.join(name)
        } else {
            path
        };
        return RemoteProjection::Incompatible {
            path: issue_path,
            reason,
        };
    }
    let projected_utf16_len = utf16_len
        .saturating_add(usize::from(depth > 0))
        .saturating_add(component_utf16_len);
    if projected_utf16_len > MAX_WINDOWS_PATH_CHARS {
        return RemoteProjection::Incompatible {
            path,
            reason: format!(
                "path is longer than {MAX_WINDOWS_PATH_CHARS} Windows UTF-16 characters"
            ),
        };
    }
    path.push(name);
    RemoteProjection::Compatible {
        path,
        depth: depth + 1,
        utf16_len: projected_utf16_len,
    }
}

fn remote_component_issue(name: &str, utf16_len: usize) -> Option<String> {
    if name.is_empty() || name.ends_with([' ', '.']) {
        return Some("a Windows name may not be empty or end with a space or period".to_string());
    }
    if utf16_len > MAX_WINDOWS_COMPONENT_CHARS {
        return Some(format!(
            "a Windows path component is longer than {MAX_WINDOWS_COMPONENT_CHARS} UTF-16 characters"
        ));
    }
    if name.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            )
    }) {
        return Some("name contains a character Windows cannot create".to_string());
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    ) {
        return Some("name is reserved by Windows".to_string());
    }
    if !name.chars().all(is_supported_windows_name_character) {
        return Some(
            "contains Unicode whose Windows normalization or case mapping is not safely supported in v0.1"
                .to_string(),
        );
    }
    None
}

fn reserve_remote_output(
    retained: &mut usize,
    remote_id: &str,
    path: &Path,
    reason: &str,
) -> Result<()> {
    let additional = remote_id
        .len()
        .saturating_add(path.to_string_lossy().len())
        .saturating_add(reason.len());
    *retained = retained.saturating_add(additional);
    if *retained > MAX_REMOTE_PATH_OUTPUT_BYTES {
        return Err(DesktopError::InvalidState(format!(
            "remote path metadata exceeds the {MAX_REMOTE_PATH_OUTPUT_BYTES}-byte desktop limit"
        )));
    }
    Ok(())
}
