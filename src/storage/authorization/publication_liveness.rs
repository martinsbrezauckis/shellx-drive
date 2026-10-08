use std::collections::{HashMap, HashSet};

use rusqlite::{params, OptionalExtension, Transaction};

use crate::error::{ApiError, ApiResult};

use super::super::{MAX_FILE_TREE_DEPTH, MAX_FILE_TREE_NODES};

const BULK_LIVENESS_THRESHOLD: usize = 64;

pub(super) fn ensure_files_effectively_live(
    tx: &Transaction<'_>,
    workspace_id: &str,
    file_ids: &[String],
) -> ApiResult<()> {
    if file_ids.len() <= BULK_LIVENESS_THRESHOLD {
        return ensure_files_live_individually(tx, workspace_id, file_ids);
    }
    let mut statement = tx.prepare(
        "SELECT id, parent_id, trashed FROM files
         WHERE workspace_id = ?1 LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![workspace_id, (MAX_FILE_TREE_NODES + 1) as i64],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                (row.get::<_, Option<String>>(1)?, row.get::<_, i64>(2)? != 0),
            ))
        },
    )?;
    let nodes = rows.collect::<rusqlite::Result<HashMap<_, _>>>()?;
    if nodes.len() > MAX_FILE_TREE_NODES {
        return Err(ApiError::NotFound);
    }
    ensure_files_live_in_snapshot(&nodes, file_ids)
}

fn ensure_files_live_individually(
    tx: &Transaction<'_>,
    workspace_id: &str,
    file_ids: &[String],
) -> ApiResult<()> {
    for file_id in file_ids {
        let mut current = Some(file_id.clone());
        let mut visited = HashSet::new();
        for _ in 0..=MAX_FILE_TREE_DEPTH {
            let Some(id) = current.take() else { break };
            if !visited.insert(id.clone()) {
                return Err(ApiError::NotFound);
            }
            let (row_workspace, parent_id, trashed): (String, Option<String>, i64) = tx
                .query_row(
                    "SELECT workspace_id, parent_id, trashed FROM files WHERE id = ?1",
                    params![id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if row_workspace != workspace_id || trashed != 0 {
                return Err(ApiError::NotFound);
            }
            current = parent_id;
        }
        if current.is_some() {
            return Err(ApiError::NotFound);
        }
    }
    Ok(())
}

fn ensure_files_live_in_snapshot(
    nodes: &HashMap<String, (Option<String>, bool)>,
    file_ids: &[String],
) -> ApiResult<()> {
    let mut known_live = HashSet::new();
    for file_id in file_ids {
        let mut current = Some(file_id.as_str());
        let mut visited = HashSet::new();
        let mut path = Vec::new();
        for _ in 0..=MAX_FILE_TREE_DEPTH {
            let Some(id) = current.take() else { break };
            if known_live.contains(id) {
                break;
            }
            if !visited.insert(id) {
                return Err(ApiError::NotFound);
            }
            let (parent_id, trashed) = nodes.get(id).ok_or(ApiError::NotFound)?;
            if *trashed {
                return Err(ApiError::NotFound);
            }
            path.push(id);
            current = parent_id.as_deref();
        }
        if current.is_some_and(|id| !known_live.contains(id)) {
            return Err(ApiError::NotFound);
        }
        known_live.extend(path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_wide_snapshot_is_checked_with_shared_ancestor_work() {
        let mut nodes = HashMap::new();
        let mut parent = None;
        for depth in 0..MAX_FILE_TREE_DEPTH {
            let id = format!("folder-{depth}");
            nodes.insert(id.clone(), (parent, false));
            parent = Some(id);
        }
        let files = (0..8_000)
            .map(|index| {
                let id = format!("file-{index}");
                nodes.insert(id.clone(), (parent.clone(), false));
                id
            })
            .collect::<Vec<_>>();
        ensure_files_live_in_snapshot(&nodes, &files).unwrap();
    }
}
