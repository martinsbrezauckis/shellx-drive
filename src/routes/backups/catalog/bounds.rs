use std::{collections::HashSet, fs, path::Path, path::PathBuf};

use crate::{
    backup_v2,
    error::{ApiError, ApiResult},
};

use super::{backup_dir, validate_backup_id};

const CONTROL_ENTRY_ALLOWANCE: usize = 16;
const MAX_RAW_ENTRIES_PER_GENERATION: usize = 3;
const MAX_BACKUP_CATALOG_RAW_ENTRIES: usize = super::super::MAX_BACKUP_CATALOG_ENTRIES
    * MAX_RAW_ENTRIES_PER_GENERATION
    + CONTROL_ENTRY_ALLOWANCE;

pub(in crate::routes::backups) fn bounded_backup_catalog_paths(
    data_dir: &Path,
) -> ApiResult<Vec<PathBuf>> {
    let dir = backup_dir(data_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir)? {
        if paths.len() >= MAX_BACKUP_CATALOG_RAW_ENTRIES {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup directory has more than {MAX_BACKUP_CATALOG_RAW_ENTRIES} raw entries"
            )));
        }
        paths.push(entry?.path());
    }
    ensure_logical_generation_bound(&paths)?;
    Ok(paths)
}

fn ensure_logical_generation_bound(paths: &[PathBuf]) -> ApiResult<()> {
    let mut generations = HashSet::new();
    for path in paths {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(backup_id) = catalog_generation_id(name) else {
            continue;
        };
        if validate_backup_id(backup_id).is_err() || !generations.insert(backup_id) {
            continue;
        }
        if generations.len() > super::super::MAX_BACKUP_CATALOG_ENTRIES {
            return Err(ApiError::PayloadTooLarge(format!(
                "backup catalog has more than {} logical generations",
                super::super::MAX_BACKUP_CATALOG_ENTRIES
            )));
        }
    }
    Ok(())
}

fn catalog_generation_id(name: &str) -> Option<&str> {
    name.strip_suffix(".meta.json.partial")
        .or_else(|| name.strip_suffix(".meta.json"))
        .or_else(|| name.strip_suffix(&format!(".{}", backup_v2::ARCHIVE_EXTENSION)))
        .or_else(|| name.strip_suffix(".json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_retention_ceiling_accepts_archive_sidecar_pairs_and_controls() {
        let mut paths = vec![PathBuf::from(".metadata-key"), PathBuf::from(".staging")];
        for index in 0..super::super::super::MAX_BACKUP_CATALOG_ENTRIES {
            paths.push(PathBuf::from(format!("backup-{index}.sxdbackup")));
            paths.push(PathBuf::from(format!("backup-{index}.meta.json")));
        }
        assert!(paths.len() <= MAX_BACKUP_CATALOG_RAW_ENTRIES);
        ensure_logical_generation_bound(&paths).unwrap();
    }

    #[test]
    fn ten_thousand_and_first_logical_generation_is_rejected() {
        let paths = (0..=super::super::super::MAX_BACKUP_CATALOG_ENTRIES)
            .map(|index| PathBuf::from(format!("backup-{index}.sxdbackup")))
            .collect::<Vec<_>>();
        assert!(matches!(
            ensure_logical_generation_bound(&paths),
            Err(ApiError::PayloadTooLarge(message)) if message.contains("logical generations")
        ));
    }
}
