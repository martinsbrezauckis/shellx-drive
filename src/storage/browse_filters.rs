use rusqlite::types::Value as SqlValue;

#[derive(Debug, Clone, Default)]
pub struct FileBrowseFilters {
    pub type_filter: Option<String>,
    pub owner_scope: Option<String>,
    pub modified_since: Option<String>,
    pub workspace_id: Option<String>,
    pub folder_id: Option<String>,
    pub state_filter: Option<String>,
}

impl FileBrowseFilters {
    pub(super) fn sql(
        &self,
        actor_email: &str,
        parameters: &mut Vec<SqlValue>,
        next_parameter: &mut usize,
    ) -> String {
        let mut predicates = Vec::new();
        if let Some(value) = self.type_filter.as_deref() {
            const EXTENSIONS: &[(&str, &[&str])] = &[
                ("docs", &["doc", "docx", "md", "odt", "rtf", "txt"]),
                ("sheets", &["csv", "ods", "xls", "xlsx"]),
                ("pdfs", &["pdf"]),
                ("images", &["bmp", "gif", "jpeg", "jpg", "png", "webp"]),
                ("videos", &["mkv", "mov", "mp4", "webm"]),
                ("audio", &["flac", "m4a", "mp3", "ogg", "wav"]),
                ("archives", &["7z", "gz", "rar", "tar", "zip"]),
            ];
            if value == "folders" {
                predicates.push("f.kind = 'folder'".to_string());
            } else if let Some((_, extensions)) = EXTENSIONS.iter().find(|(kind, _)| *kind == value)
            {
                let suffixes = extensions
                    .iter()
                    .map(|extension| format!("lower(f.name) LIKE '%.{extension}'"))
                    .collect::<Vec<_>>()
                    .join(" OR ");
                predicates.push(format!("f.kind = 'file' AND ({suffixes})"));
            }
        }
        if let Some(owner) = self.owner_scope.as_deref() {
            predicates.push(
                if owner == "owned" {
                    "vw.access_role = 'owner'"
                } else {
                    "vw.access_role != 'owner'"
                }
                .to_string(),
            );
        }
        if let Some(since) = &self.modified_since {
            parameters.push(SqlValue::Text(since.clone()));
            predicates.push(format!(
                "julianday(f.updated_at) >= julianday(?{next_parameter})"
            ));
            *next_parameter += 1;
        }
        if let Some(workspace_id) = &self.workspace_id {
            parameters.push(SqlValue::Text(workspace_id.clone()));
            predicates.push(format!("f.workspace_id = ?{next_parameter}"));
            *next_parameter += 1;
        }
        if let Some(folder_id) = &self.folder_id {
            parameters.push(SqlValue::Text(folder_id.clone()));
            predicates.push(format!("f.id IN (WITH RECURSIVE descendants(id) AS (SELECT id FROM files WHERE id = ?{next_parameter} UNION ALL SELECT child.id FROM files child JOIN descendants parent ON child.parent_id = parent.id) SELECT id FROM descendants)"));
            *next_parameter += 1;
        }
        match self.state_filter.as_deref() {
            Some("starred") => predicates.push("f.starred = 1".to_string()),
            Some("offline") => {
                parameters.push(SqlValue::Text(actor_email.to_string()));
                predicates.push(format!("EXISTS (SELECT 1 FROM mobile_offline_files mof WHERE mof.file_id = f.id AND mof.actor_email = ?{next_parameter})"));
                *next_parameter += 1;
            }
            Some("shared") => predicates.push("EXISTS (SELECT 1 FROM shares s WHERE s.file_id = f.id AND s.revoked = 0 AND s.publication_pending = 0 AND (s.expires_at IS NULL OR julianday(s.expires_at) > julianday('now')) AND (s.max_uses IS NULL OR s.access_count < s.max_uses))".to_string()),
            _ => {}
        }
        predicates
            .into_iter()
            .map(|value| format!(" AND ({value})"))
            .collect()
    }
}
