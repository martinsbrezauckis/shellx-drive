//! Bounded ZIP64 streaming for authenticated and capability-scoped downloads.
//!
//! Archive bodies flow from immutable blob files into the HTTP response without
//! buffering the selected files or the complete ZIP in process memory. The
//! synchronous ZIP writer runs on Tokio's blocking pool and sends bounded
//! chunks to the async response body; a disconnected client stops production.

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    http::{header, Response},
};
use serde::Serialize;
use unicase::UniCase;
use unicode_normalization::UnicodeNormalization;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

use crate::{
    auth::{constant_time_str_eq, random_secret_token, token_hash, Actor, DriveCredential},
    blob,
    download_subjects::CurrentFileSubject,
    error::{ApiError, ApiResult},
    model::FileKind,
};

mod delivery;
mod path_safety;

use delivery::ChannelWriter;

pub(crate) const MAX_ARCHIVE_SELECTIONS: usize = 512;
pub(crate) const MAX_ARCHIVE_ENTRIES: usize = 10_000;
pub(crate) const MAX_ARCHIVE_BYTES: u64 = 50 * 1024 * 1024 * 1024;
pub(crate) const DOWNLOAD_TICKET_TTL_SECONDS: u64 = 120;
pub(crate) type ArchiveEntryRevalidator =
    Arc<dyn Fn(Option<&CurrentFileSubject>) -> ApiResult<()> + Send + Sync + 'static>;
const DOWNLOAD_TICKET_TTL: Duration = Duration::from_secs(DOWNLOAD_TICKET_TTL_SECONDS);
const MAX_DOWNLOAD_TICKETS: usize = 32;
const MAX_PENDING_TICKET_ENTRIES: usize = 50_000;
const MAX_PENDING_TICKETS_PER_PARTITION: usize = 4;
const MAX_PENDING_ENTRIES_PER_PARTITION: usize = MAX_ARCHIVE_ENTRIES;
const MAX_PENDING_TICKETS_PER_WORKSPACE: usize = 8;
const MAX_PENDING_ENTRIES_PER_WORKSPACE: usize = MAX_ARCHIVE_ENTRIES * 2;
const MAX_CONCURRENT_ARCHIVES: usize = 4;

#[derive(Default)]
struct ActiveProducerPartitions {
    workspaces: HashSet<String>,
    clients: HashSet<String>,
}

#[derive(Clone)]
pub(crate) struct ArchiveTickets {
    inner: Arc<Mutex<HashMap<String, ArchiveTicket>>>,
    permits: Arc<tokio::sync::Semaphore>,
    active_producer_partitions: Arc<Mutex<ActiveProducerPartitions>>,
    planning_permits: Arc<tokio::sync::Semaphore>,
    active_planning_partitions: Arc<Mutex<HashSet<String>>>,
}

impl Default for ArchiveTickets {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_ARCHIVES)),
            active_producer_partitions: Arc::new(Mutex::new(ActiveProducerPartitions::default())),
            planning_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_ARCHIVES)),
            active_planning_partitions: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

pub(crate) struct ArchiveTicket {
    pub entries: Vec<ArchiveEntry>,
    pub download_name: String,
    /// Public-share archives retain their originating capability so redemption
    /// can fail closed if an owner revokes or expires the share after prepare.
    pub source_share_id: Option<String>,
    pub source_share_root_id: Option<String>,
    pub source_share_authorization_fingerprint: Option<String>,
    pub source_share_file_ids: Vec<String>,
    pub authenticated_source: Option<AuthenticatedArchiveSource>,
    proof_fingerprint: String,
    partition_key: String,
    workspace_partition_key: String,
    expires_at: Instant,
}

pub(crate) struct AuthenticatedArchiveSource {
    pub actor: Actor,
    pub source_credential: DriveCredential,
    pub workspace_id: String,
    /// Every file-tree node used to build this archive. Redemption rechecks
    /// the complete set so a selected folder cannot retain access to a child
    /// that was trashed after the ticket was prepared.
    pub source_file_ids: Vec<String>,
}

pub(crate) struct PublicShareArchiveSource {
    pub share_id: String,
    pub share_root_id: String,
    pub workspace_id: String,
    pub authorization_fingerprint: String,
    pub source_file_ids: Vec<String>,
}

struct ArchiveTicketScope {
    source_share: Option<(String, String, String)>,
    authenticated_source: Option<AuthenticatedArchiveSource>,
    proof_fingerprint: String,
    partition_key: String,
    workspace_partition_key: String,
    source_share_file_ids: Vec<String>,
}

pub(crate) struct ArchiveProducerPermit {
    _global: tokio::sync::OwnedSemaphorePermit,
    workspace_partition_key: String,
    transport_fingerprint: String,
    active_partitions: Arc<Mutex<ActiveProducerPartitions>>,
}

impl Drop for ArchiveProducerPermit {
    fn drop(&mut self) {
        let mut active = self
            .active_partitions
            .lock()
            .expect("archive producer partition lock poisoned");
        active.workspaces.remove(&self.workspace_partition_key);
        active.clients.remove(&self.transport_fingerprint);
    }
}

pub(crate) struct ArchivePlanningPermit {
    _global: tokio::sync::OwnedSemaphorePermit,
    partition_key: String,
    active_partitions: Arc<Mutex<HashSet<String>>>,
}

impl Drop for ArchivePlanningPermit {
    fn drop(&mut self) {
        self.active_partitions
            .lock()
            .expect("archive planning partition lock poisoned")
            .remove(&self.partition_key);
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ArchiveTicketHealth {
    pub active_tickets: usize,
    pub active_entries: usize,
    pub active_source_bytes: u64,
    pub capacity: usize,
    pub entry_capacity: usize,
    pub ttl_seconds: u64,
    pub earliest_expiry_in_seconds: Option<u64>,
}

impl ArchiveTickets {
    /// Acquire expensive producer capacity only when a prepared capability is
    /// redeemed. Abandoned metadata tickets must not reserve ZIP workers.
    pub(crate) fn try_acquire_producer(
        &self,
        ticket: &ArchiveTicket,
        transport_fingerprint: &str,
    ) -> ApiResult<ArchiveProducerPermit> {
        let mut active = self
            .active_producer_partitions
            .lock()
            .expect("archive producer partition lock poisoned");
        if active.workspaces.contains(&ticket.workspace_partition_key)
            || active.clients.contains(transport_fingerprint)
        {
            return Err(ApiError::TooManyRequests);
        }
        let global = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::TooManyRequests)?;
        active
            .workspaces
            .insert(ticket.workspace_partition_key.clone());
        active.clients.insert(transport_fingerprint.to_string());
        Ok(ArchiveProducerPermit {
            _global: global,
            workspace_partition_key: ticket.workspace_partition_key.clone(),
            transport_fingerprint: transport_fingerprint.to_string(),
            active_partitions: self.active_producer_partitions.clone(),
        })
    }

    pub(crate) fn try_acquire_planner_for_actor(
        &self,
        actor_partition: &str,
        workspace_id: &str,
    ) -> ApiResult<ArchivePlanningPermit> {
        self.try_acquire_planner(
            archive_partition_key("actor", actor_partition),
            archive_partition_key("workspace", workspace_id),
        )
    }

    pub(crate) fn try_acquire_planner_for_share(
        &self,
        share_id: &str,
        workspace_id: &str,
    ) -> ApiResult<ArchivePlanningPermit> {
        self.try_acquire_planner(
            archive_partition_key("share", share_id),
            archive_partition_key("workspace", workspace_id),
        )
    }

    fn try_acquire_planner(
        &self,
        partition_key: String,
        workspace_partition_key: String,
    ) -> ApiResult<ArchivePlanningPermit> {
        {
            let mut tickets = self.inner.lock().expect("archive ticket lock poisoned");
            let now = Instant::now();
            tickets.retain(|_, ticket| ticket.expires_at > now);
            let workspace_ticket_count = tickets
                .values()
                .filter(|ticket| ticket.workspace_partition_key == workspace_partition_key)
                .count();
            if tickets.len() >= MAX_DOWNLOAD_TICKETS
                || workspace_ticket_count >= MAX_PENDING_TICKETS_PER_WORKSPACE
                || tickets
                    .values()
                    .filter(|ticket| ticket.partition_key == partition_key)
                    .count()
                    >= MAX_PENDING_TICKETS_PER_PARTITION
            {
                return Err(ApiError::TooManyRequests);
            }
        }
        let mut active = self
            .active_planning_partitions
            .lock()
            .expect("archive planning partition lock poisoned");
        if active.contains(&workspace_partition_key) {
            return Err(ApiError::TooManyRequests);
        }
        let global = self
            .planning_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::TooManyRequests)?;
        active.insert(workspace_partition_key.clone());
        Ok(ArchivePlanningPermit {
            _global: global,
            partition_key: workspace_partition_key,
            active_partitions: self.active_planning_partitions.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn issue(
        &self,
        entries: Vec<ArchiveEntry>,
        download_name: String,
        actor_partition: &str,
        proof_fingerprint: &str,
    ) -> ApiResult<String> {
        self.issue_scoped(
            entries,
            download_name,
            ArchiveTicketScope {
                source_share: None,
                authenticated_source: None,
                proof_fingerprint: proof_fingerprint.to_string(),
                partition_key: archive_partition_key("actor", actor_partition),
                workspace_partition_key: archive_partition_key("workspace", actor_partition),
                source_share_file_ids: Vec::new(),
            },
        )
    }

    pub(crate) fn issue_for_actor(
        &self,
        entries: Vec<ArchiveEntry>,
        download_name: String,
        source: AuthenticatedArchiveSource,
        proof_fingerprint: String,
    ) -> ApiResult<String> {
        let partition_key = archive_partition_key("actor", &source.actor.email);
        let workspace_partition_key = archive_partition_key("workspace", &source.workspace_id);
        self.issue_scoped(
            entries,
            download_name,
            ArchiveTicketScope {
                source_share: None,
                authenticated_source: Some(source),
                proof_fingerprint,
                partition_key,
                workspace_partition_key,
                source_share_file_ids: Vec::new(),
            },
        )
    }

    pub(crate) fn issue_for_share(
        &self,
        entries: Vec<ArchiveEntry>,
        download_name: String,
        source: PublicShareArchiveSource,
        proof_fingerprint: String,
    ) -> ApiResult<String> {
        ensure_share_entry_subjects(&entries, &source.source_file_ids)?;
        let partition_key = archive_partition_key("share", &source.share_id);
        let workspace_partition_key = archive_partition_key("workspace", &source.workspace_id);
        self.issue_scoped(
            entries,
            download_name,
            ArchiveTicketScope {
                source_share: Some((
                    source.share_id,
                    source.share_root_id,
                    source.authorization_fingerprint,
                )),
                authenticated_source: None,
                proof_fingerprint,
                partition_key,
                workspace_partition_key,
                source_share_file_ids: source.source_file_ids,
            },
        )
    }

    fn issue_scoped(
        &self,
        entries: Vec<ArchiveEntry>,
        download_name: String,
        scope: ArchiveTicketScope,
    ) -> ApiResult<String> {
        let mut tickets = self.inner.lock().expect("archive ticket lock poisoned");
        let now = Instant::now();
        tickets.retain(|_, ticket| ticket.expires_at > now);
        let pending_entries = tickets
            .values()
            .map(|ticket| ticket.entries.len())
            .sum::<usize>();
        let partition_ticket_count = tickets
            .values()
            .filter(|ticket| ticket.partition_key == scope.partition_key)
            .count();
        let partition_entry_count = tickets
            .values()
            .filter(|ticket| ticket.partition_key == scope.partition_key)
            .map(|ticket| ticket.entries.len())
            .sum::<usize>();
        let workspace_ticket_count = tickets
            .values()
            .filter(|ticket| ticket.workspace_partition_key == scope.workspace_partition_key)
            .count();
        let workspace_entry_count = tickets
            .values()
            .filter(|ticket| ticket.workspace_partition_key == scope.workspace_partition_key)
            .map(|ticket| ticket.entries.len())
            .sum::<usize>();
        if tickets.len() >= MAX_DOWNLOAD_TICKETS
            || pending_entries.saturating_add(entries.len()) > MAX_PENDING_TICKET_ENTRIES
            || partition_ticket_count >= MAX_PENDING_TICKETS_PER_PARTITION
            || partition_entry_count.saturating_add(entries.len())
                > MAX_PENDING_ENTRIES_PER_PARTITION
            || workspace_ticket_count >= MAX_PENDING_TICKETS_PER_WORKSPACE
            || workspace_entry_count.saturating_add(entries.len())
                > MAX_PENDING_ENTRIES_PER_WORKSPACE
        {
            return Err(ApiError::TooManyRequests);
        }

        let raw = random_secret_token();
        tickets.insert(
            token_hash(&raw),
            ArchiveTicket {
                entries,
                download_name,
                source_share_id: scope.source_share.as_ref().map(|(id, _, _)| id.clone()),
                source_share_root_id: scope
                    .source_share
                    .as_ref()
                    .map(|(_, root_id, _)| root_id.clone()),
                source_share_authorization_fingerprint: scope
                    .source_share
                    .map(|(_, _, fingerprint)| fingerprint),
                authenticated_source: scope.authenticated_source,
                proof_fingerprint: scope.proof_fingerprint,
                source_share_file_ids: scope.source_share_file_ids,
                partition_key: scope.partition_key,
                workspace_partition_key: scope.workspace_partition_key,
                expires_at: now + DOWNLOAD_TICKET_TTL,
            },
        );
        Ok(raw)
    }

    /// Atomically validate and consume a one-use archive ticket for its bound
    /// client. A copied ticket must remain available to its rightful client.
    pub(crate) fn redeem(
        &self,
        raw: &str,
        transport_fingerprint: &str,
        public_proof_fingerprint: Option<&str>,
    ) -> ApiResult<ArchiveTicket> {
        if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ApiError::NotFound);
        }
        let mut tickets = self.inner.lock().expect("archive ticket lock poisoned");
        let ticket_hash = token_hash(raw);
        let ticket = tickets.get(&ticket_hash).ok_or(ApiError::NotFound)?;
        if ticket.expires_at <= Instant::now() {
            tickets.remove(&ticket_hash);
            return Err(ApiError::NotFound);
        }
        let expected = if ticket.source_share_id.is_some() {
            public_proof_fingerprint.ok_or(ApiError::NotFound)?
        } else {
            transport_fingerprint
        };
        if !constant_time_str_eq(&ticket.proof_fingerprint, expected) {
            return Err(ApiError::NotFound);
        }
        tickets.remove(&ticket_hash).ok_or(ApiError::NotFound)
    }

    pub(crate) fn health(&self) -> ArchiveTicketHealth {
        let mut tickets = self.inner.lock().expect("archive ticket lock poisoned");
        let now = Instant::now();
        tickets.retain(|_, ticket| ticket.expires_at > now);
        ArchiveTicketHealth {
            active_tickets: tickets.len(),
            active_entries: tickets.values().map(|ticket| ticket.entries.len()).sum(),
            active_source_bytes: tickets.values().fold(0_u64, |total, ticket| {
                ticket.entries.iter().fold(total, |subtotal, entry| {
                    subtotal.saturating_add(entry.expected_size)
                })
            }),
            capacity: MAX_DOWNLOAD_TICKETS,
            entry_capacity: MAX_PENDING_TICKET_ENTRIES,
            ttl_seconds: DOWNLOAD_TICKET_TTL_SECONDS,
            earliest_expiry_in_seconds: tickets
                .values()
                .map(|ticket| ticket.expires_at.saturating_duration_since(now).as_secs())
                .min(),
        }
    }
}

fn ensure_share_entry_subjects(
    entries: &[ArchiveEntry],
    source_file_ids: &[String],
) -> ApiResult<()> {
    let scoped = source_file_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let valid = entries
        .iter()
        .all(|entry| match (&entry.blob_path, &entry.content_subject) {
            (None, None) => true,
            (Some(_), Some(subject)) => {
                entry.expected_size == subject.expected_size
                    && scoped.contains(subject.file_id.as_str())
                    && entry
                        .statistics_target
                        .as_ref()
                        .is_some_and(|(file_id, _)| file_id == &subject.file_id)
            }
            _ => false,
        });
    valid.then_some(()).ok_or(ApiError::NotFound)
}

fn archive_partition_key(kind: &str, identity: &str) -> String {
    token_hash(&format!("archive-ticket-partition\0{kind}\0{identity}"))
}

#[derive(Debug, Clone)]
pub(crate) struct ArchiveEntry {
    pub path: String,
    pub blob_path: Option<PathBuf>,
    pub expected_size: u64,
    pub statistics_target: Option<(String, String)>,
    pub content_subject: Option<CurrentFileSubject>,
}

impl ArchiveEntry {
    pub(crate) fn directory(path: String) -> Self {
        Self {
            path,
            blob_path: None,
            expected_size: 0,
            statistics_target: None,
            content_subject: None,
        }
    }

    pub(crate) fn file(
        path: String,
        blob_path: PathBuf,
        content_subject: CurrentFileSubject,
        workspace_id: String,
    ) -> Self {
        let expected_size = content_subject.expected_size;
        let file_id = content_subject.file_id.clone();
        Self {
            path,
            blob_path: Some(blob_path),
            expected_size,
            statistics_target: Some((file_id, workspace_id)),
            content_subject: Some(content_subject),
        }
    }
}

pub(crate) fn entries_from_nodes(
    data_dir: &std::path::Path,
    nodes: Vec<(String, crate::model::DriveFile)>,
) -> ApiResult<Vec<ArchiveEntry>> {
    nodes
        .into_iter()
        .map(|(path, file)| {
            let path = path_safety::portable_archive_path(&path)?;
            match file.kind {
                FileKind::Folder => Ok(ArchiveEntry::directory(path)),
                FileKind::File => {
                    let subject = CurrentFileSubject::from_file(&file)?;
                    let blob_path = blob::blob_file_path(data_dir, &subject.content_hash)?;
                    Ok(ArchiveEntry::file(
                        path,
                        blob_path,
                        subject,
                        file.workspace_id,
                    ))
                }
            }
        })
        .collect()
}

/// Validate the complete archive plan before any response bytes are emitted,
/// then start a bounded producer and return a chunked ZIP response.
pub(crate) async fn response<G>(
    mut entries: Vec<ArchiveEntry>,
    download_name: &str,
    admission_permit: ArchiveProducerPermit,
    response_permit: G,
    entry_revalidator: Option<ArchiveEntryRevalidator>,
) -> ApiResult<Response<Body>>
where
    G: Send + 'static,
{
    validate_entries(&mut entries).await?;

    let timeout = delivery::archive_total_timeout(&entries);
    let body = delivery::archive_body(
        entries,
        admission_permit,
        response_permit,
        entry_revalidator,
        timeout,
    );

    let filename = archive_filename(download_name);
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; sandbox",
        )
        .body(body)
        .unwrap())
}

pub(crate) async fn validate_entries(entries: &mut [ArchiveEntry]) -> ApiResult<()> {
    if entries.is_empty() {
        return Err(ApiError::Validation(
            "the selected items contain no downloadable entries".to_string(),
        ));
    }
    if entries.len() > MAX_ARCHIVE_ENTRIES {
        return Err(ApiError::PayloadTooLarge(format!(
            "archive expands to more than {MAX_ARCHIVE_ENTRIES} entries"
        )));
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));
    validate_archive_member_names(entries)?;
    let mut total_bytes = 0_u64;
    for entry in entries.iter() {
        if let Some(path) = entry.blob_path.as_deref() {
            let actual = tokio::fs::metadata(path).await?.len();
            if actual != entry.expected_size {
                return Err(ApiError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stored blob size does not match file metadata",
                )));
            }
            total_bytes = total_bytes.checked_add(actual).ok_or_else(|| {
                ApiError::PayloadTooLarge("archive byte count overflow".to_string())
            })?;
            if total_bytes > MAX_ARCHIVE_BYTES {
                return Err(ApiError::PayloadTooLarge(format!(
                    "archive exceeds the {} GiB download limit",
                    MAX_ARCHIVE_BYTES / 1024 / 1024 / 1024
                )));
            }
        }
    }
    Ok(())
}

/// Reject names that would alias on common case-insensitive or Unicode-normalizing
/// extractors, including a file used as another member's parent directory.
fn validate_archive_member_names(entries: &[ArchiveEntry]) -> ApiResult<()> {
    let mut names = HashMap::with_capacity(entries.len());
    for entry in entries {
        validate_archive_path(&entry.path, entry.blob_path.is_none())?;
        let components = entry
            .path
            .trim_end_matches('/')
            .split('/')
            .map(|segment| {
                let normalized = segment.nfkc().collect::<String>();
                UniCase::new(normalized)
                    .to_folded_case()
                    .nfkc()
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        if names
            .insert(components, entry.blob_path.is_some())
            .is_some()
        {
            return Err(ApiError::Validation(
                "archive contains duplicate paths".to_string(),
            ));
        }
    }
    for path in names.keys() {
        for prefix_length in 1..path.len() {
            if names.get(&path[..prefix_length]) == Some(&true) {
                return Err(ApiError::Validation(
                    "archive contains a file used as a directory".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn write_archive(
    writer: ChannelWriter,
    entries: Vec<ArchiveEntry>,
    entry_revalidator: Option<ArchiveEntryRevalidator>,
) -> io::Result<()> {
    let mut zip = ZipWriter::new_stream(writer).set_auto_large_file();
    for entry in entries {
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .large_file(entry.expected_size >= u64::from(u32::MAX));
        match entry.blob_path {
            Some(path) => {
                let mut file = File::open(path)?;
                if let Some(revalidate) = entry_revalidator.as_ref() {
                    revalidate(entry.content_subject.as_ref()).map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!("archive authorization changed: {error}"),
                        )
                    })?;
                }
                zip.start_file(entry.path, options).map_err(zip_error)?;
                let copied = io::copy(&mut file, &mut zip)?;
                if copied != entry.expected_size {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stored blob changed while building archive",
                    ));
                }
            }
            None => {
                if let Some(revalidate) = entry_revalidator.as_ref() {
                    revalidate(None).map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!("archive authorization changed: {error}"),
                        )
                    })?;
                }
                let path = format!("{}/", entry.path.trim_end_matches('/'));
                zip.add_directory(path, options).map_err(zip_error)?;
            }
        }
    }
    zip.finish().map_err(zip_error)?;
    Ok(())
}

fn zip_error(error: zip::result::ZipError) -> io::Error {
    io::Error::other(error)
}

fn validate_archive_path(path: &str, directory: bool) -> ApiResult<()> {
    let normalized = if directory {
        path.trim_end_matches('/')
    } else {
        path
    };
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.contains('\\')
        || normalized.len() > usize::from(u16::MAX)
        || normalized
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(ApiError::Validation(
            "archive contains an unsafe path".to_string(),
        ));
    }
    path_safety::validate_portable_archive_path(normalized)?;
    Ok(())
}

fn archive_filename(name: &str) -> String {
    let mut safe = name
        .chars()
        .take(100)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    safe = safe.trim_matches('.').to_string();
    if safe.is_empty() {
        safe = "shellx-drive-selection".to_string();
    }
    if !safe.to_ascii_lowercase().ends_with(".zip") {
        safe.push_str(".zip");
    }
    safe
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use sha2::Digest;
    use std::io::Write;
    use tokio::sync::mpsc;

    #[test]
    fn archive_paths_and_names_are_bounded() {
        assert!(validate_archive_path("folder/file.txt", false).is_ok());
        assert!(validate_archive_path("folder/", true).is_ok());
        assert!(validate_archive_path("../escape.txt", false).is_err());
        assert!(validate_archive_path("folder\\escape.txt", false).is_err());
        assert!(validate_archive_path("C:/payload.txt", false).is_err());
        assert!(validate_archive_path("file.txt:stream", false).is_err());
        assert!(validate_archive_path("folder/CON.txt", false).is_err());
        assert_eq!(archive_filename("Team files"), "Team_files.zip");
    }

    #[test]
    fn portable_archives_reject_case_and_unicode_aliases() {
        for (first, second) in [
            ("Report.txt", "report.txt"),
            ("Caf\u{e9}.txt", "Cafe\u{301}.txt"),
            ("stra\u{df}e.txt", "strasse.txt"),
            ("Folder/Item.txt", "folder/item.txt"),
        ] {
            let entries = [
                ArchiveEntry::directory(first.to_string()),
                ArchiveEntry::directory(second.to_string()),
            ];
            assert!(
                validate_archive_member_names(&entries).is_err(),
                "{first} / {second}"
            );
        }
        assert!(validate_archive_member_names(&[
            ArchiveEntry::directory("M\u{101}rti\u{146}\u{161}/\u{6587}\u{6863}".to_string()),
            ArchiveEntry::directory("M\u{101}rti\u{146}\u{161}/notes".to_string()),
        ])
        .is_ok());
    }

    #[test]
    fn portable_archives_reject_file_directory_prefix_aliases() {
        let file = ArchiveEntry {
            path: "Report".to_string(),
            blob_path: Some(PathBuf::from("unused")),
            expected_size: 0,
            statistics_target: None,
            content_subject: None,
        };
        let entries = [file, ArchiveEntry::directory("report/child".to_string())];
        assert!(validate_archive_member_names(&entries).is_err());
    }

    #[test]
    fn archive_writer_times_out_when_response_queue_stops_draining() {
        let (sender, _receiver) = mpsc::channel(1);
        sender
            .try_send(Ok(Bytes::from_static(b"occupied")))
            .unwrap();
        let mut writer = ChannelWriter {
            sender,
            backpressure_timeout: Duration::ZERO,
            delivery_deadline: Instant::now() + Duration::from_secs(60),
        };
        let error = writer.write(b"next").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[cfg(unix)]
    #[test]
    fn archive_entry_revalidation_runs_after_open_and_before_zip_publication() {
        let temp = tempfile::tempdir().unwrap();
        let blob_path = temp.path().join("blob");
        std::fs::write(&blob_path, b"terminal body").unwrap();
        let entry = ArchiveEntry::file(
            "terminal.txt".to_string(),
            blob_path.clone(),
            CurrentFileSubject {
                file_id: uuid::Uuid::now_v7().to_string(),
                revision: 1,
                content_hash: hex::encode(sha2::Sha256::digest(b"terminal body")),
                expected_size: 13,
            },
            uuid::Uuid::now_v7().to_string(),
        );
        let revalidator: ArchiveEntryRevalidator = Arc::new(move |_| {
            std::fs::remove_file(&blob_path)?;
            Ok(())
        });
        let (sender, _receiver) = mpsc::channel(64);

        write_archive(
            ChannelWriter {
                sender,
                backpressure_timeout: Duration::ZERO,
                delivery_deadline: Instant::now() + Duration::from_secs(60),
            },
            vec![entry],
            Some(revalidator),
        )
        .unwrap();
    }

    #[test]
    fn directory_only_archive_runs_terminal_revalidation() {
        let revalidator: ArchiveEntryRevalidator = Arc::new(|_| Err(ApiError::NotFound));
        let (sender, _receiver) = mpsc::channel(64);

        let error = write_archive(
            ChannelWriter {
                sender,
                backpressure_timeout: Duration::ZERO,
                delivery_deadline: Instant::now() + Duration::from_secs(60),
            },
            vec![ArchiveEntry::directory("folder".to_string())],
            Some(revalidator),
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn leading_directory_revalidates_before_the_first_file() {
        let temp = tempfile::tempdir().unwrap();
        let blob_path = temp.path().join("blob");
        std::fs::write(&blob_path, b"body").unwrap();
        let file_entry = ArchiveEntry::file(
            "folder/file.txt".to_string(),
            blob_path,
            CurrentFileSubject {
                file_id: uuid::Uuid::now_v7().to_string(),
                revision: 1,
                content_hash: hex::encode(sha2::Sha256::digest(b"body")),
                expected_size: 4,
            },
            uuid::Uuid::now_v7().to_string(),
        );
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let revalidator: ArchiveEntryRevalidator = Arc::new(move |subject| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if subject.is_none() {
                return Err(ApiError::NotFound);
            }
            Ok(())
        });
        let (sender, _receiver) = mpsc::channel(64);

        let error = write_archive(
            ChannelWriter {
                sender,
                backpressure_timeout: Duration::ZERO,
                delivery_deadline: Instant::now() + Duration::from_secs(60),
            },
            vec![ArchiveEntry::directory("folder".to_string()), file_entry],
            Some(revalidator),
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn pending_tickets_do_not_hold_archive_producer_capacity() {
        let tickets = ArchiveTickets::default();
        let mut tokens = Vec::new();
        for index in 0..MAX_PENDING_TICKETS_PER_PARTITION {
            tokens.push(
                tickets
                    .issue(
                        Vec::new(),
                        format!("archive-{index}.zip"),
                        "actor-a",
                        "client-a",
                    )
                    .unwrap(),
            );
        }
        assert!(matches!(
            tickets.issue(
                Vec::new(),
                "one-too-many.zip".to_string(),
                "actor-a",
                "client-a",
            ),
            Err(ApiError::TooManyRequests)
        ));

        let same_partition_ticket = tickets.redeem(&tokens[0], "client-a", None).unwrap();
        let same_partition_permit = tickets
            .try_acquire_producer(&same_partition_ticket, "client-a")
            .unwrap();
        let second_same_partition = tickets.redeem(&tokens[1], "client-a", None).unwrap();
        assert!(matches!(
            tickets.try_acquire_producer(&second_same_partition, "client-a"),
            Err(ApiError::TooManyRequests)
        ));
        drop(same_partition_permit);

        let mut permits = Vec::new();
        permits.push(
            tickets
                .try_acquire_producer(&second_same_partition, "client-a")
                .unwrap(),
        );
        for index in 1..MAX_CONCURRENT_ARCHIVES {
            let token = tickets
                .issue(
                    Vec::new(),
                    format!("other-{index}.zip"),
                    &format!("actor-{index}"),
                    &format!("client-{index}"),
                )
                .unwrap();
            let ticket = tickets
                .redeem(&token, &format!("client-{index}"), None)
                .unwrap();
            permits.push(
                tickets
                    .try_acquire_producer(&ticket, &format!("client-{index}"))
                    .unwrap(),
            );
        }
        let overflow_token = tickets
            .issue(
                Vec::new(),
                "overflow.zip".to_string(),
                "overflow-actor",
                "overflow-client",
            )
            .unwrap();
        let overflow_ticket = tickets
            .redeem(&overflow_token, "overflow-client", None)
            .unwrap();
        assert!(matches!(
            tickets.try_acquire_producer(&overflow_ticket, "overflow-client"),
            Err(ApiError::TooManyRequests)
        ));
        permits.pop();
        assert!(tickets
            .try_acquire_producer(&overflow_ticket, "overflow-client")
            .is_ok());
    }

    #[test]
    fn archive_ticket_admission_reaps_expired_metadata_and_is_partitioned() {
        let tickets = ArchiveTickets::default();
        let mut tokens = Vec::new();
        for index in 0..MAX_PENDING_TICKETS_PER_PARTITION {
            tokens.push(
                tickets
                    .issue(
                        Vec::new(),
                        format!("archive-{index}.zip"),
                        "actor-a",
                        "client-a",
                    )
                    .unwrap(),
            );
        }
        assert!(tickets
            .issue(Vec::new(), "other.zip".to_string(), "actor-b", "client-b",)
            .is_ok());
        let expired_hash = token_hash(&tokens[0]);
        tickets
            .inner
            .lock()
            .unwrap()
            .get_mut(&expired_hash)
            .unwrap()
            .expires_at = Instant::now() - Duration::from_secs(1);

        assert!(tickets
            .issue(
                Vec::new(),
                "replacement.zip".to_string(),
                "actor-a",
                "client-a",
            )
            .is_ok());
        assert!(matches!(
            tickets.redeem(&tokens[0], "client-a", None),
            Err(ApiError::NotFound)
        ));
    }

    #[test]
    fn one_workspace_cannot_exhaust_global_public_archive_tickets() {
        let tickets = ArchiveTickets::default();
        for index in 0..MAX_PENDING_TICKETS_PER_WORKSPACE {
            tickets
                .issue_for_share(
                    Vec::new(),
                    format!("workspace-a-{index}.zip"),
                    PublicShareArchiveSource {
                        share_id: format!("share-a-{index}"),
                        share_root_id: "root-a".to_string(),
                        workspace_id: "workspace-a".to_string(),
                        authorization_fingerprint: "authorization".to_string(),
                        source_file_ids: Vec::new(),
                    },
                    format!("client-a-{index}"),
                )
                .unwrap();
        }
        assert!(matches!(
            tickets.issue_for_share(
                Vec::new(),
                "workspace-a-overflow.zip".to_string(),
                PublicShareArchiveSource {
                    share_id: "share-a-overflow".to_string(),
                    share_root_id: "root-a".to_string(),
                    workspace_id: "workspace-a".to_string(),
                    authorization_fingerprint: "authorization".to_string(),
                    source_file_ids: Vec::new(),
                },
                "client-a-overflow".to_string(),
            ),
            Err(ApiError::TooManyRequests)
        ));
        assert!(tickets
            .issue_for_share(
                Vec::new(),
                "workspace-b.zip".to_string(),
                PublicShareArchiveSource {
                    share_id: "share-b".to_string(),
                    share_root_id: "root-b".to_string(),
                    workspace_id: "workspace-b".to_string(),
                    authorization_fingerprint: "authorization".to_string(),
                    source_file_ids: Vec::new(),
                },
                "client-b".to_string(),
            )
            .is_ok());
    }

    #[test]
    fn archive_redemption_is_bound_to_client_and_one_client_partition() {
        let tickets = ArchiveTickets::default();
        let first = tickets
            .issue(
                Vec::new(),
                "first.zip".to_string(),
                "workspace-a",
                "client-a",
            )
            .unwrap();
        let second = tickets
            .issue(
                Vec::new(),
                "second.zip".to_string(),
                "workspace-b",
                "client-a",
            )
            .unwrap();
        assert!(matches!(
            tickets.redeem(&first, "client-b", None),
            Err(ApiError::NotFound)
        ));
        let first = tickets.redeem(&first, "client-a", None).unwrap();
        let second = tickets.redeem(&second, "client-a", None).unwrap();
        let _permit = tickets.try_acquire_producer(&first, "client-a").unwrap();
        assert!(matches!(
            tickets.try_acquire_producer(&second, "client-a"),
            Err(ApiError::TooManyRequests)
        ));
    }

    #[test]
    fn rotated_public_archive_proofs_do_not_multiply_transport_capacity() {
        let tickets = ArchiveTickets::default();
        let first = tickets
            .issue_for_share(
                Vec::new(),
                "first.zip".to_string(),
                PublicShareArchiveSource {
                    share_id: "share-a".to_string(),
                    share_root_id: "root-a".to_string(),
                    workspace_id: "workspace-a".to_string(),
                    authorization_fingerprint: "authorization-a".to_string(),
                    source_file_ids: Vec::new(),
                },
                "proof-before-rotation".to_string(),
            )
            .unwrap();
        let second = tickets
            .issue_for_share(
                Vec::new(),
                "second.zip".to_string(),
                PublicShareArchiveSource {
                    share_id: "share-b".to_string(),
                    share_root_id: "root-b".to_string(),
                    workspace_id: "workspace-b".to_string(),
                    authorization_fingerprint: "authorization-b".to_string(),
                    source_file_ids: Vec::new(),
                },
                "proof-after-rotation".to_string(),
            )
            .unwrap();

        assert!(matches!(
            tickets.redeem(
                &first,
                "server-derived-client-a",
                Some("proof-from-another-client"),
            ),
            Err(ApiError::NotFound)
        ));
        let first = tickets
            .redeem(
                &first,
                "server-derived-client-a",
                Some("proof-before-rotation"),
            )
            .unwrap();
        let second = tickets
            .redeem(
                &second,
                "server-derived-client-a",
                Some("proof-after-rotation"),
            )
            .unwrap();
        let _permit = tickets
            .try_acquire_producer(&first, "server-derived-client-a")
            .unwrap();
        assert!(matches!(
            tickets.try_acquire_producer(&second, "server-derived-client-a"),
            Err(ApiError::TooManyRequests)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canceled_blocking_plan_keeps_its_workspace_admission() {
        let tickets = ArchiveTickets::default();
        let permit = tickets
            .try_acquire_planner_for_share("share-a", "workspace-a")
            .unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocking = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(permit);
        });
        started_rx.recv().unwrap();
        blocking.abort();
        assert!(matches!(
            tickets.try_acquire_planner_for_share("share-b", "workspace-a"),
            Err(ApiError::TooManyRequests)
        ));

        release_tx.send(()).unwrap();
        for _ in 0..100 {
            if tickets
                .try_acquire_planner_for_share("share-b", "workspace-a")
                .is_ok()
            {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("archive planner admission outlived its blocking traversal");
    }
}
