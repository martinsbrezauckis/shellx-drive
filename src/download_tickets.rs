//! Short-lived capabilities for native, disk-streamed single-file downloads.
//!
//! The authenticated request authorizes a file and stores only bounded
//! metadata. The browser then follows an unauthenticated capability URL, so
//! the response can flow directly to the platform download manager instead of
//! becoming a JavaScript `Blob`. Raw capabilities never enter debug output.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::Serialize;

use crate::{
    auth::{constant_time_str_eq, random_secret_token, token_hash, Actor, DriveCredential},
    download_subjects::{CurrentFileSubject, FileContentSubject},
    error::{ApiError, ApiResult},
};

pub(crate) const FILE_DOWNLOAD_TICKET_TTL_SECONDS: u64 = 120;
const FILE_DOWNLOAD_TICKET_TTL: Duration = Duration::from_secs(FILE_DOWNLOAD_TICKET_TTL_SECONDS);
const MAX_FILE_DOWNLOAD_TICKETS: usize = 128;
const MAX_FILE_DOWNLOAD_TICKETS_PER_PARTITION: usize = 16;
const MAX_FILE_DOWNLOAD_TICKETS_PER_WORKSPACE: usize = 32;
const MAX_PREVIEW_REQUESTS_PER_TICKET: u16 = 64;

#[derive(Clone, Default)]
pub(crate) struct FileDownloadTickets {
    inner: Arc<Mutex<Registry>>,
}

#[derive(Default)]
struct Registry {
    tickets: HashMap<String, FileDownloadTicket>,
    issued_total: u64,
    redeemed_total: u64,
    expired_total: u64,
    rejected_total: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileTicketDisposition {
    Inline,
    Attachment,
}

#[derive(Clone)]
pub(crate) struct FileDownloadTicket {
    pub file_name: String,
    pub blob_path: PathBuf,
    pub expected_size: u64,
    pub disposition: FileTicketDisposition,
    pub statistics_target: Option<FileStatisticsTarget>,
    pub record_statistics: bool,
    pub authorization: Option<FileDownloadAuthorization>,
    pub share_authorization: Option<PublicShareFileAuthorization>,
    partition_key: String,
    workspace_partition_key: Option<String>,
    remaining_uses: u16,
    expires_at: Instant,
}

#[derive(Clone)]
pub(crate) struct FileDownloadAuthorization {
    pub actor: Actor,
    pub source_credential: DriveCredential,
    pub subject: FileContentSubject,
    pub workspace_id: String,
}

/// The public-share state that must still hold when an unauthenticated native
/// browser ticket is redeemed. This is separate from user-credential
/// authorization: the share itself is the authorization source.
#[derive(Clone)]
pub(crate) struct PublicShareFileAuthorization {
    pub share_id: String,
    pub share_root_id: String,
    pub subject: CurrentFileSubject,
    pub authorization_fingerprint: String,
    pub client_binding: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileStatisticsTarget {
    pub file_id: String,
    pub workspace_id: String,
}

struct FileDownloadTicketSpec {
    file_name: String,
    blob_path: PathBuf,
    expected_size: u64,
    disposition: FileTicketDisposition,
    statistics_target: Option<FileStatisticsTarget>,
    partition_key: String,
    workspace_partition_key: Option<String>,
    remaining_uses: u16,
    authorization: Option<FileDownloadAuthorization>,
    share_authorization: Option<PublicShareFileAuthorization>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FileDownloadTicketHealth {
    pub active_tickets: usize,
    pub active_downloads: usize,
    pub active_previews: usize,
    pub active_bytes: u64,
    pub issued_total: u64,
    pub redeemed_total: u64,
    pub expired_total: u64,
    pub rejected_total: u64,
    pub capacity: usize,
    pub ttl_seconds: u64,
    pub earliest_expiry_in_seconds: Option<u64>,
}

impl FileDownloadTickets {
    pub(crate) fn issue(
        &self,
        file_name: String,
        blob_path: PathBuf,
        expected_size: u64,
    ) -> ApiResult<String> {
        self.issue_with_ttl(
            FileDownloadTicketSpec {
                file_name,
                blob_path,
                expected_size,
                disposition: FileTicketDisposition::Attachment,
                statistics_target: None,
                partition_key: file_ticket_partition_key("internal", "service-twin"),
                workspace_partition_key: None,
                remaining_uses: 1,
                authorization: None,
                share_authorization: None,
            },
            FILE_DOWNLOAD_TICKET_TTL,
        )
    }

    // File identity, response metadata, and the exact authorization source are
    // intentionally explicit at this capability-minting boundary.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue_for_file(
        &self,
        file_name: String,
        blob_path: PathBuf,
        subject: FileContentSubject,
        workspace_id: String,
        actor_partition: &str,
        actor: Actor,
        source_credential: DriveCredential,
    ) -> ApiResult<String> {
        let file_id = subject.file_id().to_string();
        self.issue_with_ttl(
            FileDownloadTicketSpec {
                file_name,
                blob_path,
                expected_size: subject.expected_size(),
                disposition: FileTicketDisposition::Attachment,
                statistics_target: Some(FileStatisticsTarget {
                    file_id: file_id.clone(),
                    workspace_id: workspace_id.clone(),
                }),
                partition_key: file_ticket_partition_key("actor", actor_partition),
                workspace_partition_key: Some(file_ticket_partition_key(
                    "workspace",
                    &workspace_id,
                )),
                remaining_uses: 1,
                authorization: Some(FileDownloadAuthorization {
                    actor,
                    source_credential,
                    subject,
                    workspace_id,
                }),
                share_authorization: None,
            },
            FILE_DOWNLOAD_TICKET_TTL,
        )
    }

    pub(crate) fn issue_preview(
        &self,
        file_name: String,
        blob_path: PathBuf,
        expected_size: u64,
    ) -> ApiResult<String> {
        self.issue_with_ttl(
            FileDownloadTicketSpec {
                file_name,
                blob_path,
                expected_size,
                disposition: FileTicketDisposition::Inline,
                statistics_target: None,
                partition_key: file_ticket_partition_key("internal", "service-twin"),
                workspace_partition_key: None,
                remaining_uses: MAX_PREVIEW_REQUESTS_PER_TICKET,
                authorization: None,
                share_authorization: None,
            },
            FILE_DOWNLOAD_TICKET_TTL,
        )
    }

    // Keep preview capability issuance bound to the same explicit file and
    // credential context as ordinary downloads.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue_preview_for_file(
        &self,
        file_name: String,
        blob_path: PathBuf,
        subject: FileContentSubject,
        workspace_id: String,
        actor_partition: &str,
        actor: Actor,
        source_credential: DriveCredential,
    ) -> ApiResult<String> {
        let file_id = subject.file_id().to_string();
        self.issue_with_ttl(
            FileDownloadTicketSpec {
                file_name,
                blob_path,
                expected_size: subject.expected_size(),
                disposition: FileTicketDisposition::Inline,
                statistics_target: Some(FileStatisticsTarget {
                    file_id: file_id.clone(),
                    workspace_id: workspace_id.clone(),
                }),
                partition_key: file_ticket_partition_key("actor", actor_partition),
                workspace_partition_key: Some(file_ticket_partition_key(
                    "workspace",
                    &workspace_id,
                )),
                remaining_uses: MAX_PREVIEW_REQUESTS_PER_TICKET,
                authorization: Some(FileDownloadAuthorization {
                    actor,
                    source_credential,
                    subject,
                    workspace_id,
                }),
                share_authorization: None,
            },
            FILE_DOWNLOAD_TICKET_TTL,
        )
    }

    /// Issue a native file capability from a public share. The share is
    /// revalidated at redemption, including its current revocation, expiry,
    /// policy, root scope, and password-policy fingerprint.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue_for_share(
        &self,
        file_name: String,
        blob_path: PathBuf,
        disposition: FileTicketDisposition,
        share_id: String,
        share_root_id: String,
        subject: CurrentFileSubject,
        workspace_id: String,
        authorization_fingerprint: String,
        client_binding: String,
    ) -> ApiResult<String> {
        let file_id = subject.file_id.clone();
        let remaining_uses = match disposition {
            FileTicketDisposition::Attachment => 1,
            FileTicketDisposition::Inline => MAX_PREVIEW_REQUESTS_PER_TICKET,
        };
        self.issue_with_ttl(
            FileDownloadTicketSpec {
                file_name,
                blob_path,
                expected_size: subject.expected_size,
                disposition,
                statistics_target: Some(FileStatisticsTarget {
                    file_id: file_id.clone(),
                    workspace_id: workspace_id.clone(),
                }),
                partition_key: file_ticket_partition_key("share", &share_id),
                workspace_partition_key: Some(file_ticket_partition_key(
                    "workspace",
                    &workspace_id,
                )),
                remaining_uses,
                authorization: None,
                share_authorization: Some(PublicShareFileAuthorization {
                    share_id,
                    share_root_id,
                    subject,
                    authorization_fingerprint,
                    client_binding,
                }),
            },
            FILE_DOWNLOAD_TICKET_TTL,
        )
    }

    fn issue_with_ttl(&self, spec: FileDownloadTicketSpec, ttl: Duration) -> ApiResult<String> {
        let mut registry = self
            .inner
            .lock()
            .expect("file download ticket lock poisoned");
        prune_expired(&mut registry, Instant::now());
        let partition_count = registry
            .tickets
            .values()
            .filter(|ticket| ticket.partition_key == spec.partition_key)
            .count();
        let workspace_partition_count = spec.workspace_partition_key.as_ref().map_or(0, |key| {
            registry
                .tickets
                .values()
                .filter(|ticket| ticket.workspace_partition_key.as_ref() == Some(key))
                .count()
        });
        if registry.tickets.len() >= MAX_FILE_DOWNLOAD_TICKETS
            || partition_count >= MAX_FILE_DOWNLOAD_TICKETS_PER_PARTITION
            || workspace_partition_count >= MAX_FILE_DOWNLOAD_TICKETS_PER_WORKSPACE
        {
            registry.rejected_total = registry.rejected_total.saturating_add(1);
            return Err(ApiError::TooManyRequests);
        }

        let raw = random_secret_token();
        registry.tickets.insert(
            token_hash(&raw),
            FileDownloadTicket {
                file_name: spec.file_name,
                blob_path: spec.blob_path,
                expected_size: spec.expected_size,
                disposition: spec.disposition,
                statistics_target: spec.statistics_target,
                record_statistics: true,
                authorization: spec.authorization,
                share_authorization: spec.share_authorization,
                partition_key: spec.partition_key,
                workspace_partition_key: spec.workspace_partition_key,
                remaining_uses: spec.remaining_uses,
                expires_at: Instant::now() + ttl,
            },
        );
        registry.issued_total = registry.issued_total.saturating_add(1);
        Ok(raw)
    }

    pub(crate) fn redeem(
        &self,
        raw: &str,
        public_client_binding: Option<&str>,
    ) -> ApiResult<FileDownloadTicket> {
        if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ApiError::NotFound);
        }
        let mut registry = self
            .inner
            .lock()
            .expect("file download ticket lock poisoned");
        let now = Instant::now();
        prune_expired(&mut registry, now);
        let key = token_hash(raw);
        let mut ticket = registry
            .tickets
            .get(&key)
            .cloned()
            .ok_or(ApiError::NotFound)?;
        if let Some(authorization) = ticket.share_authorization.as_ref() {
            let binding_matches = public_client_binding.is_some_and(|binding| {
                constant_time_str_eq(&authorization.client_binding, binding)
            });
            if !binding_matches {
                registry.rejected_total = registry.rejected_total.saturating_add(1);
                return Err(ApiError::NotFound);
            }
        }
        if ticket.expires_at <= now {
            registry.tickets.remove(&key);
            registry.expired_total = registry.expired_total.saturating_add(1);
            return Err(ApiError::NotFound);
        }
        if ticket.remaining_uses <= 1 {
            registry.tickets.remove(&key);
        } else if let Some(stored) = registry.tickets.get_mut(&key) {
            stored.remaining_uses -= 1;
            stored.record_statistics = false;
            ticket.remaining_uses = stored.remaining_uses;
        }
        registry.redeemed_total = registry.redeemed_total.saturating_add(1);
        Ok(ticket)
    }

    pub(crate) fn health(&self) -> FileDownloadTicketHealth {
        let mut registry = self
            .inner
            .lock()
            .expect("file download ticket lock poisoned");
        let now = Instant::now();
        prune_expired(&mut registry, now);
        let active_bytes = registry.tickets.values().fold(0_u64, |total, ticket| {
            total.saturating_add(ticket.expected_size)
        });
        let earliest_expiry_in_seconds = registry
            .tickets
            .values()
            .map(|ticket| ticket.expires_at.saturating_duration_since(now).as_secs())
            .min();
        FileDownloadTicketHealth {
            active_tickets: registry.tickets.len(),
            active_downloads: registry
                .tickets
                .values()
                .filter(|ticket| ticket.disposition == FileTicketDisposition::Attachment)
                .count(),
            active_previews: registry
                .tickets
                .values()
                .filter(|ticket| ticket.disposition == FileTicketDisposition::Inline)
                .count(),
            active_bytes,
            issued_total: registry.issued_total,
            redeemed_total: registry.redeemed_total,
            expired_total: registry.expired_total,
            rejected_total: registry.rejected_total,
            capacity: MAX_FILE_DOWNLOAD_TICKETS,
            ttl_seconds: FILE_DOWNLOAD_TICKET_TTL_SECONDS,
            earliest_expiry_in_seconds,
        }
    }
}

fn file_ticket_partition_key(kind: &str, identity: &str) -> String {
    token_hash(&format!(
        "file-download-ticket-partition\0{kind}\0{identity}"
    ))
}

fn prune_expired(registry: &mut Registry, now: Instant) {
    let before = registry.tickets.len();
    registry.tickets.retain(|_, ticket| ticket.expires_at > now);
    registry.expired_total = registry
        .expired_total
        .saturating_add((before - registry.tickets.len()) as u64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_hashed_one_use_and_expire() {
        let registry = FileDownloadTickets::default();
        let raw = registry
            .issue("report.bin".to_string(), PathBuf::from("blob"), 42)
            .unwrap();
        assert_eq!(raw.len(), 64);
        assert!(!format!("{:?}", registry.health()).contains(&raw));
        let ticket = registry.redeem(&raw, None).unwrap();
        assert_eq!(ticket.file_name, "report.bin");
        assert_eq!(ticket.expected_size, 42);
        assert!(registry.redeem(&raw, None).is_err());

        let preview = registry
            .issue_preview("movie.mp4".to_string(), PathBuf::from("blob"), 99)
            .unwrap();
        assert_eq!(
            registry.redeem(&preview, None).unwrap().disposition,
            FileTicketDisposition::Inline
        );
        assert!(registry.redeem(&preview, None).is_ok());

        let expired = registry
            .issue_with_ttl(
                FileDownloadTicketSpec {
                    file_name: "expired.bin".to_string(),
                    blob_path: PathBuf::from("blob"),
                    expected_size: 1,
                    disposition: FileTicketDisposition::Attachment,
                    statistics_target: None,
                    partition_key: file_ticket_partition_key("test", "expired"),
                    workspace_partition_key: None,
                    remaining_uses: 1,
                    authorization: None,
                    share_authorization: None,
                },
                Duration::ZERO,
            )
            .unwrap();
        assert!(registry.redeem(&expired, None).is_err());
        let health = registry.health();
        assert_eq!(health.active_tickets, 1);
        assert_eq!(health.active_previews, 1);
        assert_eq!(health.issued_total, 3);
        assert_eq!(health.redeemed_total, 3);
        assert_eq!(health.expired_total, 1);
    }

    #[test]
    fn public_share_ticket_rejects_other_client_without_consuming_it() {
        let registry = FileDownloadTickets::default();
        let raw = registry
            .issue_for_share(
                "shared.bin".to_string(),
                PathBuf::from("blob"),
                FileTicketDisposition::Attachment,
                "share-id".to_string(),
                "root-id".to_string(),
                CurrentFileSubject {
                    file_id: "file-id".to_string(),
                    revision: 1,
                    content_hash: "a".repeat(64),
                    expected_size: 42,
                },
                "workspace-id".to_string(),
                "authorization-fingerprint".to_string(),
                "client-a".to_string(),
            )
            .unwrap();

        assert!(matches!(
            registry.redeem(&raw, Some("client-b")),
            Err(ApiError::NotFound)
        ));
        assert!(registry.redeem(&raw, Some("client-a")).is_ok());
        assert!(registry.redeem(&raw, Some("client-a")).is_err());
    }

    #[test]
    fn one_partition_cannot_exhaust_global_file_ticket_capacity() {
        let registry = FileDownloadTickets::default();
        for index in 0..MAX_FILE_DOWNLOAD_TICKETS_PER_PARTITION {
            registry
                .issue_with_ttl(
                    FileDownloadTicketSpec {
                        file_name: format!("actor-a-{index}.bin"),
                        blob_path: PathBuf::from("blob"),
                        expected_size: 1,
                        disposition: FileTicketDisposition::Attachment,
                        statistics_target: None,
                        partition_key: file_ticket_partition_key("actor", "actor-a"),
                        workspace_partition_key: None,
                        remaining_uses: 1,
                        authorization: None,
                        share_authorization: None,
                    },
                    FILE_DOWNLOAD_TICKET_TTL,
                )
                .unwrap();
        }
        assert!(matches!(
            registry.issue_with_ttl(
                FileDownloadTicketSpec {
                    file_name: "blocked.bin".to_string(),
                    blob_path: PathBuf::from("blob"),
                    expected_size: 1,
                    disposition: FileTicketDisposition::Attachment,
                    statistics_target: None,
                    partition_key: file_ticket_partition_key("actor", "actor-a"),
                    workspace_partition_key: None,
                    remaining_uses: 1,
                    authorization: None,
                    share_authorization: None,
                },
                FILE_DOWNLOAD_TICKET_TTL,
            ),
            Err(ApiError::TooManyRequests)
        ));
        assert!(registry
            .issue_with_ttl(
                FileDownloadTicketSpec {
                    file_name: "actor-b.bin".to_string(),
                    blob_path: PathBuf::from("blob"),
                    expected_size: 1,
                    disposition: FileTicketDisposition::Attachment,
                    statistics_target: None,
                    partition_key: file_ticket_partition_key("actor", "actor-b"),
                    workspace_partition_key: None,
                    remaining_uses: 1,
                    authorization: None,
                    share_authorization: None,
                },
                FILE_DOWNLOAD_TICKET_TTL,
            )
            .is_ok());
    }

    #[test]
    fn one_workspace_cannot_exhaust_global_file_ticket_capacity() {
        let registry = FileDownloadTickets::default();
        let workspace_a = file_ticket_partition_key("workspace", "workspace-a");
        for index in 0..MAX_FILE_DOWNLOAD_TICKETS_PER_WORKSPACE {
            registry
                .issue_with_ttl(
                    FileDownloadTicketSpec {
                        file_name: format!("workspace-a-{index}.bin"),
                        blob_path: PathBuf::from("blob"),
                        expected_size: 1,
                        disposition: FileTicketDisposition::Attachment,
                        statistics_target: None,
                        partition_key: file_ticket_partition_key(
                            "share",
                            &format!("share-{index}"),
                        ),
                        workspace_partition_key: Some(workspace_a.clone()),
                        remaining_uses: 1,
                        authorization: None,
                        share_authorization: None,
                    },
                    FILE_DOWNLOAD_TICKET_TTL,
                )
                .unwrap();
        }
        assert!(matches!(
            registry.issue_with_ttl(
                FileDownloadTicketSpec {
                    file_name: "workspace-a-blocked.bin".to_string(),
                    blob_path: PathBuf::from("blob"),
                    expected_size: 1,
                    disposition: FileTicketDisposition::Attachment,
                    statistics_target: None,
                    partition_key: file_ticket_partition_key("share", "workspace-a-new-share"),
                    workspace_partition_key: Some(workspace_a),
                    remaining_uses: 1,
                    authorization: None,
                    share_authorization: None,
                },
                FILE_DOWNLOAD_TICKET_TTL,
            ),
            Err(ApiError::TooManyRequests)
        ));
        assert!(registry
            .issue_with_ttl(
                FileDownloadTicketSpec {
                    file_name: "workspace-b.bin".to_string(),
                    blob_path: PathBuf::from("blob"),
                    expected_size: 1,
                    disposition: FileTicketDisposition::Attachment,
                    statistics_target: None,
                    partition_key: file_ticket_partition_key("share", "workspace-b-share"),
                    workspace_partition_key: Some(file_ticket_partition_key(
                        "workspace",
                        "workspace-b",
                    )),
                    remaining_uses: 1,
                    authorization: None,
                    share_authorization: None,
                },
                FILE_DOWNLOAD_TICKET_TTL,
            )
            .is_ok());
    }
}
