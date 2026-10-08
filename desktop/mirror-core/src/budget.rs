use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{DesktopError, RemoteEntry, Result, SyncAction};

pub(crate) const RESUMABLE_UPLOAD_CHUNK_BYTES: u64 = 512 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncPassLimits {
    pub max_manifest_items: usize,
    pub max_actions: usize,
    pub max_downloads: usize,
    pub max_download_bytes: u64,
    pub max_upload_bytes: u64,
    pub max_requests: usize,
}

impl Default for SyncPassLimits {
    fn default() -> Self {
        Self {
            max_manifest_items: 10_000,
            max_actions: 20_000,
            max_downloads: 10_000,
            max_download_bytes: 20 * 1024 * 1024 * 1024,
            max_upload_bytes: 20 * 1024 * 1024 * 1024,
            max_requests: 50_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncPassAdmission {
    pub manifest_items: usize,
    pub actions: usize,
    pub downloads: usize,
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub estimated_requests: usize,
}

/// One admission envelope for every configured root visited by a sync cycle.
/// A rejected root leaves the charged total unchanged.
#[derive(Clone, Debug)]
pub struct SyncCycleBudget {
    limits: SyncPassLimits,
    used: SyncPassAdmission,
    manifest_transport: Arc<Mutex<ManifestTransport>>,
}

#[derive(Debug)]
struct ManifestTransport {
    remaining_bytes: usize,
    remaining_requests: usize,
    remaining_items: usize,
}

impl SyncCycleBudget {
    pub fn new(limits: SyncPassLimits) -> Self {
        Self::with_manifest_transport_limit(limits, 64 * 1024 * 1024)
    }

    pub fn with_manifest_transport_limit(limits: SyncPassLimits, max_bytes: usize) -> Self {
        Self {
            limits,
            used: SyncPassAdmission {
                manifest_items: 0,
                actions: 0,
                downloads: 0,
                download_bytes: 0,
                upload_bytes: 0,
                estimated_requests: 0,
            },
            manifest_transport: Arc::new(Mutex::new(ManifestTransport {
                remaining_bytes: max_bytes,
                remaining_requests: limits.max_requests,
                remaining_items: limits.max_manifest_items.saturating_mul(10),
            })),
        }
    }

    /// Reserve response bytes before appending them to the JSON body. Clones
    /// share this counter across all root clients and terminal refetches.
    pub fn charge_transport_bytes(&self, bytes: usize) -> Result<()> {
        let mut transport = self
            .manifest_transport
            .lock()
            .map_err(|_| DesktopError::InvalidState("sync cycle budget lock failed".to_string()))?;
        transport.remaining_bytes =
            transport
                .remaining_bytes
                .checked_sub(bytes)
                .ok_or_else(|| {
                    DesktopError::SyncCycleBudgetExceeded("sync transport bytes".to_string())
                })?;
        Ok(())
    }

    pub fn charge_transport_request(&self) -> Result<()> {
        let mut transport = self
            .manifest_transport
            .lock()
            .map_err(|_| DesktopError::InvalidState("sync cycle budget lock failed".to_string()))?;
        transport.remaining_requests =
            transport.remaining_requests.checked_sub(1).ok_or_else(|| {
                DesktopError::SyncCycleBudgetExceeded("sync transport requests".to_string())
            })?;
        Ok(())
    }

    pub fn charge_manifest_items(&self, items: usize) -> Result<()> {
        let mut transport = self
            .manifest_transport
            .lock()
            .map_err(|_| DesktopError::InvalidState("sync cycle budget lock failed".to_string()))?;
        transport.remaining_items =
            transport
                .remaining_items
                .checked_sub(items)
                .ok_or_else(|| {
                    DesktopError::SyncCycleBudgetExceeded("manifest transport items".to_string())
                })?;
        Ok(())
    }

    /// Reserve the next root's plan before staging or remote mutation. Each
    /// initial/final manifest may require a root revalidation and refetch, so
    /// the cycle reserves six requests for the two manifest calls.
    pub fn admit(
        &mut self,
        remote: &[RemoteEntry],
        actions: &[SyncAction],
    ) -> Result<SyncPassAdmission> {
        let mut next = validate_sync_pass(remote, actions, self.limits)?;
        next.estimated_requests = next.estimated_requests.checked_add(4).ok_or_else(|| {
            DesktopError::InvalidState("sync cycle request estimate overflowed".to_string())
        })?;
        self.charge(next)
    }

    /// Charge separately confirmed review or restore work in this cycle.
    /// The caller must reserve before initiating its transfers.
    pub fn admit_extra(
        &mut self,
        actions: usize,
        downloads: usize,
        download_bytes: u64,
        estimated_requests: usize,
    ) -> Result<SyncPassAdmission> {
        self.charge(SyncPassAdmission {
            manifest_items: 0,
            actions,
            downloads,
            download_bytes,
            upload_bytes: 0,
            estimated_requests,
        })
    }

    fn charge(&mut self, next: SyncPassAdmission) -> Result<SyncPassAdmission> {
        let add = |used: usize, charge: usize, limit: usize, name: &str| {
            used.checked_add(charge)
                .filter(|total| *total <= limit)
                .ok_or_else(|| {
                    DesktopError::SyncCycleBudgetExceeded(format!(
                        "sync cycle exceeds its {limit}-{name} limit"
                    ))
                })
        };
        let manifest_items = add(
            self.used.manifest_items,
            next.manifest_items,
            self.limits.max_manifest_items,
            "manifest-item",
        )?;
        let actions = add(
            self.used.actions,
            next.actions,
            self.limits.max_actions,
            "action",
        )?;
        let downloads = add(
            self.used.downloads,
            next.downloads,
            self.limits.max_downloads,
            "download",
        )?;
        let download_bytes = self
            .used
            .download_bytes
            .checked_add(next.download_bytes)
            .filter(|total| *total <= self.limits.max_download_bytes)
            .ok_or_else(|| {
                DesktopError::SyncCycleBudgetExceeded(format!(
                    "sync cycle exceeds its {}-byte aggregate download limit",
                    self.limits.max_download_bytes
                ))
            })?;
        let estimated_requests = add(
            self.used.estimated_requests,
            next.estimated_requests,
            self.limits.max_requests,
            "request-estimate",
        )?;
        let upload_bytes = self
            .used
            .upload_bytes
            .checked_add(next.upload_bytes)
            .filter(|total| *total <= self.limits.max_upload_bytes)
            .ok_or_else(|| {
                DesktopError::SyncCycleBudgetExceeded(format!(
                    "sync cycle exceeds its {}-byte aggregate upload limit",
                    self.limits.max_upload_bytes
                ))
            })?;
        self.used = SyncPassAdmission {
            manifest_items,
            actions,
            downloads,
            download_bytes,
            upload_bytes,
            estimated_requests,
        };
        Ok(self.used)
    }

    pub fn used(&self) -> SyncPassAdmission {
        self.used
    }
}

/// Validate the complete desktop plan before any staging or remote mutation.
/// Individual HTTP/body limits remain defense in depth; this is the aggregate
/// envelope that prevents their product from becoming one unbounded pass.
pub fn validate_sync_pass(
    remote: &[RemoteEntry],
    actions: &[SyncAction],
    limits: SyncPassLimits,
) -> Result<SyncPassAdmission> {
    if remote.len() > limits.max_manifest_items {
        return Err(DesktopError::InvalidState(format!(
            "Drive manifest exceeds the {}-item pass limit",
            limits.max_manifest_items
        )));
    }
    if actions.len() > limits.max_actions {
        return Err(DesktopError::InvalidState(format!(
            "sync plan exceeds the {}-action pass limit",
            limits.max_actions
        )));
    }
    let by_id = remote
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<HashMap<_, _>>();
    let mut downloads = 0usize;
    let mut download_bytes = 0u64;
    let mut upload_bytes = 0u64;
    // Every action needs one request. A resumable upload also needs a
    // session request and one PUT for each chunk, including an empty finish.
    // Reserve the worst case before the first remote mutation.
    let mut estimated_requests = actions.len().checked_add(2).ok_or_else(|| {
        DesktopError::InvalidState("sync pass request estimate overflowed".to_string())
    })?;
    for action in actions {
        let uploaded = match action {
            SyncAction::UploadNew {
                is_directory: false,
                local,
                ..
            }
            | SyncAction::UploadExisting { local, .. } => local.size_bytes,
            _ => 0,
        };
        upload_bytes = upload_bytes.checked_add(uploaded).ok_or_else(|| {
            DesktopError::InvalidState("sync pass upload byte count overflowed".to_string())
        })?;
        if matches!(
            action,
            SyncAction::UploadNew {
                is_directory: false,
                ..
            } | SyncAction::UploadExisting { .. }
        ) {
            let chunks = uploaded.div_ceil(RESUMABLE_UPLOAD_CHUNK_BYTES).max(1);
            estimated_requests = estimated_requests
                .checked_add(usize::try_from(chunks).map_err(|_| {
                    DesktopError::InvalidState("sync pass request estimate overflowed".to_string())
                })?)
                .ok_or_else(|| {
                    DesktopError::InvalidState("sync pass request estimate overflowed".to_string())
                })?;
        }
        let remote_id = match action {
            SyncAction::Download { remote_id, .. }
            | SyncAction::WriteRemoteConflictCopy { remote_id, .. } => remote_id,
            _ => continue,
        };
        let entry = by_id.get(remote_id.as_str()).ok_or_else(|| {
            DesktopError::InvalidState(
                "sync plan references a download missing from the manifest".to_string(),
            )
        })?;
        let bytes = entry.size_bytes.ok_or_else(|| {
            DesktopError::InvalidState(format!(
                "Drive manifest omitted the size of remote file {remote_id}"
            ))
        })?;
        downloads = downloads.checked_add(1).ok_or_else(|| {
            DesktopError::InvalidState("sync pass download count overflowed".to_string())
        })?;
        download_bytes = download_bytes.checked_add(bytes).ok_or_else(|| {
            DesktopError::InvalidState("sync pass download byte count overflowed".to_string())
        })?;
    }
    if downloads > limits.max_downloads {
        return Err(DesktopError::InvalidState(format!(
            "sync pass exceeds its {}-download limit",
            limits.max_downloads
        )));
    }
    if download_bytes > limits.max_download_bytes {
        return Err(DesktopError::InvalidState(format!(
            "sync pass exceeds its {}-byte aggregate download limit",
            limits.max_download_bytes
        )));
    }
    if upload_bytes > limits.max_upload_bytes {
        return Err(DesktopError::InvalidState(format!(
            "sync pass exceeds its {}-byte aggregate upload limit",
            limits.max_upload_bytes
        )));
    }
    if estimated_requests > limits.max_requests {
        return Err(DesktopError::InvalidState(format!(
            "sync pass exceeds its {}-request estimate limit",
            limits.max_requests
        )));
    }
    Ok(SyncPassAdmission {
        manifest_items: remote.len(),
        actions: actions.len(),
        downloads,
        download_bytes,
        upload_bytes,
        estimated_requests,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{DownloadPrecondition, LocalEntry, RemoteEntryKind};

    fn upload(bytes: u64) -> SyncAction {
        SyncAction::UploadNew {
            relative_path: PathBuf::from("upload.bin"),
            is_directory: false,
            local: LocalEntry {
                relative_path: PathBuf::from("upload.bin"),
                content_hash: Some("a".repeat(64)),
                size_bytes: bytes,
                is_directory: false,
                directory_identity: None,
            },
        }
    }

    fn remote(id: &str, bytes: u64) -> RemoteEntry {
        RemoteEntry {
            id: id.to_string(),
            parent_id: None,
            name: format!("{id}.bin"),
            kind: RemoteEntryKind::File,
            revision: 1,
            content_hash: Some("a".repeat(64)),
            size_bytes: Some(bytes),
            trashed: false,
        }
    }

    #[test]
    fn aggregate_download_bytes_are_rejected_before_execution() {
        let remote = [remote("one", 3), remote("two", 3)];
        let actions = [
            SyncAction::Download {
                remote_id: "one".to_string(),
                relative_path: PathBuf::from("one.bin"),
                revision: 1,
                precondition: DownloadPrecondition::Absent,
            },
            SyncAction::Download {
                remote_id: "two".to_string(),
                relative_path: PathBuf::from("two.bin"),
                revision: 1,
                precondition: DownloadPrecondition::Absent,
            },
        ];
        let limits = SyncPassLimits {
            max_download_bytes: 5,
            ..SyncPassLimits::default()
        };
        assert!(validate_sync_pass(&remote, &actions, limits).is_err());
    }

    #[test]
    fn cycle_admits_exact_boundary_then_refuses_next_root_without_charging_it() {
        let remote = [remote("one", 3)];
        let actions = [SyncAction::Download {
            remote_id: "one".to_string(),
            relative_path: PathBuf::from("one.bin"),
            revision: 1,
            precondition: DownloadPrecondition::Absent,
        }];
        let limits = SyncPassLimits {
            max_manifest_items: 2,
            max_actions: 2,
            max_downloads: 2,
            max_download_bytes: 6,
            max_upload_bytes: 6,
            max_requests: 14,
        };
        let mut cycle = SyncCycleBudget::new(limits);
        cycle.admit(&remote, &actions).unwrap();
        let at_limit = cycle.admit(&remote, &actions).unwrap();
        assert_eq!(at_limit.manifest_items, 2);
        assert_eq!(at_limit.actions, 2);
        assert_eq!(at_limit.downloads, 2);
        assert_eq!(at_limit.download_bytes, 6);
        assert_eq!(at_limit.estimated_requests, 14);
        assert!(cycle.admit(&remote, &actions).is_err());
        assert_eq!(cycle.used(), at_limit);
    }

    #[test]
    fn each_cycle_counter_rejects_a_second_individually_valid_root() {
        let remote = [remote("one", 3)];
        let actions = [SyncAction::Download {
            remote_id: "one".to_string(),
            relative_path: PathBuf::from("one.bin"),
            revision: 1,
            precondition: DownloadPrecondition::Absent,
        }];
        let cases = [
            SyncPassLimits {
                max_manifest_items: 1,
                ..SyncPassLimits::default()
            },
            SyncPassLimits {
                max_actions: 1,
                ..SyncPassLimits::default()
            },
            SyncPassLimits {
                max_downloads: 1,
                ..SyncPassLimits::default()
            },
            SyncPassLimits {
                max_download_bytes: 3,
                ..SyncPassLimits::default()
            },
            SyncPassLimits {
                max_requests: 7,
                ..SyncPassLimits::default()
            },
        ];
        for limits in cases {
            let mut cycle = SyncCycleBudget::new(limits);
            let first = cycle.admit(&remote, &actions).unwrap();
            assert!(cycle.admit(&remote, &actions).is_err(), "{limits:?}");
            assert_eq!(cycle.used(), first);
        }
    }

    #[test]
    fn planning_only_roots_still_charge_manifest_and_request_estimate() {
        let remote = [remote("one", 3)];
        let mut cycle = SyncCycleBudget::new(SyncPassLimits {
            max_manifest_items: 2,
            max_requests: 12,
            ..SyncPassLimits::default()
        });
        cycle.admit(&remote, &[]).unwrap();
        let at_limit = cycle.admit(&remote, &[]).unwrap();
        assert_eq!(at_limit.manifest_items, 2);
        assert_eq!(at_limit.estimated_requests, 12);
        assert!(cycle.admit(&remote, &[]).is_err());
    }

    #[test]
    fn one_maximum_manifest_is_admitted_with_final_refresh_reserved() {
        let limits = SyncPassLimits::default();
        let remote = (0..limits.max_manifest_items)
            .map(|index| remote(&index.to_string(), 0))
            .collect::<Vec<_>>();
        let mut cycle = SyncCycleBudget::new(limits);
        let charged = cycle.admit(&remote, &[]).unwrap();
        assert_eq!(charged.manifest_items, limits.max_manifest_items);
        assert_eq!(charged.estimated_requests, 6);
    }

    #[test]
    fn reviewed_restore_transfers_share_the_cycle_envelope() {
        let mut cycle = SyncCycleBudget::new(SyncPassLimits {
            max_downloads: 2,
            max_download_bytes: 5,
            ..SyncPassLimits::default()
        });
        cycle.admit(&[remote("one", 3)], &[]).unwrap();
        let admitted = cycle.admit_extra(1, 1, 3, 1).unwrap();
        assert_eq!(admitted.download_bytes, 3);
        assert!(cycle.admit_extra(1, 1, 3, 1).is_err());
        assert_eq!(cycle.used(), admitted);
    }

    #[test]
    fn manifest_transport_counters_are_shared_before_decode_across_clients() {
        let budget = SyncCycleBudget::with_manifest_transport_limit(
            SyncPassLimits {
                max_manifest_items: 1,
                max_requests: 2,
                ..SyncPassLimits::default()
            },
            5,
        );
        let other_root_client = budget.clone();
        budget.charge_transport_request().unwrap();
        budget.charge_transport_bytes(3).unwrap();
        other_root_client.charge_transport_request().unwrap();
        other_root_client.charge_transport_bytes(2).unwrap();
        other_root_client.charge_manifest_items(10).unwrap();
        assert!(matches!(
            budget.charge_transport_request(),
            Err(DesktopError::SyncCycleBudgetExceeded(_))
        ));
        assert!(matches!(
            budget.charge_transport_bytes(1),
            Err(DesktopError::SyncCycleBudgetExceeded(_))
        ));
        assert!(matches!(
            budget.charge_manifest_items(1),
            Err(DesktopError::SyncCycleBudgetExceeded(_))
        ));
    }

    #[test]
    fn planned_upload_bytes_have_an_exact_cycle_boundary() {
        let mut cycle = SyncCycleBudget::new(SyncPassLimits {
            max_upload_bytes: 5,
            ..SyncPassLimits::default()
        });
        cycle.admit(&[], &[upload(3)]).unwrap();
        let exact = cycle.admit(&[], &[upload(2)]).unwrap();
        assert_eq!(exact.upload_bytes, 5);
        assert!(matches!(
            cycle.admit(&[], &[upload(1)]),
            Err(DesktopError::SyncCycleBudgetExceeded(_))
        ));
        assert_eq!(cycle.used(), exact);
    }

    #[test]
    fn chunked_upload_requests_are_reserved_before_any_mutation() {
        let chunk = RESUMABLE_UPLOAD_CHUNK_BYTES;
        let limits = SyncPassLimits {
            max_requests: 7,
            ..SyncPassLimits::default()
        };
        let one = validate_sync_pass(&[], &[upload(chunk + 1)], limits).unwrap();
        // Two manifests, one session, and two chunk PUTs.
        assert_eq!(one.estimated_requests, 5);
        let mut cycle = SyncCycleBudget::new(limits);
        cycle.admit(&[], &[upload(chunk + 1)]).unwrap_err();
        assert_eq!(cycle.used().estimated_requests, 0);

        let empty = validate_sync_pass(&[], &[upload(0)], limits).unwrap();
        assert_eq!(empty.estimated_requests, 4);
        assert!(validate_sync_pass(&[], &[upload(chunk * 5)], limits).is_err());
    }
}
