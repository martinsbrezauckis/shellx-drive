use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::http::Method;

const UNATTRIBUTED_AUDIT_WINDOW: Duration = Duration::from_secs(60);
const MAX_UNATTRIBUTED_AUDIT_PARTITIONS: usize = 256;
const LOW_AUTHORITY_AUDIT_WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_LOW_AUTHORITY_AUDIT_PARTITIONS: usize = 512;

#[derive(Clone)]
pub(crate) struct SecurityAuditAdmission {
    unattributed: Arc<Mutex<AuditWindow>>,
    low_authority: Arc<Mutex<AuditWindow>>,
}

struct AuditWindow {
    started: Instant,
    partitions: HashSet<String>,
}

impl Default for SecurityAuditAdmission {
    fn default() -> Self {
        Self {
            unattributed: Arc::new(Mutex::new(AuditWindow {
                started: Instant::now(),
                partitions: HashSet::new(),
            })),
            low_authority: Arc::new(Mutex::new(AuditWindow {
                started: Instant::now(),
                partitions: HashSet::new(),
            })),
        }
    }
}

impl SecurityAuditAdmission {
    /// Keep one representative event per client/route/outcome each minute,
    /// with a process-wide cardinality ceiling. Unmatched anonymous paths are
    /// scanner noise and never become durable audit records.
    pub(super) fn admit_unattributed(
        &self,
        route: &str,
        method: &Method,
        status: u16,
        client_fingerprint: &str,
    ) -> bool {
        if route == "/unmatched" {
            return false;
        }
        let mut window = self.unattributed.lock().unwrap();
        if window.started.elapsed() >= UNATTRIBUTED_AUDIT_WINDOW {
            window.started = Instant::now();
            window.partitions.clear();
        }
        let partition = format!(
            "{client_fingerprint}\0{route}\0{}\0{status}",
            method.as_str()
        );
        if window.partitions.contains(&partition)
            || window.partitions.len() >= MAX_UNATTRIBUTED_AUDIT_PARTITIONS
        {
            return false;
        }
        window.partitions.insert(partition);
        true
    }

    /// Keep one durable representative for each low-authority target/outcome
    /// per fixed window. Login successes remain unsampled; callers use this
    /// only for failed/blocked logins and successful guest traffic.
    pub(in crate::server) fn admit_low_authority(&self, partition: &str) -> bool {
        let mut window = self.low_authority.lock().unwrap();
        if window.started.elapsed() >= LOW_AUTHORITY_AUDIT_WINDOW {
            window.started = Instant::now();
            window.partitions.clear();
        }
        if window.partitions.contains(partition)
            || window.partitions.len() >= MAX_LOW_AUTHORITY_AUDIT_PARTITIONS
        {
            return false;
        }
        window.partitions.insert(partition.to_string());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unattributed_audit_noise_is_nonqueueing_and_bounded() {
        let admission = SecurityAuditAdmission::default();
        assert!(!admission.admit_unattributed("/unmatched", &Method::GET, 404, "client-a"));
        assert!(admission.admit_unattributed("/admin/sessions", &Method::GET, 401, "client-a"));
        assert!(!admission.admit_unattributed("/admin/sessions", &Method::GET, 401, "client-a"));
        for index in 1..MAX_UNATTRIBUTED_AUDIT_PARTITIONS {
            assert!(admission.admit_unattributed(
                "/admin/sessions",
                &Method::GET,
                401,
                &format!("client-{index}")
            ));
        }
        assert!(!admission.admit_unattributed(
            "/pub/shares/{share_id}",
            &Method::GET,
            404,
            "overflow-client"
        ));
    }

    #[test]
    fn low_authority_replays_keep_one_representative_per_target() {
        let admission = SecurityAuditAdmission::default();
        let login = "login\0user@example.test\0status-401";
        assert!(admission.admit_low_authority(login));
        assert!(!admission.admit_low_authority(login));
        assert!(admission.admit_low_authority("guest\0share-a\0status-200"));
    }
}
