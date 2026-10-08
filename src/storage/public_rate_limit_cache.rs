use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const MAX_DENIED_PARTITIONS: usize = 8_192;

/// Bounded, process-local cache for public partitions that SQLite has already
/// established are over limit. Repeated 429 traffic stays out of the shared
/// database connection until the durable window expires.
#[derive(Clone, Default)]
pub(super) struct PublicRateLimitDenyCache {
    denied_until: Arc<Mutex<HashMap<String, Instant>>>,
}

impl PublicRateLimitDenyCache {
    pub(super) fn denies(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut denied = self.denied_until.lock().unwrap();
        match denied.get(key).copied() {
            Some(until) if until > now => true,
            Some(_) => {
                denied.remove(key);
                false
            }
            None => false,
        }
    }

    pub(super) fn deny_for(&self, key: &str, duration: Duration) {
        if duration.is_zero() {
            return;
        }
        let now = Instant::now();
        let mut denied = self.denied_until.lock().unwrap();
        denied.retain(|_, until| *until > now);
        if denied.len() >= MAX_DENIED_PARTITIONS {
            if let Some(oldest) = denied
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(key, _)| key.clone())
            {
                denied.remove(&oldest);
            }
        }
        denied.insert(key.to_string(), now + duration);
    }

    #[cfg(test)]
    pub(super) fn clear_for_test(&self, key: &str) {
        self.denied_until.lock().unwrap().remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_entries_fail_open_and_are_removed() {
        let cache = PublicRateLimitDenyCache::default();
        cache.deny_for("partition", Duration::from_millis(1));
        assert!(cache.denies("partition"));
        std::thread::sleep(Duration::from_millis(2));
        assert!(!cache.denies("partition"));
    }
}
