use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic witness for asynchronous desktop authentication attempts.
///
/// Network replies may arrive after a newer sign-in or an explicit disconnect.
/// Only the attempt holding the current generation may publish credentials or
/// an in-memory second-factor continuation.
#[derive(Default)]
pub struct AuthAttemptEpoch {
    current: AtomicU64,
}

impl AuthAttemptEpoch {
    pub fn begin(&self) -> u64 {
        self.advance()
    }

    pub fn invalidate(&self) {
        self.advance();
    }

    pub fn is_current(&self, generation: u64) -> bool {
        generation != 0 && self.current.load(Ordering::Acquire) == generation
    }

    fn advance(&self) -> u64 {
        let mut current = self.current.load(Ordering::Acquire);
        loop {
            let next = current.checked_add(1).unwrap_or(1);
            match self.current.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return next,
                Err(actual) => current = actual,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{atomic::AtomicU64, Barrier},
        thread,
    };

    use super::AuthAttemptEpoch;

    #[test]
    fn newer_login_invalidates_an_older_network_reply() {
        let epochs = AuthAttemptEpoch::default();
        let first = epochs.begin();
        let second = epochs.begin();

        assert!(!epochs.is_current(first));
        assert!(epochs.is_current(second));
    }

    #[test]
    fn disconnect_invalidation_rejects_the_inflight_reply() {
        let epochs = AuthAttemptEpoch::default();
        let inflight = epochs.begin();
        epochs.invalidate();

        assert!(!epochs.is_current(inflight));
    }

    #[test]
    fn generation_wrap_preserves_nonzero_admission_and_invalidates_its_predecessor() {
        let epochs = AuthAttemptEpoch {
            current: AtomicU64::new(u64::MAX),
        };
        assert!(epochs.is_current(u64::MAX));
        assert!(!epochs.is_current(0));
        assert_eq!(epochs.begin(), 1);
        assert!(!epochs.is_current(u64::MAX));
        assert!(epochs.is_current(1));
        assert_eq!(epochs.begin(), 2);
        assert!(!epochs.is_current(1));
        assert!(epochs.is_current(2));
    }

    #[test]
    fn concurrent_attempts_publish_unique_generations_and_only_the_latest_is_current() {
        let epochs = AuthAttemptEpoch::default();
        let barrier = Barrier::new(8);
        let mut generations = thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        (0..32).map(|_| epochs.begin()).collect::<Vec<_>>()
                    })
                })
                .collect();
            workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        generations.sort_unstable();
        assert_eq!(generations, (1..=256).collect::<Vec<_>>());
        for generation in generations {
            assert_eq!(epochs.is_current(generation), generation == 256);
        }
    }
}
