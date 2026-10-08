//! Atomic admission boundary between sign-in attempts and Disconnect.

use std::sync::Mutex;

use crate::{AuthAttemptEpoch, DesktopError, Result};

#[derive(Default)]
struct AdmissionState {
    offboarding: bool,
}

/// Keeps the sign-in generation and Disconnect latch in one short critical
/// section. A login admitted before the latch is invalidated; one admitted
/// after it is refused without starting a network request.
#[derive(Default)]
pub struct AuthOffboardingGate {
    state: Mutex<AdmissionState>,
    attempts: AuthAttemptEpoch,
}

impl AuthOffboardingGate {
    pub fn admit_login(&self) -> Result<u64> {
        let state = self.state.lock().expect("auth offboarding lock");
        if state.offboarding {
            return Err(DesktopError::InvalidState(
                "Disconnect is in progress; finish it before signing in.".to_string(),
            ));
        }
        Ok(self.attempts.begin())
    }

    /// Recheck at every candidate-publication boundary. Holding the
    /// publication serializer makes a login that passed just before the latch
    /// safe: Disconnect waits for it, then retires the resulting credential.
    pub fn may_publish(&self, generation: u64) -> bool {
        let state = self.state.lock().expect("auth offboarding lock");
        !state.offboarding && self.attempts.is_current(generation)
    }

    /// The returned latch stays active through auth publication, remote
    /// retirement, and local cleanup. Drop releases it only after the caller
    /// has published the terminal state image.
    pub fn begin_offboarding(&self) -> Result<OffboardingLatch<'_>> {
        let mut state = self.state.lock().expect("auth offboarding lock");
        if state.offboarding {
            return Err(DesktopError::InvalidState(
                "Disconnect is already in progress.".to_string(),
            ));
        }
        state.offboarding = true;
        self.attempts.invalidate();
        Ok(OffboardingLatch { gate: self })
    }
}

/// RAII release for a Disconnect latch. It intentionally carries no mutable
/// state: all error paths clear the latch only after their surrounding scope
/// has published or retained its terminal state.
pub struct OffboardingLatch<'a> {
    gate: &'a AuthOffboardingGate,
}

impl Drop for OffboardingLatch<'_> {
    fn drop(&mut self) {
        self.gate
            .state
            .lock()
            .expect("auth offboarding lock")
            .offboarding = false;
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use super::*;

    #[test]
    fn concurrent_offboarding_invalidates_prior_admission_and_refuses_later_one() {
        let gate = Arc::new(AuthOffboardingGate::default());
        let admitted = Arc::new(std::sync::Barrier::new(2));
        let latched = Arc::new(std::sync::Barrier::new(2));
        let worker_gate = Arc::clone(&gate);
        let worker_admitted = Arc::clone(&admitted);
        let worker_latched = Arc::clone(&latched);
        let worker = thread::spawn(move || {
            let generation = worker_gate.admit_login().unwrap();
            worker_admitted.wait();
            worker_latched.wait();
            assert!(!worker_gate.may_publish(generation));
        });

        admitted.wait();
        let latch = gate.begin_offboarding().unwrap();
        assert!(gate.admit_login().is_err());
        latched.wait();
        worker.join().unwrap();
        drop(latch);
        assert!(gate.admit_login().is_ok());
    }
}
