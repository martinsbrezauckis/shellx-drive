//! Bounded same-cycle replanning after a final tree changed concurrently.

use super::*;

const MAX_CONVERGENCE_ATTEMPTS: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SyncAttemptDisposition {
    Complete,
    TreeChanged,
}

#[derive(Default)]
pub(super) struct Convergence {
    attempts: usize,
}

impl Convergence {
    pub(super) fn begin_attempt(&mut self, run: &SyncRun) -> CoreResult<()> {
        run.ensure_not_cancelled()?;
        if self.attempts == MAX_CONVERGENCE_ATTEMPTS {
            return Err(DesktopError::SyncCycleBudgetExceeded(
                "Drive or local files kept changing during three reconciliation attempts; the prior baseline was retained and remaining work was deferred".to_string(),
            ));
        }
        self.attempts += 1;
        Ok(())
    }

    pub(super) fn complete_attempt(
        &self,
        run: &SyncRun,
        disposition: SyncAttemptDisposition,
    ) -> CoreResult<bool> {
        run.ensure_not_cancelled()?;
        Ok(disposition == SyncAttemptDisposition::Complete)
    }
}

#[cfg(test)]
mod tests;
