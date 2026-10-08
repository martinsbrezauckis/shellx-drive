//! Scoped-root state and terminal projections for one serialized sync run.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::{
    conflicts::stabilize_pending_content_conflicts,
    mirror::{plan_reconciliation, LocalEntry, ReconcilePlan, RemoteEntry},
    sync_pair_id, ActivityEntry, BaselineEntry, DesktopError, DesktopState, Result, ReviewItem,
    SyncRoot, SyncRootAccessRemovalReason, SyncRootMetadata, SyncRootReconciliation,
};

use super::SyncRun;

impl SyncRun {
    pub fn state(&self) -> &DesktopState {
        &self.state
    }

    /// Stop at a safe boundary after an exact Disconnect request targets this
    /// run generation. The guard remains held until the caller unwinds.
    pub fn ensure_not_cancelled(&self) -> Result<()> {
        let inner = self
            .coordinator
            .inner
            .lock()
            .expect("mirror coordinator lock");
        if inner.sync_cancellation.is_some_and(|(sync_generation, _)| {
            sync_generation == self.generation
                && inner.active_sync_generation == Some(self.generation)
        }) {
            return Err(DesktopError::SyncCancelledForDisconnect);
        }
        Ok(())
    }

    /// Return every materialized root in a stable order for one server/account
    /// reconciliation cycle. The first entry is the root selected for display;
    /// callers must restore that selection before publishing the final state.
    ///
    /// The list intentionally includes unavailable roots. Their individual
    /// reconciliation turns turn them into retained local-review state without
    /// touching their local bytes.
    pub fn configured_pair_ids(&self) -> Result<Vec<String>> {
        if self.state.pair.is_none() {
            return Err(DesktopError::NeedsSetup);
        }
        Ok(self.state.pairs().map(sync_pair_id).collect())
    }

    /// Resume after the last root that exhausted a cycle, including after restart.
    pub fn cycle_pair_ids(&self) -> Result<Vec<String>> {
        let mut ids = self.cycle_order.clone();
        if ids.is_empty() {
            return Err(DesktopError::NeedsSetup);
        }
        if let Some(offset) = ids
            .iter()
            .position(|id| self.state.sync_cycle_resume_pair_id.as_deref() == Some(id.as_str()))
        {
            ids.rotate_left(offset);
        }
        Ok(ids)
    }

    pub fn defer_cycle_after(&mut self, pair_id: &str) -> Result<()> {
        let ids = &self.cycle_order;
        let offset = ids.iter().position(|id| id == pair_id).ok_or_else(|| {
            DesktopError::InvalidState("deferred sync pair is no longer configured".to_string())
        })?;
        self.state.sync_cycle_resume_pair_id = Some(ids[(offset + 1) % ids.len()].clone());
        Ok(())
    }

    /// The profile selected by the person in the UI. Background reconciliation
    /// may temporarily activate other roots, but this selection is restored
    /// before state is published.
    pub fn selected_pair_id(&self) -> Result<String> {
        self.state
            .pair
            .as_ref()
            .map(sync_pair_id)
            .ok_or(DesktopError::NeedsSetup)
    }

    /// Switch the detached run snapshot to one already configured root. This
    /// does not affect the coordinator's live display state until `finish_*`.
    pub fn activate_configured_pair(&mut self, pair_id: &str) -> Result<()> {
        self.state.activate_pair(pair_id)?;
        Ok(())
    }

    pub fn has_active_reviews(&self) -> bool {
        !self.state.reviews.is_empty()
    }

    pub fn has_any_reviews(&self) -> bool {
        self.state.has_any_reviews()
    }

    pub fn plan(
        &self,
        remote: &[RemoteEntry],
        local: &[LocalEntry],
        now: DateTime<Utc>,
    ) -> Result<ReconcilePlan> {
        let pair = self.state.pair.as_ref().ok_or(DesktopError::NeedsSetup)?;
        let mut plan = plan_reconciliation(
            &self.state.baseline,
            pair.remote_root_id.as_deref(),
            remote,
            local,
            now,
        )?;
        stabilize_pending_content_conflicts(&mut plan, &self.state.reviews);
        Ok(plan)
    }

    pub fn reconcile_sync_roots(
        &mut self,
        discovered: &[SyncRoot],
        now: DateTime<Utc>,
    ) -> Result<SyncRootReconciliation> {
        self.state.reconcile_sync_roots(discovered, now)
    }

    pub fn sync_root_for_active_pair(&self) -> Result<&SyncRootMetadata> {
        let pair = self.state.pair.as_ref().ok_or(DesktopError::NeedsSetup)?;
        self.state.sync_root_for_pair(pair).ok_or_else(|| {
            DesktopError::InvalidState(
                "this Drive location has no current root authority; syncing remains stopped"
                    .to_string(),
            )
        })
    }

    /// Only an authority response for the active pair's original opaque
    /// manifest subject can refresh its saved role/generation.
    pub fn refresh_active_sync_root(&mut self, root: SyncRoot, now: DateTime<Utc>) -> Result<()> {
        let pair = self.state.pair.as_ref().ok_or(DesktopError::NeedsSetup)?;
        crate::validate_root_pair_binding(pair, &root)?;
        let metadata = self
            .state
            .sync_roots
            .get_mut(&crate::sync_pair_id(pair))
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "this Drive location has no root authority to refresh".to_string(),
                )
            })?;
        if !metadata.root.same_manifest_subject(&root) {
            return Err(DesktopError::InvalidState(
                "scoped Drive manifest returned a different root subject".to_string(),
            ));
        }
        metadata.root = root;
        if metadata.root.is_available_at(now) {
            metadata.access_removed = None;
        } else {
            metadata.mark_access_removed(SyncRootAccessRemovalReason::Expired, now);
        }
        Ok(())
    }

    /// Record a successful root result without releasing the cycle-wide
    /// reservation. A later root cannot overwrite this baseline because a
    /// temporary profile switch captures it into that root's own state.
    pub fn record_success(
        &mut self,
        baseline: BTreeMap<String, BaselineEntry>,
        now: DateTime<Utc>,
    ) {
        self.state.baseline = baseline;
        self.state.reviews.clear();
        self.state.last_successful_sync = Some(now);
        self.state.last_error = None;
    }

    /// Retain root-scoped reviews while continuing the same serialized cycle
    /// with other accessible roots.
    pub fn record_reviews(&mut self, reviews: Vec<ReviewItem>) {
        self.state.reviews = reviews;
        self.state.last_error = None;
    }

    pub fn record_recheck_pending(&mut self) {}

    pub fn record_recheck_compatible(&mut self) {
        self.state.reviews.clear();
        self.state.last_error = None;
    }

    /// A root-local failure must not discard or corrupt the independently
    /// persisted results of other roots in this same run.
    pub fn record_active_error(&mut self, message: impl AsRef<str>) {
        self.state.last_error = Some(super::redact_error(message.as_ref()));
    }

    /// Restore the displayed root after one every-root cycle. Root-local
    /// reviews and failures remain on their owning profile; the aggregate
    /// projection derives its own status from all configured profiles.
    pub fn finalize_all_roots_state(&mut self, selected_pair_id: &str) -> Result<DesktopState> {
        self.activate_configured_pair(selected_pair_id)?;
        Ok(self.state.clone())
    }

    pub fn append_active_activity(&mut self, entry: ActivityEntry) {
        self.state.append_activity(entry);
    }

    pub fn mark_active_root_removed(
        &mut self,
        reason: SyncRootAccessRemovalReason,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let pair = self.state.pair.as_ref().ok_or(DesktopError::NeedsSetup)?;
        let metadata = self
            .state
            .sync_roots
            .get_mut(&crate::sync_pair_id(pair))
            .ok_or_else(|| {
                DesktopError::InvalidState(
                    "this Drive location has no root authority to revoke".to_string(),
                )
            })?;
        metadata.mark_access_removed(reason, now);
        Ok(())
    }

    pub fn finish_state(&mut self, mut state: DesktopState) {
        let mut inner = self
            .coordinator
            .inner
            .lock()
            .expect("mirror coordinator lock");
        state.desktop_agent_control = inner.state.desktop_agent_control.clone();
        inner.state = state;
        inner.offline = false;
        Self::release(&mut inner, &mut self.active, self.generation);
    }

    /// Persist and publish a terminal sync image while retaining exclusivity.
    /// Concurrent agent journal fields are merged before the durable write.
    pub fn finish_persisted_state(
        &mut self,
        mut state: DesktopState,
        persist: impl FnOnce(&DesktopState) -> Result<()>,
    ) -> Result<()> {
        let mut inner = self
            .coordinator
            .inner
            .lock()
            .expect("mirror coordinator lock");
        state.desktop_agent_control = inner.state.desktop_agent_control.clone();
        persist(&state)?;
        inner.state = state;
        inner.offline = false;
        Self::release(&mut inner, &mut self.active, self.generation);
        Ok(())
    }

    pub fn finish_success(
        &mut self,
        baseline: BTreeMap<String, BaselineEntry>,
        now: DateTime<Utc>,
    ) {
        self.record_success(baseline, now);
        let mut inner = self
            .coordinator
            .inner
            .lock()
            .expect("mirror coordinator lock");
        inner.state.baseline = self.state.baseline.clone();
        inner.state.sync_roots = self.state.sync_roots.clone();
        inner.state.reviews = self.state.reviews.clone();
        inner.state.last_successful_sync = self.state.last_successful_sync;
        inner.state.last_error = self.state.last_error.clone();
        inner.offline = false;
        Self::release(&mut inner, &mut self.active, self.generation);
    }

    pub fn finish_with_reviews(&mut self, reviews: Vec<ReviewItem>) {
        self.record_reviews(reviews);
        let mut inner = self
            .coordinator
            .inner
            .lock()
            .expect("mirror coordinator lock");
        inner.state.reviews = self.state.reviews.clone();
        inner.state.sync_roots = self.state.sync_roots.clone();
        inner.state.last_error = self.state.last_error.clone();
        inner.offline = false;
        Self::release(&mut inner, &mut self.active, self.generation);
    }

    pub fn finish_recheck_pending(&mut self) {
        self.record_recheck_pending();
        let mut inner = self
            .coordinator
            .inner
            .lock()
            .expect("mirror coordinator lock");
        inner.state.sync_roots = self.state.sync_roots.clone();
        Self::release(&mut inner, &mut self.active, self.generation);
    }

    pub fn finish_recheck_compatible(&mut self) {
        self.record_recheck_compatible();
        let mut inner = self
            .coordinator
            .inner
            .lock()
            .expect("mirror coordinator lock");
        inner.state.reviews = self.state.reviews.clone();
        inner.state.sync_roots = self.state.sync_roots.clone();
        inner.state.last_error = self.state.last_error.clone();
        inner.offline = false;
        Self::release(&mut inner, &mut self.active, self.generation);
    }

    fn release(inner: &mut super::CoordinatorInner, active: &mut bool, generation: u64) {
        if *active {
            if inner.active_sync_generation == Some(generation) {
                inner.active_run = false;
                inner.active_sync_generation = None;
                inner.sync_cancellation = None;
            }
            *active = false;
        }
    }
}

impl Drop for SyncRun {
    fn drop(&mut self) {
        if self.active {
            let mut inner = self
                .coordinator
                .inner
                .lock()
                .expect("mirror coordinator lock");
            if inner.active_sync_generation == Some(self.generation) {
                inner.active_run = false;
                inner.active_sync_generation = None;
                inner.sync_cancellation = None;
            }
        }
    }
}
