//! Bounded multi-location state layered over the selected legacy sync pair.

use std::path::{Component, Path};

use sha2::{Digest, Sha256};

use crate::{
    sync_pair_identity_matches, DesktopError, DesktopState, Result, SyncPair, SyncPairState,
};

pub const MAX_SYNC_PAIRS: usize = crate::MAX_DISCOVERY_ROOTS;

pub fn sync_pair_id(pair: &SyncPair) -> String {
    let mut digest = Sha256::new();
    digest.update(b"shellx-drive-sync-pair-v1\0");
    hash_field(&mut digest, pair.server_url.trim_end_matches('/'));
    hash_field(&mut digest, &pair.workspace_id);
    hash_field(&mut digest, pair.remote_root_id.as_deref().unwrap_or(""));
    format!(
        "pair-v1-{}",
        crate::hex_digest(digest.finalize().as_slice())
    )
}

fn hash_field(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value.as_bytes());
}

impl SyncPairState {
    fn capture(state: &DesktopState) -> Option<Self> {
        Some(Self {
            pair: state.pair.clone()?,
            baseline: state.baseline.clone(),
            change_cursor: state.change_cursor,
            reviews: state.reviews.clone(),
            activity: state.activity.clone(),
            paused: state.paused,
            last_successful_sync: state.last_successful_sync,
            last_error: state.last_error.clone(),
        })
    }

    fn install(self, state: &mut DesktopState) {
        state.pair = Some(self.pair);
        state.baseline = self.baseline;
        state.change_cursor = self.change_cursor;
        state.reviews = self.reviews;
        state.activity = self.activity;
        state.paused = self.paused;
        state.last_successful_sync = self.last_successful_sync;
        state.last_error = self.last_error;
    }
}

impl DesktopState {
    /// Reviews remain attached to their own location, but their count is an
    /// account-wide sync status. This keeps a selected clean location from
    /// reporting Synced while another configured location needs a decision.
    pub fn pending_review_count(&self) -> usize {
        self.reviews.len()
            + self
                .inactive_pairs
                .iter()
                .map(|profile| profile.reviews.len())
                .sum::<usize>()
    }

    pub fn has_any_reviews(&self) -> bool {
        self.pending_review_count() != 0
    }

    pub fn has_any_pair_error(&self) -> bool {
        self.last_error.is_some()
            || self
                .inactive_pairs
                .iter()
                .any(|profile| profile.last_error.is_some())
    }

    /// UI-wide error copy is derived from root-local state. It must not be
    /// persisted onto the selected profile, where it would identify the
    /// wrong local location as failed.
    pub fn aggregate_error(&self) -> Option<String> {
        self.last_error.clone().or_else(|| {
            self.inactive_pairs
                .iter()
                .any(|profile| profile.last_error.is_some())
                .then(|| {
                    "One or more other Drive locations did not finish syncing; review each configured location before retrying."
                        .to_string()
                })
        })
    }

    pub fn pair_count(&self) -> usize {
        usize::from(self.pair.is_some()) + self.inactive_pairs.len()
    }

    pub fn pairs(&self) -> impl Iterator<Item = &SyncPair> {
        self.pair
            .iter()
            .chain(self.inactive_pairs.iter().map(|profile| &profile.pair))
    }

    /// Pause applies to the one signed-in Drive account, not merely to the
    /// root presently selected in the UI. Keeping all materialized roots in
    /// lockstep prevents a hidden shared root from transferring while the
    /// person believes Drive is paused.
    pub fn set_all_pairs_paused(&mut self, paused: bool) {
        self.paused = paused;
        for profile in &mut self.inactive_pairs {
            profile.paused = paused;
        }
    }

    pub fn configure_pair(&mut self, pair: SyncPair) -> Result<()> {
        self.ensure_pair_can_be_added(&pair)?;
        if let Some(active) = SyncPairState::capture(self) {
            self.inactive_pairs.push(active);
        }
        SyncPairState {
            pair,
            baseline: Default::default(),
            change_cursor: 0,
            reviews: Vec::new(),
            activity: Vec::new(),
            paused: self.paused,
            last_successful_sync: None,
            last_error: None,
        }
        .install(self);
        self.sort_inactive_pairs();
        Ok(())
    }

    pub fn activate_pair(&mut self, requested_id: &str) -> Result<bool> {
        if self
            .pair
            .as_ref()
            .is_some_and(|pair| sync_pair_id(pair) == requested_id)
        {
            return Ok(false);
        }
        let index = self
            .inactive_pairs
            .iter()
            .position(|profile| sync_pair_id(&profile.pair) == requested_id)
            .ok_or_else(|| DesktopError::InvalidState("unknown Drive location".to_string()))?;
        let selected = self.inactive_pairs.remove(index);
        if let Some(active) = SyncPairState::capture(self) {
            self.inactive_pairs.push(active);
        }
        selected.install(self);
        self.sort_inactive_pairs();
        Ok(true)
    }

    /// The caller must first move this exact root to recovery. State removal
    /// itself never deletes local bytes.
    pub fn remove_pair(&mut self, requested_id: &str) -> Result<SyncPair> {
        let active_id = self.pair.as_ref().map(sync_pair_id);
        let removed = if active_id.as_deref() == Some(requested_id) {
            let removed = self.pair.take().expect("active pair was present");
            if !self.inactive_pairs.is_empty() {
                self.sort_inactive_pairs();
                self.inactive_pairs.remove(0).install(self);
            }
            removed
        } else {
            let index = self
                .inactive_pairs
                .iter()
                .position(|profile| sync_pair_id(&profile.pair) == requested_id)
                .ok_or_else(|| DesktopError::InvalidState("unknown Drive location".to_string()))?;
            self.inactive_pairs.remove(index).pair
        };
        self.sync_roots.remove(requested_id);
        self.sort_inactive_pairs();
        Ok(removed)
    }

    pub(crate) fn validate_pair_profiles(&self) -> Result<()> {
        if self.pair_count() > MAX_SYNC_PAIRS {
            return Err(DesktopError::InvalidState(format!(
                "desktop state contains more than {MAX_SYNC_PAIRS} sync locations"
            )));
        }
        let pairs = self.pairs().collect::<Vec<_>>();
        for (index, pair) in pairs.iter().enumerate() {
            for other in pairs.iter().skip(index + 1) {
                ensure_compatible_identity(pair, other)?;
                if same_remote_location(pair, other) {
                    return Err(DesktopError::InvalidState(
                        "the same Drive location is configured more than once".to_string(),
                    ));
                }
                if local_roots_overlap(&pair.local_root, &other.local_root) {
                    return Err(DesktopError::InvalidState(
                        "configured local Drive folders overlap".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn ensure_pair_can_be_added(&self, pair: &SyncPair) -> Result<()> {
        if self.pair_count() >= MAX_SYNC_PAIRS {
            return Err(DesktopError::InvalidState(format!(
                "this PC already has the maximum of {MAX_SYNC_PAIRS} Drive locations"
            )));
        }
        for existing in self.pairs() {
            ensure_compatible_identity(existing, pair)?;
            if same_remote_location(existing, pair) {
                return Err(DesktopError::InvalidState(
                    "this Drive location is already configured on this PC".to_string(),
                ));
            }
            if local_roots_overlap(&existing.local_root, &pair.local_root) {
                return Err(DesktopError::InvalidState(
                    "choose a local folder outside every existing Drive folder".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn sort_inactive_pairs(&mut self) {
        self.inactive_pairs
            .sort_by_key(|profile| sync_pair_id(&profile.pair));
    }
}

fn ensure_compatible_identity(left: &SyncPair, right: &SyncPair) -> Result<()> {
    if sync_pair_identity_matches(left, &right.server_url, &right.account_email) {
        Ok(())
    } else {
        Err(DesktopError::InvalidState(
            "v0.1 supports multiple Drive locations for one server and account; disconnect this PC before changing identity".to_string(),
        ))
    }
}

fn same_remote_location(left: &SyncPair, right: &SyncPair) -> bool {
    left.server_url.trim_end_matches('/') == right.server_url.trim_end_matches('/')
        && left.workspace_id == right.workspace_id
        && left.remote_root_id == right.remote_root_id
}

fn local_roots_overlap(left: &Path, right: &Path) -> bool {
    let left = normalized_components(left);
    let right = normalized_components(right);
    left[..left.len().min(right.len())] == right[..left.len().min(right.len())]
}

fn normalized_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::CurDir => None,
            value => Some(value.as_os_str().to_string_lossy().to_ascii_lowercase()),
        })
        .collect()
}

#[cfg(test)]
#[path = "pair_profiles_tests.rs"]
mod tests;
