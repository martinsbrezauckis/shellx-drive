//! Role-aware Drive root discovery and local namespace planning.
//!
//! A root is a capability-scoped view of one canonical Drive tree, never a
//! copied workspace.  The desktop retains the server-issued opaque root ID so
//! a rename cannot create a second local identity, while paths shown to people
//! use only bounded owner and root labels.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{DesktopError, DesktopState, Result, SyncPair};

pub const MAX_DISCOVERY_ROOTS: usize = 100;
const MAX_ROOT_FIELD_BYTES: usize = 4 * 1024;
const MAX_ROOT_LABEL_BYTES: usize = 1024;

/// The server's authority shape for an authorized desktop root.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncRootKind {
    Workspace,
    ItemGrant,
}

/// The effective authority for the exact root, never inferred from a missing
/// field or from the client-side namespace.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncRootRole {
    Owner,
    Editor,
    Viewer,
}

impl SyncRootRole {
    pub fn may_write(self) -> bool {
        matches!(self, Self::Owner | Self::Editor)
    }
}

/// One currently authorized desktop sync root returned by `GET /sync/roots`.
/// `id` is an opaque server subject; it is deliberately not a local path or a
/// human-facing label.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncRoot {
    pub id: String,
    pub kind: SyncRootKind,
    pub workspace_id: String,
    #[serde(default)]
    pub root_file_id: Option<String>,
    #[serde(default)]
    pub grant_id: Option<String>,
    pub owner_label: String,
    pub role: SyncRootRole,
    /// Server-owned monotonic access version. Omission is rejected during
    /// decoding rather than allowing a client to guess current authority.
    pub access_generation: u64,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    pub label: String,
}

impl SyncRoot {
    pub fn validate(&self) -> Result<()> {
        required("sync root ID", &self.id, MAX_ROOT_FIELD_BYTES)?;
        required(
            "sync root workspace ID",
            &self.workspace_id,
            MAX_ROOT_FIELD_BYTES,
        )?;
        required(
            "sync root owner label",
            &self.owner_label,
            MAX_ROOT_LABEL_BYTES,
        )?;
        required("sync root label", &self.label, MAX_ROOT_LABEL_BYTES)?;
        if self.access_generation == 0 {
            return Err(DesktopError::InvalidState(
                "sync root access generation must be a positive server value".to_string(),
            ));
        }
        optional(
            "sync root file ID",
            self.root_file_id.as_deref(),
            MAX_ROOT_FIELD_BYTES,
        )?;
        optional(
            "sync root grant ID",
            self.grant_id.as_deref(),
            MAX_ROOT_FIELD_BYTES,
        )?;
        match self.kind {
            SyncRootKind::Workspace => {
                if self.root_file_id.is_some() || self.grant_id.is_some() {
                    return Err(DesktopError::InvalidState(
                        "Drive workspace root carried an item-grant subject".to_string(),
                    ));
                }
            }
            SyncRootKind::ItemGrant => {
                if self.root_file_id.is_none() || self.grant_id.is_none() {
                    return Err(DesktopError::InvalidState(
                        "Drive item-grant root is missing its canonical file or grant identity"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// The stable, non-display key used to retain one local materialization
    /// across a server-side rename. It is intentionally derived from the
    /// canonical workspace/root identity instead of a mutable label or a
    /// replaceable direct/group/everyone grant subject.
    pub fn local_identity_key(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"shellx-drive-desktop-root-v1\0");
        digest.update(self.workspace_id.as_bytes());
        digest.update(b"\0");
        digest.update(
            self.root_file_id
                .as_deref()
                .unwrap_or("workspace-root")
                .as_bytes(),
        );
        format!(
            "root-v1-{}",
            crate::hex_digest(digest.finalize().as_slice())
        )
    }

    pub fn is_available_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|expiry| expiry > now)
    }

    pub fn same_manifest_subject(&self, other: &Self) -> bool {
        self.id == other.id
            && self.kind == other.kind
            && self.workspace_id == other.workspace_id
            && self.root_file_id == other.root_file_id
            && self.grant_id == other.grant_id
    }

    /// Direct, group, and everyone grants may overlap one canonical file or
    /// folder. They converge on this identity instead of duplicating bytes.
    pub fn same_canonical_root(&self, other: &Self) -> bool {
        self.workspace_id == other.workspace_id && self.root_file_id == other.root_file_id
    }

    fn namespace_components(&self) -> Vec<String> {
        if self.kind == SyncRootKind::Workspace && self.role == SyncRootRole::Owner {
            return vec!["My files".to_string()];
        }
        vec![
            "Shared with me".to_string(),
            namespace_component(&self.owner_label),
            namespace_component(&self.label),
        ]
    }
}

/// A bounded, deterministic local namespace plan. Existing persisted root
/// keys keep their assigned local folders even if an owner or root is renamed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalRootLocation {
    pub root_id: String,
    pub stable_key: String,
    pub relative_path: PathBuf,
}

pub fn plan_local_root_locations(roots: &[SyncRoot]) -> Result<Vec<LocalRootLocation>> {
    let mut roots = converge_sync_roots(roots)?;
    roots.sort_by(|left, right| left.id.cmp(&right.id));
    let mut seen = BTreeSet::new();
    let mut used = BTreeSet::new();
    let mut locations = Vec::with_capacity(roots.len());
    for root in roots {
        root.validate()?;
        if !seen.insert(root.id.clone()) {
            return Err(DesktopError::InvalidState(
                "Drive root discovery returned the same opaque root twice".to_string(),
            ));
        }
        let stable_key = root.local_identity_key();
        let mut components = root.namespace_components();
        let mut relative_path = components.iter().collect::<PathBuf>();
        if !used.insert(namespace_collision_key(&relative_path)) {
            let suffix = stable_key.rsplit('-').next().unwrap_or("root");
            let last = components.last_mut().expect("root namespace has a label");
            *last = format!("{last} ({})", &suffix[..8.min(suffix.len())]);
            relative_path = components.iter().collect();
            if !used.insert(namespace_collision_key(&relative_path)) {
                return Err(DesktopError::InvalidState(
                    "Drive root discovery produced an ambiguous local namespace".to_string(),
                ));
            }
        }
        locations.push(LocalRootLocation {
            root_id: root.id,
            stable_key,
            relative_path,
        });
    }
    Ok(locations)
}

/// Plan one explicitly selected root against folders already assigned to
/// configured pairs. A page contains only that root, so page-local collision
/// detection alone cannot protect the existing local namespace.
pub fn plan_selected_root_location(
    state: &DesktopState,
    root: &SyncRoot,
    base: &Path,
) -> Result<LocalRootLocation> {
    let mut location = plan_local_root_locations(std::slice::from_ref(root))?
        .pop()
        .expect("one selected root has one location");
    if let Some(pair) = state.pairs().find(|pair| {
        pair.workspace_id == root.workspace_id && pair.remote_root_id == root.root_file_id
    }) {
        location.relative_path = configured_relative_path(pair, base)?;
        return Ok(location);
    }
    let occupied: BTreeSet<_> = state
        .pairs()
        .map(|pair| configured_relative_path(pair, base).map(|path| namespace_collision_key(&path)))
        .collect::<Result<_>>()?;
    if occupied.contains(&namespace_collision_key(&location.relative_path)) {
        let mut components = root.namespace_components();
        let suffix = location.stable_key.rsplit('-').next().unwrap_or("root");
        for length in [8, 16, suffix.len()] {
            let last = components.last_mut().expect("root namespace has a label");
            *last = format!(
                "{} ({})",
                root.namespace_components().last().unwrap(),
                &suffix[..length]
            );
            let proposed = components.iter().collect::<PathBuf>();
            if !occupied.contains(&namespace_collision_key(&proposed)) {
                location.relative_path = proposed;
                return Ok(location);
            }
        }
        return Err(DesktopError::InvalidState(
            "Drive root selection conflicts with an existing local namespace".to_string(),
        ));
    }
    Ok(location)
}

fn configured_relative_path(pair: &SyncPair, base: &Path) -> Result<PathBuf> {
    let path = pair.local_root.strip_prefix(base).map_err(|_| {
        DesktopError::InvalidState("configured Drive root is outside its local base".to_string())
    })?;
    if path.as_os_str().is_empty()
        || !path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(DesktopError::InvalidState(
            "configured Drive root has an unsafe local namespace".to_string(),
        ));
    }
    Ok(path.to_path_buf())
}

/// Server discovery normally returns top-level effective roots, but this
/// second boundary prevents a direct/group/everyone overlap from producing a
/// second local namespace during compatibility migration or a response race.
pub fn converge_sync_roots(roots: &[SyncRoot]) -> Result<Vec<SyncRoot>> {
    converge_sync_roots_at(roots, Utc::now())
}

/// Apply effective-root convergence at a fixed observation time. An expired
/// stronger grant cannot hide an active weaker grant, while an all-expired
/// canonical root remains available for a truthful expiry transition.
pub fn converge_sync_roots_at(roots: &[SyncRoot], now: DateTime<Utc>) -> Result<Vec<SyncRoot>> {
    if roots.len() > MAX_DISCOVERY_ROOTS {
        return Err(root_limit_error());
    }
    let mut canonical = BTreeMap::<(String, Option<String>), SyncRoot>::new();
    for root in roots {
        root.validate()?;
        let key = (root.workspace_id.clone(), root.root_file_id.clone());
        match canonical.get(&key) {
            None => {
                canonical.insert(key, root.clone());
            }
            Some(current) => {
                if current.owner_label != root.owner_label {
                    return Err(DesktopError::InvalidState(
                        "overlapping Drive roots disagree about their canonical owner".to_string(),
                    ));
                }
                if prefer_root(root, current, now) {
                    canonical.insert(key, root.clone());
                }
            }
        }
    }
    let workspace_roots = canonical
        .iter()
        .filter(|((_, root_file_id), root)| root_file_id.is_none() && root.is_available_at(now))
        .map(|((workspace_id, _), root)| (workspace_id.clone(), root.role))
        .collect::<BTreeMap<_, _>>();
    let mut roots = canonical
        .into_values()
        .filter(|root| {
            root.root_file_id.is_none()
                || workspace_roots
                    .get(&root.workspace_id)
                    .is_none_or(|role| role_rank(*role) < role_rank(root.role))
        })
        .collect::<Vec<_>>();
    roots.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(roots)
}

/// Per-pair non-secret root metadata persisted alongside desktop state. It
/// retains the exact grant/root identity and a revocation/expiry observation
/// without retaining a bearer capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncRootMetadata {
    pub root: SyncRoot,
    #[serde(default)]
    pub access_removed: Option<SyncRootAccessRemoval>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncRootAccessRemoval {
    pub reason: SyncRootAccessRemovalReason,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncRootAccessRemovalReason {
    Expired,
    RevokedOrRemoved,
}

impl SyncRootMetadata {
    pub fn is_available_at(&self, now: DateTime<Utc>) -> bool {
        self.access_removed.is_none() && self.root.is_available_at(now)
    }

    pub fn mark_access_removed(&mut self, reason: SyncRootAccessRemovalReason, now: DateTime<Utc>) {
        self.access_removed = Some(SyncRootAccessRemoval {
            reason,
            observed_at: now,
        });
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SyncRootReconciliation {
    pub updated_pair_ids: Vec<String>,
    pub access_removed_pair_ids: Vec<String>,
}

impl DesktopState {
    /// Update only the configured pair for a user-selected root. Other pair
    /// authorities are refreshed separately with the complete configured set.
    pub fn record_selected_sync_root(&mut self, root: &SyncRoot) -> Result<()> {
        let pair = self
            .pairs()
            .find(|pair| {
                pair.workspace_id == root.workspace_id && pair.remote_root_id == root.root_file_id
            })
            .cloned();
        if let Some(pair) = pair {
            self.record_sync_root(&pair, root.clone())?;
        }
        Ok(())
    }

    pub fn sync_root_for_pair(&self, pair: &SyncPair) -> Option<&SyncRootMetadata> {
        self.sync_roots.get(&crate::sync_pair_id(pair))
    }

    pub fn record_sync_root(&mut self, pair: &SyncPair, root: SyncRoot) -> Result<()> {
        root.validate()?;
        validate_root_pair_binding(pair, &root)?;
        self.sync_roots.insert(
            crate::sync_pair_id(pair),
            SyncRootMetadata {
                root,
                access_removed: None,
            },
        );
        Ok(())
    }

    /// Reconcile only already-configured pairs. New-root materialization needs
    /// an atomically created local namespace and remains a shell-level step;
    /// this method never creates or deletes local bytes.
    pub fn reconcile_sync_roots(
        &mut self,
        discovered: &[SyncRoot],
        now: DateTime<Utc>,
    ) -> Result<SyncRootReconciliation> {
        if discovered.len() > MAX_DISCOVERY_ROOTS {
            return Err(root_limit_error());
        }
        let mut current = BTreeMap::new();
        for root in converge_sync_roots(discovered)? {
            if current.insert(root.id.clone(), root).is_some() {
                return Err(DesktopError::InvalidState(
                    "Drive root discovery returned duplicate root identities".to_string(),
                ));
            }
        }
        let mut outcome = SyncRootReconciliation::default();
        for (pair_id, metadata) in &mut self.sync_roots {
            match current
                .values()
                .find(|root| metadata.root.same_canonical_root(root))
            {
                Some(root) if root.is_available_at(now) => {
                    if metadata.root != *root || metadata.access_removed.is_some() {
                        metadata.root = (*root).clone();
                        metadata.access_removed = None;
                        outcome.updated_pair_ids.push(pair_id.clone());
                    }
                }
                Some(root) => {
                    metadata.root = (*root).clone();
                    metadata.mark_access_removed(SyncRootAccessRemovalReason::Expired, now);
                    outcome.access_removed_pair_ids.push(pair_id.clone());
                }
                _ => {
                    metadata
                        .mark_access_removed(SyncRootAccessRemovalReason::RevokedOrRemoved, now);
                    outcome.access_removed_pair_ids.push(pair_id.clone());
                }
            }
        }
        outcome.updated_pair_ids.sort();
        outcome.access_removed_pair_ids.sort();
        outcome.access_removed_pair_ids.dedup();
        Ok(outcome)
    }
}

fn prefer_root(candidate: &SyncRoot, current: &SyncRoot, now: DateTime<Utc>) -> bool {
    let candidate_available = candidate.is_available_at(now);
    let current_available = current.is_available_at(now);
    (candidate_available && !current_available)
        || (candidate_available == current_available
            && (role_rank(candidate.role) > role_rank(current.role)
                || (role_rank(candidate.role) == role_rank(current.role)
                    && expiry_rank(candidate.expires_at) > expiry_rank(current.expires_at))
                || (role_rank(candidate.role) == role_rank(current.role)
                    && expiry_rank(candidate.expires_at) == expiry_rank(current.expires_at)
                    && candidate.id < current.id)))
}

fn role_rank(role: SyncRootRole) -> u8 {
    match role {
        SyncRootRole::Owner => 3,
        SyncRootRole::Editor => 2,
        SyncRootRole::Viewer => 1,
    }
}

fn expiry_rank(expiry: Option<DateTime<Utc>>) -> i64 {
    expiry.map_or(i64::MAX, |value| value.timestamp())
}

fn root_limit_error() -> DesktopError {
    DesktopError::InvalidState(format!(
        "Drive returned too many sync roots for one desktop discovery pass (limit {MAX_DISCOVERY_ROOTS})"
    ))
}

fn required(label: &str, value: &str, maximum: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > maximum {
        return Err(DesktopError::InvalidState(format!(
            "{label} is empty or exceeds its {maximum}-byte limit"
        )));
    }
    Ok(())
}

fn optional(label: &str, value: Option<&str>, maximum: usize) -> Result<()> {
    if let Some(value) = value {
        required(label, value, maximum)?;
    }
    Ok(())
}

fn namespace_component(label: &str) -> String {
    let mut component = label
        .trim()
        .chars()
        .map(|character| match character {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => ' ',
            value if value.is_control() => ' ',
            value => value,
        })
        .collect::<String>();
    component = component.trim_matches([' ', '.']).to_string();
    component = if component.is_empty() {
        "Shared root".to_string()
    } else {
        component.chars().take(120).collect()
    };
    if crate::validate_windows_compatible_relative(PathBuf::from(&component).as_path()).is_err() {
        "Shared root".to_string()
    } else {
        component
    }
}

/// Namespace components use the same intentionally narrow Unicode/case policy
/// as desktop publication. Combining aliases are rejected before this point,
/// so lowercasing this supported subset is a stable Windows/macOS collision
/// key without placing opaque server IDs in the visible path.
fn namespace_collision_key(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().to_lowercase())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn validate_root_pair_binding(pair: &SyncPair, root: &SyncRoot) -> Result<()> {
    if root.workspace_id != pair.workspace_id || root.root_file_id != pair.remote_root_id {
        return Err(DesktopError::InvalidState(
            "saved sync root authority does not bind this pair workspace and remote root"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root(id: &str, kind: SyncRootKind, role: SyncRootRole) -> SyncRoot {
        SyncRoot {
            id: id.to_string(),
            kind,
            workspace_id: "workspace-1".to_string(),
            root_file_id: (kind == SyncRootKind::ItemGrant).then(|| "folder-1".to_string()),
            grant_id: (kind == SyncRootKind::ItemGrant).then(|| "grant-1".to_string()),
            owner_label: "Avery Example".to_string(),
            role,
            access_generation: 1,
            expires_at: None,
            label: "Projects".to_string(),
        }
    }

    fn pair() -> SyncPair {
        SyncPair {
            server_url: "https://drive.example.test".to_string(),
            account_email: "casey@example.test".to_string(),
            workspace_id: "workspace-1".to_string(),
            workspace_name: "Workspace".to_string(),
            remote_root_id: Some("folder-1".to_string()),
            remote_root_name: Some("Projects".to_string()),
            local_root: PathBuf::from("C:/Drive/Shared with me/Avery Example/Projects"),
            local_root_identity: None,
        }
    }

    #[test]
    fn local_locations_show_my_files_and_shared_owner_root_without_remote_ids() {
        let mut owned = root(
            "workspace:workspace-1",
            SyncRootKind::Workspace,
            SyncRootRole::Owner,
        );
        owned.owner_label = "Casey Example".to_string();
        owned.label = "Private Drive".to_string();
        let shared = root(
            "item-grant:opaque-grant",
            SyncRootKind::ItemGrant,
            SyncRootRole::Viewer,
        );
        let mut shared = shared;
        shared.workspace_id = "workspace-2".to_string();
        let locations = plan_local_root_locations(&[shared.clone(), owned]).unwrap();
        assert_eq!(
            locations[0].relative_path,
            PathBuf::from("Shared with me/Avery Example/Projects")
        );
        assert_eq!(locations[1].relative_path, PathBuf::from("My files"));
        assert!(locations.iter().all(|location| {
            !location
                .relative_path
                .to_string_lossy()
                .contains(&shared.id)
        }));
    }

    #[test]
    fn collisions_gain_a_stable_non_identity_suffix() {
        let one = root(
            "item-grant:one",
            SyncRootKind::ItemGrant,
            SyncRootRole::Viewer,
        );
        let mut two = one.clone();
        two.id = "item-grant:two".to_string();
        two.grant_id = Some("grant-2".to_string());
        two.root_file_id = Some("folder-2".to_string());
        let locations = plan_local_root_locations(&[one, two]).unwrap();
        assert_ne!(locations[0].relative_path, locations[1].relative_path);
        assert!(locations.iter().all(|location| {
            !location
                .relative_path
                .to_string_lossy()
                .contains("item-grant")
        }));
    }

    #[test]
    fn explicit_add_preserves_existing_authority_and_avoids_occupied_folder() {
        let base = PathBuf::from("C:/Drive");
        let existing = root(
            "item-grant:first",
            SyncRootKind::ItemGrant,
            SyncRootRole::Viewer,
        );
        let mut second = existing.clone();
        second.id = "item-grant:second".to_string();
        second.grant_id = Some("grant-2".to_string());
        second.root_file_id = Some("folder-2".to_string());
        let mut state = DesktopState::default();
        let mut first_pair = pair();
        first_pair.local_root = base.join(
            plan_local_root_locations(std::slice::from_ref(&existing)).unwrap()[0]
                .relative_path
                .clone(),
        );
        state.configure_pair(first_pair.clone()).unwrap();
        state
            .record_sync_root(&first_pair, existing.clone())
            .unwrap();

        let selected_again = plan_selected_root_location(&state, &existing, &base).unwrap();
        assert_eq!(
            base.join(selected_again.relative_path),
            first_pair.local_root
        );
        assert_eq!(state.pair_count(), 1);

        let second_location = plan_selected_root_location(&state, &second, &base).unwrap();
        assert_ne!(
            base.join(&second_location.relative_path),
            first_pair.local_root
        );
        assert!(second_location
            .relative_path
            .to_string_lossy()
            .contains('('));
        let mut second_pair = first_pair.clone();
        second_pair.remote_root_id = second.root_file_id.clone();
        second_pair.local_root = base.join(second_location.relative_path);
        state.configure_pair(second_pair.clone()).unwrap();
        state
            .record_sync_root(&second_pair, second.clone())
            .unwrap();

        let mut selected = second.clone();
        selected.access_generation += 1;
        state.record_selected_sync_root(&selected).unwrap();
        assert_eq!(
            state.sync_root_for_pair(&first_pair).unwrap().root,
            existing
        );
        assert!(state
            .sync_root_for_pair(&first_pair)
            .unwrap()
            .access_removed
            .is_none());
        assert_eq!(
            state.sync_root_for_pair(&second_pair).unwrap().root,
            selected
        );
    }

    #[test]
    fn overlapping_grants_converge_on_one_canonical_local_root() {
        let direct = root(
            "item-grant:direct",
            SyncRootKind::ItemGrant,
            SyncRootRole::Viewer,
        );
        let mut group = direct.clone();
        group.id = "item-grant:group".to_string();
        group.grant_id = Some("group-grant".to_string());
        group.role = SyncRootRole::Editor;
        group.access_generation = 2;
        assert_eq!(
            converge_sync_roots(&[direct, group.clone()]).unwrap(),
            vec![group]
        );
    }

    #[test]
    fn discovery_admits_one_hundred_unique_roots_and_rejects_one_hundred_one() {
        let roots = (1..=MAX_DISCOVERY_ROOTS)
            .map(|index| {
                let mut root = root(
                    &format!("item-grant:{index:03}"),
                    SyncRootKind::ItemGrant,
                    SyncRootRole::Viewer,
                );
                root.workspace_id = format!("workspace-{index:03}");
                root.root_file_id = Some(format!("folder-{index:03}"));
                root.grant_id = Some(format!("grant-{index:03}"));
                root.label = format!("Root {index:03}");
                root
            })
            .collect::<Vec<_>>();
        assert_eq!(
            converge_sync_roots(&roots).expect("100 discovered roots"),
            roots
        );

        let mut too_many = roots.clone();
        let mut overflow = root(
            "item-grant:101",
            SyncRootKind::ItemGrant,
            SyncRootRole::Viewer,
        );
        overflow.workspace_id = "workspace-101".to_string();
        overflow.root_file_id = Some("folder-101".to_string());
        overflow.grant_id = Some("grant-101".to_string());
        too_many.push(overflow);
        let error =
            converge_sync_roots(&too_many).expect_err("101 roots are over the desktop limit");
        assert!(error.to_string().contains("limit 100"));
        assert_eq!(roots.len(), MAX_DISCOVERY_ROOTS);
    }

    #[test]
    fn active_lower_role_beats_an_expired_higher_role() {
        let now = Utc::now();
        let mut expired_owner = root(
            "item-grant:expired-owner",
            SyncRootKind::ItemGrant,
            SyncRootRole::Owner,
        );
        expired_owner.expires_at = Some(now - chrono::Duration::seconds(1));
        let mut active_viewer = expired_owner.clone();
        active_viewer.id = "item-grant:active-viewer".to_string();
        active_viewer.grant_id = Some("active-viewer".to_string());
        active_viewer.role = SyncRootRole::Viewer;
        active_viewer.expires_at = None;
        assert_eq!(
            converge_sync_roots_at(&[expired_owner, active_viewer.clone()], now).unwrap(),
            vec![active_viewer]
        );
    }

    #[test]
    fn whole_workspace_suppresses_no_stronger_item_root() {
        let workspace = root(
            "workspace:workspace-1",
            SyncRootKind::Workspace,
            SyncRootRole::Editor,
        );
        let item = root(
            "item-grant:viewer",
            SyncRootKind::ItemGrant,
            SyncRootRole::Viewer,
        );
        assert_eq!(
            converge_sync_roots(&[item, workspace.clone()]).unwrap(),
            vec![workspace]
        );
    }

    #[test]
    fn namespace_collisions_are_windows_safe_without_opaque_ids() {
        let mut upper = root(
            "item-grant:upper",
            SyncRootKind::ItemGrant,
            SyncRootRole::Viewer,
        );
        upper.workspace_id = "workspace-2".to_string();
        upper.owner_label = "AUX".to_string();
        upper.label = "Projects".to_string();
        let mut lower = upper.clone();
        lower.id = "item-grant:lower".to_string();
        lower.grant_id = Some("lower".to_string());
        lower.root_file_id = Some("folder-2".to_string());
        lower.owner_label = "aux".to_string();
        let locations = plan_local_root_locations(&[upper, lower]).unwrap();
        assert_ne!(locations[0].relative_path, locations[1].relative_path);
        assert!(locations.iter().all(|location| {
            crate::validate_windows_compatible_relative(&location.relative_path).is_ok()
                && !location
                    .relative_path
                    .to_string_lossy()
                    .contains("item-grant")
        }));
    }

    #[test]
    fn root_metadata_must_bind_its_pair_and_reconciliation_keeps_its_path() {
        let pair = pair();
        let mut state = DesktopState::default();
        state.configure_pair(pair.clone()).unwrap();
        let shared = root(
            "item-grant:opaque-grant",
            SyncRootKind::ItemGrant,
            SyncRootRole::Editor,
        );
        state.record_sync_root(&pair, shared.clone()).unwrap();
        let mut renamed = shared;
        renamed.label = "Renamed Projects".to_string();
        state.reconcile_sync_roots(&[renamed], Utc::now()).unwrap();
        assert_eq!(state.pair.as_ref().unwrap().local_root, pair.local_root);

        let mut wrong = root(
            "item-grant:wrong",
            SyncRootKind::ItemGrant,
            SyncRootRole::Viewer,
        );
        wrong.workspace_id = "other-workspace".to_string();
        assert!(state.record_sync_root(&pair, wrong).is_err());
    }

    #[test]
    fn reconcile_marks_missing_or_expired_roots_without_touching_local_pair_data() {
        let pair = pair();
        let mut state = DesktopState::default();
        state.configure_pair(pair.clone()).unwrap();
        let shared = root(
            "item-grant:opaque-grant",
            SyncRootKind::ItemGrant,
            SyncRootRole::Editor,
        );
        state.record_sync_root(&pair, shared.clone()).unwrap();
        let now = Utc::now();
        let outcome = state.reconcile_sync_roots(&[], now).unwrap();
        assert_eq!(
            outcome.access_removed_pair_ids,
            vec![crate::sync_pair_id(&pair)]
        );
        let metadata = state.sync_root_for_pair(&pair).unwrap();
        assert_eq!(metadata.root, shared);
        assert_eq!(
            metadata.access_removed.as_ref().unwrap().reason,
            SyncRootAccessRemovalReason::RevokedOrRemoved
        );
        assert_eq!(state.pair.as_ref().unwrap().local_root, pair.local_root);
    }

    #[test]
    fn role_changes_are_retained_on_current_subject_but_subject_changes_revoke() {
        let pair = pair();
        let mut state = DesktopState::default();
        state.configure_pair(pair.clone()).unwrap();
        let shared = root(
            "item-grant:opaque-grant",
            SyncRootKind::ItemGrant,
            SyncRootRole::Editor,
        );
        state.record_sync_root(&pair, shared).unwrap();
        let mut downgraded = root(
            "item-grant:opaque-grant",
            SyncRootKind::ItemGrant,
            SyncRootRole::Viewer,
        );
        downgraded.expires_at = Some(Utc::now() + chrono::Duration::hours(1));
        downgraded.access_generation = 2;
        let outcome = state
            .reconcile_sync_roots(&[downgraded], Utc::now())
            .unwrap();
        assert_eq!(outcome.updated_pair_ids, vec![crate::sync_pair_id(&pair)]);
        assert_eq!(
            state.sync_root_for_pair(&pair).unwrap().root.role,
            SyncRootRole::Viewer
        );
    }
}
