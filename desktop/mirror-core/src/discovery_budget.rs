use crate::{DesktopError, Result};

pub const MAX_DISCOVERY_WORKSPACES: usize = 100;
pub const MAX_DISCOVERY_MANIFEST_ITEMS: usize = 100_000;
pub const MAX_DISCOVERY_CHOICES: usize = 20_000;
pub const MAX_DISCOVERY_LABEL_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct WorkspaceDiscoveryBudget {
    manifests: usize,
    manifest_items: usize,
    choices: usize,
    label_bytes: usize,
}

impl WorkspaceDiscoveryBudget {
    pub fn admit_workspace_count(&self, count: usize) -> Result<()> {
        if count > MAX_DISCOVERY_WORKSPACES {
            return Err(limit_error("workspaces", MAX_DISCOVERY_WORKSPACES));
        }
        Ok(())
    }

    pub fn admit_manifest(&mut self, items: usize) -> Result<()> {
        self.manifests = checked_add(self.manifests, 1, "workspace manifests")?;
        if self.manifests > MAX_DISCOVERY_WORKSPACES {
            return Err(limit_error("workspace manifests", MAX_DISCOVERY_WORKSPACES));
        }
        self.manifest_items = checked_add(self.manifest_items, items, "manifest items")?;
        if self.manifest_items > MAX_DISCOVERY_MANIFEST_ITEMS {
            return Err(limit_error(
                "aggregate manifest items",
                MAX_DISCOVERY_MANIFEST_ITEMS,
            ));
        }
        Ok(())
    }

    pub fn admit_choice_labels(
        &mut self,
        label_lengths: impl IntoIterator<Item = usize>,
    ) -> Result<()> {
        for length in label_lengths {
            self.choices = checked_add(self.choices, 1, "folder choices")?;
            self.label_bytes = checked_add(self.label_bytes, length, "folder choice labels")?;
            if self.choices > MAX_DISCOVERY_CHOICES {
                return Err(limit_error("folder choices", MAX_DISCOVERY_CHOICES));
            }
            if self.label_bytes > MAX_DISCOVERY_LABEL_BYTES {
                return Err(limit_error(
                    "folder choice label bytes",
                    MAX_DISCOVERY_LABEL_BYTES,
                ));
            }
        }
        Ok(())
    }
}

fn checked_add(current: usize, additional: usize, name: &str) -> Result<usize> {
    current.checked_add(additional).ok_or_else(|| {
        DesktopError::InvalidState(format!(
            "Drive {name} exceeded the desktop discovery budget"
        ))
    })
}

fn limit_error(name: &str, limit: usize) -> DesktopError {
    DesktopError::InvalidState(format!(
        "Drive returned too many {name} for one desktop discovery pass (limit {limit})"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_manifest_and_choice_limits_are_enforced() {
        let mut budget = WorkspaceDiscoveryBudget::default();
        budget.admit_workspace_count(2).unwrap();
        budget.admit_manifest(MAX_DISCOVERY_MANIFEST_ITEMS).unwrap();
        assert!(budget.admit_manifest(1).is_err());

        let mut budget = WorkspaceDiscoveryBudget::default();
        budget
            .admit_choice_labels(std::iter::repeat_n(1, MAX_DISCOVERY_CHOICES))
            .unwrap();
        assert!(budget.admit_choice_labels([1]).is_err());
    }

    #[test]
    fn label_byte_budget_is_independent_of_choice_count() {
        let mut budget = WorkspaceDiscoveryBudget::default();
        budget
            .admit_choice_labels([MAX_DISCOVERY_LABEL_BYTES])
            .unwrap();
        assert!(budget.admit_choice_labels([1]).is_err());
    }
}
