//! Deterministic ordering for staged-candidate restart recovery.

use std::cmp::Ordering;

use crate::{DesktopState, RemoteSessionRecord};

use super::recovery_action::candidate_recovery_locator;

/// Put the durable candidate locator first, then retain deterministic lexical
/// ordering for every other staged slot. The locator is pending-first and only
/// falls back to active state when no pending marker exists.
pub fn compare_staged_candidate_recovery_order(
    state: &DesktopState,
    left: (&str, &str, &str),
    right: (&str, &str, &str),
) -> Ordering {
    let locator = candidate_recovery_locator(state);
    slot_matches(locator, right)
        .cmp(&slot_matches(locator, left))
        .then_with(|| left.cmp(&right))
}

fn slot_matches(locator: Option<&RemoteSessionRecord>, slot: (&str, &str, &str)) -> bool {
    locator.is_some_and(|record| {
        record.identity_matches(slot.0, slot.1) && record.session_id == slot.2
    })
}

#[cfg(test)]
mod tests;
