use chrono::{Duration, Utc};

use super::*;
use crate::{confirm_pending_remote_retirements, DesktopError, RemoteSessionRevocationOutcome};

mod candidate_recovery;
mod durable_progress;
mod partial_cleanup;

#[derive(Debug, Eq, PartialEq)]
struct Authorizer {
    label: &'static str,
    server_url: &'static str,
    email: &'static str,
}

fn record(session_id: &str, server_url: &str, email: &str) -> RemoteSessionRecord {
    RemoteSessionRecord::new(
        server_url,
        email,
        session_id,
        Utc::now() + Duration::hours(1),
    )
    .unwrap()
}

fn matches(record: &RemoteSessionRecord, authorizer: &Authorizer) -> bool {
    record.identity_matches(authorizer.server_url, authorizer.email)
}

#[test]
fn fresh_candidate_precedes_a_stale_same_identity_authorizer() {
    let pending = record(
        "older-session",
        "https://drive.example.test",
        "person@example.test",
    );
    let stale = Authorizer {
        label: "stale-logged-out",
        server_url: "https://drive.example.test",
        email: "person@example.test",
    };
    let fresh = Authorizer {
        label: "fresh-valid",
        server_url: "https://drive.example.test",
        email: "person@example.test",
    };

    let retained = [stale];
    let selected = select_pending_retirement_authorizer(&pending, Some(&fresh), &retained, matches)
        .expect("the fresh candidate authorizes the pending retirement");

    assert_eq!(selected.label, "fresh-valid");
    let outcome = if selected.label == "fresh-valid" {
        Ok(RemoteSessionRevocationOutcome::Revoked)
    } else {
        Err(DesktopError::InvalidState(
            "stale authorizer was already logged out".to_string(),
        ))
    };
    let retired = confirm_pending_remote_retirements([(pending.clone(), outcome)]).unwrap();
    assert_eq!(retired, [pending]);
}

#[test]
fn retained_authorizer_is_used_when_the_preferred_candidate_is_other_identity() {
    let pending = record(
        "older-session",
        "https://drive.example.test",
        "person@example.test",
    );
    let retained = Authorizer {
        label: "retained-match",
        server_url: "https://drive.example.test",
        email: "person@example.test",
    };
    let other = Authorizer {
        label: "other-account",
        server_url: "https://other.example.test",
        email: "person@example.test",
    };

    let retained = [retained];
    let selected = select_pending_retirement_authorizer(&pending, Some(&other), &retained, matches);

    assert_eq!(
        selected.map(|authorizer| authorizer.label),
        Some("retained-match")
    );
}

#[test]
fn candidate_session_is_excluded_but_other_pending_sessions_are_retired() {
    let candidate = record(
        "candidate-session",
        "https://drive.example.test",
        "person@example.test",
    );
    let older = record(
        "older-session",
        "https://drive.example.test",
        "person@example.test",
    );

    assert!(!pending_record_requires_retirement(
        &candidate,
        Some(&candidate)
    ));
    assert!(pending_record_requires_retirement(&older, Some(&candidate)));
}

#[test]
fn missing_authorizer_and_revoke_failure_both_fail_closed_without_detail() {
    let pending = record(
        "older-session",
        "https://drive.example.test",
        "person@example.test",
    );

    assert!(
        select_pending_retirement_authorizer::<Authorizer>(&pending, None, &[], matches,).is_none()
    );
    let error = confirm_pending_remote_retirements([(
        pending,
        Err(DesktopError::InvalidState(
            "simulated revoke failure".to_string(),
        )),
    )])
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "credential store error: pending remote session retirement was not confirmed; credentials were kept for retry"
    );
    assert!(!error.to_string().contains("simulated revoke failure"));
}
