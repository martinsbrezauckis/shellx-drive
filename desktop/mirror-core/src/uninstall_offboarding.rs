//! Fail-closed remote retirement for uninstall-time credential removal.

use crate::{DesktopError, LogoutOutcome, RemoteSessionRevocationOutcome, Result};

/// Confirms remote retirement for every locally retained credential before a
/// caller removes any of those credentials. The callback owns transport and
/// platform-specific details; this boundary deliberately discards its error
/// text so a status or log cannot disclose a bearer token.
///
/// `LogoutOutcome::AlreadyInvalid` is a successful proof that the bearer can
/// no longer authorize a session. On every other outcome, callers must leave
/// all local credentials intact so a later uninstall attempt can retry.
pub fn confirm_remote_retirement<T, I, F>(credentials: I, mut logout: F) -> Result<()>
where
    I: IntoIterator<Item = T>,
    F: FnMut(&T) -> Result<LogoutOutcome>,
{
    for credential in credentials {
        match logout(&credential) {
            Ok(LogoutOutcome::Revoked | LogoutOutcome::AlreadyInvalid) => {}
            Err(_) => {
                return Err(DesktopError::Credential(
                    "remote session retirement was not confirmed; credentials were kept for retry"
                        .to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// Return remote-session records only after every exact-session retirement has
/// been proven. Callers leave durable state untouched until this succeeds, so
/// one offline or unauthorized request cannot discard another retry record.
/// Transport errors are deliberately discarded to keep bearer material out of
/// user-facing cleanup errors.
pub fn confirm_pending_remote_retirements<T, I>(attempts: I) -> Result<Vec<T>>
where
    I: IntoIterator<Item = (T, Result<RemoteSessionRevocationOutcome>)>,
{
    let mut confirmed = Vec::new();
    for (record, outcome) in attempts {
        match outcome {
            Ok(
                RemoteSessionRevocationOutcome::Revoked
                | RemoteSessionRevocationOutcome::AlreadyAbsent,
            ) => confirmed.push(record),
            Err(_) => {
                return Err(DesktopError::Credential(
                    "pending remote session retirement was not confirmed; credentials were kept for retry"
                        .to_string(),
                ));
            }
        }
    }
    Ok(confirmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninstall_retirement_accepts_online_success_for_every_credential() {
        let credentials = ["first", "second"];
        let mut attempted = Vec::new();

        confirm_remote_retirement(credentials, |credential| {
            attempted.push(*credential);
            Ok(if *credential == "first" {
                LogoutOutcome::Revoked
            } else {
                LogoutOutcome::AlreadyInvalid
            })
        })
        .unwrap();

        assert_eq!(attempted, ["first", "second"]);
    }

    #[test]
    fn uninstall_retirement_refuses_offline_cleanup() {
        let mut attempted = 0;
        let error = confirm_remote_retirement(["first", "second"], |_| {
            attempted += 1;
            Err(DesktopError::InvalidState("offline".to_string()))
        })
        .unwrap_err();

        assert_eq!(attempted, 1);
        assert_eq!(
            error.to_string(),
            "credential store error: remote session retirement was not confirmed; credentials were kept for retry"
        );
    }

    #[test]
    fn uninstall_retirement_error_never_includes_a_bearer() {
        let bearer = "opaque-bearer-must-not-reach-uninstall-output";
        let error = confirm_remote_retirement([bearer], |_| {
            Err(DesktopError::InvalidState(format!(
                "network failure while using {bearer}"
            )))
        })
        .unwrap_err();

        assert!(!error.to_string().contains(bearer));
    }

    #[test]
    fn pending_retirement_accepts_revoked_and_already_absent_sessions() {
        let retired = confirm_pending_remote_retirements([
            ("first", Ok(RemoteSessionRevocationOutcome::Revoked)),
            ("second", Ok(RemoteSessionRevocationOutcome::AlreadyAbsent)),
        ])
        .unwrap();

        assert_eq!(retired, ["first", "second"]);
    }

    #[test]
    fn pending_retirement_refuses_an_unavailable_authorizer_without_echoing_it() {
        let bearer = "opaque-bearer-must-not-reach-pending-retirement-output";
        let error = confirm_pending_remote_retirements([(
            "pending-session",
            Err(DesktopError::Credential(format!(
                "no matching credential for {bearer}"
            ))),
        )])
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "credential store error: pending remote session retirement was not confirmed; credentials were kept for retry"
        );
        assert!(!error.to_string().contains(bearer));
    }

    #[test]
    fn pending_retirement_refuses_a_transient_failure_without_confirming_a_partial_set() {
        let error = confirm_pending_remote_retirements([
            ("first", Ok(RemoteSessionRevocationOutcome::Revoked)),
            (
                "second",
                Err(DesktopError::InvalidState("temporary outage".to_string())),
            ),
        ])
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "credential store error: pending remote session retirement was not confirmed; credentials were kept for retry"
        );
    }
}
