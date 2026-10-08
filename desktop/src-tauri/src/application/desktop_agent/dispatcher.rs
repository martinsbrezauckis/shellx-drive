use chrono::Utc;
use shellx_drive_desktop_core::{
    DesktopAgentProgressReport, DesktopAgentTerminalReport, DesktopError, DesktopState,
    DriveHttpClient, Result as CoreResult, SyncPair,
};
use std::{collections::BTreeSet, time::Duration};
use tauri::AppHandle;

use super::actions::{
    agent_sync_result, agent_view_result, check_update, dispatch_authorized_root_refresh,
    dispatch_review_confirmation, dispatch_select_pair, refresh_platform_tray,
    roots_discovered_result, server_validated_result,
};
use super::{current_agent_assertion, update_agent_state, DesktopView, Runtime};

mod disconnect;
mod outcome;
mod update_install;

pub(super) use disconnect::resume as resume_pending_disconnect_completion;
use outcome::CommandOutcome;

/// A 45-second server lease is renewed well before expiry. The server bounds
/// each renewal by the original command deadline, so this cadence cannot turn
/// a finite command into an indefinitely held device mutation.
const AGENT_LEASE_RENEWAL_MAX_INTERVAL: Duration = Duration::from_secs(15);
const AGENT_LEASE_RENEWAL_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Transport and identity data bound to one claimed broker command.
pub(super) struct CommandLease<'a> {
    pub(super) client: &'a DriveHttpClient,
    pub(super) device_credential: &'a str,
    pub(super) command_id: &'a str,
    pub(super) lease_id: &'a str,
    pub(super) expires_at: chrono::DateTime<Utc>,
    pub(super) disconnect_completion_capability: Option<&'a str>,
    pub(super) disconnect_completion_expires_at: Option<chrono::DateTime<Utc>>,
}

/// The durable terminal record is written before the HTTP call. A timeout
/// after a server commit leaves that same record available for the exact
/// idempotent retry on the next poll or restart.
pub(super) async fn record_and_report_terminal(
    runtime: &Runtime,
    client: &DriveHttpClient,
    device_credential: &str,
    command_id: &str,
    lease_id: &str,
    outcome: CommandOutcome,
) -> CoreResult<()> {
    let terminal_sequence = update_agent_state(runtime, |control| {
        control.mark_terminal(
            command_id,
            outcome.status,
            outcome.code,
            outcome.result_code,
            outcome.result.clone(),
            Utc::now(),
        )
    })?;
    let terminal_assertion = current_agent_assertion(runtime)?;
    client
        .report_desktop_agent_terminal(
            device_credential,
            DesktopAgentTerminalReport {
                command_id,
                lease_id,
                event_sequence: terminal_sequence,
                assertion: &terminal_assertion,
                status: outcome.status,
                terminal_code: outcome.code,
                result_code: outcome.result_code,
                result: outcome.result.as_ref(),
            },
        )
        .await?;
    update_agent_state(runtime, |control| {
        control.mark_terminal_reported(command_id, Utc::now())
    })?;
    Ok(())
}

pub(super) async fn execute_typed_command(
    app: &AppHandle,
    runtime: &Runtime,
    lease: &CommandLease<'_>,
    command: shellx_drive_desktop_core::DesktopAgentCommand,
) -> CommandExecution {
    use shellx_drive_desktop_core::{
        DesktopAgentCommand as Command, DesktopAgentResultCode, DesktopAgentResultPayload,
    };

    let result = match command {
        Command::DesktopView { page } => agent_view_result(runtime, &page)
            .map(|result| (DesktopAgentResultCode::ViewRead, result)),
        Command::SyncNow => dispatch_sync_with_lease_renewal(app, runtime, lease, false)
            .await
            .and_then(|view| agent_sync_result_after_completion(runtime, &view))
            .map(|result| (DesktopAgentResultCode::SyncCompleted, result)),
        Command::RecheckReviews => dispatch_sync_with_lease_renewal(app, runtime, lease, true)
            .await
            .and_then(|view| agent_sync_result_after_completion(runtime, &view))
            .map(|result| (DesktopAgentResultCode::ReviewsRechecked, result)),
        Command::SetPaused { paused } => {
            super::super::lifecycle::persist_paused_state(runtime, paused)
                .await
                .map(|_| {
                    refresh_platform_tray(app, runtime);
                    (
                        DesktopAgentResultCode::PausePersisted,
                        DesktopAgentResultPayload::Pause {
                            paused: runtime.coordinator.snapshot().paused,
                        },
                    )
                })
        }
        Command::SetLaunchAtLogin { enabled } => {
            super::super::commands::persist_launch_at_login_state(runtime, enabled)
                .await
                .map(|_| {
                    (
                        DesktopAgentResultCode::LaunchAtLoginPersisted,
                        DesktopAgentResultPayload::LaunchAtLogin {
                            enabled: runtime.coordinator.snapshot().launch_at_login,
                        },
                    )
                })
        }
        Command::PrepareReviewAction {
            pair_id,
            review_id,
            action,
        } => dispatch_select_pair(app, runtime, pair_id.clone())
            .await
            .and_then(|_| {
                super::super::review::prepare_review_confirmation_for_pair(
                    runtime,
                    pair_id.clone(),
                    review_id.clone(),
                    action,
                )
            })
            .map(|confirmation| {
                (
                    DesktopAgentResultCode::ReviewPrepared,
                    DesktopAgentResultPayload::ReviewPrepared {
                        pair_id,
                        review_id,
                        action,
                        prepared_confirmation_id: confirmation.confirmation_id,
                        fingerprint: confirmation.fingerprint,
                    },
                )
            }),
        Command::ConfirmReviewAction {
            pair_id,
            review_id,
            action,
            prepared_confirmation_id,
            fingerprint,
        } => match super::super::review::ensure_review_confirmation_pair(
            runtime,
            &pair_id,
            &review_id,
            action,
            &prepared_confirmation_id,
            &fingerprint,
        ) {
            Ok(()) => {
                dispatch_review_confirmation(
                    app,
                    runtime,
                    review_id.clone(),
                    action,
                    prepared_confirmation_id.clone(),
                )
                .await
            }
            Err(error) => Err(error),
        }
        .map(|_| {
            (
                DesktopAgentResultCode::ReviewConfirmed,
                DesktopAgentResultPayload::ReviewConfirmed {
                    pair_id,
                    review_id,
                    action,
                    prepared_confirmation_id,
                    fingerprint,
                },
            )
        }),
        Command::OpenLocalFolder { pair_id } => {
            let result_pair_id = pair_id.clone();
            selected_pair(runtime, pair_id.as_deref())
                .and_then(|pair| runtime.platform.open_local_root(&pair.local_root))
                .map(|_| {
                    (
                        DesktopAgentResultCode::LocalFolderDispatchAttempted,
                        DesktopAgentResultPayload::LocalFolderDispatch {
                            dispatched: true,
                            pair_id: result_pair_id,
                        },
                    )
                })
        }
        Command::OpenDrive { pair_id } => {
            let result_pair_id = pair_id.clone();
            selected_pair(runtime, pair_id.as_deref())
                .and_then(|pair| runtime.platform.open_drive_url(&pair.server_url))
                .map(|_| {
                    (
                        DesktopAgentResultCode::DriveDispatchAttempted,
                        DesktopAgentResultPayload::DriveDispatch {
                            dispatched: true,
                            pair_id: result_pair_id,
                        },
                    )
                })
        }
        Command::DiscoverRoots { page } => {
            let discovered = super::super::root_discovery::page::discover_workspace_choice_page(
                runtime,
                page.after.as_deref(),
                page.limit,
            )
            .await;
            discovered
                .and_then(|page_result| {
                    roots_discovered_result(
                        runtime,
                        &page_result.workspaces,
                        &page,
                        page_result.next_cursor,
                    )
                })
                .map(|result| (DesktopAgentResultCode::RootsDiscovered, result))
        }
        Command::StartPair { workspace_id } => {
            let state = runtime.coordinator.snapshot();
            if state.sync_root_base.is_none()
                || !state.pairs().any(|pair| pair.workspace_id == workspace_id)
            {
                return CommandExecution::Terminal(CommandOutcome::local_gesture());
            }
            refresh_requested_workspace(runtime, &workspace_id)
                .await
                .map(|(added_root_count, existing_root_count)| {
                    (
                        DesktopAgentResultCode::RootsRefreshed,
                        DesktopAgentResultPayload::RootsRefreshed {
                            workspace_id,
                            added_root_count,
                            existing_root_count,
                        },
                    )
                })
        }
        Command::ValidateServer => super::super::commands::validate_current_server(runtime)
            .await
            .and_then(|_| server_validated_result(runtime))
            .map(|result| (DesktopAgentResultCode::ServerValidated, result)),
        Command::Disconnect => {
            return match disconnect::execute(runtime, lease).await {
                Ok(disconnect::Execution::Completed) => CommandExecution::DisconnectCompleted,
                Ok(disconnect::Execution::Cancelled) => CommandExecution::DisconnectInterrupted,
                Ok(disconnect::Execution::Blocked) => CommandExecution::DisconnectBlocked,
                Err(error)
                    if runtime
                        .coordinator
                        .snapshot()
                        .pending_desktop_agent_disconnect()
                        .is_some() =>
                {
                    let _ = error;
                    CommandExecution::DisconnectPending
                }
                Err(error) => CommandExecution::Terminal(command_outcome_for_error(&error)),
            };
        }
        Command::SelectPair { pair_id } => dispatch_select_pair(app, runtime, pair_id.clone())
            .await
            .map(|_| {
                (
                    DesktopAgentResultCode::PairSelected,
                    DesktopAgentResultPayload::PairSelected { pair_id },
                )
            }),
        Command::CheckDesktopUpdate => check_update(app)
            .await
            .map(|result| (DesktopAgentResultCode::UpdateChecked, result)),
        // Install waits for the updater's durable restart proof rather than
        // claiming success before the restarted binary is observed.
        Command::InstallDesktopUpdate { candidate_id } => {
            return update_install::install(
                app,
                runtime,
                lease.client,
                lease.device_credential,
                lease.command_id,
                lease.lease_id,
                candidate_id,
            )
            .await;
        }
        // These commands have a concrete continuation in the signed-in native
        // UI. The queue receives a fixed rejection rather than a guessed
        // invoke, shell command, update decision, or Disconnect success.
        Command::RequiresLocalGesture(_) => {
            return CommandExecution::Terminal(CommandOutcome::local_gesture());
        }
    };
    CommandExecution::Terminal(match result {
        Ok((result_code, result)) => CommandOutcome::succeeded(result_code, result),
        Err(error) => command_outcome_for_error(&error),
    })
}

/// An updater owns its durable post-verification continuation and asks the
/// platform to restart. It must not be terminalized by this running process:
/// the next launch proves the installed version, reports the exact success,
/// and then clears the matching restart intent after broker acceptance.
pub(super) enum CommandExecution {
    Terminal(CommandOutcome),
    RelaunchPending,
    /// Server-side Disconnect terminalization is capability-authenticated and
    /// cannot be duplicated through the generic device-bearer terminal route.
    DisconnectCompleted,
    DisconnectInterrupted,
    DisconnectBlocked,
    DisconnectPending,
}

fn selected_pair(runtime: &Runtime, requested_pair_id: Option<&str>) -> CoreResult<SyncPair> {
    let state = runtime.coordinator.snapshot();
    match requested_pair_id {
        Some(pair_id) => state
            .pairs()
            .find(|pair| shellx_drive_desktop_core::sync_pair_id(pair) == pair_id)
            .cloned()
            .ok_or_else(|| {
                DesktopError::InvalidState("selected Drive location is unavailable".to_string())
            }),
        None => state.pair.ok_or(DesktopError::NeedsSetup),
    }
}

async fn refresh_requested_workspace(
    runtime: &Runtime,
    workspace_id: &str,
) -> CoreResult<(u16, u16)> {
    runtime.require_candidate_recovery_complete()?;
    runtime.ensure_disconnect_cleanup_complete()?;
    let before = configured_workspace_pair_ids(&runtime.coordinator.snapshot(), workspace_id);
    dispatch_authorized_root_refresh(runtime).await?;
    let after = usable_workspace_pair_ids(&runtime.coordinator.snapshot(), workspace_id);
    workspace_refresh_counts(before, after)
}

pub(super) fn usable_workspace_pair_ids(
    state: &shellx_drive_desktop_core::DesktopState,
    workspace_id: &str,
) -> BTreeSet<String> {
    let now = Utc::now();
    state
        .pairs()
        .filter(|pair| pair.workspace_id == workspace_id)
        .filter(|pair| {
            state
                .sync_root_for_pair(pair)
                .is_some_and(|metadata| metadata.is_available_at(now))
        })
        .map(shellx_drive_desktop_core::sync_pair_id)
        .collect()
}

fn configured_workspace_pair_ids(state: &DesktopState, workspace_id: &str) -> BTreeSet<String> {
    state
        .pairs()
        .filter(|pair| pair.workspace_id == workspace_id)
        .map(shellx_drive_desktop_core::sync_pair_id)
        .collect()
}

pub(super) fn workspace_refresh_counts(
    before: BTreeSet<String>,
    after: BTreeSet<String>,
) -> CoreResult<(u16, u16)> {
    if after.is_empty() {
        return Err(DesktopError::InvalidState(
            "desktop-agent root refresh did not retain an authorized requested workspace root"
                .to_string(),
        ));
    }
    let added_root_count = after.difference(&before).count();
    let existing_root_count = after.intersection(&before).count();
    Ok((
        u16::try_from(added_root_count).map_err(|_| {
            DesktopError::InvalidState(
                "desktop-agent added root count exceeds its wire limit".to_string(),
            )
        })?,
        u16::try_from(existing_root_count).map_err(|_| {
            DesktopError::InvalidState(
                "desktop-agent existing root count exceeds its wire limit".to_string(),
            )
        })?,
    ))
}

/// Run a potentially long native synchronization pass while renewing only its
/// fixed broker lease. `select!` drops the in-flight future as soon as a
/// renewal loses authority or expires; each existing platform dispatcher is
/// asynchronous and therefore observes cancellation at its next await point.
async fn dispatch_sync_with_lease_renewal(
    app: &AppHandle,
    runtime: &Runtime,
    lease: &CommandLease<'_>,
    recheck_reviews: bool,
) -> CoreResult<DesktopView> {
    let sync = dispatch_sync(app, runtime, recheck_reviews);
    tokio::pin!(sync);
    let interval = lease_renewal_interval(lease.expires_at.to_owned(), Utc::now());
    let mut renewals = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);

    loop {
        tokio::select! {
            result = &mut sync => {
                return result.map_err(DesktopError::InvalidState);
            }
            _ = renewals.tick() => {
                renew_sync_lease(runtime, lease).await?;
            }
        }
    }
}

/// Linux and Windows retain a view after a transport failure so a local user
/// can retry. Only a completed pass or a completed pass that produced reviews
/// may become a broker success; every other state leaves the command failed.
fn agent_sync_result_after_completion(
    runtime: &Runtime,
    view: &DesktopView,
) -> CoreResult<shellx_drive_desktop_core::DesktopAgentResultPayload> {
    require_completed_sync_status(view.status)?;
    agent_sync_result(runtime)
}

fn require_completed_sync_status(status: &str) -> CoreResult<()> {
    match status {
        "synced" | "needs_review" => Ok(()),
        _ => Err(DesktopError::InvalidState(
            "desktop-agent synchronization did not reach a completed Drive state".to_string(),
        )),
    }
}

async fn renew_sync_lease(runtime: &Runtime, lease: &CommandLease<'_>) -> CoreResult<()> {
    let phase = shellx_drive_desktop_core::DesktopAgentProgressPhase::Syncing;
    let event_sequence = update_agent_state(runtime, |control| {
        control.begin_progress(lease.command_id, phase, Utc::now())
    })?;
    let assertion = current_agent_assertion(runtime)?;
    lease
        .client
        .report_desktop_agent_progress(
            lease.device_credential,
            DesktopAgentProgressReport {
                command_id: lease.command_id,
                lease_id: lease.lease_id,
                event_sequence,
                assertion: &assertion,
                phase,
                progress_basis_points: None,
            },
        )
        .await?;
    update_agent_state(runtime, |control| {
        control.mark_progress_reported(lease.command_id, event_sequence, phase, Utc::now())
    })
}

fn lease_renewal_interval(
    lease_expires_at: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
) -> Duration {
    let remaining = (lease_expires_at - now)
        .to_std()
        .unwrap_or(AGENT_LEASE_RENEWAL_MIN_INTERVAL);
    remaining
        .checked_div(2)
        .unwrap_or(AGENT_LEASE_RENEWAL_MIN_INTERVAL)
        .clamp(
            AGENT_LEASE_RENEWAL_MIN_INTERVAL,
            AGENT_LEASE_RENEWAL_MAX_INTERVAL,
        )
}

pub(super) fn command_outcome_for_error(error: &DesktopError) -> CommandOutcome {
    match error {
        DesktopError::Server {
            status: 401 | 403, ..
        } => CommandOutcome::failed_with(
            shellx_drive_desktop_core::DesktopAgentTerminalCode::AuthorizationLost,
        ),
        DesktopError::Server {
            status: 408 | 410, ..
        } => CommandOutcome::failed_with(
            shellx_drive_desktop_core::DesktopAgentTerminalCode::LeaseExpired,
        ),
        _ => CommandOutcome::failed(),
    }
}

async fn dispatch_sync(
    app: &AppHandle,
    runtime: &Runtime,
    recheck_reviews: bool,
) -> Result<DesktopView, String> {
    #[cfg(target_os = "linux")]
    {
        crate::application::linux::sync::sync_or_recheck(app, runtime, recheck_reviews).await
    }
    #[cfg(target_os = "macos")]
    {
        if recheck_reviews {
            crate::application::macos::sync::recheck_reviews_impl(app, runtime).await
        } else {
            crate::application::macos::sync::sync_now_impl(app, runtime).await
        }
    }
    #[cfg(target_os = "windows")]
    {
        if recheck_reviews {
            crate::application::windows::sync_runtime::recheck_reviews_impl(app, runtime, true)
                .await
        } else {
            crate::application::windows::sync_runtime::sync_now_impl(app, runtime).await
        }
    }
}

#[cfg(test)]
#[path = "dispatcher_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "dispatcher/start_pair_tests.rs"]
mod start_pair_tests;
