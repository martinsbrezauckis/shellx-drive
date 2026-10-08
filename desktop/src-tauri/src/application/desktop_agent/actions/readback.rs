//! Bounded product-data readback for remote desktop-agent actions.

use shellx_drive_desktop_core::{
    product_label, review_cursor, sync_pair_id, DesktopAgentDesktopViewPage,
    DesktopAgentDesktopViewPageRequest, DesktopAgentDesktopViewSection, DesktopAgentPairRow,
    DesktopAgentPairStatus, DesktopAgentResultPayload, DesktopAgentReviewRow, DesktopAgentRootRow,
    DesktopAgentRootSelectionStatus, DesktopAgentRootsPage, DesktopAgentRootsPageRequest,
    DesktopError, Result as CoreResult, ReviewItem, SyncPair, MAX_DESKTOP_AGENT_PAGE_BYTES,
};

use super::super::super::root_discovery::{workspace_choice_counts, WorkspaceChoice};
use super::super::{current_agent_assertion, Runtime};

pub(in crate::application::desktop_agent) fn agent_view_result(
    runtime: &Runtime,
    request: &DesktopAgentDesktopViewPageRequest,
) -> CoreResult<DesktopAgentResultPayload> {
    request.validate()?;
    let state = runtime.coordinator.snapshot();
    let active_pair_count = count_u8(state.pair_count(), "active pair count")?;
    let pending_review_count = count_u32(state.pending_review_count(), "review count")?;
    let (page, next_after) = match request.section {
        DesktopAgentDesktopViewSection::Pairs => pair_page(&state, request),
        DesktopAgentDesktopViewSection::Reviews => review_page(&state, request),
    }?;
    let mut result = DesktopAgentResultPayload::DesktopView {
        status: current_agent_assertion(runtime)?.status,
        paused: state.paused,
        active_pair_count,
        pending_review_count,
        page,
        next_after,
    };
    if request.section == DesktopAgentDesktopViewSection::Reviews {
        fit_review_result(&mut result)?;
    }
    Ok(result)
}

/// Measure the whole wire result, including both cursors and JSON escaping.
/// A removed tail stays reachable through the exact last retained review.
fn fit_review_result(result: &mut DesktopAgentResultPayload) -> CoreResult<()> {
    loop {
        let bytes = serde_json::to_vec(&*result).map_err(|_| {
            DesktopError::InvalidState("desktop-agent page is not serializable".to_string())
        })?;
        let DesktopAgentResultPayload::DesktopView {
            page: DesktopAgentDesktopViewPage::Reviews { rows, .. },
            next_after,
            ..
        } = result
        else {
            return Err(DesktopError::InvalidState(
                "desktop-agent byte pagination requires a review page".to_string(),
            ));
        };
        if bytes.len() <= MAX_DESKTOP_AGENT_PAGE_BYTES {
            break;
        }
        if rows.len() <= 1 {
            return Err(DesktopError::InvalidState(
                "desktop-agent page exceeds its result limit".to_string(),
            ));
        }
        rows.pop();
        *next_after = rows.last().map(review_cursor);
    }
    if let DesktopAgentResultPayload::DesktopView {
        page, next_after, ..
    } = result
    {
        page.validate(next_after.as_deref())?;
    }
    Ok(())
}

pub(in crate::application::desktop_agent) fn roots_discovered_result(
    runtime: &Runtime,
    choices: &[WorkspaceChoice],
    request: &DesktopAgentRootsPageRequest,
    next_cursor: Option<String>,
) -> CoreResult<DesktopAgentResultPayload> {
    let (workspace_count, candidate_count) = workspace_choice_counts(choices);
    let state = runtime.coordinator.snapshot();
    let rows = choices
        .iter()
        .flat_map(|workspace| {
            workspace
                .locations
                .iter()
                .map(|location| DesktopAgentRootRow {
                    workspace_id: workspace.id.clone(),
                    workspace_name: product_label(&workspace.name),
                    sync_root_id: location.sync_root_id.clone(),
                    remote_root_id: location.remote_root_id.clone(),
                    root_name: product_label(&location.label),
                    owner_label: product_label(&location.owner_label),
                    role: location.role,
                    selection_status: if state.pairs().any(|pair| {
                        pair.workspace_id == workspace.id
                            && pair.remote_root_id == location.remote_root_id
                    }) {
                        DesktopAgentRootSelectionStatus::Configured
                    } else {
                        DesktopAgentRootSelectionStatus::Available
                    },
                })
        })
        .collect::<Vec<_>>();
    if rows.len() > usize::from(request.limit) {
        return Err(DesktopError::InvalidState(
            "desktop-agent root page exceeds its requested limit".to_string(),
        ));
    }
    Ok(DesktopAgentResultPayload::RootsDiscovered {
        workspace_count: count_u16(workspace_count, "workspace count")?,
        candidate_count: count_u16(candidate_count, "candidate count")?,
        requires_local_selection: state.sync_root_base.is_none(),
        page: DesktopAgentRootsPage {
            after: request.after.clone(),
            limit: request.limit,
            rows,
        },
        next_after: next_cursor,
    })
}

fn pair_page(
    state: &shellx_drive_desktop_core::DesktopState,
    request: &DesktopAgentDesktopViewPageRequest,
) -> CoreResult<(DesktopAgentDesktopViewPage, Option<String>)> {
    let mut rows = Vec::new();
    if let Some(pair) = state.pair.as_ref() {
        rows.push(pair_row(
            pair,
            true,
            state.paused,
            &state.reviews,
            state.last_error.is_some(),
        )?);
    }
    for profile in &state.inactive_pairs {
        rows.push(pair_row(
            &profile.pair,
            false,
            profile.paused,
            &profile.reviews,
            profile.last_error.is_some(),
        )?);
    }
    rows.sort_by(|left, right| left.pair_id.cmp(&right.pair_id));
    let next_after = paginate(&mut rows, request.after.as_deref(), request.limit, |row| {
        row.pair_id.clone()
    });
    Ok((
        DesktopAgentDesktopViewPage::Pairs {
            after: request.after.clone(),
            limit: request.limit,
            rows,
        },
        next_after,
    ))
}

fn pair_row(
    pair: &SyncPair,
    selected: bool,
    paused: bool,
    reviews: &[ReviewItem],
    has_error: bool,
) -> CoreResult<DesktopAgentPairRow> {
    let status = if !reviews.is_empty() {
        DesktopAgentPairStatus::NeedsReview
    } else if has_error {
        DesktopAgentPairStatus::Error
    } else if paused {
        DesktopAgentPairStatus::Paused
    } else if selected {
        DesktopAgentPairStatus::Ready
    } else {
        DesktopAgentPairStatus::Managed
    };
    Ok(DesktopAgentPairRow {
        pair_id: sync_pair_id(pair),
        workspace_id: pair.workspace_id.clone(),
        workspace_name: product_label(&pair.workspace_name),
        remote_root_id: pair.remote_root_id.clone(),
        remote_root_name: pair.remote_root_name.as_deref().map(product_label),
        selected,
        status,
        pending_review_count: count_u16(reviews.len(), "pair review count")?,
    })
}

fn review_page(
    state: &shellx_drive_desktop_core::DesktopState,
    request: &DesktopAgentDesktopViewPageRequest,
) -> CoreResult<(DesktopAgentDesktopViewPage, Option<String>)> {
    let mut rows = Vec::new();
    if let Some(pair) = state.pair.as_ref() {
        rows.extend(review_rows(&sync_pair_id(pair), &state.reviews));
    }
    for profile in &state.inactive_pairs {
        rows.extend(review_rows(&sync_pair_id(&profile.pair), &profile.reviews));
    }
    rows.sort_by_key(review_cursor);
    let next_after = paginate(
        &mut rows,
        request.after.as_deref(),
        request.limit,
        review_cursor,
    );
    Ok((
        DesktopAgentDesktopViewPage::Reviews {
            after: request.after.clone(),
            limit: request.limit,
            rows,
        },
        next_after,
    ))
}

fn review_rows(pair_id: &str, reviews: &[ReviewItem]) -> Vec<DesktopAgentReviewRow> {
    reviews
        .iter()
        .map(|review| DesktopAgentReviewRow {
            review_id: review.id.clone(),
            pair_id: pair_id.to_string(),
            item_label: product_label(
                review
                    .relative_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("item"),
            ),
            reason: review.kind.clone(),
            actions: review.actions.clone(),
        })
        .collect()
}

fn paginate<T>(
    rows: &mut Vec<T>,
    after: Option<&str>,
    limit: u8,
    cursor: impl Fn(&T) -> String,
) -> Option<String> {
    if let Some(after) = after {
        rows.retain(|row| cursor(row).as_str() > after);
    }
    let has_more = rows.len() > usize::from(limit);
    rows.truncate(usize::from(limit));
    has_more.then(|| cursor(rows.last().expect("a nonempty page has a final cursor")))
}

fn count_u8(value: usize, label: &str) -> CoreResult<u8> {
    u8::try_from(value).map_err(|_| {
        DesktopError::InvalidState(format!("desktop-agent {label} exceeds its wire limit"))
    })
}

fn count_u16(value: usize, label: &str) -> CoreResult<u16> {
    u16::try_from(value).map_err(|_| {
        DesktopError::InvalidState(format!("desktop-agent {label} exceeds its wire limit"))
    })
}

fn count_u32(value: usize, label: &str) -> CoreResult<u32> {
    u32::try_from(value).map_err(|_| {
        DesktopError::InvalidState(format!("desktop-agent {label} exceeds its wire limit"))
    })
}

#[cfg(test)]
#[path = "readback/tests.rs"]
mod tests;
