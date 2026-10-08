export const STATUS = Object.freeze([
  "needs_setup",
  "needs_reconnect",
  "synced",
  "syncing",
  "paused",
  "offline",
  "needs_review",
  "error",
]);

const STATUS_COPY = Object.freeze({
  needs_setup: { label: "Needs setup", action: "Set up Drive", detail: "Connect one Drive account to one local Drive folder." },
  needs_reconnect: { label: "Needs reconnect", action: "Sign in again", detail: "Your pair and local files are retained. Sign in to resume it without choosing folders again." },
  synced: { label: "Synced", action: "Open folder", detail: "Last sync completed successfully." },
  syncing: { label: "Syncing", action: "Show activity", detail: "A serialized pass is reconciling configured Drive locations. Exact file progress is not estimated." },
  paused: { label: "Paused", action: "Resume", detail: "Changes are retained until you resume." },
  offline: { label: "Offline", action: "Retry now", detail: "Local changes are safe and will be retried." },
  needs_review: { label: "Needs review", action: "Review", detail: "Drive needs your decision before any deletion, overwrite, or incompatible path." },
  error: { label: "Error", action: "View error", detail: "The next safe step is shown below." },
});

export function statusCopy(status) {
  return STATUS_COPY[status] ?? STATUS_COPY.error;
}

export function trayTooltip(view) {
  const copy = statusCopy(view.status);
  if (view.status === "syncing") return "ShellX Drive — Syncing configured locations";
  if (view.status === "needs_review") return `ShellX Drive — Needs review (${view.reviewCount})`;
  return `ShellX Drive — ${copy.label}`;
}

export function mayRunSync(status) {
  return status !== "needs_setup" && status !== "needs_reconnect" && status !== "syncing" && status !== "paused" && status !== "needs_review";
}

// A pending deletion review may be safely replanned after reconnecting, but
// ordinary Sync now stays blocked until that review has converged.
export function mayRecheckReviews(view) {
  const count = Number(view?.reviewCount ?? view?.review_count ?? 0);
  return count > 0 && !["needs_setup", "needs_reconnect", "syncing", "paused"].includes(view?.status);
}

const DELETION_ACTIONS = Object.freeze({
  delete_from_drive: "Move to Drive trash",
  restore_local_copy: "Restore local copy",
  remove_local_copy: "Move local copy to recovery",
  restore_to_drive: "Restore to Drive",
});

export function normalizedReviewAction(action) {
  return String(action ?? "")
    .replace(/([a-z])([A-Z])/g, "$1_$2")
    .replaceAll("-", "_")
    .toLowerCase();
}

export function deletionReviewChoices(item) {
  const kind = String(item.kind ?? item.review_kind ?? "").toLowerCase();
  if (kind !== "local_deletion" && kind !== "remote_deletion" && kind !== "access_removed") return [];
  const choices = (item.actions ?? [])
    .map(normalizedReviewAction)
    .filter((action) => !(Boolean(item.isDirectory ?? item.is_directory) && action === "delete_from_drive"))
    .filter((action) => Object.hasOwn(DELETION_ACTIONS, action));
  return kind === "access_removed"
    ? choices.filter((action) => action === "remove_local_copy")
    : choices;
}

export function reviewActionLabel(action) {
  return DELETION_ACTIONS[normalizedReviewAction(action)] ?? "Unavailable action";
}

export function reviewConfirmationCopy(item, action) {
  const path = item.relativePath ?? item.relative_path ?? "this item";
  const descendants = Number(item.descendantCount ?? item.descendant_count ?? 0);
  const impact = descendants === 0 ? "This affects one item." : `This affects this folder and ${descendants} descendant${descendants === 1 ? "" : "s"}.`;
  return `Confirm ${reviewActionLabel(action)} for ${path}. ${impact}`;
}
