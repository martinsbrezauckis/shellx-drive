import { driveLocationChoices } from "./sync-root-choices.mjs";

export function completeWorkspacePage(setup, page, requestedCursor = null) {
  const workspaces = Array.isArray(page?.workspaces) ? page.workspaces : [];
  const nextRootCursor = page?.nextCursor ?? page?.next_cursor ?? null;
  if (nextRootCursor !== null && (typeof nextRootCursor !== "string" || !nextRootCursor || nextRootCursor.length > 2048)) {
    throw new Error("Drive returned an invalid root page cursor");
  }
  return {
    ...setup,
    workspaces,
    nextRootCursor,
    rootPageIndex: requestedCursor ? setup.rootPageIndex + 1 : 0,
    workspacesLoaded: true,
    workspaceDiscoveryError: null,
    selectedWorkspaceId: "",
    selectedRemoteRootId: null,
    selectedSyncRootId: "",
  };
}

export function selectDiscoveredRoot(setup, syncRootId) {
  const selected = driveLocationChoices(setup.workspaces).find((location) => location.syncRootId === syncRootId);
  if (!selected) return setup;
  return {
    ...setup,
    selectedWorkspaceId: selected.workspaceId,
    selectedRemoteRootId: selected.remoteRootId,
    selectedSyncRootId: selected.syncRootId,
  };
}
