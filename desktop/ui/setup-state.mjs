export function emptySetupState() {
  return {
    serverUrl: "",
    serverValidated: false,
    signedIn: false,
    accountEmail: "",
    workspaces: [],
    workspacesLoaded: false,
    nextRootCursor: null,
    rootPageIndex: 0,
    workspaceDiscoveryError: null,
    authNeeds2fa: false,
    selectedWorkspaceId: "",
    selectedRemoteRootId: null,
    selectedSyncRootId: "",
    selectedLocalRoot: "",
  };
}

export function applyLoginReply(setup, reply, submittedEmail) {
  const signedIn = reply.kind === "authenticated";
  return {
    ...setup,
    authNeeds2fa: reply.kind === "requires_second_factor",
    signedIn,
    accountEmail: signedIn
      ? (reply.accountEmail ?? reply.account_email ?? submittedEmail)
      : setup.accountEmail,
    workspaces: signedIn ? [] : setup.workspaces,
    workspacesLoaded: false,
    nextRootCursor: null,
    rootPageIndex: 0,
    workspaceDiscoveryError: null,
    selectedWorkspaceId: signedIn ? "" : setup.selectedWorkspaceId,
    selectedRemoteRootId: signedIn ? null : setup.selectedRemoteRootId,
    selectedSyncRootId: signedIn ? "" : setup.selectedSyncRootId,
    selectedLocalRoot: signedIn ? "" : setup.selectedLocalRoot,
  };
}

export function beginWorkspaceDiscovery(setup) {
  return {
    ...setup,
    workspacesLoaded: false,
    workspaceDiscoveryError: null,
  };
}

export function failWorkspaceDiscovery(setup, error) {
  return {
    ...setup,
    workspaces: [],
    workspacesLoaded: false,
    nextRootCursor: null,
    workspaceDiscoveryError: error?.message ?? String(error),
  };
}

export function resetExpiredSetupSession(setup) {
  return { ...emptySetupState(), serverUrl: setup.serverUrl,
    serverValidated: Boolean(setup.serverValidated || setup.serverUrl), accountEmail: setup.accountEmail };
}

export function hasRetiredSetupSession(setup, view) {
  return Boolean(
    setup.signedIn
    && view.status === "needs_setup"
    && !view.activePairId
    && !view.disconnectCleanupPending
    && !view.account
    && !view.serverUrl,
  );
}

export function selectLocalRoot(setup, path) {
  return { ...setup, selectedLocalRoot: String(path ?? "").trim() };
}

export function pairSelectionReady(setup) {
  return Boolean(setup.selectedWorkspaceId && setup.selectedSyncRootId && setup.selectedLocalRoot);
}
import { driveLocationChoices, rootLocationLabel } from "./sync-root-choices.mjs";

export { driveLocationChoices, rootLocationLabel };
