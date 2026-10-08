export function shouldRefreshDesktopView({
  browserPreview,
  documentHidden,
  foregroundActionInFlight,
  backgroundRefreshInFlight,
  confirmationOpen,
  status,
}) {
  return !browserPreview
    && !documentHidden
    && !foregroundActionInFlight
    && !backgroundRefreshInFlight
    && !confirmationOpen
    && status !== "needs_setup";
}

export function shouldDeferReconnectRender(current, next) {
  return current?.status === "needs_reconnect"
    && next?.status === "needs_reconnect"
    && !next.disconnectCleanupPending
    && Boolean(current.activePairId)
    && current.activePairId === next.activePairId
    && current.account === next.account
    && current.serverHost === next.serverHost
    && current.serverUrl === next.serverUrl;
}

export function shouldDeferCredentialRecoveryRender(current, next) {
  return Boolean(current?.credentialRecoveryPending && next?.credentialRecoveryPending)
    && !next.disconnectCleanupPending
    && Boolean(current.account && current.serverUrl)
    && current.activePairId === next.activePairId
    && current.account === next.account
    && current.serverUrl === next.serverUrl;
}

export function desktopViewChanged(current, next) {
  return JSON.stringify(current) !== JSON.stringify(next);
}

export function shouldPreserveBackgroundViewport(current, next) {
  return Boolean(current?.activePairId)
    && current.activePairId === next?.activePairId
    && current.account === next.account
    && current.serverUrl === next.serverUrl
    && current.serverHost === next.serverHost
    && ![current, next].some((view) => view.disconnectCleanupPending || view.disconnectRequested
      || ["needs_setup", "needs_reconnect"].includes(view.status));
}
