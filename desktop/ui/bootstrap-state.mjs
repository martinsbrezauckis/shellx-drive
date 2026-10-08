export const DEMO_SCENARIOS = Object.freeze([
  "needs_setup",
  "needs_reconnect",
  "synced",
  "syncing",
  "offline",
  "needs_review",
  "needs_review_other_root",
  "error",
  "disconnect_cleanup_pending",
  "disconnect_remote_retirement_pending",
]);

export function frontendMode({ hasNativeInvoke, search = "" }) {
  if (hasNativeInvoke) return { kind: "native" };
  const demo = new URLSearchParams(search).get("demo");
  if (DEMO_SCENARIOS.includes(demo)) return { kind: "demo", demo };
  return { kind: "blocked" };
}

export function backendHandshakeIsValid(view) {
  return Boolean(view && typeof view.status === "string");
}

export async function routeDesktopInvoke(mode, nativeInvoke, demoInvoke, command, args = {}) {
  if (mode.kind === "native") return nativeInvoke(command, args);
  if (mode.kind === "demo") return demoInvoke(command, args);
  throw new Error("ShellX Drive native backend is unavailable. Browser preview requires an explicit ?demo= state.");
}
