// One browser-wide authentication epoch. Account separation scrubs actor-bound
// state; same-account credential rotation keeps that state while sibling tabs
// reconcile against the shared replacement cookie.
(function attachDriveAuthLifecycle(root) {
  "use strict";

  const CHANNEL_NAME = "shellx-drive-auth-lifecycle";
  const STORAGE_KEY = "shellx-drive:auth-separation";

  class StaleAuthenticationError extends Error {
    constructor() {
      super("");
      this.name = "AbortError";
      this.code = "STALE_AUTHENTICATION";
    }
  }

  function createController(options = {}) {
    const host = options.root || root;
    const source = options.source || host.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}`;
    let generation = 0;
    let epochController = new host.AbortController();
    let remoteHandler = () => {};
    const seen = new Set();
    let storage = null;
    let channel = null;

    try { storage = options.storage || host.localStorage; } catch {}
    try {
      if (host.BroadcastChannel) channel = new host.BroadcastChannel(CHANNEL_NAME);
    } catch {}

    function eventId() {
      return host.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}`;
    }

    function rotate() {
      generation += 1;
      epochController.abort();
      epochController = new host.AbortController();
    }

    function receive(message) {
      if (!["account-separation", "credential-rotation"].includes(message?.kind)
          || !message.id || message.source === source) return;
      if (seen.has(message.id)) return;
      if (seen.size > 100) seen.clear();
      seen.add(message.id);
      rotate();
      remoteHandler(message.kind);
    }

    if (channel) channel.onmessage = (event) => receive(event.data);
    const onStorage = (event) => {
      if (event.key !== STORAGE_KEY || !event.newValue) return;
      try { receive(JSON.parse(event.newValue)); } catch {}
    };
    host.addEventListener?.("storage", onStorage);

    function publish(kind) {
      const message = { kind, version: 1, id: eventId(), source };
      try { channel?.postMessage(message); } catch {}
      try {
        storage?.setItem(STORAGE_KEY, JSON.stringify(message));
        storage?.removeItem(STORAGE_KEY);
      } catch {}
    }

    function separate({ broadcast = true } = {}) {
      rotate();
      if (broadcast) publish("account-separation");
    }

    function rotateCredential({ broadcast = true } = {}) {
      rotate();
      if (broadcast) publish("credential-rotation");
    }

    function capture(callerSignal) {
      const controller = new host.AbortController();
      const abort = () => controller.abort();
      const epochSignal = epochController.signal;
      if (epochSignal.aborted || callerSignal?.aborted) abort();
      else {
        epochSignal.addEventListener("abort", abort, { once: true });
        callerSignal?.addEventListener("abort", abort, { once: true });
      }
      return {
        generation,
        signal: controller.signal,
        cleanup() {
          epochSignal.removeEventListener("abort", abort);
          callerSignal?.removeEventListener("abort", abort);
        },
      };
    }

    function isCurrent(lease) {
      return lease.generation === generation;
    }

    async function run(task, callerSignal) {
      const lease = capture(callerSignal);
      try {
        const value = await task(lease.signal);
        if (!isCurrent(lease)) throw new StaleAuthenticationError();
        return value;
      } catch (error) {
        if (!isCurrent(lease)) throw new StaleAuthenticationError();
        throw error;
      } finally {
        lease.cleanup();
      }
    }

    return Object.freeze({
      capture,
      destroy() {
        channel?.close();
        host.removeEventListener?.("storage", onStorage);
      },
      isCurrent,
      run,
      rotateCredential,
      separate,
      setRemoteHandler(handler) { remoteHandler = typeof handler === "function" ? handler : () => {}; },
    });
  }

  async function recoverHydrationFailure({ logout, scrub, onLogoutFailure }) {
    try {
      await logout();
    } catch (error) {
      onLogoutFailure?.(error);
      return false;
    }
    scrub();
    return true;
  }

  const controller = createController();
  root.ShellXDriveAuthLifecycle = Object.freeze({
    controller,
    createController,
    isAuthenticationRejection: (error) => Number(error?.status) === 401,
    isStale: (error) => error?.code === "STALE_AUTHENTICATION",
    recoverHydrationFailure,
  });
})(window);
