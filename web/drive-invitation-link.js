// Ephemeral workspace-invitation link presentation.
//
// Invitation capabilities stay only in the read-only input while this surface
// is visible. They are deliberately not retained in application state, storage,
// diagnostics, or DOM attributes.
(() => {
  function createController({
    root,
    getClipboard = () => globalThis.navigator?.clipboard,
    onCopied = () => {},
  }) {
    const linkInput = root.querySelector("#workspace-invitation-link-input");
    const status = root.querySelector("#workspace-invitation-link-status");
    const copyButton = root.querySelector("#workspace-invitation-copy-link-button");
    const hideButton = root.querySelector("#workspace-invitation-hide-link-button");

    function clear() {
      linkInput.value = "";
      status.textContent = "";
      root.hidden = true;
    }

    function show(link) {
      clear();
      if (!link) return false;
      linkInput.value = String(link);
      root.hidden = false;
      status.textContent = "Copy this one-time invitation link now. It is hidden after copying or when you choose Hide link.";
      return true;
    }

    async function copy() {
      const link = linkInput.value;
      if (!link) return false;
      try {
        const clipboard = getClipboard();
        if (typeof clipboard?.writeText !== "function") throw new Error("Clipboard access is unavailable.");
        await clipboard.writeText(link);
      } catch {
        linkInput.focus?.();
        linkInput.select?.();
        status.textContent = "Clipboard permission is unavailable. The invitation link is selected; copy it with your browser.";
        return false;
      }
      clear();
      onCopied();
      return true;
    }

    function bind() {
      copyButton.addEventListener("click", () => { copy(); });
      hideButton.addEventListener("click", clear);
    }

    return { bind, clear, copy, show };
  }

  window.ShellXDriveInvitationLink = { createController };
})();
