// Administrator-only manual recovery-link UI. The plaintext link is rendered
// only from the immediate authenticated response and can be cleared from this
// tab after copying; Drive never lists or reconstructs it later.
(() => {
  "use strict";

  function button(label) {
    const element = document.createElement("button");
    element.type = "button";
    element.textContent = label;
    return element;
  }

  async function copyText(value, input) {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
    input.focus();
    input.select();
    return false;
  }

  function createController(options) {
    const createButton = document.getElementById("admin-auth-create-reset-link");
    const revokeButton = document.getElementById("admin-auth-revoke-reset-link");
    const output = document.getElementById("admin-auth-reset-link-output");
    const accountSelect = document.getElementById("admin-auth-update-email");
    if (!createButton || !revokeButton || !output) return Object.freeze({ clear() {} });
    let shownForEmail = "";

    function selectedEmail() {
      return String(options.getSelectedEmail() || "").trim();
    }

    function clear() {
      shownForEmail = "";
      output.replaceChildren();
    }

    function renderLink(data) {
      shownForEmail = selectedEmail();
      const expiresAt = String(data.expires_at || "");
      let resetLink = String(data.reset_link || "");
      const heading = document.createElement("strong");
      heading.textContent = "One-time recovery link";
      const details = document.createElement("small");
      details.textContent = `Expires ${expiresAt}. Copy it through a secure channel; Drive will not show it again.`;
      const input = document.createElement("input");
      input.type = "text";
      input.readOnly = true;
      input.value = resetLink;
      input.autocomplete = "off";
      input.setAttribute("aria-label", "One-time password reset link");
      const status = document.createElement("small");
      const actions = document.createElement("div");
      actions.className = "admin-form-actions";
      const copy = button("Copy link");
      const hide = button("Hide link");
      copy.addEventListener("click", async () => {
        try {
          const copied = await copyText(resetLink, input);
          if (copied) {
            input.value = "";
            input.hidden = true;
            copy.disabled = true;
            resetLink = "";
            status.textContent = "Copied. The link is now hidden in this tab.";
            options.showToast("Recovery link copied.");
          } else {
            status.textContent = "Select and copy the highlighted link, then hide it.";
          }
        } catch (error) {
          status.textContent = error.message || "Could not copy the link.";
        }
      });
      hide.addEventListener("click", () => {
        input.value = "";
        input.hidden = true;
        copy.disabled = true;
        resetLink = "";
        status.textContent = "Link hidden. Generate a replacement if you still need it.";
      });
      actions.append(copy, hide);
      output.replaceChildren(heading, details, input, actions, status);
    }

    async function create() {
      const email = selectedEmail();
      if (!email) throw new Error("Select an account first.");
      createButton.disabled = true;
      try {
        const data = await options.api(`/admin/auth/users/${encodeURIComponent(email)}/password-reset-link`, {
          method: "POST",
          body: JSON.stringify({}),
        });
        renderLink(data);
        options.showToast("One-time recovery link created.");
      } finally {
        createButton.disabled = false;
      }
    }

    async function revoke() {
      const email = selectedEmail();
      if (!email) throw new Error("Select an account first.");
      revokeButton.disabled = true;
      try {
        await options.api(`/admin/auth/users/${encodeURIComponent(email)}/password-reset-link`, {
          method: "DELETE",
        });
        clear();
        output.textContent = "Recovery link revoked.";
        options.showToast("Recovery link revoked.");
      } finally {
        revokeButton.disabled = false;
      }
    }

    createButton.addEventListener("click", () => create().catch(options.onError));
    revokeButton.addEventListener("click", () => revoke().catch(options.onError));
    accountSelect?.addEventListener("change", clear);
    return Object.freeze({ clear });
  }

  window.ShellXDriveAdminPasswordReset = Object.freeze({ createController });
})();
