// Account-security interactions. Password values stay in form controls and are
// never copied into shared application state.
(function attachDriveAccount(root) {
  "use strict";

  function passwordChangeValidation(newPassword, confirmation) {
    if (newPassword !== confirmation) return "New passwords do not match.";
    return "";
  }

  function secondFactorPayload(value) {
    const code = value.trim();
    if (!code) return {};
    return /^\d{6}$/.test(code) ? { totp_code: code } : { recovery_code: code };
  }

  function clearLocalStoragePrefix(prefix) {
    try {
      for (let index = localStorage.length - 1; index >= 0; index -= 1) {
        const key = localStorage.key(index);
        if (key?.startsWith(prefix)) localStorage.removeItem(key);
      }
    } catch {
      // Blocked browser storage must not stop server-side sign-out.
    }
  }

  function createPasswordChangeController(options) {
    const form = document.getElementById("change-password-form");
    const current = document.getElementById("change-password-current");
    const next = document.getElementById("change-password-new");
    const confirmation = document.getElementById("change-password-confirm");
    const secondFactorStep = document.getElementById("change-password-second-factor-step");
    const secondFactor = document.getElementById("change-password-second-factor");
    const status = document.getElementById("change-password-status");
    const button = document.getElementById("change-password-button");

    function setStatus(message, state = "") {
      status.textContent = message;
      status.hidden = !message;
      if (state) status.dataset.state = state;
      else status.removeAttribute("data-state");
    }

    function showSecondFactor(show) {
      secondFactorStep.hidden = !show;
      secondFactor.required = show;
      button.textContent = show ? "Confirm password change" : "Change password";
      if (show) secondFactor.focus();
      else secondFactor.value = "";
    }

    function reset(clearPasswords = false) {
      if (clearPasswords) {
        current.value = "";
        next.value = "";
        confirmation.value = "";
      }
      showSecondFactor(false);
      setStatus("");
    }

    async function changePassword(event) {
      event.preventDefault();
      const validation = passwordChangeValidation(next.value, confirmation.value);
      if (validation) {
        setStatus(validation, "error");
        confirmation.focus();
        return;
      }
      const waitingForSecondFactor = !secondFactorStep.hidden;
      button.disabled = true;
      setStatus(waitingForSecondFactor ? "Confirming 2FA…" : "Checking password…", "working");
      try {
        const data = await options.api("/auth/password/change", {
          method: "POST",
          body: JSON.stringify({
            current_password: current.value,
            new_password: next.value,
            ...secondFactorPayload(secondFactor.value),
          }),
        });
        if (data.requires_2fa) {
          showSecondFactor(true);
          setStatus("2FA is required to finish this change.");
          return;
        }
        const email = options.getAccountEmail();
        reset(true);
        options.onPasswordChanged(email);
      } catch (error) {
        const message = error.status === 401
          ? waitingForSecondFactor
            ? "That authenticator or recovery code was not accepted."
            : "The current password was not accepted."
          : error.message;
        setStatus(message, "error");
        if (waitingForSecondFactor) secondFactor.focus();
      } finally {
        button.disabled = false;
      }
    }

    form.addEventListener("submit", (event) => void changePassword(event));
    for (const input of [current, next, confirmation]) {
      input.addEventListener("input", () => reset());
    }

    return Object.freeze({ changePassword, reset });
  }

  root.ShellXDriveAccount = Object.freeze({
    createPasswordChangeController,
    clearLocalStoragePrefix,
    passwordChangeValidation,
    secondFactorPayload,
  });
})(window);
