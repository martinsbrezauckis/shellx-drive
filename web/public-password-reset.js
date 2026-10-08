// The reset token is read only from a fragment. Fragments never reach Drive,
// proxies, static assets, or Referer headers, and the value is never persisted.
(() => {
  const form = document.getElementById("password-reset-form");
  const next = document.getElementById("password-reset-new");
  const confirm = document.getElementById("password-reset-confirm");
  const submit = document.getElementById("password-reset-submit");
  const status = document.getElementById("password-reset-status");
  const guidance = document.getElementById("password-reset-guidance");
  const signIn = document.getElementById("password-reset-sign-in");
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const token = fragment.get("token") || "";
  const validToken = /^[a-f0-9]{64}$/i.test(token);

  if (window.location.hash) {
    window.history.replaceState(null, document.title, window.location.pathname);
  }

  function unavailable() {
    status.textContent = "Reset link unavailable";
    guidance.textContent = "This reset link is unavailable.";
    form.hidden = true;
    signIn.hidden = false;
  }

  if (!validToken) {
    unavailable();
    return;
  }

  status.textContent = "Choose a new password";
  guidance.textContent = "This will sign out existing Drive sessions for this account.";
  form.hidden = false;
  next.focus();

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (next.value !== confirm.value) {
      status.textContent = "Passwords do not match";
      confirm.focus();
      return;
    }
    submit.disabled = true;
    status.textContent = "Resetting password…";
    try {
      const response = await fetch("/auth/password/reset/consume", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ token, new_password: next.value }),
      });
      next.value = "";
      confirm.value = "";
      if (!response.ok) {
        unavailable();
        return;
      }
      status.textContent = "Password reset complete";
      guidance.textContent = "Your password was changed. Sign in to Drive with the new password.";
      form.hidden = true;
      signIn.hidden = false;
    } catch {
      status.textContent = "Could not reset password";
      guidance.textContent = "Check your connection, then try again.";
    } finally {
      submit.disabled = false;
    }
  });
})();
