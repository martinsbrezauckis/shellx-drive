// Workspace invitation acceptance deliberately reads the capability only from
// the URL fragment. Fragments never reach Drive, proxies, asset requests, or
// the Referer header. The value remains only in this page's JavaScript memory.
(() => {
  const status = document.getElementById("invitation-status");
  const guidance = document.getElementById("invitation-guidance");
  const accept = document.getElementById("invitation-accept");
  const refresh = document.getElementById("invitation-refresh");
  const signIn = document.getElementById("invitation-sign-in");
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const token = fragment.get("token") || "";
  const validToken = /^[a-f0-9]{64}$/i.test(token);

  // Remove the capability from browser history as soon as this script runs.
  if (window.location.hash) {
    window.history.replaceState(null, document.title, window.location.pathname);
  }

  function unavailable() {
    status.textContent = "Invitation unavailable";
    guidance.textContent = "This invitation is unavailable.";
    accept.disabled = true;
    accept.hidden = true;
    refresh.hidden = true;
    signIn.hidden = true;
  }

  async function checkSignIn() {
    if (!validToken) {
      unavailable();
      return;
    }
    accept.hidden = false;
    accept.disabled = true;
    status.textContent = "Checking your sign-in…";
    try {
      const response = await fetch("/auth/me", {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        status.textContent = "Sign in required";
        guidance.textContent = "Sign in to the Drive account that received this invitation in another tab, then return here and choose Check sign-in.";
        signIn.hidden = false;
        refresh.hidden = false;
        return;
      }
      const account = await response.json();
      status.textContent = `Signed in as ${account.actor}.`;
      guidance.textContent = "Accepting adds this signed-in account to the workspace. If this is not the invited account, the invitation will not be accepted.";
      accept.disabled = false;
      signIn.hidden = true;
      refresh.hidden = false;
    } catch {
      status.textContent = "Could not check sign-in";
      guidance.textContent = "Check your connection, then try again.";
      refresh.hidden = false;
    }
  }

  async function acceptInvitation() {
    if (!validToken) return unavailable();
    accept.disabled = true;
    status.textContent = "Accepting invitation…";
    try {
      const response = await fetch("/pub/invitations/accept", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ token }),
      });
      if (response.ok) {
        status.textContent = "Invitation accepted";
        guidance.textContent = "You now have access to the workspace. Return to Drive to open it.";
        refresh.hidden = true;
        signIn.hidden = false;
        signIn.textContent = "Open Drive";
        return;
      }
      if (response.status === 401) {
        status.textContent = "Sign in required";
        guidance.textContent = "Sign in to the Drive account that received this invitation, then check your sign-in again.";
        signIn.hidden = false;
        refresh.hidden = false;
        return;
      }
      unavailable();
    } catch {
      status.textContent = "Could not accept invitation";
      guidance.textContent = "Check your connection, then try again.";
      refresh.hidden = false;
    }
  }

  refresh.addEventListener("click", () => checkSignIn());
  accept.addEventListener("click", () => acceptInvitation());
  checkSignIn();
})();
