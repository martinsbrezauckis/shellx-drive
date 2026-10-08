// Truthful login/bootstrap hydration and cross-tab session reconciliation.
(function attachDriveAuthHydration(root) {
  "use strict";

  function createController(options) {
    const {
      state, els, api, publicApi, authLifecycle, applyUiState,
      clearSensitiveAccountState, currentAccountEmail, hasAuthenticatedSession,
      loadCurrentAccount, loadNotifications, loadSelfSessions, loadWorkspaces, persistSession,
      setPasswordResetStatus, setStatus, setAuthStatus, showSecondFactorChallenge,
      showToast, togglePasswordReset,
    } = options;

    function setAuthenticationUncertain(message) {
      state.authUncertain = true;
      state.offlineShell = Boolean(root.navigator?.onLine === false);
      if (els.authCardTitle) els.authCardTitle.textContent = "Session status unavailable";
      setStatus(state.offlineShell ? "Offline" : "Connection unavailable");
      setAuthStatus(state.offlineShell
        ? "Drive is offline. Reconnect to confirm this browser session."
        : message);
      applyUiState();
    }

    async function loadBootstrapStatus() {
      const data = await publicApi("/auth/bootstrap/status");
      state.authBootstrapRequired = Boolean(data.required);
      if (els.bootstrapForm) els.bootstrapForm.hidden = !state.authBootstrapRequired;
      if (els.loginForm) els.loginForm.hidden = state.authBootstrapRequired;
      if (els.forgotPasswordButton) {
        els.forgotPasswordButton.hidden = state.authBootstrapRequired;
        if (state.authBootstrapRequired) {
          els.forgotPasswordButton.setAttribute("aria-expanded", "false");
          if (els.passwordResetRequestForm) els.passwordResetRequestForm.hidden = true;
          setPasswordResetStatus("");
        }
      }
      if (els.authCardTitle) {
        els.authCardTitle.textContent = state.authBootstrapRequired ? "Secure server setup" : "Sign in";
      }
      setAuthStatus(state.authBootstrapRequired
        ? "A server-generated setup token is required."
        : "Password login ready");
      applyUiState();
      return data;
    }

    async function applyLoginResponse(data, label = "Sign-in") {
      const departingActor = currentAccountEmail();
      if (hasAuthenticatedSession() || departingActor) clearSensitiveAccountState(departingActor);
      else authLifecycle.separate();
      persistSession(data.token, data.actor, data.session_id || "");
      state.authUncertain = false;
      state.offlineShell = false;
      state.currentAccount = {
        actor: data.actor, is_admin: Boolean(data.is_admin), auth_mode: "local_account",
        account_security_available: true, session_management_available: true,
        notifications_available: true, admin_tools_available: Boolean(data.is_admin),
      };
      setStatus("Connecting");
      setAuthStatus(data.is_admin ? "Admin session" : "Signed in");
      try {
        await loadCurrentAccount();
        await loadWorkspaces();
        await loadNotifications(false).catch(() => {});
        return true;
      } catch (hydrationError) {
        if (root.ShellXDriveAuthLifecycle.isStale(hydrationError)) return false;
        const signedOut = await root.ShellXDriveAuthLifecycle.recoverHydrationFailure({
          logout: () => api("/auth/logout", { method: "POST" }),
          scrub: () => clearSensitiveAccountState(data.actor),
          onLogoutFailure: () => setAuthenticationUncertain(
            `${label} succeeded, but Drive could not load and automatic sign-out could not be confirmed. Reload to retry.`,
          ),
        });
        if (signedOut) {
          setAuthStatus(`${label} succeeded, but Drive could not load. The new session was signed out; try again.`);
          showToast("Drive could not finish loading. Please sign in again.");
        }
        els.debugOutput.textContent = hydrationError.message;
        return signedOut ? "signed_out" : false;
      }
    }

    async function bootstrapFirstAdmin(event) {
      event.preventDefault();
      const operatorToken = els.bootstrapOperatorToken.value.trim();
      if (!operatorToken) throw new Error("Enter the server setup token configured by the operator.");
      const password = els.bootstrapPassword.value;
      if (password !== els.bootstrapPasswordConfirm.value) {
        throw new Error("Administrator passwords do not match.");
      }
      const data = await publicApi("/auth/bootstrap/wizard", {
        method: "POST",
        headers: { authorization: `Bearer ${operatorToken}` },
        body: JSON.stringify({
          email: els.bootstrapEmail.value,
          password,
          workspace_name: els.bootstrapWorkspaceName.value.trim() || "Personal Drive",
          cookie_only: true,
        }),
      });
      els.bootstrapOperatorToken.value = "";
      els.bootstrapPassword.value = "";
      els.bootstrapPasswordConfirm.value = "";
      const hydrated = await applyLoginResponse(data.login, "Setup");
      if (hydrated !== false) await loadBootstrapStatus();
      if (hydrated === true) showToast("First admin and workspace created.");
    }

    async function loginWithPassword(event) {
      event.preventDefault();
      const secondFactor = els.loginSecondFactor.value.trim();
      const payload = { email: els.loginEmail.value, password: els.loginPassword.value, cookie_only: true };
      if (secondFactor) {
        if (/^\d{6}$/.test(secondFactor)) payload.totp_code = secondFactor;
        else payload.recovery_code = secondFactor;
      }
      const data = await publicApi("/auth/login", { method: "POST", body: JSON.stringify(payload) });
      if (data.requires_2fa && !data.token) {
        setAuthStatus("2FA required");
        showSecondFactorChallenge(true);
        showToast("Enter authenticator or recovery code.");
        return;
      }
      els.loginPassword.value = "";
      showSecondFactorChallenge(false);
      togglePasswordReset(false);
      if (await applyLoginResponse(data, "Sign-in") === true) showToast("Signed in.");
    }

    async function reconcileRemoteAuthentication() {
      clearSensitiveAccountState(currentAccountEmail(), { advance: false, broadcast: false });
      setAuthenticationUncertain("Account changed in another tab. Checking the current session…");
      try {
        await loadCurrentAccount();
        state.authUncertain = false;
        state.offlineShell = false;
        await loadWorkspaces();
        await loadNotifications(false).catch(() => {});
        setAuthStatus("Session refreshed after an account change in another tab.");
      } catch (error) {
        if (root.ShellXDriveAuthLifecycle.isStale(error)) return;
        if (root.ShellXDriveAuthLifecycle.isAuthenticationRejection(error)) {
          state.authUncertain = false;
          await loadBootstrapStatus().catch(() => {});
          setAuthStatus("Signed out in another tab. Sign in again.");
          applyUiState();
        } else {
          setAuthenticationUncertain("Account changed in another tab, but Drive could not confirm the current session. Reload to retry.");
        }
      }
    }

    async function reconcileRemoteCredentialRotation() {
      const actor = currentAccountEmail() || state.actor;
      persistSession("", actor, "");
      setAuthenticationUncertain("Security settings changed in another tab. Checking the replacement session…");
      try {
        const confirmed = await api("/auth/me");
        const actorChanged = actor.trim().toLowerCase()
          !== String(confirmed.actor || "").trim().toLowerCase();
        if (actorChanged) {
          clearSensitiveAccountState(actor, { advance: false, broadcast: false });
        }
        await loadCurrentAccount();
        await loadSelfSessions();
        if (actorChanged) {
          await loadWorkspaces();
          await loadNotifications(false).catch(() => {});
        }
        state.authUncertain = false;
        setAuthStatus("Session refreshed after a security change in another tab.");
        applyUiState();
      } catch (error) {
        if (root.ShellXDriveAuthLifecycle.isStale(error)) return;
        if (root.ShellXDriveAuthLifecycle.isAuthenticationRejection(error)) {
          state.authUncertain = false;
          clearSensitiveAccountState(actor, { advance: false, broadcast: false });
          setAuthStatus("The replacement session is unavailable. Sign in again.");
        } else {
          setAuthenticationUncertain("Security settings changed in another tab, but Drive could not confirm the replacement session. Reload to retry.");
        }
        applyUiState();
      }
    }

    async function initializeAuthentication() {
      await loadBootstrapStatus().catch(() => setAuthStatus("Auth status unavailable"));
      if (state.authBootstrapRequired) return;
      try {
        await loadCurrentAccount();
        state.authUncertain = false;
      } catch (error) {
        if (root.ShellXDriveAuthLifecycle.isStale(error)) return;
        if (root.ShellXDriveAuthLifecycle.isAuthenticationRejection(error)) clearSensitiveAccountState();
        else setAuthenticationUncertain("Drive could not confirm whether this browser is signed in. Reload to retry.");
        return;
      }
      try {
        await loadWorkspaces();
        await loadNotifications(false).catch(() => {});
      } catch (error) {
        setStatus("Disconnected");
        setAuthStatus("Signed in, but Drive data could not load. Reload to retry.");
        els.debugOutput.textContent = error.message;
        applyUiState();
      }
    }

    function localLoginFailureCopy(error) {
      return Number(error?.status) === 423 || Number(error?.status) === 429
        ? "Too many sign-in attempts. Wait a few minutes and try again."
        : "We could not sign you in. Check your email, password, and verification code.";
    }

    return Object.freeze({
      bootstrapFirstAdmin, initializeAuthentication, loadBootstrapStatus,
      localLoginFailureCopy, loginWithPassword, reconcileRemoteAuthentication,
      reconcileRemoteCredentialRotation,
    });
  }

  root.ShellXDriveAuthHydration = Object.freeze({ createController });
})(window);
