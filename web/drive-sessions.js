// Session-management UI stays separate from the Drive composition file. It
// owns the self-service revoke-others action and the complete, cursor-based
// server-admin session listing.
(function attachDriveSessions(root) {
  "use strict";

  const ADMIN_PAGE_SIZE = 100;

  function createController(options) {
    const revokeOthersButton = document.querySelector("[data-revoke-other-self-sessions]");
    const adminPreviousButton = document.querySelector("[data-admin-sessions-previous]");
    const adminNextButton = document.querySelector("[data-admin-sessions-next]");
    const adminPageStatus = document.getElementById("admin-sessions-page-status");
    let adminPageCursors = [null];
    let adminPageIndex = 0;
    let adminNextCursor = null;
    let adminTotal = 0;

    function updateCurrentSession(data) {
      if (!data?.current_session_id) return;
      options.state.currentSessionId = data.current_session_id;
      sessionStorage.setItem("shellx-drive-session-id", data.current_session_id);
    }

    function renderSelfSessions() {
      const element = options.els.selfSessionsList;
      if (!element) return;
      if (!options.hasAuthenticatedSession()) {
        options.renderLiveList(element, [["Sessions", "Sign in with email and password"]]);
        if (revokeOthersButton) revokeOthersButton.disabled = true;
        return;
      }
      if (!options.hasSessionManagement()) {
        options.renderLiveList(element, [["Sessions", "Not available for this credential"]]);
        if (revokeOthersButton) revokeOthersButton.disabled = true;
        return;
      }
      if (!options.state.selfSessions) {
        options.renderLiveList(element, [["Sessions", "Not checked"]]);
        if (revokeOthersButton) revokeOthersButton.disabled = true;
        return;
      }
      const sessions = options.settings.orderedSelfSessions(
        options.state.selfSessions,
        options.state.currentSessionId,
      );
      options.adminClarity.renderSessions({
        element,
        sessions,
        currentSessionId: options.state.currentSessionId,
        admin: false,
        escapeHtml: options.escapeHtml,
        formatDate: options.formatDate,
        relativeTime: options.relativeTime,
        renderEmpty: options.renderEmpty,
      });
      if (revokeOthersButton) revokeOthersButton.disabled = sessions.length < 2;
    }

    async function loadSelfSessions() {
      const data = await options.api("/auth/sessions");
      updateCurrentSession(data);
      options.state.selfSessions = data.sessions || [];
      renderSelfSessions();
      return options.state.selfSessions;
    }

    async function revokeSelfSession(sessionId) {
      const data = await options.api(`/auth/sessions/${encodeURIComponent(sessionId)}/revoke`, {
        method: "POST",
      });
      options.state.selfSessions = (options.state.selfSessions || []).filter(
        (session) => session.id !== data.session.id,
      );
      renderSelfSessions();
      if (sessionId === options.state.currentSessionId) {
        options.clearSensitiveAccountState();
      }
      options.showToast("Session revoked.");
    }

    async function revokeOtherSelfSessions() {
      if (!window.confirm("Sign out every other browser session?")) return;
      const data = await options.api("/auth/sessions/revoke-others", { method: "POST" });
      await loadSelfSessions();
      options.showToast(
        data.revoked_sessions ? "Other browser sessions were signed out." : "No other browser sessions.",
      );
    }

    function renderAdminPagination() {
      if (!adminPageStatus) return;
      if (!options.state.adminSessions) {
        adminPageStatus.textContent = "";
      } else if (!adminTotal) {
        adminPageStatus.textContent = "No active sessions.";
      } else {
        const first = adminPageIndex * ADMIN_PAGE_SIZE + 1;
        const last = first + options.state.adminSessions.length - 1;
        adminPageStatus.textContent = `Showing ${first}\u2013${last} of ${adminTotal} active sessions.`;
      }
      if (adminPreviousButton) adminPreviousButton.disabled = adminPageIndex === 0;
      if (adminNextButton) adminNextButton.disabled = !adminNextCursor;
    }

    function renderAdminSessions() {
      if (!options.els.adminSessionsSummary) return;
      if (!options.state.adminSessions) {
        options.renderSkeleton(options.els.adminSessionsSummary, "rows", 3);
        renderAdminPagination();
        return;
      }
      const sessions = options.settings.activeAuthSessions(options.state.adminSessions);
      options.adminClarity.renderSessions({
        element: options.els.adminSessionsSummary,
        sessions,
        currentSessionId: options.state.currentSessionId,
        query: options.els.adminSessionsSearch?.value,
        admin: true,
        escapeHtml: options.escapeHtml,
        formatDate: options.formatDate,
        relativeTime: options.relativeTime,
        renderEmpty: options.renderEmpty,
      });
      renderAdminPagination();
    }

    async function loadAdminPage(index) {
      const cursor = adminPageCursors[index];
      const query = new URLSearchParams({ limit: String(ADMIN_PAGE_SIZE) });
      if (cursor) query.set("cursor", cursor);
      const data = await options.api(`/admin/sessions?${query.toString()}`);
      updateCurrentSession(data);
      adminPageIndex = index;
      adminNextCursor = data.next_cursor || null;
      adminTotal = Number(data.total || 0);
      options.state.adminSessions = data.sessions || [];
      renderAdminSessions();
      return data;
    }

    async function loadAdminSessions() {
      adminPageCursors = [null];
      adminPageIndex = 0;
      adminNextCursor = null;
      adminTotal = 0;
      return loadAdminPage(0);
    }

    async function loadAllAdminSessions() {
      const sessions = [];
      let cursor = null;
      do {
        const query = new URLSearchParams({ limit: String(ADMIN_PAGE_SIZE) });
        if (cursor) query.set("cursor", cursor);
        const data = await options.api(`/admin/sessions?${query.toString()}`);
        updateCurrentSession(data);
        sessions.push(...(data.sessions || []));
        cursor = data.next_cursor || null;
      } while (cursor);
      return sessions;
    }

    async function revokeAdminSession(sessionId) {
      const data = await options.api(`/admin/sessions/${encodeURIComponent(sessionId)}/revoke`, {
        method: "POST",
      });
      if (data.session.id === options.state.currentSessionId) {
        options.clearSensitiveAccountState();
        options.showToast("Session revoked. This browser was signed out.");
        return;
      }
      options.state.adminSessions = (options.state.adminSessions || []).filter(
        (session) => session.id !== data.session.id,
      );
      adminTotal = Math.max(0, adminTotal - 1);
      renderAdminSessions();
      await options.loadAdminSummary().catch((error) => {
        options.els.adminOutput.textContent = error.message;
      });
      options.showToast("Session revoked.");
    }

    function bind() {
      options.els.refreshSelfSessionsButton?.addEventListener("click", () =>
        loadSelfSessions().catch((error) => {
          options.renderLiveList(options.els.selfSessionsList, [["Sessions", error.message]]);
        }),
      );
      options.els.selfSessionsList?.addEventListener("click", (event) => {
        const button = event.target.closest("[data-revoke-self-session]");
        if (!button) return;
        revokeSelfSession(button.dataset.revokeSelfSession).catch((error) => {
          options.showToast(error.message);
        });
      });
      revokeOthersButton?.addEventListener("click", () =>
        revokeOtherSelfSessions().catch((error) => options.showToast(error.message)),
      );
      options.els.adminSessionsSearch?.addEventListener("input", renderAdminSessions);
      options.els.adminSessionsSummary?.addEventListener("click", (event) => {
        const button = event.target.closest("[data-revoke-session]");
        if (!button) return;
        revokeAdminSession(button.dataset.revokeSession).catch((error) => {
          options.els.adminSessionsSummary.textContent = error.message;
          options.showToast(error.message);
        });
      });
      adminPreviousButton?.addEventListener("click", () => {
        if (adminPageIndex > 0) {
          loadAdminPage(adminPageIndex - 1).catch((error) => options.showToast(error.message));
        }
      });
      adminNextButton?.addEventListener("click", () => {
        if (!adminNextCursor) return;
        adminPageCursors[adminPageIndex + 1] = adminNextCursor;
        loadAdminPage(adminPageIndex + 1).catch((error) => options.showToast(error.message));
      });
    }

    return Object.freeze({
      bind,
      loadAdminSessions,
      loadAllAdminSessions,
      loadSelfSessions,
      renderAdminSessions,
      renderSelfSessions,
    });
  }

  root.ShellXDriveSessions = Object.freeze({ createController });
})(window);
