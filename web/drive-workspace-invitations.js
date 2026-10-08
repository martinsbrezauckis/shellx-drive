// Workspace invitation lifecycle and its one-time invitation capability.
//
// The collaboration composition root owns shared session state; this module
// owns only invitation rendering, requests, and the non-persistent link UI.

(() => {
  function memberAccessLabel(seconds) {
    const value = Number(seconds || 0);
    if (!value) return "does not expire";
    if (value % 86400 === 0) {
      const days = value / 86400;
      return `${days} ${days === 1 ? "day" : "days"}`;
    }
    const hours = Math.round(value / 3600);
    return `${hours} ${hours === 1 ? "hour" : "hours"}`;
  }

  function createController({ state, els, api, callbacks }) {
    const { escapeHtml, showToast, canManage, renderAdminLiveList, report } = callbacks;
    const invitationLink = window.ShellXDriveInvitationLink.createController({
      root: els.workspaceInvitationLink,
      onCopied: () => showToast("Invitation link copied and hidden."),
    });

    function presentInvitationLink(token) {
      if (!/^[a-f0-9]{64}$/i.test(String(token || ""))) throw new Error("Drive returned an invalid invitation capability.");
      invitationLink.show(`${window.location.origin}/pub/invitations/accept#token=${token}`);
    }

    function renderWorkspaceInvitations() {
      if (!els.invitationList) return;
      els.invitationList.replaceChildren();
      if (!state.currentWorkspace) {
        renderAdminLiveList(els.invitationList, [["Invitations", "No workspace"]]);
        return;
      }
      if (!canManage()) {
        renderAdminLiveList(els.invitationList, [["Invitations", "Owner only"]]);
        return;
      }
      const invitations = state.workspaceInvitations || [];
      if (!invitations.length) {
        renderAdminLiveList(els.invitationList, [["Pending invitations", "None"]]);
        return;
      }
      els.invitationList.replaceChildren(
        ...invitations.slice(0, 12).map((invitation) => {
          const row = document.createElement("div");
          row.className = "invitation-row";
          const pending = invitation.status === "pending";
          row.innerHTML = `<span><b>${escapeHtml(invitation.email)}</b><small>${escapeHtml(invitation.role || "viewer")} · ${escapeHtml(invitation.status || "pending")} · access ${escapeHtml(memberAccessLabel(invitation.member_expires_in_seconds))}</small></span><span class="button-grid"><button type="button" class="admin-inline-button" data-resend-invitation="${escapeHtml(invitation.id || "")}" ${pending ? "" : "disabled"}>New link</button><button type="button" class="admin-inline-button" data-cancel-invitation="${escapeHtml(invitation.id || "")}" ${pending ? "" : "disabled"}>Cancel</button></span>`;
          return row;
        }),
      );
    }

    async function loadWorkspaceInvitations(
      workspaceId = state.currentWorkspace?.id,
      isCurrent = () => true,
    ) {
      if (!workspaceId || !canManage()) {
        if (!isCurrent()) return [];
        invitationLink.clear();
        state.workspaceInvitations = [];
        renderWorkspaceInvitations();
        return [];
      }
      try {
        const data = await api(`/workspaces/${workspaceId}/invitations`);
        if (!isCurrent()) return [];
        state.workspaceInvitations = data.invitations || [];
      } catch (error) {
        if (window.ShellXDriveAuthLifecycle?.isStale?.(error)) throw error;
        if (!isCurrent()) return [];
        state.workspaceInvitations = [{ email: error.message, role: "unavailable", status: "unavailable" }];
      }
      renderWorkspaceInvitations();
      return state.workspaceInvitations;
    }

    async function createWorkspaceInvitation(eventOrData) {
      eventOrData?.preventDefault?.();
      if (!state.currentWorkspace || !canManage()) return;
      const email = eventOrData?.email || els.workspaceInvitationEmail.value.trim();
      const role = eventOrData?.role || els.workspaceInvitationRole.value || "viewer";
      const rawExpiry = eventOrData?.memberExpiresInSeconds ?? els.workspaceInvitationExpiry.value;
      if (!email) return showToast("Enter an email to invite.");
      const memberExpiry = role === "owner" ? 0 : Number(rawExpiry || 0);
      const payload = { email, role };
      if (memberExpiry > 0) payload.member_expires_in_seconds = memberExpiry;
      const workspaceId = state.currentWorkspace.id;
      const data = await api(`/workspaces/${workspaceId}/invitations`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      els.workspaceInvitationEmail.value = "";
      if (state.currentWorkspace?.id !== workspaceId) return data;
      presentInvitationLink(data.token);
      await loadWorkspaceInvitations(workspaceId);
      showToast("Invitation created.");
      return data;
    }

    async function resendInvitation(invitationId) {
      if (!state.currentWorkspace || !invitationId) return;
      const workspaceId = state.currentWorkspace.id;
      const data = await api(`/workspaces/${workspaceId}/invitations/${encodeURIComponent(invitationId)}/resend`, { method: "POST" });
      if (state.currentWorkspace?.id !== workspaceId) return;
      presentInvitationLink(data.token);
      await loadWorkspaceInvitations(workspaceId);
      showToast("New invitation link created.");
    }

    async function cancelInvitation(invitationId) {
      if (!state.currentWorkspace || !invitationId) return;
      const workspaceId = state.currentWorkspace.id;
      await api(`/workspaces/${workspaceId}/invitations/${encodeURIComponent(invitationId)}/cancel`, { method: "POST" });
      if (state.currentWorkspace?.id !== workspaceId) return;
      invitationLink.clear();
      await loadWorkspaceInvitations(workspaceId);
      showToast("Invitation canceled.");
    }

    function syncInvitationExpiryControl() {
      const owner = els.workspaceInvitationRole.value === "owner";
      els.workspaceInvitationExpiry.disabled = owner || !canManage();
      if (owner) els.workspaceInvitationExpiry.value = "0";
    }

    function bind() {
      invitationLink.bind();
      els.workspaceInvitationForm.addEventListener("submit", (event) => createWorkspaceInvitation(event).catch(report));
      els.workspaceInvitationRole.addEventListener("change", syncInvitationExpiryControl);
      els.invitationList.addEventListener("click", (event) => {
        const resend = event.target.closest("[data-resend-invitation]");
        const cancel = event.target.closest("[data-cancel-invitation]");
        if (resend) resendInvitation(resend.dataset.resendInvitation).catch(report);
        if (cancel) cancelInvitation(cancel.dataset.cancelInvitation).catch(report);
      });
      syncInvitationExpiryControl();
    }

    return {
      bind,
      clearLink: () => invitationLink.clear(),
      renderWorkspaceInvitations,
      loadWorkspaceInvitations,
      createWorkspaceInvitation,
      resendWorkspaceInvitation: resendInvitation,
      cancelWorkspaceInvitation: cancelInvitation,
    };
  }

  window.ShellXDriveWorkspaceInvitations = { memberAccessLabel, createController };
})();
