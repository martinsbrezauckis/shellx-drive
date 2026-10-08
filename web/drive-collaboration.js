// Comments, revision history, guest links, and collaborator invitations.
//
// This controller keeps the collaboration lifecycle out of drive.js while the
// composition root continues to own shared session state and navigation.

(() => {
  const SHARE_EXPIRY_CHOICES = [
    [3600, "1 hour"],
    [86400, "24 hours"],
    [604800, "7 days"],
    [2592000, "30 days"],
    [0, "Never"],
  ];

  const agentAccessModule = window.ShellXDriveAgentAccess;
  const {
    AGENT_EXPIRY_CHOICES,
    isActiveAgentAccess,
    agentAccessPayload,
    existingAgentAccessPayload,
    agentAccessPagePath,
    agentPrincipalPagePath,
    agentPrincipalGrantPagePath,
    agentPrincipalRemovalPath,
    nextAgentPrincipalCursor,
  } = agentAccessModule;

  const isActiveShare = window.ShellXDriveGuestLinks.isActiveShare;

  function shareExpiryChoice(share, now = Date.now()) {
    const rawStored = share?.expires_in_seconds;
    const stored = Number(rawStored);
    if (rawStored !== null && rawStored !== undefined && rawStored !== "" && Number.isFinite(stored)) {
      return Math.max(0, stored);
    }
    if (!share?.expires_at) return 0;
    const remaining = Math.max(0, (Date.parse(share.expires_at) - now) / 1000);
    return SHARE_EXPIRY_CHOICES.filter(([value]) => value > 0).reduce(
      (closest, [value]) =>
        Math.abs(value - remaining) < Math.abs(closest - remaining) ? value : closest,
      3600,
    );
  }

  function optionalPositiveInteger(value) {
    if (value === null || value === undefined || String(value).trim() === "") return null;
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > 1_000_000) {
      throw new Error("Maximum visits must be a whole number from 1 to 1,000,000.");
    }
    return parsed;
  }

  function shareMutationPayload(settings, updating = false) {
    const maxUses = optionalPositiveInteger(settings.maxUses);
    const note = String(settings.recipientNote || "").trim();
    const payload = {
      expires_in_seconds: Number(settings.expiresInSeconds),
      allow_download: Boolean(settings.allowDownload),
    };
    if (!Number.isFinite(payload.expires_in_seconds)) {
      throw new Error("Choose a valid link expiry.");
    }
    if (settings.password) payload.password = settings.password;
    if (updating) {
      if (note) payload.recipient_note = note;
      else payload.clear_recipient_note = true;
      if (maxUses === null) payload.clear_max_uses = true;
      else payload.max_uses = maxUses;
    } else {
      payload.recipient_note = note || null;
      payload.max_uses = maxUses;
    }
    return payload;
  }

  function workspaceRoleLabel(role) {
    return ({ owner: "Owner", editor: "Can edit", viewer: "Can view" })[role]
      || String(role || "Member").replaceAll("_", " ");
  }

  function shareExpiryLabel(seconds) {
    const value = Number(seconds || 0);
    if (!value) return "does not expire";
    const [amount, unit] = value % 86400 === 0 ? [value / 86400, "day"] : [Math.round(value / 3600), "hour"];
    return `${amount} ${amount === 1 ? unit : `${unit}s`}`;
  }

  function createController({ state, els, api, callbacks }) {
    const {
      escapeHtml,
      compactDate,
      compactShareExpiry,
      formatShareExpiry,
      formatFileSize,
      pretty,
      showToast,
      canWrite,
      canManage,
      isAdmin,
      renderSelectionSummary,
      setSelectionControlState,
      renderAdminLiveList,
      loadManifest,
      loadSyncHealth,
      loadNotifications,
      loadAdminSummary,
      syncSharedItemBadge,
      confirmAction,
      authHeaders,
      selectFile,
      closeWorkspaceSettings,
      initialsForEmail,
    } = callbacks;

    const agents = agentAccessModule.createController({
      state,
      els,
      api,
      callbacks: {
        escapeHtml,
        compactDate,
        showToast,
        canWrite, canManageAiAccess: callbacks.canManageAiAccess,
        confirmAction,
        renderShareDrawer,
        report,
      },
    });
    const invitations = window.ShellXDriveWorkspaceInvitations.createController({
      state,
      els,
      api,
      callbacks: { escapeHtml, showToast, canManage, renderAdminLiveList, report },
    });

    const guestLinks = window.ShellXDriveGuestLinks.createController({
      state, api,
      callbacks: { isActiveShare, canManageGuestLink: callbacks.canManageGuestLink,
        syncInspectorShareForm, renderShareSummary, renderShareDrawer,
        setSelectionControlState, syncSharedItemBadge, renderManagedShares },
    });

    function activeShareForFile(fileId) {
      return (state.workspaceShares || []).find(
        (share) => share.file_id === fileId && isActiveShare(share),
      ) || null;
    }

    function activeShareForSelectedFile() {
      if (!state.selectedFile) return null;
      return (state.selectedFile.guest_link_lookup?.shares || state.managedShares || []).find(
        (share) => share.file_id === state.selectedFile.id && isActiveShare(share),
      ) || null;
    }

    function authorCanMutate(item) {
      return Boolean(canWrite() && item && !item.deleted_at && (isAdmin() || item.author_email === state.actor));
    }

    function renderComments(comments = []) {
      els.commentList.replaceChildren();
      if (!state.selectedFile) return;
      if (comments.length === 0) {
        const empty = document.createElement("div");
        empty.className = "activity-item";
        empty.innerHTML = `<span class="activity-dot"></span><span>No comments yet.</span>`;
        els.commentList.append(empty);
        renderSelectionSummary();
        return;
      }
      for (const comment of comments) {
        const row = document.createElement("article");
        row.className = `comment-row${comment.deleted_at ? " is-deleted" : ""}`;
        const status = comment.deleted_at ? "deleted" : comment.resolved ? "resolved" : "open";
        const edited = comment.edited_at ? " · edited" : "";
        const replies = (comment.replies || [])
          .map((reply) => {
            const replyBody = reply.deleted_at ? "Reply deleted" : reply.body;
            const replyEdited = reply.edited_at ? " · edited" : "";
            const actions = authorCanMutate(reply)
              ? `<span class="comment-actions">
                   <button type="button" data-edit-reply="${escapeHtml(reply.id)}">Edit</button>
                   <button type="button" data-delete-reply="${escapeHtml(reply.id)}">Delete</button>
                 </span>`
              : "";
            return `<div class="comment-reply${reply.deleted_at ? " is-deleted" : ""}">
              <strong>${escapeHtml(reply.author_email)}</strong>
              <span>${escapeHtml(replyBody)}${escapeHtml(replyEdited)}</span>
              <small>${escapeHtml(compactDate(reply.updated_at || reply.created_at))}</small>${actions}
            </div>`;
          })
          .join("");
        const authorActions = authorCanMutate(comment)
          ? `<button type="button" data-edit-comment="${escapeHtml(comment.id)}">Edit</button>
             <button type="button" data-delete-comment="${escapeHtml(comment.id)}">Delete</button>`
          : "";
        const threadActions = canWrite() && !comment.deleted_at
          ? `<button type="button" data-comment-reply="${escapeHtml(comment.id)}">Reply</button>
             ${comment.resolved ? "" : `<button type="button" data-comment-resolve="${escapeHtml(comment.id)}">Resolve</button>`}`
          : "";
        row.innerHTML = `
          <header><span>${escapeHtml(comment.author_email || "system")}</span><span>${escapeHtml(status)}${escapeHtml(edited)} · ${escapeHtml(compactDate(comment.updated_at || comment.created_at))}</span></header>
          <div class="comment-body">${escapeHtml(comment.deleted_at ? "Comment deleted" : comment.body)}</div>
          ${replies ? `<div class="comment-replies">${replies}</div>` : ""}
          ${authorActions || threadActions ? `<div class="comment-actions">${threadActions}${authorActions}</div>` : ""}
        `;
        els.commentList.append(row);
      }
      renderSelectionSummary();
    }

    async function loadSelectedComments() {
      if (!state.selectedFile) return [];
      const fileId = state.selectedFile.id;
      const data = await api(`/files/${fileId}/comments`);
      if (state.selectedFile?.id !== fileId) return [];
      state.selectedComments = data.comments || [];
      renderComments(state.selectedComments);
      return state.selectedComments;
    }

    async function createComment(event) {
      event?.preventDefault?.();
      if (!state.selectedFile || !canWrite()) return;
      const body = els.commentBody.value.trim();
      if (!body) return;
      await api(`/files/${state.selectedFile.id}/comments`, {
        method: "POST",
        body: JSON.stringify({ body }),
      });
      els.commentBody.value = "";
      await loadSelectedComments();
      await loadAdminSummary().catch(() => {});
      await loadNotifications(false).catch(() => {});
      showToast("Comment added.");
    }

    async function replyToComment(commentId, body) {
      if (!state.selectedFile || !canWrite() || !commentId || !body?.trim()) return;
      await api(`/comments/${encodeURIComponent(commentId)}/replies`, {
        method: "POST",
        body: JSON.stringify({ body: body.trim() }),
      });
      await loadSelectedComments();
      await loadNotifications(false).catch(() => {});
      showToast("Reply added.");
    }

    async function resolveComment(commentId) {
      if (!state.selectedFile || !canWrite() || !commentId) return;
      await api(`/comments/${encodeURIComponent(commentId)}/resolve`, { method: "POST" });
      await loadSelectedComments();
      showToast("Comment resolved.");
    }

    async function editEntry(kind, id, currentBody) {
      const body = canWrite() ? window.prompt(`Edit ${kind}`, currentBody || "") : "";
      if (!body?.trim()) return;
      const path = kind === "comment" ? `/comments/${id}` : `/comment-replies/${id}`;
      await api(path, { method: "PATCH", body: JSON.stringify({ body: body.trim() }) });
      await loadSelectedComments();
      await loadNotifications(false).catch(() => {});
      showToast(`${kind === "comment" ? "Comment" : "Reply"} updated.`);
    }

    async function deleteEntry(kind, id) {
      const confirmed = canWrite() && await confirmAction({
        title: `Delete ${kind}?`,
        message: "The text will become a tombstone so the discussion and audit trail remain intact.",
        confirmLabel: "Delete",
      });
      if (!confirmed) return;
      const path = kind === "comment" ? `/comments/${id}` : `/comment-replies/${id}`;
      await api(path, { method: "DELETE" });
      await loadSelectedComments();
      await loadNotifications(false).catch(() => {});
      showToast(`${kind === "comment" ? "Comment" : "Reply"} deleted.`);
    }

    function revisionStorageText() {
      const storage = state.selectedRevisionStorage;
      if (!storage) return "";
      return `${storage.revision_count} versions · ${formatFileSize(storage.content_bytes)} stored · ${formatFileSize(storage.reclaimable_content_bytes)} reclaimable`;
    }

    function renderRevisionOptions() {
      const selected = els.revisionSelect.value;
      els.revisionSelect.replaceChildren();
      for (const revision of state.selectedRevisions || []) {
        const option = document.createElement("option");
        option.value = revision.revision;
        option.textContent = `r${revision.revision}${revision.current ? " · current" : ""}${revision.has_content ? "" : " · metadata"}${revision.pinned ? " · pinned" : ""}`;
        option.selected = String(revision.revision) === selected;
        els.revisionSelect.append(option);
      }
      els.revisionsOutput.hidden = !(state.selectedRevisions || []).length;
      els.revisionsOutput.textContent = revisionStorageText();
    }

    function renderVersionsLog() {
      if (!els.versionsList) return;
      if (!state.selectedFile) {
        els.versionsList.innerHTML = `<div class="activity-item"><span class="activity-dot"></span><span>Select a file to see its version history.</span></div>`;
        return;
      }
      const rows = (state.selectedRevisions || [])
        .slice()
        .sort((a, b) => b.revision - a.revision)
        .map((revision) => `
          <div class="version-row">
            <span><strong>Revision ${revision.revision}</strong><small>${escapeHtml(compactDate(revision.created_at))}${revision.conflict_of_revision ? ` · conflict of r${escapeHtml(revision.conflict_of_revision)}` : ""}</small></span>
            <span class="member-role">${revision.current ? "current" : revision.pinned ? "pinned" : revision.has_content ? formatFileSize(revision.content_bytes) : "metadata"}</span>
          </div>`)
        .join("");
      els.versionsList.innerHTML = `${revisionStorageText() ? `<div class="activity-item"><span class="activity-dot"></span><span>${escapeHtml(revisionStorageText())}</span></div>` : ""}${rows || `<div class="activity-item"><span class="activity-dot"></span><span>Expand to load revision history for this file.</span></div>`}`;
    }

    async function loadSelectedRevisions() {
      if (!state.selectedFile) return [];
      const fileId = state.selectedFile.id;
      const data = await api(`/files/${fileId}/revisions`);
      if (state.selectedFile?.id !== fileId) return [];
      state.selectedRevisions = data.revisions || [];
      state.selectedRevisionStorage = data.storage || null;
      renderRevisionOptions();
      renderVersionsLog();
      renderSelectionSummary();
      setSelectionControlState();
      showToast("Revisions loaded.");
      return state.selectedRevisions;
    }

    function selectedRevision() {
      const revision = Number(els.revisionSelect.value);
      return (state.selectedRevisions || []).find((item) => item.revision === revision) || null;
    }

    async function restoreSelectedRevision() {
      const revision = selectedRevision();
      if (!state.selectedFile || !state.currentWorkspace || !revision || !canWrite()) return;
      const confirmed = await confirmAction({
        title: `Restore revision ${revision.revision}?`,
        message: "The current file will become a new version; existing history is kept.",
        confirmLabel: "Restore revision",
      });
      if (!confirmed) return;
      const data = await api(`/files/${state.selectedFile.id}/revisions/${revision.revision}/restore`, {
        method: "POST",
      });
      state.selectedFile = data.file;
      state.selectedBaseRevision = null;
      els.selectedContent.value = "";
      await loadManifest(state.currentWorkspace.id);
      els.selectedMeta.textContent = pretty(data);
      await loadSelectedRevisions();
      await loadSyncHealth().catch(() => {});
      showToast("Revision restored.");
    }

    async function setSelectedRevisionPinned(pinned) {
      const revision = selectedRevision();
      if (!state.selectedFile || !revision || !canWrite()) return;
      const data = await api(
        `/files/${state.selectedFile.id}/revisions/${revision.revision}/${pinned ? "pin" : "unpin"}`,
        { method: "POST" },
      );
      state.selectedRevisions = data.revisions || [];
      state.selectedRevisionStorage = data.storage || null;
      renderRevisionOptions();
      renderVersionsLog();
      setSelectionControlState();
      showToast(pinned ? "Revision pinned." : "Revision unpinned.");
    }

    async function downloadSelectedRevision() {
      const revision = selectedRevision();
      if (!state.selectedFile || !revision?.has_content) return;
      await window.ShellXDownloadTickets.start({
        endpoint: `/files/${encodeURIComponent(state.selectedFile.id)}/revisions/${revision.revision}/download`,
        body: {},
        headers: authHeaders(),
      });
      showToast(`Revision ${revision.revision} download started.`);
    }

    async function deleteSelectedRevision() {
      const revision = selectedRevision();
      if (!state.selectedFile || !revision || revision.current || revision.pinned || !canWrite()) return;
      const confirmed = await confirmAction({
        title: `Delete revision ${revision.revision}?`,
        message: `This can reclaim ${formatFileSize(revision.content_bytes)}. The current and pinned versions are protected.`,
        confirmLabel: "Delete revision",
      });
      if (!confirmed) return;
      const data = await api(`/files/${state.selectedFile.id}/revisions/${revision.revision}`, {
        method: "DELETE",
      });
      state.selectedRevisions = data.revisions || [];
      state.selectedRevisionStorage = data.storage || null;
      renderRevisionOptions();
      renderVersionsLog();
      setSelectionControlState();
      showToast("Revision deleted.");
    }

    async function pruneSelectedRevisions() {
      if (!state.selectedFile || !canWrite() || !canManage()) return;
      const confirmed = await confirmAction({
        title: "Prune old revisions?",
        message: "Versions beyond the workspace retention policy will be removed. Current and pinned versions remain protected.",
        confirmLabel: "Prune revisions",
      });
      if (!confirmed) return;
      const data = await api(`/files/${state.selectedFile.id}/revisions/prune`, { method: "POST" });
      state.selectedRevisions = data.revisions || [];
      state.selectedRevisionStorage = data.storage || null;
      renderRevisionOptions();
      renderVersionsLog();
      setSelectionControlState();
      showToast(`Pruned ${data.deleted_revisions || 0} revisions.`);
    }

    async function clearSelectedLabels() {
      if (!state.selectedFile || !state.currentWorkspace || !canWrite()) return;
      const data = await api(`/files/${state.selectedFile.id}`, {
        method: "PATCH",
        body: JSON.stringify({ labels: [] }),
      });
      state.selectedFile = data.file;
      state.selectedMetadata = data.metadata;
      els.fileLabels.value = "";
      await loadManifest(state.currentWorkspace.id);
      renderSelectionSummary();
      showToast("Labels cleared.");
    }

    function shareExpiryAllowed(value) {
      const policy = state.browseScope ? state.selectedFile?.guest_link_lookup?.policy : state.workspacePolicy;
      if (state.browseScope && (!policy || policy.workspace_id !== state.selectedFile?.workspace_id)) return false;
      if (!policy) return true;
      const ttl = Number(value);
      if (ttl <= 0) return Boolean(policy.allow_never_expire);
      return ttl <= Number(policy.max_link_ttl_seconds ?? 2592000);
    }
    function firstAllowedShareExpiry() {
      return SHARE_EXPIRY_CHOICES.find(([value]) => shareExpiryAllowed(value))?.[0] ?? 3600;
    }
    function syncShareExpirySelect(select) {
      if (!select) return;
      for (const option of select.options) {
        const allowed = shareExpiryAllowed(option.value);
        option.disabled = !allowed;
        if (Number(option.value) === 0) {
          option.textContent = allowed ? "Never" : "Never (blocked by workspace policy)";
        }
      }
      if (select.selectedOptions[0]?.disabled) select.value = String(firstAllowedShareExpiry());
    }
    function selectStoredShareExpiry(select, share) {
      if (!select || !share) return;
      select.querySelector("[data-custom-share-expiry]")?.remove();
      const value = shareExpiryChoice(share);
      if (![...select.options].some((option) => Number(option.value) === value)) {
        const option = document.createElement("option");
        option.value = String(value);
        option.textContent = shareExpiryLabel(value);
        option.dataset.customShareExpiry = "true";
        select.append(option);
      }
      select.value = String(value);
      syncShareExpirySelect(select);
    }
    function syncShareExpiryControls() {
      syncShareExpirySelect(els.shareExpiry);
      if (!shareExpiryAllowed(state.shareDraftExpiry)) state.shareDraftExpiry = firstAllowedShareExpiry();
    }

    function shareMetaText() {
      const share = activeShareForSelectedFile();
      if (!share) return "Anyone with the link can preview.";
      const parts = ["Read-only guest access"];
      parts.push(share.allow_download ? "Downloads allowed" : "Preview only (best effort)");
      if (share.uses_remaining !== null && share.uses_remaining !== undefined) {
        parts.push(`${share.uses_remaining} visits left`);
      }
      parts.push(`Expires ${formatShareExpiry(share.expires_at)}`);
      return parts.join(" · ");
    }

    function renderShareSummary() {
      if (!state.selectedFile) {
        els.shareSummary.innerHTML = `<span class="link-icon" aria-hidden="true">↗</span><span><strong>Link access</strong><small>Select a file to create or copy a link.</small></span>`;
        return;
      }
      if (!callbacks.canManageGuestLink?.(state.selectedFile)) {
        const status = state.selectedFile.guest_link_lookup?.status;
        const message = status === "loading" ? "Checking guest-link access…" : status === "error" ? "Guest-link access could not be verified. Select this item to retry." : "Guest-link controls are not available for this access role.";
        els.shareSummary.innerHTML = `<span class="link-icon" aria-hidden="true">↗</span><span><strong>Guest link</strong><small>${message}</small></span>`;
        return;
      }
      if (state.selectedFile.guest_link_lookup?.status !== "loaded") {
        const failed = state.selectedFile.guest_link_lookup?.status === "error";
        const known = activeShareForFile(state.selectedFile.id);
        els.shareSummary.innerHTML = `<span class="link-icon" aria-hidden="true">↗</span><span><strong>${known ? "Guest link recorded" : "Guest link"}</strong><small>${failed ? "Could not load guest-link details." : "Loading guest-link details…"}</small>${failed ? '<button type="button" data-share-retry>Retry</button>' : ""}</span>`;
        return;
      }
      const share = activeShareForSelectedFile();
      const linkDetails = share && state.latestShareUrl
        ? `<strong>Guest link active</strong>
           <small>${escapeHtml(shareMetaText())}</small>
           <a class="active-share-url" href="${escapeHtml(state.latestShareUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(state.latestShareUrl)}</a>
           <div class="active-share-actions"><button type="button" data-active-share-copy>Copy link</button><a href="${escapeHtml(state.latestShareUrl)}" target="_blank" rel="noopener noreferrer">Open link</a><button type="button" class="danger-action" data-active-share-revoke="${escapeHtml(share.id)}">Revoke</button></div>`
        : `<strong>Link access</strong><small>No active guest link.</small>`;
      els.shareSummary.innerHTML = `<span class="link-icon" aria-hidden="true">↗</span><span class="link-access-content">${linkDetails}</span>`;
    }

    function syncInspectorShareForm(share) {
      if (!callbacks.canManageGuestLink?.(state.selectedFile)) return;
      const submit = els.shareForm.querySelector('button[type="submit"]');
      const editing = Boolean(share);
      els.shareForm.dataset.mode = editing ? "update" : "create";
      els.shareAllowDownload.checked = share?.allow_download !== false;
      els.shareRecipientNote.value = share?.recipient_note || "";
      els.shareMaxUses.value = share?.max_uses || "";
      if (editing) selectStoredShareExpiry(els.shareExpiry, share);
      else {
        els.shareExpiry.value = String(state.shareDraftExpiry);
        syncShareExpirySelect(els.shareExpiry);
      }
      submit.textContent = editing ? "Update guest link" : "Create guest link";
    }

    function settingsFromForm() {
      return {
        password: els.sharePassword.value,
        expiresInSeconds: Number(els.shareExpiry.value),
        allowDownload: els.shareAllowDownload.checked,
        recipientNote: els.shareRecipientNote.value,
        maxUses: els.shareMaxUses.value,
      };
    }

    async function ensureWorkspacePolicy() {
      if (state.browseScope) {
        const policy = state.selectedFile?.guest_link_lookup?.policy;
        if (!policy || policy.workspace_id !== state.selectedFile.workspace_id) throw new Error("Load this item's workspace policy before changing its guest link.");
        return policy;
      }
      if (state.workspacePolicy) return state.workspacePolicy;
      if (!state.currentWorkspace) return null;
      try {
        await callbacks.loadWorkspacePolicyAndUsage();
        return state.workspacePolicy;
      } catch {
        return null;
      }
    }

    function presentShareError(error) {
      const message = String(error?.message || "Could not update the guest link.");
      els.shareOutput.hidden = false;
      els.shareOutput.textContent = message;
      showToast(message);
    }

    async function submitShare(event) {
      event?.preventDefault?.();
      if (!state.selectedFile) return;
      if (!callbacks.canManageGuestLink?.(state.selectedFile)) throw new Error("Guest-link access is not authorized for this item.");
      if (state.selectedFile.guest_link_lookup?.status !== "loaded") throw new Error("Load guest-link details before changing this link.");
      const settings = settingsFromForm();
      const policy = await ensureWorkspacePolicy();
      if (settings.expiresInSeconds <= 0 && policy && !policy.allow_never_expire) {
        throw new Error("Permanent links are disabled for this workspace. Choose a timed expiry.");
      }
      state.shareDraftExpiry = settings.expiresInSeconds;
      const active = activeShareForSelectedFile();
      const updating = Boolean(active && els.shareForm.dataset.mode === "update");
      const payload = shareMutationPayload(settings, updating);
      if (!updating) {
        payload.file_id = state.selectedFile.id;
        payload.password = settings.password;
      }
      const data = await api(updating ? `/shares/${active.id}` : "/shares", {
        method: updating ? "PATCH" : "POST",
        body: JSON.stringify(payload),
      });
      state.selectedShareId = data.share.id;
      state.latestShareUrl = `${window.location.origin}/pub/shares/${data.share.id}`;
      els.sharePassword.value = "";
      await loadManagedShares();
      await loadNotifications(false).catch(() => {});
      els.shareOutput.hidden = false;
      els.shareOutput.textContent = `${updating ? "Guest link updated" : "Guest link ready"}\n${state.latestShareUrl}\n${shareMetaText()}`;
      showToast(updating ? "Guest link updated." : "Guest link created.");
    }

    function loadSelectedGuestLinks(file, options) { return guestLinks.loadSelected(file, options); }

    async function loadManagedShares({ workspaceWide = false } = {}) {
      if (!workspaceWide && state.selectedFile && state.currentWorkspace) return guestLinks.loadShares();
      if (!state.currentWorkspace) {
        state.managedShares = [];
        state.workspaceShares = [];
        renderManagedShares();
        return [];
      }
      const workspaceId = state.currentWorkspace.id;
      const previousIds = new Set((state.workspaceShares || []).map((share) => share.file_id));
      const data = await api(`/workspaces/${workspaceId}/shares`);
      if (state.currentWorkspace?.id !== workspaceId) return [];
      if (!Array.isArray(data?.shares)) throw new Error("Guest-link details could not be verified.");
      state.managedShares = data.shares;
      state.workspaceShares = data.shares;
      for (const share of data.shares) previousIds.add(share.file_id);
      for (const fileId of previousIds) syncSharedItemBadge(fileId);
      state.selectedShareId = data.shares.find(isActiveShare)?.id || data.shares[0]?.id || "";
      renderManagedShares();
      return data.shares;
    }

    async function loadWorkspaceShareState(
      workspaceId = state.currentWorkspace?.id,
      isCurrent = () => true,
    ) {
      if (!workspaceId || !(callbacks.canWriteWorkspace?.() ?? canWrite())) {
        if (!isCurrent()) return [];
        state.workspaceShares = [];
        return [];
      }
      const data = await api(`/workspaces/${workspaceId}/shares`);
      if (!isCurrent()) return [];
      state.workspaceShares = data.shares || [];
      return state.workspaceShares;
    }

    function renderManagedShares() {
      if (!els.shareManagementList) return;
      const shares = state.managedShares || [];
      if (!state.currentWorkspace) {
        renderAdminLiveList(els.shareManagementList, [["Shared links", "No workspace"]]);
        return;
      }
      if (!shares.length) {
        renderAdminLiveList(els.shareManagementList, [["Shared links", "None"]]);
        return;
      }
      els.shareManagementList.replaceChildren(
        ...shares.slice(0, 12).map((share) => {
          const row = document.createElement("div");
          row.className = "managed-link-row";
          const remaining = share.uses_remaining === null || share.uses_remaining === undefined
            ? "unlimited visits"
            : `${share.uses_remaining} visits left`;
          row.innerHTML = `<span><b>${escapeHtml(share.revoked ? "Revoked link" : "Guest link")}</b><small>${escapeHtml(remaining)} · ${share.allow_download ? "downloads on" : "preview only (best effort)"} · expires ${escapeHtml(compactShareExpiry(share.expires_at))}</small></span><button type="button" class="admin-inline-button" data-open-share-settings="${escapeHtml(share.id)}" ${share.revoked ? "disabled" : ""}>${share.revoked ? "Revoked" : "Open settings"}</button>`;
          return row;
        }),
      );
    }

    function openManagedShare(shareId) {
      const share = (state.managedShares || []).find((item) => item.id === shareId);
      const file = state.files.find((item) => item.id === share?.file_id);
      if (!share || !file) {
        showToast("That shared item is not in the current workspace view.");
        return;
      }
      state.selectedShareId = share.id;
      selectFile(file);
      closeWorkspaceSettings();
      const details = els.shareForm.closest("details.share-options");
      if (details) details.open = true;
      syncInspectorShareForm(share);
      els.shareExpiry.focus();
    }

    async function revokeShare(shareId) {
      if (!shareId) return;
      if (!callbacks.canManageGuestLink?.(state.selectedFile)) throw new Error("Guest-link access is not authorized for this item.");
      const confirmed = await confirmAction({
        title: "Revoke guest link?",
        message: "Anyone using this link will immediately lose access.",
        confirmLabel: "Revoke link",
      });
      if (!confirmed) return;
      await api(`/shares/${shareId}/revoke`, { method: "POST" });
      await loadManagedShares();
      showToast("Guest link revoked.");
    }

    async function copyLatestShareLink() {
      if (!state.latestShareUrl) {
        showToast("Create a guest link first.");
        return;
      }
      try {
        await navigator.clipboard?.writeText(state.latestShareUrl);
      } catch {
        // The visible link remains available when clipboard permission is denied.
      }
      showToast("Share link copied.");
    }

    function renderShareDrawer() {
      if (els.shareDrawer.hidden || !state.selectedFile) return;
      const share = activeShareForSelectedFile();
      const loaded = state.selectedFile.guest_link_lookup?.status === "loaded";
      const guestLinkSection = callbacks.canManageGuestLink?.(state.selectedFile)
        ? `<section class="drawer-section"><div class="drawer-section-head"><strong>Guest link</strong><span class="status-chip ${loaded && share ? "active" : ""}">${loaded ? share ? "Enabled" : "No active link" : "Not verified"}</span></div><div class="drawer-link-row"><span><strong>${loaded ? share ? "Anyone with the link can preview" : "No active guest link" : "Guest-link details are not verified"}</strong><span>${escapeHtml(loaded ? share ? shareMetaText() : "Create and change this separate external link in its settings panel." : "Check the link status in the inspector, then retry if needed.")}</span></span></div><button type="button" data-open-link-settings ${loaded ? "" : "disabled"}>Open Guest link settings</button></section>`
        : "";
      const aiAccessSection = callbacks.canManageAiAccess?.(state.selectedFile) ? agents.section() : "";
      els.shareDrawer.querySelector("h2").textContent = `Share "${state.selectedFile.name}"`;
      els.shareDrawer.querySelector(".drawer-share-form").innerHTML = `
        ${callbacks.renderHumanSharingDrawer?.() || `<section class="drawer-section"><div class="drawer-section-head"><strong>People and groups</strong></div><p class="drawer-copy">Item access is loading.</p></section>`}
        ${guestLinkSection}
        ${aiAccessSection}`;
    }

    function renderAgentSettingsPanel() {
      agents.renderSettings();
      agents.renderDelegatedAgentSettings();
    }
    function loadAgentPrincipals() { return agents.loadPrincipals(); }

    function openShareDrawer() {
      if (!state.selectedFile) return showToast("Select a file before sharing.");
      agents.prepareShareDrawer();
      els.shareDrawer.hidden = false;
      renderShareDrawer();
      els.closeShareDrawerButton.focus();
      callbacks.openHumanSharing?.(state.selectedFile);
      if (state.selectedFile.kind === "folder" && callbacks.canManageAiAccess?.(state.selectedFile)) {
        agents.loadSelected();
        agents.loadPrincipals();
      }
    }

    function closeShareDrawer() {
      agents.closeShareDrawer();
      els.shareDrawer.hidden = true;
    }

    function openAgentSettings() { agents.openSettings(); }
    function closeAgentSettings() { agents.closeSettings(); }
    function clearAgentState() {
      invitations.clearLink();
      agents.clearState();
    }

    function openInlineLinkSettings() {
      if (!callbacks.canManageGuestLink?.(state.selectedFile) || state.selectedFile.guest_link_lookup?.status !== "loaded") return;
      closeShareDrawer();
      const details = els.shareForm.closest("details.share-options");
      if (details) details.open = true;
      syncInspectorShareForm(activeShareForSelectedFile());
      els.sharePassword.focus();
    }

    function bind() {
      els.commentForm.addEventListener("submit", (event) => createComment(event).catch(report));
      els.commentList.addEventListener("click", (event) => {
        const button = event.target.closest("button");
        if (!button) return;
        const comment = state.selectedComments.find((item) => item.id === (button.dataset.editComment || button.dataset.deleteComment || button.dataset.commentReply || button.dataset.commentResolve));
        const reply = state.selectedComments.flatMap((item) => item.replies || []).find((item) => item.id === (button.dataset.editReply || button.dataset.deleteReply));
        let action;
        if (button.dataset.commentReply) {
          const body = window.prompt("Reply to comment");
          action = body && replyToComment(button.dataset.commentReply, body);
        } else if (button.dataset.commentResolve) action = resolveComment(button.dataset.commentResolve);
        else if (button.dataset.editComment && comment) action = editEntry("comment", comment.id, comment.body);
        else if (button.dataset.deleteComment && comment) action = deleteEntry("comment", comment.id);
        else if (button.dataset.editReply && reply) action = editEntry("reply", reply.id, reply.body);
        else if (button.dataset.deleteReply && reply) action = deleteEntry("reply", reply.id);
        Promise.resolve(action).catch(report);
      });
      els.loadRevisionsButton.addEventListener("click", () => loadSelectedRevisions().catch(reportRevision));
      els.restoreRevisionButton.addEventListener("click", () => restoreSelectedRevision().catch(reportRevision));
      els.revisionPinButton.addEventListener("click", () => setSelectedRevisionPinned(true).catch(reportRevision));
      els.revisionUnpinButton.addEventListener("click", () => setSelectedRevisionPinned(false).catch(reportRevision));
      els.revisionDownloadButton.addEventListener("click", () => downloadSelectedRevision().catch(reportRevision));
      els.revisionDeleteButton.addEventListener("click", () => deleteSelectedRevision().catch(reportRevision));
      els.revisionPruneButton.addEventListener("click", () => pruneSelectedRevisions().catch(reportRevision));
      els.revisionSelect.addEventListener("change", setSelectionControlState);
      els.inspectorVersionsSection?.addEventListener("toggle", () => {
        if (!els.inspectorVersionsSection.open || !state.selectedFile) return;
        if (state.selectedRevisions?.length) renderVersionsLog();
        else loadSelectedRevisions().catch(reportRevision);
      });
      els.clearFileLabelsButton.addEventListener("click", () => clearSelectedLabels().catch(report));
      els.shareForm.addEventListener("submit", (event) => submitShare(event).catch(presentShareError));
      els.shareExpiry.addEventListener("change", () => { state.shareDraftExpiry = Number(els.shareExpiry.value); });
      els.shareSummary.addEventListener("click", (event) => {
        if (event.target.closest("[data-share-retry]")) loadSelectedGuestLinks(state.selectedFile, { preserveForm: true }).catch(report);
        if (event.target.closest("[data-active-share-copy]")) copyLatestShareLink().catch(report);
        const revoke = event.target.closest("[data-active-share-revoke]");
        if (revoke) revokeShare(revoke.dataset.activeShareRevoke).catch(report);
      });
      els.shareManagementRefreshButton.addEventListener("click", () => loadManagedShares().catch(report));
      els.shareManagementList.addEventListener("click", (event) => {
        const button = event.target.closest("[data-open-share-settings]");
        if (button) openManagedShare(button.dataset.openShareSettings);
      });
      els.openShareDrawerButton.addEventListener("click", openShareDrawer);
      els.bottomShareButton.addEventListener("click", openShareDrawer);
      els.closeShareDrawerButton.addEventListener("click", closeShareDrawer);
      els.shareDrawer.addEventListener("click", (event) => {
        if (event.target === els.shareDrawer) return closeShareDrawer();
        if (event.target.closest("[data-open-link-settings]")) return openInlineLinkSettings();
      });
      agents.bind();
      invitations.bind();
    }

    function report(error) {
      els.selectedMeta.textContent = error.message;
      showToast(error.message);
    }

    function reportRevision(error) {
      els.revisionsOutput.hidden = false;
      els.revisionsOutput.textContent = error.message;
      showToast(error.message);
    }

    return {
      bind,
      isActiveShare,
      activeShareForFile,
      activeShareForSelectedFile,
      renderShareSummary,
      syncShareExpiryControls,
      syncInspectorShareForm,
      loadManagedShares,
      loadSelectedGuestLinks,
      loadWorkspaceShareState,
      renderManagedShares,
      renderShareDrawer,
      openShareDrawer,
      closeShareDrawer,
      openAgentSettings,
      closeAgentSettings,
      clearAgentState,
      clearInvitationLink: invitations.clearLink,
      renderAgentSettingsPanel,
      loadAgentPrincipals,
      copyLatestShareLink,
      renderComments,
      loadSelectedComments,
      renderRevisionOptions,
      renderVersionsLog,
      loadSelectedRevisions,
      renderWorkspaceInvitations: invitations.renderWorkspaceInvitations,
      loadWorkspaceInvitations: invitations.loadWorkspaceInvitations,
      createWorkspaceInvitation: invitations.createWorkspaceInvitation,
      resendWorkspaceInvitation: invitations.resendWorkspaceInvitation,
      cancelWorkspaceInvitation: invitations.cancelWorkspaceInvitation,
      selectedRevision,
    };
  }

  window.ShellXDriveCollaboration = {
    SHARE_EXPIRY_CHOICES,
    AGENT_EXPIRY_CHOICES,
    isActiveShare,
    isActiveAgentAccess,
    agentAccessPayload,
    existingAgentAccessPayload,
    agentAccessPagePath,
    agentPrincipalPagePath,
    agentPrincipalGrantPagePath,
    agentPrincipalRemovalPath,
    nextAgentPrincipalCursor,
    shareExpiryChoice,
    optionalPositiveInteger,
    shareMutationPayload,
    createController,
  };
})();
