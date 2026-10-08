// Reusable AI-worker principals, folder grants, and one-time key handling.
(() => {
  const AGENT_EXPIRY_CHOICES = [
    [86400, "1 day"],
    [604800, "7 days"],
    [2592000, "30 days"],
    [7776000, "90 days"],
  ];
  const NEW_AGENT_PRINCIPAL = "__add_ai_worker__";
  const PAGE_LIMIT = 25;

  function isActiveAgentAccess(access, now = Date.now()) {
    if (!access || access.active === false || access.grant_revoked_at || access.token_revoked_at || access.principal_disabled) return false;
    const grantExpiry = Date.parse(access.expires_at);
    const tokenExpiry = Date.parse(access.token_expires_at || access.expires_at);
    return Number.isFinite(grantExpiry) && Number.isFinite(tokenExpiry) && grantExpiry > now && tokenExpiry > now;
  }

  function validatePermissionAndExpiry(permission, expiresInSeconds) {
    if (!["view", "edit"].includes(permission)) throw new Error("Choose View or Edit access.");
    const expiry = Number(expiresInSeconds);
    if (!AGENT_EXPIRY_CHOICES.some(([value]) => value === expiry)) {
      throw new Error("Choose a valid agent access duration.");
    }
    return expiry;
  }

  function agentAccessPayload(name, permission, expiresInSeconds) {
    const normalizedName = String(name || "").trim();
    if (!normalizedName || new TextEncoder().encode(normalizedName).length > 120) {
      throw new Error("Agent name must contain 1 to 120 bytes.");
    }
    return {
      name: normalizedName,
      permission,
      expires_in_seconds: validatePermissionAndExpiry(permission, expiresInSeconds),
    };
  }

  function existingAgentAccessPayload(principalId, permission, expiresInSeconds) {
    const normalizedPrincipalId = String(principalId || "").trim();
    if (!normalizedPrincipalId) throw new Error("Choose an existing AI worker or add a new one.");
    return {
      principal_id: normalizedPrincipalId,
      permission,
      expires_in_seconds: validatePermissionAndExpiry(permission, expiresInSeconds),
    };
  }

  function agentPrincipalPagePath(cursor) {
    const base = `/agent-principals?limit=${PAGE_LIMIT}`;
    return cursor ? `${base}&cursor=${encodeURIComponent(cursor)}` : base;
  }

  function agentPrincipalGrantPagePath(principalId, cursor) {
    return `/agent-principals/${encodeURIComponent(principalId)}/grants?limit=${PAGE_LIMIT}&cursor=${encodeURIComponent(cursor)}`;
  }

  function agentPrincipalRemovalPath(principalId) {
    return `/agent-principals/${encodeURIComponent(principalId)}`;
  }

  function agentAccessPagePath(fileId, cursor) {
    const base = `/files/${encodeURIComponent(fileId)}/agent-access?limit=${PAGE_LIMIT}`;
    return cursor ? `${base}&cursor=${encodeURIComponent(cursor)}` : base;
  }

  function nextAgentPrincipalCursor(nextCursor, seenCursors) {
    if (nextCursor === null || nextCursor === undefined) return null;
    if (typeof nextCursor !== "string" || !nextCursor || seenCursors.has(nextCursor)) {
      throw new Error("AI worker pagination returned a repeated or invalid cursor.");
    }
    seenCursors.add(nextCursor);
    return nextCursor;
  }

  function reconcileSelectedAgentPrincipalId(selected, principals, loaded, loading, error) {
    if (!selected || selected === NEW_AGENT_PRINCIPAL || !loaded || loading || error) return selected;
    return principals.some((agent) => agent.principal_id === selected) ? selected : "";
  }

  function createController({ state, els, api, callbacks }) {
    const {
      escapeHtml, compactDate, showToast, canWrite, confirmAction,
      renderShareDrawer, report,
    } = callbacks;

    state.selectedAgentAccess ||= [];
    state.agentAccessLoading ||= false;
    state.agentAccessError ||= "";
    state.agentAccessNextCursor ??= null;
    state.agentAccessLoadingMore ||= false;
    state.agentAccessCursors ||= new Set();
    state.latestAgentCredential ||= null;
    state.agentPrincipals ||= [];
    state.agentPrincipalsLoading ||= false;
    state.agentPrincipalsLoaded ||= false;
    state.agentPrincipalsError ||= "";
    state.agentPrincipalGrantLoads ||= new Set();
    state.selectedAgentPrincipalId ||= "";
    const delegations = window.ShellXDriveAgentDelegations?.createController({
      state, api, callbacks: { escapeHtml, compactDate, showToast, confirmAction, report },
    });
    if (!delegations) throw new Error("Account-wide AI delegation controls did not load.");

    function destroyOneTimeCredentialNodes(root) {
      for (const node of root?.querySelectorAll?.(".drawer-agent-token, [data-agent-token]") || []) {
        node.replaceChildren();
        node.remove();
      }
    }

    function canManageAccess() {
      return (callbacks.canManageAiAccess?.(state.selectedFile) ?? canWrite()) && state.currentAccount?.auth_mode !== "app_token";
    }

    function canManagePrincipals() {
      return Boolean(state.currentAccount) && state.currentAccount.auth_mode !== "app_token";
    }

    function availablePrincipals() {
      return (state.agentPrincipals || []).filter((agent) => agent && !agent.principal_disabled && agent.active);
    }

    function accessRows() {
      const access = state.selectedAgentAccess || [];
      if (state.agentAccessLoading) return `<div class="drawer-agent-status" role="status">Loading AI access…</div>`;
      if (state.agentAccessError) return `<div class="drawer-agent-status is-error" role="alert">${escapeHtml(state.agentAccessError)}</div>`;
      if (!access.length) return `<div class="drawer-empty">No AI agents can access this folder.</div>`;
      const more = state.agentAccessNextCursor
        ? `<button type="button" data-agent-access-load-more ${state.agentAccessLoadingMore ? "disabled" : ""}>${state.agentAccessLoadingMore ? "Loading more AI access…" : "Load more AI access"}</button>`
        : "";
      return `<div class="drawer-agent-list">${access.map((item) => {
        const removable = !item.grant_revoked_at;
        const permission = item.permission === "edit" ? "Edit" : "View";
        const lastUsed = item.token_last_used_at ? `last used ${compactDate(item.token_last_used_at)}` : "not used yet";
        return `<div class="drawer-agent-row"><span><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(permission)} · ${escapeHtml(lastUsed)} · expires ${escapeHtml(compactDate(item.expires_at))}</small></span><span class="drawer-agent-actions"><button type="button" class="danger-action" data-agent-revoke="${escapeHtml(item.grant_id)}" aria-label="Remove ${escapeHtml(item.name)} from this folder" ${removable ? "" : "disabled"}>${removable ? "Remove from folder" : "Removed from folder"}</button></span></div>`;
      }).join("")}${more}</div>`;
    }

    function oneTimeCredential() {
      const credential = state.latestAgentCredential;
      if (!credential?.token || credential.surface !== "share") return "";
      return `<div class="drawer-agent-token" role="status" aria-label="New AI worker key"><strong>Copy this new AI worker key now</strong><p>Drive will not show it again. Store it with the agent, not in the shared folder.</p><code data-agent-token>${escapeHtml(credential.token)}</code><button type="button" class="primary-action" data-copy-agent-token>Copy key</button></div>`;
    }

    function section() {
      if (state.selectedFile?.kind !== "folder") {
        return `<section class="drawer-section" aria-label="AI access"><div class="drawer-section-head"><strong>AI access</strong><span class="member-role">Folders only</span></div><p class="drawer-copy">Select a folder to give an AI worker access to only that folder and its contents.</p></section>`;
      }
      const activeCount = (state.selectedAgentAccess || []).filter((item) => isActiveAgentAccess(item)).length;
      if (!canManageAccess()) {
        const reason = state.currentAccount?.auth_mode === "app_token"
          ? "Sign in with your account to manage AI access. App tokens cannot delegate permissions."
          : "You need edit access to share this folder with an AI worker.";
        return `<section class="drawer-section" aria-label="AI access"><div class="drawer-section-head"><strong>AI access</strong><span class="member-role">Unavailable</span></div><p class="drawer-copy">${escapeHtml(reason)}</p>${accessRows()}</section>`;
      }
      const principals = availablePrincipals();
      state.selectedAgentPrincipalId = reconcileSelectedAgentPrincipalId(
        state.selectedAgentPrincipalId, principals, state.agentPrincipalsLoaded,
        state.agentPrincipalsLoading, state.agentPrincipalsError,
      );
      if (state.agentPrincipalsLoaded && !state.agentPrincipalsError && !principals.length && !state.selectedAgentPrincipalId) {
        state.selectedAgentPrincipalId = NEW_AGENT_PRINCIPAL;
      }
      const selected = state.selectedAgentPrincipalId;
      const adding = selected === NEW_AGENT_PRINCIPAL;
      const existing = Boolean(selected) && !adding;
      const disabled = state.agentAccessLoading || state.agentPrincipalsLoading ? "disabled" : "";
      const options = principals.map((agent) => `<option value="${escapeHtml(agent.principal_id)}" ${agent.principal_id === selected ? "selected" : ""}>${escapeHtml(agent.name)}</option>`).join("");
      const loadError = state.agentPrincipalsError
        ? `<p class="drawer-agent-choice-note is-error" role="alert">${escapeHtml(state.agentPrincipalsError)}</p>` : "";
      return `<section class="drawer-section" aria-label="AI access"><div class="drawer-section-head"><strong>AI access</strong><span class="status-chip ${activeCount ? "active" : ""}">${activeCount ? `${activeCount} active` : "None"}</span></div><p class="drawer-copy">Choose a reusable AI worker for this folder. View is read-only; Edit can create, update, rename and move items only inside it.</p><form class="drawer-agent-form" data-agent-access-form><label>AI worker<select name="agent_principal" data-agent-principal-select aria-describedby="agent-worker-choice-note" ${disabled}><option value="" ${!selected ? "selected" : ""} disabled>Choose AI worker…</option>${options}<option value="${NEW_AGENT_PRINCIPAL}" ${adding ? "selected" : ""}>+ Add AI worker</option></select></label><p id="agent-worker-choice-note" class="drawer-agent-choice-note" data-agent-form-copy>${adding ? "Add a named worker once. Its key is shown once, only after it is created." : existing ? "This adds access to this folder only. It will not create or show a key." : "Choose an existing AI worker, or add a new one."}</p><label data-agent-new-name ${adding ? "" : "hidden"}>AI worker name<input name="agent_name" type="text" maxlength="120" autocomplete="off" placeholder="Research worker" ${adding ? "required" : ""} ${disabled}/></label><label>Permission<select name="agent_permission" ${disabled}><option value="view">View</option><option value="edit">Edit</option></select></label><label>Expires after<select name="agent_expiry" ${disabled}>${AGENT_EXPIRY_CHOICES.map(([value, label]) => `<option value="${value}" ${value === 2592000 ? "selected" : ""}>${label}</option>`).join("")}</select></label><button type="submit" class="primary-action" ${disabled || !selected ? "disabled" : ""}>${adding ? "Add worker & share" : existing ? "Add to this folder" : "Choose AI worker"}</button><div class="drawer-agent-status" data-agent-form-status aria-live="polite"></div></form>${loadError}${oneTimeCredential()}${accessRows()}</section>`;
    }

    async function loadSelected() {
      if (state.selectedFile?.kind !== "folder" || !canManageAccess()) {
        state.selectedAgentAccess = [];
        state.agentAccessLoading = false;
        renderShareDrawer();
        return [];
      }
      const fileId = state.selectedFile.id;
      Object.assign(state, { agentAccessLoading: true, agentAccessError: "", selectedAgentAccess: [], agentAccessNextCursor: null, agentAccessLoadingMore: false, agentAccessCursors: new Set() });
      renderShareDrawer();
      try {
        const data = await api(agentAccessPagePath(fileId));
        if (state.selectedFile?.id !== fileId) return [];
        state.selectedAgentAccess = Array.isArray(data.access) ? data.access : [];
        state.agentAccessNextCursor = data.next_cursor || null;
        return state.selectedAgentAccess;
      } catch (error) {
        if (window.ShellXDriveAuthLifecycle?.isStale?.(error)) throw error;
        if (state.selectedFile?.id === fileId) state.agentAccessError = error.message;
        return [];
      } finally {
        if (state.selectedFile?.id === fileId) {
          state.agentAccessLoading = false;
          renderShareDrawer();
        }
      }
    }

    async function loadMoreSelected() {
      const fileId = state.selectedFile?.id;
      const cursor = state.agentAccessNextCursor;
      if (!fileId || !cursor || state.agentAccessLoadingMore) return;
      if (state.agentAccessCursors.has(cursor)) {
        state.agentAccessError = "AI access pagination returned a repeated cursor.";
        return renderShareDrawer();
      }
      state.agentAccessLoadingMore = true;
      state.agentAccessError = "";
      renderShareDrawer();
      try {
        const data = await api(agentAccessPagePath(fileId, cursor));
        if (state.selectedFile?.id !== fileId) return;
        state.agentAccessCursors.add(cursor);
        const next = data.next_cursor;
        if (next !== null && next !== undefined && (typeof next !== "string" || !next || next === cursor || state.agentAccessCursors.has(next))) {
          throw new Error("AI access pagination returned a repeated or invalid cursor.");
        }
        const ids = new Set((state.selectedAgentAccess || []).map((item) => item.grant_id));
        const more = (Array.isArray(data.access) ? data.access : []).filter((item) => {
          if (!item?.grant_id || ids.has(item.grant_id)) return false;
          ids.add(item.grant_id);
          return true;
        });
        state.selectedAgentAccess = [...(state.selectedAgentAccess || []), ...more];
        state.agentAccessNextCursor = next || null;
      } catch (error) {
        if (window.ShellXDriveAuthLifecycle?.isStale?.(error)) throw error;
        state.agentAccessError = error.message;
      } finally {
        if (state.selectedFile?.id === fileId) {
          state.agentAccessLoadingMore = false;
          renderShareDrawer();
        }
      }
    }

    function renderSettings() {
      const sectionNode = document.getElementById("settings-ai-agents-section");
      const list = document.getElementById("settings-ai-agents-list");
      const credential = document.getElementById("settings-ai-agents-credential");
      if (!sectionNode || !list || !credential) return;
      if (!canManagePrincipals()) {
        sectionNode.hidden = true;
        credential.replaceChildren();
        return;
      }
      sectionNode.hidden = false;
      const latest = state.latestAgentCredential;
      credential.innerHTML = latest?.token && latest.surface === "settings"
        ? `<div class="drawer-agent-token settings-agent-token" role="status" aria-label="Replacement AI worker key"><strong>Copy this replacement key now</strong><p>Drive will not show it again. Rotation replaces the key for every assigned folder.</p><code data-agent-token>${escapeHtml(latest.token)}</code><button type="button" class="primary-action" data-copy-agent-token>Copy key</button></div>` : "";
      if (state.agentPrincipalsLoading) return void (list.innerHTML = `<div class="drawer-agent-status" role="status">Loading AI workers…</div>`);
      if (state.agentPrincipalsError) return void (list.innerHTML = `<div class="drawer-agent-status is-error" role="alert">${escapeHtml(state.agentPrincipalsError)}</div>`);
      const principals = state.agentPrincipals || [];
      if (!principals.length) return void (list.innerHTML = `<div class="drawer-empty">No AI workers yet. Add one from a folder’s Share with AI picker.</div>`);
      list.innerHTML = principals.map((agent) => {
        const status = agent.principal_disabled ? "Disabled" : agent.active ? "Active" : "Key needs rotation";
        const lastUsed = agent.token_last_used_at ? `last used ${compactDate(agent.token_last_used_at)}` : "not used yet";
        const grants = agent.grants || [];
        const grantRows = grants.length ? grants.map((grant) => `<div class="settings-agent-grant"><span><strong>${escapeHtml(grant.workspace_name || "Workspace")} / ${escapeHtml(grant.root_name || "Folder")}</strong><small>${escapeHtml(grant.permission === "edit" ? "Edit" : "View")} · expires ${escapeHtml(compactDate(grant.expires_at))}</small></span></div>`).join("") : `<div class="drawer-empty">No active folder grants.</div>`;
        const more = agent.grants_next_cursor ? `<button type="button" data-agent-principal-load-more="${escapeHtml(agent.principal_id)}" data-agent-principal-grants-cursor="${escapeHtml(agent.grants_next_cursor)}" ${state.agentPrincipalGrantLoads.has(agent.principal_id) ? "disabled" : ""}>${state.agentPrincipalGrantLoads.has(agent.principal_id) ? "Loading folder access…" : "Load more folder access"}</button>` : "";
        const error = agent._grants_error ? `<div class="drawer-agent-status is-error" role="alert">${escapeHtml(agent._grants_error)}</div>` : "";
        return `<article class="settings-agent-row"><div class="settings-agent-row-head"><span><strong>${escapeHtml(agent.name)}</strong><small>${escapeHtml(status)} · ${escapeHtml(lastUsed)}</small></span><span class="settings-agent-actions"><label>Key lifetime<select data-agent-principal-expiry="${escapeHtml(agent.principal_id)}" aria-label="Key lifetime for ${escapeHtml(agent.name)}">${AGENT_EXPIRY_CHOICES.map(([value, label]) => `<option value="${value}" ${value === 2592000 ? "selected" : ""}>${label}</option>`).join("")}</select></label><button type="button" data-agent-principal-rotate="${escapeHtml(agent.principal_id)}" aria-label="Rotate key for ${escapeHtml(agent.name)}" ${agent.principal_disabled ? "disabled" : ""}>Rotate key</button><button type="button" class="danger-action" data-agent-principal-remove="${escapeHtml(agent.principal_id)}" aria-label="Remove AI worker ${escapeHtml(agent.name)}">Remove AI worker</button></span></div><div class="settings-agent-grants" aria-label="Folder grants for ${escapeHtml(agent.name)}">${grantRows}${more}${error}</div></article>`;
      }).join("");
    }

    async function loadPrincipals() {
      if (!canManagePrincipals()) {
        Object.assign(state, { agentPrincipals: [], agentPrincipalsLoading: false, agentPrincipalsError: "" });
        renderShareDrawer();
        renderSettings();
        return [];
      }
      state.agentPrincipalsLoading = true;
      state.agentPrincipalsError = "";
      renderShareDrawer();
      renderSettings();
      try {
        const principals = [];
        const seen = new Set();
        let cursor = null;
        do {
          const data = await api(agentPrincipalPagePath(cursor));
          principals.push(...(Array.isArray(data.agents) ? data.agents : []));
          cursor = nextAgentPrincipalCursor(data.next_cursor, seen);
        } while (cursor);
        state.agentPrincipals = principals;
        state.agentPrincipalGrantLoads = new Set();
        state.agentPrincipalsLoaded = true;
        return principals;
      } catch (error) {
        if (window.ShellXDriveAuthLifecycle?.isStale?.(error)) throw error;
        state.agentPrincipals = [];
        state.agentPrincipalsLoaded = false;
        state.agentPrincipalsError = error.message;
        return [];
      } finally {
        state.agentPrincipalsLoading = false;
        renderShareDrawer();
        renderSettings();
      }
    }

    async function loadMorePrincipalGrants(principalId, cursor) {
      const agent = (state.agentPrincipals || []).find((item) => item.principal_id === principalId);
      if (!agent || !cursor || state.agentPrincipalGrantLoads.has(principalId)) return;
      agent._grant_cursors ||= new Set();
      if (agent._grant_cursors.has(cursor)) return;
      state.agentPrincipalGrantLoads.add(principalId);
      agent._grants_error = "";
      renderSettings();
      try {
        const data = await api(agentPrincipalGrantPagePath(principalId, cursor));
        agent._grant_cursors.add(cursor);
        const next = data.next_cursor;
        if (next !== null && next !== undefined && (typeof next !== "string" || !next || next === cursor || agent._grant_cursors.has(next))) {
          throw new Error("AI worker folder-access pagination returned a repeated or invalid cursor.");
        }
        const ids = new Set((agent.grants || []).map((grant) => grant.grant_id));
        const more = (Array.isArray(data.grants) ? data.grants : []).filter((grant) => {
          if (!grant?.grant_id || ids.has(grant.grant_id)) return false;
          ids.add(grant.grant_id);
          return true;
        });
        agent.grants = [...(agent.grants || []), ...more];
        agent.grants_next_cursor = next || null;
      } catch (error) {
        if (window.ShellXDriveAuthLifecycle?.isStale?.(error)) throw error;
        agent._grants_error = error.message;
      } finally {
        state.agentPrincipalGrantLoads.delete(principalId);
        renderSettings();
      }
    }

    function syncForm(form) {
      const principalId = String(form?.elements?.agent_principal?.value || "").trim();
      state.selectedAgentPrincipalId = principalId;
      const adding = principalId === NEW_AGENT_PRINCIPAL;
      const existing = Boolean(principalId) && !adding;
      const nameField = form.querySelector("[data-agent-new-name]");
      const nameInput = form.elements.agent_name;
      const note = form.querySelector("[data-agent-form-copy]");
      const submit = form.querySelector('button[type="submit"]');
      if (nameField) nameField.hidden = !adding;
      if (nameInput) nameInput.required = adding;
      if (note) note.textContent = adding ? "Add a named worker once. Its key is shown once, only after it is created." : existing ? "This adds access to this folder only. It will not create or show a key." : "Choose an existing AI worker, or add a new one.";
      if (submit) {
        submit.disabled = !principalId;
        submit.textContent = adding ? "Add worker & share" : existing ? "Add to this folder" : "Choose AI worker";
      }
    }

    async function submit(form) {
      if (!state.selectedFile || state.selectedFile.kind !== "folder" || !canManageAccess()) return;
      const status = form.querySelector("[data-agent-form-status]");
      const submitButton = form.querySelector('button[type="submit"]');
      submitButton.disabled = true;
      submitButton.setAttribute("aria-busy", "true");
      status.classList.remove("is-error");
      const principalId = String(form.elements.agent_principal?.value || "").trim();
      const adding = principalId === NEW_AGENT_PRINCIPAL;
      if (!principalId) {
        submitButton.disabled = false;
        submitButton.removeAttribute("aria-busy");
        status.classList.add("is-error");
        status.textContent = "Choose an existing AI worker or add a new one.";
        return;
      }
      status.textContent = adding ? "Creating AI worker and folder access…" : "Adding this worker to the folder…";
      try {
        const payload = adding
          ? agentAccessPayload(form.elements.agent_name.value, form.elements.agent_permission.value, form.elements.agent_expiry.value)
          : existingAgentAccessPayload(principalId, form.elements.agent_permission.value, form.elements.agent_expiry.value);
        const fileId = state.selectedFile.id;
        const data = await api(`/files/${encodeURIComponent(fileId)}/agent-access`, { method: "POST", body: JSON.stringify(payload) });
        if (state.selectedFile?.id !== fileId) return;
        state.selectedAgentPrincipalId = data.access.principal_id || principalId;
        state.latestAgentCredential = data.token ? { token: data.token, principalId: data.access.principal_id, surface: "share" } : null;
        await loadPrincipals();
        await loadSelected();
        (data.token ? els.shareDrawer.querySelector("[data-copy-agent-token]") : els.shareDrawer.querySelector("[data-agent-form-status]"))?.focus();
        showToast(data.token ? `AI worker created for ${data.access.name}. Copy the key now.` : `${data.access.name} now has access to this folder.`);
      } catch (error) {
        status.classList.add("is-error");
        status.textContent = error.message;
        submitButton.disabled = false;
        submitButton.removeAttribute("aria-busy");
        showToast(error.message);
      }
    }

    async function copyToken() {
      const token = state.latestAgentCredential?.token;
      if (!token) return;
      try {
        if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
        await navigator.clipboard.writeText(token);
        showToast("AI worker key copied.");
      } catch {
        const node = state.latestAgentCredential?.surface === "settings"
          ? document.querySelector("#settings-ai-agents-credential [data-agent-token]")
          : els.shareDrawer.querySelector("[data-agent-token]");
        const selection = window.getSelection?.();
        if (node && selection) {
          const range = document.createRange();
          range.selectNodeContents(node);
          selection.removeAllRanges();
          selection.addRange(range);
        }
        showToast("AI worker key selected. Copy it manually.");
      }
    }

    async function rotatePrincipal(principalId) {
      const agent = (state.agentPrincipals || []).find((item) => item.principal_id === principalId);
      if (!agent || agent.principal_disabled) return;
      const expiry = Number(document.querySelector(`[data-agent-principal-expiry="${CSS.escape(principalId)}"]`)?.value || 2592000);
      if (!await confirmAction({ title: `Rotate ${agent.name}'s key?`, message: `This immediately replaces the key for every assigned folder (${(agent.grants || []).length}). Copy the replacement before closing Settings.`, confirmLabel: "Rotate key" })) return;
      const data = await api(`/agent-principals/${encodeURIComponent(principalId)}/rotate`, { method: "POST", body: JSON.stringify({ expires_in_seconds: expiry }) });
      state.latestAgentCredential = { token: data.token, principalId, surface: "settings" };
      await loadPrincipals();
      await loadSelected();
      renderSettings();
      document.querySelector("#settings-ai-agents-section [data-copy-agent-token]")?.focus();
      showToast(`Key rotated for ${data.agent.name}. Copy the replacement now.`);
    }

    async function removePrincipal(principalId) {
      const agent = (state.agentPrincipals || []).find((item) => item.principal_id === principalId);
      if (!agent || agent.principal_disabled) return;
      if (!await confirmAction({ title: `Remove ${agent.name}?`, message: "This removes the AI worker from selection and Settings, immediately revokes its access to every folder, and disables its key. Historical records stay for audit.", confirmLabel: "Remove AI worker" })) return;
      await api(agentPrincipalRemovalPath(principalId), { method: "DELETE" });
      state.latestAgentCredential = null;
      await loadPrincipals();
      await loadSelected();
      renderSettings();
      showToast(`${agent.name} was removed from all folders.`);
    }

    async function revokeAccess(grantId) {
      const access = (state.selectedAgentAccess || []).find((item) => item.grant_id === grantId);
      if (!access || access.grant_revoked_at) return;
      if (!await confirmAction({ title: `Remove ${access.name} from this folder?`, message: "This removes only this folder. The AI worker keeps any access assigned to its other folders.", confirmLabel: "Remove from folder" })) return;
      await api(`/agent-access/${encodeURIComponent(grantId)}/revoke`, { method: "POST" });
      await loadSelected();
      showToast(`${access.name} was removed from this folder.`);
    }

    function prepareShareDrawer() {
      Object.assign(state, { selectedAgentAccess: [], agentAccessError: "", agentAccessNextCursor: null, agentAccessLoadingMore: false, agentAccessCursors: new Set(), latestAgentCredential: null, selectedAgentPrincipalId: "", agentAccessLoading: state.selectedFile?.kind === "folder" && canManageAccess() });
    }

    function closeShareDrawer() {
      destroyOneTimeCredentialNodes(els.shareDrawer);
      Object.assign(state, { latestAgentCredential: null, selectedAgentAccess: [], agentAccessError: "", agentAccessNextCursor: null, agentAccessLoadingMore: false, agentAccessCursors: new Set(), selectedAgentPrincipalId: "" });
    }

    function openSettings() {
      state.latestAgentCredential = null;
      renderSettings();
      delegations.openSettings();
      if (canManagePrincipals()) loadPrincipals();
    }

    function closeSettings() {
      destroyOneTimeCredentialNodes(document.getElementById("settings-ai-agents-credential"));
      if (state.latestAgentCredential?.surface === "settings") state.latestAgentCredential = null;
      renderSettings();
      delegations.closeSettings();
    }

    function clearState() {
      destroyOneTimeCredentialNodes(document);
      Object.assign(state, {
        latestAgentCredential: null,
        agentPrincipals: [],
        agentPrincipalsError: "",
        agentPrincipalsLoading: false,
        agentPrincipalsLoaded: false,
        selectedAgentPrincipalId: "",
      });
      renderSettings();
      delegations.clearState();
    }

    function bind() {
      delegations.bind(els.settingsDrawer);
      els.shareDrawer.addEventListener("submit", (event) => {
        const form = event.target.closest("[data-agent-access-form]");
        if (!form) return;
        event.preventDefault();
        submit(form).catch(report);
      });
      els.shareDrawer.addEventListener("change", (event) => {
        if (event.target.matches("[data-agent-principal-select]")) syncForm(event.target.closest("form"));
      });
      els.shareDrawer.addEventListener("click", (event) => {
        if (event.target.closest("[data-copy-agent-token]")) return copyToken().catch(report);
        if (event.target.closest("[data-agent-access-load-more]")) return loadMoreSelected().catch(report);
        const revoke = event.target.closest("[data-agent-revoke]");
        if (revoke) return revokeAccess(revoke.dataset.agentRevoke).catch(report);
      });
      els.settingsDrawer?.addEventListener("click", (event) => {
        if (event.target.closest("[data-copy-agent-token]")) return copyToken().catch(report);
        const more = event.target.closest("[data-agent-principal-load-more]");
        if (more) return loadMorePrincipalGrants(more.dataset.agentPrincipalLoadMore, more.dataset.agentPrincipalGrantsCursor).catch(report);
        const remove = event.target.closest("[data-agent-principal-remove]");
        if (remove) return removePrincipal(remove.dataset.agentPrincipalRemove).catch(report);
        const rotate = event.target.closest("[data-agent-principal-rotate]");
        if (rotate) return rotatePrincipal(rotate.dataset.agentPrincipalRotate).catch(report);
      });
    }

    return {
      bind, section, canManageAccess, prepareShareDrawer, closeShareDrawer,
      loadSelected, loadPrincipals, renderSettings, openSettings, closeSettings,
      clearState, loadDelegatedAgents: delegations.loadDelegatedAgents, renderDelegatedAgentSettings: delegations.renderSettings,
    };
  }

  window.ShellXDriveAgentAccess = {
    AGENT_EXPIRY_CHOICES,
    isActiveAgentAccess,
    agentAccessPayload,
    existingAgentAccessPayload,
    agentAccessPagePath,
    agentPrincipalPagePath,
    agentPrincipalGrantPagePath,
    agentPrincipalRemovalPath,
    nextAgentPrincipalCursor,
    reconcileSelectedAgentPrincipalId,
    createController,
  };
})();
