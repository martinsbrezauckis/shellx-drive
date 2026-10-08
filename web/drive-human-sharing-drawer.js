// Drawer state, interaction, and mutation lifecycle for human item grants.
(() => {
  const contract = window.ShellXDriveHumanSharingContract;
  const { GRANT_ROLES, roleLabel, sourceLabel, displayExpiry, grantActive, normalizePrincipal, normalizeGrant, humanGrantPayload, actionCapability } = contract;

  function createController({ state, adapter, callbacks = {} } = {}) {
    const model = {
      fileId: "", grants: [], principals: [], selectedPrincipal: null, principalKind: "account", query: "", role: "viewer", expiry: "",
      loading: false, saving: false, loaded: false, error: "", feedback: "", everyoneConfirming: false, everyonePolicyEnabled: false,
      searchSequence: 0, searchTimer: null,
    };
    let drawer = null;
    const escapeHtml = callbacks.escapeHtml || ((value) => String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;"));
    const selectedFile = () => state?.selectedFile || null;
    // The server, not the workspace role, is authoritative for this action.
    const canManage = () => actionCapability(selectedFile(), "manage_human_sharing");

    function rerender(focus = "") {
      callbacks.renderDrawer?.();
      if (focus && drawer) window.requestAnimationFrame?.(() => drawer.querySelector(focus)?.focus());
    }

    function setFeedback(message, error = false) {
      model.feedback = message;
      model.error = error ? message : "";
      callbacks.showToast?.(message);
    }

    function readOnlyMessage(file = selectedFile()) {
      if (!file) return "Select an item to manage access.";
      if (["revoked", "expired"].includes(file.access_state)) return "Access to this item has been removed. Refresh Shared with me.";
      if (canManage()) return "";
      if ((file.effective_role || file.role) === "viewer" || file.read_only) return "Read-only: Viewers can read and download, but cannot change sharing.";
      return "This item does not grant you the server-authorized sharing action.";
    }

    const everyoneGrant = () => model.grants.find((grant) => grant.principal.kind === "everyone" && grantActive(grant)) || null;

    function grantRows() {
      const grants = model.grants.filter(grantActive).filter((grant) => grant.principal.kind !== "everyone");
      if (model.loading && !model.loaded) return '<div class="drawer-empty" role="status">Loading people and groups…</div>';
      if (model.error && !model.loaded) return `<div class="drawer-human-status is-error" role="alert">${escapeHtml(model.error)} <button type="button" data-human-retry>Retry</button></div>`;
      if (!grants.length) return '<div class="drawer-empty">No people or groups have direct access.</div>';
      return `<div class="drawer-human-grant-list">${grants.map((grant) => {
        const controls = canManage() && grant.direct && grant.id
          ? `<label><span class="sr-only">Role for ${escapeHtml(grant.principal.label)}</span><select data-human-role="${escapeHtml(grant.id)}"><option value="viewer" ${grant.role === "viewer" ? "selected" : ""}>Viewer</option><option value="editor" ${grant.role === "editor" ? "selected" : ""}>Editor</option></select></label><button type="button" class="danger-action" data-human-revoke="${escapeHtml(grant.id)}">Remove</button>`
          : `<span class="member-role">${escapeHtml(sourceLabel(grant))}</span>`;
        return `<div class="drawer-human-grant-row"><span><strong>${escapeHtml(grant.principal.label)}</strong><small>${escapeHtml(grant.principal.detail)} · ${escapeHtml(sourceLabel(grant))} · ${escapeHtml(displayExpiry(grant.expires_at))}</small></span><span class="drawer-human-grant-actions">${controls}</span></div>`;
      }).join("")}</div>`;
    }

    function principalResults() {
      if (!model.query.trim()) return '<p class="drawer-human-hint">Search uses an exact email address or an email-address prefix. It never grants access from unconfirmed text.</p>';
      if (model.loading) return '<p class="drawer-human-hint" role="status">Searching approved people and groups…</p>';
      if (model.error) return `<p class="drawer-human-hint is-error" role="alert">${escapeHtml(model.error)}</p>`;
      if (!model.principals.length) return '<p class="drawer-human-hint">No matching enabled accounts or groups.</p>';
      return `<div class="drawer-human-results" role="listbox" aria-label="Matching people and groups">${model.principals.map((principal, index) => `<button type="button" role="option" aria-selected="${model.selectedPrincipal?.ref === principal.ref}" data-human-select-principal="${index}"><span><strong>${escapeHtml(principal.label)}</strong><small>${escapeHtml(principal.detail)}</small></span><span>${principal.kind === "group" ? "Group" : "Person"}</span></button>`).join("")}</div>`;
    }

    function peopleSection() {
      const readOnly = readOnlyMessage();
      const selected = model.selectedPrincipal;
      const status = model.feedback ? `<p class="drawer-human-status${model.error ? " is-error" : ""}" role="status">${escapeHtml(model.feedback)}</p>` : "";
      if (readOnly) return `<section class="drawer-section drawer-human-section" aria-labelledby="human-people-heading"><div class="drawer-section-head"><strong id="human-people-heading">People and groups</strong><span class="member-role">Item access</span></div><p class="drawer-copy">Folder access inherits to its live descendants; it never copies files.</p><p class="drawer-human-read-only" role="status">${escapeHtml(readOnly)}</p>${grantRows()}</section>`;
      return `<section class="drawer-section drawer-human-section" aria-labelledby="human-people-heading"><div class="drawer-section-head"><strong id="human-people-heading">People and groups</strong><span class="member-role">Item access</span></div><p class="drawer-copy">Give a listed person or group Viewer or Editor access to this ${escapeHtml(selectedFile()?.kind || "item")}. Folder access inherits to live descendants.</p><div class="drawer-human-picker"><div class="drawer-human-picker-inputs"><label><span class="sr-only">People or groups</span><select data-human-principal-kind aria-label="Search people or groups"><option value="account" ${model.principalKind === "account" ? "selected" : ""}>People</option><option value="group" ${model.principalKind === "group" ? "selected" : ""}>Groups</option></select></label><label class="drawer-human-search"><span class="sr-only">Search recipients</span><input type="search" data-human-principal-query value="${escapeHtml(model.query)}" autocomplete="off" placeholder="Search by email address" /></label></div>${principalResults()}<div class="drawer-human-add-row"><span>${selected ? `<strong>${escapeHtml(selected.label)}</strong><button type="button" data-human-clear-principal>Change</button>` : "Choose a listed recipient"}</span><label><span class="sr-only">Access role</span><select data-human-role-select><option value="viewer" ${model.role === "viewer" ? "selected" : ""}>Viewer</option><option value="editor" ${model.role === "editor" ? "selected" : ""}>Editor</option></select></label><label><span class="sr-only">Optional expiry</span><input type="datetime-local" data-human-expiry value="${escapeHtml(model.expiry)}" aria-label="Optional access expiry" /></label><button type="button" class="primary-action" data-human-add ${selected && !model.saving ? "" : "disabled"}>${model.saving ? "Saving…" : "Add access"}</button></div></div>${status}${grantRows()}</section>`;
    }

    function everyoneSection() {
      const grant = everyoneGrant();
      const readOnly = readOnlyMessage();
      const disabled = Boolean(readOnly) || !model.everyonePolicyEnabled;
      let action = "";
      if (grant && canManage()) action = `<button type="button" class="danger-action" data-human-revoke="${escapeHtml(grant.id)}">Remove everyone access</button>`;
      else if (model.everyoneConfirming && !disabled) action = `<div class="drawer-human-confirm" role="alert"><strong>Give everyone access?</strong><p>Every signed-in Drive account will receive ${roleLabel(model.role)} access to this item. This is separate from an empty recipient search.</p><label><span class="sr-only">Everyone role</span><select data-human-everyone-role><option value="viewer" ${model.role === "viewer" ? "selected" : ""}>Viewer</option><option value="editor" ${model.role === "editor" ? "selected" : ""}>Editor</option></select></label><button type="button" class="primary-action" data-human-everyone-confirm ${model.saving ? "disabled" : ""}>${model.saving ? "Saving…" : "Confirm everyone access"}</button><button type="button" data-human-everyone-cancel>Cancel</button></div>`;
      else if (!grant) action = `<button type="button" data-human-everyone-start ${disabled ? "disabled" : ""}>Give everyone access</button>`;
      const stateText = !model.everyonePolicyEnabled
        ? grant ? `${roleLabel(grant.role)} · Existing access remains active until removed. New or changed everyone access is blocked by administrator policy.` : "Disabled by administrator policy."
        : grant ? `${roleLabel(grant.role)} · ${displayExpiry(grant.expires_at)}` : "No Drive-wide access.";
      return `<section class="drawer-section drawer-human-everyone" aria-labelledby="human-everyone-heading"><div class="drawer-section-head"><strong id="human-everyone-heading">Everyone in this Drive</strong><span class="status-chip ${grant ? "active" : ""}">${grant ? "Active" : "Off"}</span></div><p class="drawer-copy">An explicit Drive-wide principal. It is never inferred from an empty picker, failed lookup, or dismissed search.</p><div class="drawer-human-everyone-row"><span><strong>${grant ? "Everyone has access" : "Everyone does not have access"}</strong><small>${escapeHtml(stateText)}</small></span>${action}</div></section>`;
    }

    function render() { return `${peopleSection()}${everyoneSection()}`; }

    async function load(file = selectedFile()) {
      model.fileId = String(file?.id || ""); model.principals = []; model.selectedPrincipal = null; model.error = ""; model.feedback = "";
      if (!model.fileId) return [];
      if (!canManage()) { model.grants = (file?.human_grants || []).map(normalizeGrant).filter(Boolean); model.loaded = true; return model.grants; }
      const requested = model.fileId; model.loading = true; model.loaded = false; rerender();
      try {
        const data = await adapter.grants(requested);
        if (requested !== String(selectedFile()?.id || "")) return [];
        model.grants = (data?.grants || data?.direct_grants || []).map(normalizeGrant).filter(Boolean);
        model.everyonePolicyEnabled = data?.everyone_policy_enabled === true;
        model.loaded = true; return model.grants;
      } catch (error) {
        if (requested !== String(selectedFile()?.id || "")) return [];
        model.error = String(error?.message || "Could not load item access."); model.grants = []; model.loaded = false; return [];
      } finally { if (requested === String(selectedFile()?.id || "")) { model.loading = false; rerender(); } }
    }

    async function search() {
      const query = model.query.trim(); const sequence = ++model.searchSequence; model.principals = []; model.selectedPrincipal = null; model.error = "";
      if (!query) { rerender('[data-human-principal-query]'); return []; }
      if (!canManage() || !model.fileId || model.fileId !== String(selectedFile()?.id || "")) return [];
      model.loading = true; rerender('[data-human-principal-query]');
      try {
        const data = await adapter.principals({ fileId: model.fileId, kind: model.principalKind, query });
        if (sequence !== model.searchSequence) return [];
        model.principals = (data?.principals || data?.items || []).map((item) => normalizePrincipal(item, model.principalKind)).filter(Boolean); return model.principals;
      } catch (error) { if (sequence === model.searchSequence) model.error = String(error?.message || "Could not search people and groups."); return []; }
      finally { if (sequence === model.searchSequence) { model.loading = false; rerender('[data-human-principal-query]'); } }
    }

    function queueSearch() { window.clearTimeout(model.searchTimer); model.searchTimer = window.setTimeout(() => { search(); }, 180); }
    async function create(principal) {
      if (!canManage() || !model.fileId) return;
      const payload = humanGrantPayload({ principal, role: model.role, expiry: model.expiry });
      model.saving = true; model.error = ""; rerender();
      try {
        await adapter.createGrant(model.fileId, payload); model.query = ""; model.principals = []; model.selectedPrincipal = null; model.everyoneConfirming = false;
        setFeedback(principal.kind === "everyone" ? "Everyone access added." : "Access added."); await load(); callbacks.refreshAfterMutation?.();
      } catch (error) { model.error = String(error?.message || "Could not add access."); }
      finally { model.saving = false; rerender(); }
    }
    async function updateRole(id, role) {
      if (!canManage() || !GRANT_ROLES.has(role)) return;
      model.saving = true; rerender();
      try { await adapter.updateGrant(id, { role }); setFeedback(`Access changed to ${roleLabel(role)}.`); await load(); callbacks.refreshAfterMutation?.(); }
      catch (error) { model.error = String(error?.message || "Could not change access."); }
      finally { model.saving = false; rerender(); }
    }
    async function revoke(id) {
      if (!canManage() || !id) return;
      const allowed = await (callbacks.confirmAction?.({ title: "Remove access?", message: "New access ends immediately. Previously downloaded files cannot be recalled.", confirmLabel: "Remove access" }) ?? Promise.resolve(true));
      if (!allowed) return;
      model.saving = true; rerender();
      try { await adapter.revokeGrant(id); setFeedback("Access removed."); await load(); callbacks.refreshAfterMutation?.(); }
      catch (error) { model.error = String(error?.message || "Could not remove access."); }
      finally { model.saving = false; rerender(); }
    }

    function bind(nextDrawer) {
      drawer = nextDrawer || drawer;
      drawer?.addEventListener("input", (event) => { const input = event.target.closest("[data-human-principal-query]"); if (input) { model.query = input.value; queueSearch(); } });
      drawer?.addEventListener("change", (event) => {
        const kind = event.target.closest("[data-human-principal-kind]");
        if (kind) { model.principalKind = kind.value; model.query = ""; model.principals = []; model.selectedPrincipal = null; rerender('[data-human-principal-query]'); return; }
        if (event.target.matches("[data-human-role-select], [data-human-everyone-role]")) model.role = event.target.value;
        if (event.target.matches("[data-human-expiry]")) model.expiry = event.target.value;
        const role = event.target.closest("[data-human-role]"); if (role) updateRole(role.dataset.humanRole, role.value);
      });
      drawer?.addEventListener("click", (event) => {
        const button = event.target.closest("button"); if (!button) return;
        if (button.matches("[data-human-retry]")) { load(); return; }
        if (button.matches("[data-human-select-principal]")) { model.selectedPrincipal = model.principals[Number(button.dataset.humanSelectPrincipal)] || null; rerender('[data-human-add]'); return; }
        if (button.matches("[data-human-clear-principal]")) { model.selectedPrincipal = null; rerender('[data-human-principal-query]'); return; }
        if (button.matches("[data-human-add]")) { create(model.selectedPrincipal); return; }
        if (button.matches("[data-human-everyone-start]")) { model.everyoneConfirming = true; rerender('[data-human-everyone-confirm]'); return; }
        if (button.matches("[data-human-everyone-cancel]")) { model.everyoneConfirming = false; rerender('[data-human-everyone-start]'); return; }
        if (button.matches("[data-human-everyone-confirm]")) { create({ kind: "everyone", ref: "" }); return; }
        if (button.matches("[data-human-revoke]")) revoke(button.dataset.humanRevoke);
      });
      drawer?.addEventListener("keydown", (event) => { if (event.key === "Escape" && model.everyoneConfirming) { model.everyoneConfirming = false; rerender('[data-human-everyone-start]'); } });
    }

    function clear() { window.clearTimeout(model.searchTimer); Object.assign(model, { fileId: "", grants: [], principals: [], selectedPrincipal: null, query: "", error: "", feedback: "", loaded: false, everyoneConfirming: false, everyonePolicyEnabled: false }); }
    function badgeForFile(file) {
      if (String(file?.id || "") !== model.fileId || !model.grants.some(grantActive)) return "";
      const everyone = everyoneGrant(); const people = model.grants.filter((grant) => grant.principal.kind !== "everyone" && grantActive(grant)).length;
      const label = everyone ? "People + everyone" : `${people} recipient${people === 1 ? "" : "s"}`;
      return `<span class="shared-item-badge human-share-badge" title="Human item access"><svg class="icon" aria-hidden="true"><use href="#i-share"/></svg><span>${escapeHtml(label)}</span></span>`;
    }
    return { model, bind, clear, load, render, badgeForFile };
  }
  window.ShellXDriveHumanSharingDrawer = { createController };
})();
