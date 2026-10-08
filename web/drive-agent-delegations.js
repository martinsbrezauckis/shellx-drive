// Account-wide AI delegation lifecycle. Issued keys remain in memory and the DOM only once.
(() => {
  const AGENT_EXPIRY_CHOICES = [
    [86400, "1 day"],
    [604800, "7 days"],
    [2592000, "30 days"],
    [7776000, "90 days"],
  ];

  function delegatedAgentPayload(name, expiresInSeconds) {
    const normalizedName = String(name || "").trim();
    if (!normalizedName || new TextEncoder().encode(normalizedName).length > 120) {
      throw new Error("Agent name must contain 1 to 120 bytes.");
    }
    const expiry = Number(expiresInSeconds);
    if (!AGENT_EXPIRY_CHOICES.some(([value]) => value === expiry)) {
      throw new Error("Choose a valid account-wide key lifetime.");
    }
    return { name: normalizedName, expires_in_seconds: expiry };
  }

  function createController({ state, api, callbacks }) {
    const { escapeHtml, compactDate, showToast, confirmAction, report } = callbacks;
    state.delegatedAgents ||= [];
    state.delegatedAgentsLoading ||= false;
    state.delegatedAgentsError ||= "";
    state.delegatedAgentsNextCursor ||= null;
    state.latestDelegatedAgentCredential ||= null;

    function destroyOneTimeCredentialNodes(root) {
      for (const node of root?.querySelectorAll?.(".drawer-agent-token, [data-agent-token]") || []) {
        node.replaceChildren();
        node.remove();
      }
    }

    function canManageDelegatedAgents() {
      return ["local_account", "sso", "delegated_agent", "operator"].includes(state.currentAccount?.auth_mode);
    }

    function delegatedAgentElements() {
      return {
        section: document.getElementById("settings-agent-delegations-section"),
        scope: document.getElementById("settings-agent-delegations-scope"),
        form: document.getElementById("settings-agent-delegations-form"),
        status: document.getElementById("settings-agent-delegations-status"),
        credential: document.getElementById("settings-agent-delegations-credential"),
        list: document.getElementById("settings-agent-delegations-list"),
      };
    }

    function setDelegatedAgentStatus(message = "", isError = false) {
      const status = delegatedAgentElements().status;
      if (!status) return;
      status.textContent = message;
      status.classList.toggle("is-error", isError);
    }

    function clearDelegatedAgentCredential() {
      const { credential } = delegatedAgentElements();
      destroyOneTimeCredentialNodes(credential);
      state.latestDelegatedAgentCredential = null;
    }

    function renderDelegatedAgentCredential(token, agent, rotation) {
      const { credential } = delegatedAgentElements();
      if (!credential || !token) return;
      clearDelegatedAgentCredential();
      const wrapper = document.createElement("div");
      wrapper.className = "drawer-agent-token settings-agent-token";
      wrapper.setAttribute("role", "status");
      wrapper.setAttribute("aria-label", rotation ? "Replacement account-wide agent key" : "New account-wide agent key");
      const title = document.createElement("strong");
      title.textContent = rotation ? "Copy this replacement key now" : "Copy this account-wide agent key now";
      const explanation = document.createElement("p");
      explanation.textContent = rotation
        ? "Drive will not show it again. Rotation invalidates the previous account-wide key."
        : "Drive will not show it again. Store it with the agent, not in browser storage.";
      const code = document.createElement("code");
      code.dataset.agentToken = "";
      code.textContent = token;
      const copy = document.createElement("button");
      copy.type = "button";
      copy.className = "primary-action";
      copy.dataset.copyDelegatedAgentToken = "";
      copy.textContent = "Copy key";
      wrapper.append(title, explanation, code, copy);
      credential.replaceChildren(wrapper);
      state.latestDelegatedAgentCredential = { token, principalId: agent.principal_id };
      copy.focus();
    }

    function delegatedAgentScopeCopy() {
      if (state.currentAccount?.is_admin) {
        return "These agents act with this signed-in account’s current administrator authority. If the account is demoted, active keys lose administrator access on their next request.";
      }
      return "These agents act with this signed-in account’s current Drive authority. They cannot gain administrator access unless this account is promoted.";
    }

    function renderDelegatedAgentSettings() {
      const { section, scope, form, list, credential } = delegatedAgentElements();
      if (!section || !scope || !form || !list || !credential) return;
      if (!canManageDelegatedAgents()) {
        section.hidden = true;
        clearDelegatedAgentCredential();
        list.replaceChildren();
        return;
      }
      section.hidden = false;
      scope.textContent = delegatedAgentScopeCopy();
      const formControls = form.querySelectorAll("input, select, button");
      for (const control of formControls) control.disabled = state.delegatedAgentsLoading;
      if (state.delegatedAgentsLoading) {
        list.innerHTML = `<div class="drawer-agent-status" role="status">Loading account-wide AI agents…</div>`;
        return;
      }
      if (state.delegatedAgentsError) {
        list.innerHTML = `<div class="drawer-agent-status is-error" role="alert">${escapeHtml(state.delegatedAgentsError)}</div>`;
        return;
      }
      const agents = state.delegatedAgents || [];
      if (!agents.length) {
        list.innerHTML = `<div class="drawer-empty">No account-wide AI agents yet.</div>`;
        return;
      }
      list.innerHTML = agents.map((agent) => {
        const status = agent.principal_disabled ? "Revoked" : agent.active ? "Active" : "Key needs rotation";
        const authority = agent.owner_is_admin ? "Administrator authority" : "Standard Drive authority";
        const lastUsed = agent.token_last_used_at ? `last used ${compactDate(agent.token_last_used_at)}` : "not used yet";
        const disabled = agent.principal_disabled ? "disabled" : "";
        return `<article class="settings-agent-row"><div class="settings-agent-row-head"><span><strong>${escapeHtml(agent.name)}</strong><small>${escapeHtml(status)} · ${escapeHtml(authority)} · ${escapeHtml(lastUsed)} · expires ${escapeHtml(compactDate(agent.token_expires_at))}</small></span><span class="settings-agent-actions"><label>Key lifetime<select data-delegated-agent-expiry="${escapeHtml(agent.principal_id)}" aria-label="Key lifetime for ${escapeHtml(agent.name)}" ${disabled}>${AGENT_EXPIRY_CHOICES.map(([value, label]) => `<option value="${value}" ${value === 2592000 ? "selected" : ""}>${label}</option>`).join("")}</select></label><button type="button" data-delegated-agent-rotate="${escapeHtml(agent.principal_id)}" aria-label="Rotate account-wide key for ${escapeHtml(agent.name)}" ${disabled}>Rotate key</button><button type="button" class="danger-action" data-delegated-agent-revoke="${escapeHtml(agent.principal_id)}" aria-label="Revoke account-wide agent ${escapeHtml(agent.name)}" ${disabled}>${agent.principal_disabled ? "Revoked" : "Revoke agent"}</button></span></div></article>`;
      }).join("") + (state.delegatedAgentsNextCursor
        ? `<button type="button" data-delegated-agents-more>Load more agents</button>`
        : "");
    }

    async function loadDelegatedAgents(more = false) {
      if (!canManageDelegatedAgents()) {
        Object.assign(state, { delegatedAgents: [], delegatedAgentsLoading: false, delegatedAgentsError: "", delegatedAgentsNextCursor: null });
        renderDelegatedAgentSettings();
        return [];
      }
      if (state.delegatedAgentsLoading) return state.delegatedAgents;
      const cursor = more ? state.delegatedAgentsNextCursor : null;
      if (more && !cursor) return state.delegatedAgents;
      const actor = state.currentAccount?.actor;
      state.delegatedAgentsLoading = true;
      state.delegatedAgentsError = "";
      if (!more) renderDelegatedAgentSettings();
      try {
        const data = await api(cursor ? `/agent-delegations?cursor=${encodeURIComponent(cursor)}` : "/agent-delegations");
        if (state.currentAccount?.actor !== actor) return [];
        state.delegatedAgents = more
          ? [...state.delegatedAgents, ...(Array.isArray(data.agents) ? data.agents : [])]
          : (Array.isArray(data.agents) ? data.agents : []);
        state.delegatedAgentsNextCursor = data.next_cursor || null;
        return state.delegatedAgents;
      } catch (error) {
        if (window.ShellXDriveAuthLifecycle?.isStale?.(error)) throw error;
        if (state.currentAccount?.actor === actor) {
          if (more) setDelegatedAgentStatus(error.message, true);
          else {
            state.delegatedAgents = [];
            state.delegatedAgentsNextCursor = null;
            state.delegatedAgentsError = error.message;
          }
        }
        return [];
      } finally {
        if (state.currentAccount?.actor === actor) {
          state.delegatedAgentsLoading = false;
          renderDelegatedAgentSettings();
        }
      }
    }

    async function submitDelegatedAgent(form) {
      if (!canManageDelegatedAgents() || state.delegatedAgentsLoading) return;
      const submit = form.querySelector("[data-delegated-agent-create]");
      submit.disabled = true;
      submit.setAttribute("aria-busy", "true");
      setDelegatedAgentStatus("Creating account-wide AI agent…");
      try {
        const data = await api("/agent-delegations", {
          method: "POST",
          body: JSON.stringify(delegatedAgentPayload(
            form.elements.delegated_agent_name?.value,
            form.elements.delegated_agent_expiry?.value,
          )),
        });
        form.reset();
        await loadDelegatedAgents();
        renderDelegatedAgentCredential(data.token, data.agent, false);
        setDelegatedAgentStatus(`${data.agent.name} is active. Copy the key now.`);
        showToast(`${data.agent.name} was created. Copy the key now.`);
      } catch (error) {
        setDelegatedAgentStatus(error.message, true);
        showToast(error.message);
      } finally {
        submit.disabled = false;
        submit.removeAttribute("aria-busy");
      }
    }

    async function copyDelegatedAgentToken() {
      const token = state.latestDelegatedAgentCredential?.token;
      if (!token) return;
      try {
        if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
        await navigator.clipboard.writeText(token);
        showToast("Account-wide agent key copied.");
      } catch {
        const node = document.querySelector("#settings-agent-delegations-credential [data-agent-token]");
        const selection = window.getSelection?.();
        if (node && selection) {
          const range = document.createRange();
          range.selectNodeContents(node);
          selection.removeAllRanges();
          selection.addRange(range);
        }
        showToast("Account-wide agent key selected. Copy it manually.");
      }
    }

    async function rotateDelegatedAgent(principalId) {
      const agent = (state.delegatedAgents || []).find((item) => item.principal_id === principalId);
      if (!agent || agent.principal_disabled) return;
      const expiry = Number(document.querySelector(`[data-delegated-agent-expiry="${CSS.escape(principalId)}"]`)?.value || 2592000);
      if (!await confirmAction({ title: `Rotate ${agent.name}'s key?`, message: "This immediately invalidates the previous account-wide key. Copy the replacement before closing Settings.", confirmLabel: "Rotate key" })) return;
      const data = await api(`/agent-delegations/${encodeURIComponent(principalId)}/rotate`, { method: "POST", body: JSON.stringify({ expires_in_seconds: expiry }) });
      await loadDelegatedAgents();
      renderDelegatedAgentCredential(data.token, data.agent, true);
      setDelegatedAgentStatus(`Key rotated for ${data.agent.name}. Copy the replacement now.`);
      showToast(`Key rotated for ${data.agent.name}. Copy the replacement now.`);
    }

    async function revokeDelegatedAgent(principalId) {
      const agent = (state.delegatedAgents || []).find((item) => item.principal_id === principalId);
      if (!agent || agent.principal_disabled) return;
      if (!await confirmAction({ title: `Revoke ${agent.name}?`, message: "This immediately disables the agent and invalidates its account-wide key. Folder-scoped AI workers are unchanged.", confirmLabel: "Revoke agent" })) return;
      await api(`/agent-delegations/${encodeURIComponent(principalId)}/revoke`, { method: "POST" });
      if (state.latestDelegatedAgentCredential?.principalId === principalId) clearDelegatedAgentCredential();
      await loadDelegatedAgents();
      setDelegatedAgentStatus(`${agent.name} was revoked.`);
      showToast(`${agent.name} was revoked.`);
    }

    function openSettings() {
      renderDelegatedAgentSettings();
      if (canManageDelegatedAgents()) loadDelegatedAgents();
    }

    function closeSettings() {
      clearDelegatedAgentCredential();
      renderDelegatedAgentSettings();
    }

    function clearState() {
      Object.assign(state, {
        delegatedAgents: [],
        delegatedAgentsLoading: false,
        delegatedAgentsError: "",
        delegatedAgentsNextCursor: null,
        latestDelegatedAgentCredential: null,
      });
      clearDelegatedAgentCredential();
      renderDelegatedAgentSettings();
    }

    function bind(settingsDrawer) {
      settingsDrawer?.addEventListener("click", (event) => {
        if (event.target.closest("[data-delegated-agents-more]")) return loadDelegatedAgents(true).catch(report);
        if (event.target.closest("[data-copy-delegated-agent-token]")) return copyDelegatedAgentToken().catch(report);
        const revoke = event.target.closest("[data-delegated-agent-revoke]");
        if (revoke) return revokeDelegatedAgent(revoke.dataset.delegatedAgentRevoke).catch(report);
        const rotate = event.target.closest("[data-delegated-agent-rotate]");
        if (rotate) return rotateDelegatedAgent(rotate.dataset.delegatedAgentRotate).catch(report);
      });
      settingsDrawer?.addEventListener("submit", (event) => {
        const form = event.target.closest("[data-delegated-agent-form]");
        if (!form) return;
        event.preventDefault();
        submitDelegatedAgent(form).catch(report);
      });
    }

    return { bind, clearState, closeSettings, loadDelegatedAgents, openSettings, renderSettings: renderDelegatedAgentSettings };
  }

  window.ShellXDriveAgentDelegations = {
    AGENT_EXPIRY_CHOICES,
    delegatedAgentPayload,
    createController,
  };
})();
