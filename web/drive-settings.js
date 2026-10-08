// Settings surface ownership and statistics rendering. This module keeps
// account, workspace, server-admin, and agent-only controls in separate DOM
// regions without growing the main Drive composition file.
(function attachDriveSettings(root) {
  "use strict";

  function createElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function moveSection(section, target, className, disclosureLabel) {
    if (!section || !target) return;
    section.classList.remove("admin-section", "active");
    section.classList.add(className);
    section.removeAttribute("data-admin-panel");
    if (!disclosureLabel) {
      target.append(section);
      return;
    }
    const disclosure = createElement("details", "workspace-settings-disclosure");
    disclosure.append(createElement("summary", "", disclosureLabel), section);
    target.append(disclosure);
  }

  function workspaceIsEmpty(entry) {
    const usage = entry?.usage || {};
    return [usage.current_file_bytes, usage.revision_bytes, usage.trashed_file_bytes]
      .every((value) => Number(value || 0) === 0);
  }

  function canDeleteWorkspace(entry) {
    return Boolean(entry?.workspace?.archived) && workspaceIsEmpty(entry);
  }

  function auxiliaryStorageSummary(usage, formatBytes) {
    const total = Number(usage?.auxiliary_storage_bytes);
    const limit = Number(usage?.auxiliary_storage_limit_bytes);
    if (!Number.isFinite(total) || !Number.isFinite(limit)) return "";
    const state = usage?.auxiliary_storage_over_limit ? " · over limit" : "";
    return `Metadata & collaboration ${formatBytes(total)} of ${formatBytes(limit)}${state}`;
  }

  function auxiliaryStorageRows(usage, formatBytes, detailed = false) {
    const summary = auxiliaryStorageSummary(usage, formatBytes);
    if (!summary) return [];
    const rows = [["Metadata & collaboration", summary.replace("Metadata & collaboration ", "")]];
    if (!detailed) return rows;
    return rows.concat([
      ["File metadata", formatBytes(usage.auxiliary_file_metadata_bytes)],
      ["Metadata search index", formatBytes(usage.auxiliary_metadata_fts_projection_bytes)],
      ["Comments & replies", formatBytes(usage.auxiliary_comment_reply_body_bytes)],
      ["Workspace notifications", formatBytes(usage.auxiliary_notification_bytes)],
      ["Queued workspace email", formatBytes(usage.auxiliary_email_outbox_bytes)],
    ]);
  }

  function activeAuthSessions(sessions, now = Date.now()) {
    return (sessions || []).filter((session) => {
      const expiresAt = Date.parse(session?.expires_at || "");
      return !session?.revoked && Number.isFinite(expiresAt) && expiresAt > now;
    });
  }

  function orderedSelfSessions(sessions, currentSessionId, now = Date.now()) {
    return activeAuthSessions(sessions, now).sort((left, right) => {
      const leftCurrent = left.id === currentSessionId ? 1 : 0;
      const rightCurrent = right.id === currentSessionId ? 1 : 0;
      if (leftCurrent !== rightCurrent) return rightCurrent - leftCurrent;
      return Date.parse(right.created_at || "") - Date.parse(left.created_at || "");
    });
  }

  function mountScopedSurfaces() {
    const workspacePolicies = document.getElementById("workspace-policy-settings-slot");
    for (const name of ["storage", "sharing", "cleanup"]) {
      moveSection(
        document.querySelector(`[data-admin-panel="${name}"]`),
        workspacePolicies,
        "workspace-settings-section",
        name === "cleanup" ? "Advanced cleanup" : undefined,
      );
    }

    const workspaceTools = document.getElementById("workspace-tools-settings-slot");
    for (const [formId, label] of [
      ["drop-form", "Upload drop links"],
      ["template-form", "Folder templates"],
    ]) {
      const section = document.getElementById(formId)?.closest("section");
      moveSection(section, workspaceTools, "workspace-settings-section", label);
    }

    const createPanel = document.querySelector(".create-workspace-panel");
    const createSlot = document.getElementById("admin-workspace-create-slot");
    if (createPanel && createSlot) createSlot.append(createPanel);

    // Debug API and protocol exercisers remain available through authenticated
    // HTTP tooling. They have no human-facing navigation or retained DOM panel.
    document.getElementById("debug-panel")?.remove();
    document.getElementById("advanced-section-tools")?.remove();
    document.getElementById("account-advanced-button")?.remove();
    document.getElementById("advanced-tab-debug")?.remove();
    document.getElementById("advanced-tab-tools")?.remove();
    document.getElementById("debug-auth-button")?.remove();

    // Host-profile drafts are an operator API concern, not a human settings
    // surface. Keep the authenticated endpoints available to automation while
    // excluding their non-live path and command fields from the Admin Center.
    document.getElementById("admin-sandbox-panel")?.remove();
    document.querySelector('[data-admin-section="sandbox"]')?.remove();
    document.querySelector('#admin-section-select option[value="sandbox"]')?.remove();
    document.getElementById("admin-status-sandbox")?.closest(".admin-status-chip")?.remove();
    document.getElementById("admin-status-maintenance")?.closest(".admin-status-chip")?.remove();
  }

  function createController(options) {
    const statisticsSummary = document.getElementById("workspace-statistics-summary");
    const statisticsList = document.getElementById("workspace-statistics-list");
    const statisticsRefresh = document.getElementById("workspace-statistics-refresh");
    const adminWorkspaceList = document.getElementById("admin-workspace-list");
    const adminWorkspaceRefresh = document.getElementById("admin-workspace-refresh");

    function applyWorkspaceScope() {
      const canManage = options.canManageWorkspace();
      const label = canManage ? "Workspace settings" : "Workspace details";
      const title = document.getElementById("workspace-settings-title");
      if (title) title.textContent = label;
      const openButton = document.getElementById("workspace-settings-button");
      if (openButton) {
        openButton.setAttribute("aria-label", label);
        openButton.title = label;
      }
      const mobileLabel = document.getElementById("account-workspace-settings-label");
      if (mobileLabel) mobileLabel.textContent = label;
      const rename = document.getElementById("workspace-rename-form");
      if (rename) rename.hidden = !canManage;
      for (const id of [
        "workspace-lifecycle-management",
        "workspace-member-settings",
        "shared-by-me-panel",
        "workspace-file-activity",
        "workspace-policy-settings-slot",
        "workspace-tools-settings-slot",
      ]) {
        const section = document.getElementById(id);
        if (section) section.hidden = !canManage;
      }
      return canManage;
    }

    function metric(label, value) {
      const item = createElement("div", "workspace-stat");
      item.append(
        createElement("strong", "workspace-stat-value", Number(value || 0).toLocaleString()),
        createElement("span", "workspace-stat-label", label),
      );
      return item;
    }

    function renderStatistics(data) {
      statisticsSummary?.replaceChildren(
        metric("File accesses", data?.access_count),
        metric("Downloads", data?.download_count),
        metric("Tracked files", data?.files?.length),
      );
      if (!statisticsList) return;
      statisticsList.replaceChildren();
      if (!data?.files?.length) {
        statisticsList.append(
          createElement(
            "p",
            "settings-empty",
            "No file opens or downloads have been recorded in this workspace yet.",
          ),
        );
        return;
      }
      for (const file of data.files) {
        const row = createElement("div", "workspace-statistics-row");
        const identity = createElement("span", "workspace-statistics-file");
        identity.append(
          createElement("strong", "", file.name),
          createElement(
            "small",
            "",
            file.last_downloaded_at || file.last_accessed_at
              ? `Last activity ${options.formatDate(file.last_downloaded_at || file.last_accessed_at)}`
              : "No recent activity",
          ),
        );
        const counts = createElement("span", "workspace-statistics-counts");
        counts.append(
          createElement("b", "", `${Number(file.access_count).toLocaleString()} opens`),
          createElement("b", "", `${Number(file.download_count).toLocaleString()} downloads`),
        );
        row.append(identity, counts);
        statisticsList.append(row);
      }
    }

    async function loadWorkspaceStatistics() {
      const workspace = options.getCurrentWorkspace();
      if (!workspace || !options.canManageWorkspace()) {
        renderStatistics(null);
        return null;
      }
      statisticsList?.replaceChildren(createElement("p", "settings-empty", "Loading activity…"));
      const data = await options.api(`/workspaces/${workspace.id}/file-statistics`);
      if (options.getCurrentWorkspace()?.id === workspace.id) renderStatistics(data);
      return data;
    }

    function renderAdminWorkspaces(data) {
      if (!adminWorkspaceList) return;
      adminWorkspaceList.replaceChildren();
      if (!data?.workspaces?.length) {
        adminWorkspaceList.append(createElement("p", "settings-empty", "No workspaces yet."));
        return;
      }
      for (const entry of data.workspaces) {
        const workspace = entry.workspace;
        const row = createElement("div", "admin-live-row admin-workspace-row");
        const identity = createElement("span", "");
        const state = workspace.archived ? "Archived" : "Active";
        identity.append(
          createElement("b", "", workspace.name),
          createElement(
            "small",
            "",
            `${state} · ${entry.member_count} member${entry.member_count === 1 ? "" : "s"} · ${options.formatBytes(entry.usage?.current_file_bytes || 0)}`,
          ),
        );
        row.append(identity);
        if (canDeleteWorkspace(entry)) {
          const remove = createElement("button", "danger-action", "Delete empty workspace");
          remove.type = "button";
          remove.dataset.deleteAdminWorkspace = workspace.id;
          remove.dataset.workspaceName = workspace.name;
          row.append(remove);
        }
        adminWorkspaceList.append(row);
      }
    }

    async function loadAdminWorkspaces() {
      if (!options.hasAdminTools()) return null;
      adminWorkspaceList?.replaceChildren(createElement("p", "settings-empty", "Loading workspaces…"));
      const data = await options.api("/admin/workspaces");
      renderAdminWorkspaces(data);
      return data;
    }

    statisticsRefresh?.addEventListener("click", () => {
      loadWorkspaceStatistics().catch((error) => options.showToast(error.message));
    });
    adminWorkspaceRefresh?.addEventListener("click", () => {
      loadAdminWorkspaces().catch((error) => options.showToast(error.message));
    });
    adminWorkspaceList?.addEventListener("click", (event) => {
      const button = event.target.closest("[data-delete-admin-workspace]");
      if (!button) return;
      const name = button.dataset.workspaceName || "this workspace";
      if (!root.confirm(`Permanently delete the empty archived workspace “${name}”?`)) return;
      button.disabled = true;
      options
        .api(`/admin/workspaces/${button.dataset.deleteAdminWorkspace}`, { method: "DELETE" })
        .then(async () => {
          options.showToast("Empty archived workspace deleted.");
          await Promise.all([loadAdminWorkspaces(), options.reloadWorkspaces()]);
        })
        .catch((error) => {
          button.disabled = false;
          options.showToast(error.message);
        });
    });

    return Object.freeze({
      applyWorkspaceScope,
      loadAdminWorkspaces,
      loadWorkspaceStatistics,
      renderStatistics,
    });
  }

  root.ShellXDriveSettings = Object.freeze({
    activeAuthSessions,
    auxiliaryStorageRows,
    auxiliaryStorageSummary,
    canDeleteWorkspace,
    createController,
    mountScopedSurfaces,
    orderedSelfSessions,
    workspaceIsEmpty,
  });
})(window);
