// Bounded admin-only canonical ownership inventory and lazy per-kind details.
(() => {
  const DETAIL_KINDS = ["human", "guest", "ai"];
  function createController({ adapter, escapeHtml } = {}) {
    const model = { loading: false, error: "", rows: [], nextCursor: null, details: new Map() };
    let container = null; let search = null;
    const escape = escapeHtml || ((value) => String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;"));
    const detailKey = (id, kind) => `${id}:${kind}`;

    function normalizeRow(raw) {
      const file = raw?.file || raw || {}; const id = file.id || raw?.canonical_item_id;
      if (!id) return null;
      const summary = raw?.share_summary || {};
      return {
        id: String(id), ownerKey: String(raw?.owner_user_id || file.workspace_id || id), owner: String(raw?.owner_label || "Unassigned workspace"),
        name: String(file.name || "Untitled item"), itemKind: String(file.kind || "file"), path: Array.isArray(raw?.canonical_path) ? raw.canonical_path.join(" / ") : String(raw?.canonical_path || "My files"),
        summary: { human: Number(summary.human_grant_count || 0), inherited: Number(summary.inherited_human_grant_count || 0), guest: Number(summary.guest_link_count || 0), ai: Number(summary.ai_grant_count || 0) },
      };
    }

    function uniqueRows() {
      const seen = new Set();
      return model.rows.filter((row) => { const key = `${row.ownerKey}:${row.id}`; if (seen.has(key)) return false; seen.add(key); return true; });
    }
    function summaryMarkup(row) {
      const human = `${row.summary.human} human${row.summary.inherited ? ` · ${row.summary.inherited} inherited` : ""}`;
      return `<span class="admin-canonical-summary"><span>${escape(human)}</span><span>${row.summary.guest} guest</span><span>${row.summary.ai} AI</span></span>`;
    }
    function detailLabel(kind) { return kind === "ai" ? "AI" : `${kind[0].toUpperCase()}${kind.slice(1)}`; }
    function entryText(kind, entry) {
      if (entry.error) return entry.error;
      if (kind === "human") return [entry.principal_label || "Recipient", entry.principal_kind, entry.role, entry.inherited ? "Inherited" : "Direct", entry.expires_at ? `expires ${entry.expires_at}` : "No expiry"].filter(Boolean).join(" · ");
      if (kind === "guest") return ["Guest link", entry.expires_at ? `expires ${entry.expires_at}` : "No expiry", entry.allow_download === false ? "Preview only" : "Downloads allowed"].join(" · ");
      return [entry.principal_label || entry.principal_id || entry.agent_name || "AI principal", entry.role || entry.access_role, entry.expires_at ? `expires ${entry.expires_at}` : "No expiry"].filter(Boolean).join(" · ");
    }
    function detailButton(row, kind) {
      const detail = model.details.get(detailKey(row.id, kind)); const label = detailLabel(kind);
      return `<button type="button" data-human-admin-detail="${escape(row.id)}" data-human-admin-kind="${kind}" aria-expanded="${detail?.expanded === true}">${detail?.loading ? `Loading ${label}…` : `${detail?.expanded ? "Hide" : "Show"} ${label}`}</button>`;
    }
    function detailContent(row, kind) {
      const detail = model.details.get(detailKey(row.id, kind)); if (!detail?.expanded) return "";
      const label = detailLabel(kind);
      const entries = detail.entries || []; const rows = entries.length ? entries.map((entry) => `<span>${escape(entryText(kind, entry))}</span>`).join("") : `<span>No active ${label.toLowerCase()} access.</span>`;
      const more = detail.nextCursor ? `<button type="button" data-human-admin-more-detail="${escape(row.id)}" data-human-admin-kind="${kind}">Load more ${label.toLowerCase()} details</button>` : "";
      return `<div class="admin-canonical-detail"><strong>${label} access</strong>${rows}${more}</div>`;
    }
    function rowMarkup(row) {
      return `<article class="admin-canonical-row" data-human-admin-item="${escape(row.id)}"><span><strong>${escape(row.name)}</strong><small>${escape(row.itemKind)} · ${escape(row.path)}</small></span>${summaryMarkup(row)}<span class="admin-canonical-actions">${DETAIL_KINDS.map((kind) => detailButton(row, kind)).join("")}</span>${DETAIL_KINDS.map((kind) => detailContent(row, kind)).join("")}</article>`;
    }
    function render() {
      if (!container) return;
      const rows = uniqueRows();
      if (model.loading && !rows.length) { container.innerHTML = '<div class="admin-empty" role="status"><strong>Loading canonical content…</strong><span>Owners and share summaries stay bounded.</span></div>'; return; }
      if (model.error && !rows.length) { container.innerHTML = `<div class="admin-empty" role="alert"><strong>Could not load canonical content</strong><span>${escape(model.error)}</span><button type="button" data-human-admin-refresh>Retry</button></div>`; return; }
      if (!rows.length) { container.innerHTML = '<div class="admin-empty"><strong>No canonical content found</strong><span>Try a different owner, name, or path.</span></div>'; return; }
      const grouped = new Map(); for (const row of rows) grouped.set(row.ownerKey, { owner: row.owner, rows: [...(grouped.get(row.ownerKey)?.rows || []), row] });
      const alert = model.error ? `<p class="drawer-human-status is-error" role="alert">${escape(model.error)}</p>` : "";
      const more = model.nextCursor ? '<button type="button" data-human-admin-more>Load more canonical content</button>' : "";
      container.innerHTML = `${alert}<div class="admin-canonical-tree">${[...grouped.values()].map((group) => `<section class="admin-canonical-owner"><h4>${escape(group.owner)}</h4><p>My files</p>${group.rows.map(rowMarkup).join("")}</section>`).join("")}</div>${more}`;
    }
    async function load({ append = false } = {}) {
      if (append && !model.nextCursor) return; if (!append) { model.rows = []; model.nextCursor = null; model.details = new Map(); }
      model.loading = true; model.error = ""; render();
      try {
        const data = await adapter.adminContent({ query: search?.value || "", cursor: append ? model.nextCursor : "" });
        const rows = (data?.items || []).map(normalizeRow).filter(Boolean); model.rows = append ? [...model.rows, ...rows] : rows; model.nextCursor = data?.next_cursor || null;
      } catch (error) { model.error = String(error?.message || "The canonical inventory is unavailable."); }
      finally { model.loading = false; render(); }
    }
    async function loadDetails(id, kind, { append = false } = {}) {
      if (!DETAIL_KINDS.includes(kind)) return; const key = detailKey(id, kind); const existing = model.details.get(key) || { entries: [], nextCursor: null };
      if (append && !existing.nextCursor) return; model.details.set(key, { ...existing, loading: true, expanded: true }); render();
      try {
        const data = await adapter.adminDetail(id, { kind, cursor: append ? existing.nextCursor : "" }); const entries = Array.isArray(data?.entries) ? data.entries : [];
        model.details.set(key, { entries: append ? [...existing.entries, ...entries] : entries, nextCursor: data?.next_cursor || null, expanded: true, loading: false });
      } catch (error) { model.details.set(key, { ...existing, expanded: true, loading: false, entries: [{ error: `Details unavailable: ${String(error?.message || "request failed")}` }] }); }
      render();
    }
    function toggleDetail(id, kind) {
      const detail = model.details.get(detailKey(id, kind)); if (detail?.expanded && !detail.loading) { model.details.set(detailKey(id, kind), { ...detail, expanded: false }); render(); return; }
      if (detail?.entries && !detail.loading) { model.details.set(detailKey(id, kind), { ...detail, expanded: true }); render(); return; }
      loadDetails(id, kind);
    }
    function bind(nextContainer, nextSearch) {
      container = nextContainer || container; search = nextSearch || search;
      container?.addEventListener("click", (event) => {
        if (event.target.closest("[data-human-admin-refresh]")) { load(); return; }
        if (event.target.closest("[data-human-admin-more]")) { load({ append: true }); return; }
        const more = event.target.closest("[data-human-admin-more-detail]"); if (more) { loadDetails(more.dataset.humanAdminMoreDetail, more.dataset.humanAdminKind, { append: true }); return; }
        const detail = event.target.closest("[data-human-admin-detail]"); if (detail) toggleDetail(detail.dataset.humanAdminDetail, detail.dataset.humanAdminKind);
      });
      search?.addEventListener("search", () => load());
    }
    function clear() { Object.assign(model, { loading: false, error: "", rows: [], nextCursor: null, details: new Map() }); }
    return { model, bind, clear, load, loadDetails, render };
  }
  window.ShellXDriveHumanSharingAdmin = { createController };
})();
