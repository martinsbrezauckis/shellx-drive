// API paths and normalization for canonical human item sharing.
(() => {
  const PRINCIPAL_KINDS = new Set(["account", "group"]);
  const GRANT_ROLES = new Set(["viewer", "editor"]);
  const MAX_PRINCIPAL_LIMIT = 50;
  const ADMIN_PAGE_LIMIT = 50;
  const pathPart = (value) => encodeURIComponent(String(value || ""));
  const roleLabel = (role) => role === "editor" ? "Editor" : role === "viewer" ? "Viewer" : "Read-only";

  function accessGenerationPart(value) {
    if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) return String(value);
    if (typeof value === "string" && /^(?:[1-9][0-9]{0,19})$/.test(value)) {
      if (BigInt(value) <= 18_446_744_073_709_551_615n) return value;
    }
    throw new Error("This shared item needs refreshed access details. Refresh Shared with me.");
  }

  function sourceLabel(grant) {
    if (grant?.direct === false || grant?.inherited) return "Inherited";
    if (grant?.source === "group") return "Via group";
    if (grant?.source === "everyone") return "Everyone";
    if (grant?.source === "workspace") return "Workspace";
    return "Direct";
  }

  function displayExpiry(value) {
    if (!value) return "No expiry";
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed)) return "Expiry unavailable";
    return `Expires ${new Date(parsed).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}`;
  }

  function grantActive(grant, now = Date.now()) {
    if (!grant || grant.revoked || grant.active === false) return false;
    if (!grant.expires_at) return true;
    const expiresAt = Date.parse(grant.expires_at);
    return Number.isFinite(expiresAt) && expiresAt > now;
  }

  function normalizePrincipal(raw, kindHint = "account", { requireEnabled = true } = {}) {
    const kind = raw?.kind === "group" || raw?.principal_kind === "group" ? "group" : kindHint;
    const ref = raw?.principal_ref || raw?.reference || raw?.ref || raw?.id || raw?.account_id || raw?.group_id || "";
    // A contact is not a grantable recipient until server authentication is enabled.
    const enabled = raw?.auth_enabled === true || raw?.can_receive_grant === true;
    if (!PRINCIPAL_KINDS.has(kind) || !String(ref).trim() || raw?.auth_enabled === false || raw?.can_receive_grant === false) return null;
    if (kind === "account" && requireEnabled && !enabled) return null;
    return {
      kind,
      ref: String(ref),
      label: String(raw?.principal_label || raw?.display_name || raw?.name || raw?.email || raw?.label || "Unnamed recipient"),
      detail: String(raw?.detail || raw?.email || (kind === "group" ? "Group" : "Account")),
    };
  }

  function normalizeGrant(raw) {
    const kind = raw?.principal_kind || raw?.kind || "account";
    const principal = kind === "everyone"
      ? { kind: "everyone", ref: "", label: "Everyone in this Drive", detail: "Explicit Drive-wide access" }
      : normalizePrincipal({ ...raw, kind }, kind, { requireEnabled: false });
    if (!principal) return null;
    return {
      id: String(raw?.grant_id || raw?.id || ""), principal,
      role: GRANT_ROLES.has(raw?.role) ? raw.role : "viewer",
      expires_at: raw?.expires_at || null, revoked: Boolean(raw?.revoked || raw?.revoked_at), active: raw?.active !== false,
      direct: raw?.direct !== false && !raw?.inherited, inherited: Boolean(raw?.inherited),
      source: raw?.source || raw?.source_kind || (kind === "everyone" ? "everyone" : "direct"),
    };
  }

  function optionalExpiry(value, now = Date.now()) {
    const input = String(value || "").trim();
    if (!input) return undefined;
    const millis = Date.parse(input);
    if (!Number.isFinite(millis) || millis <= now) throw new Error("Choose an expiry in the future, or leave it empty.");
    return new Date(millis).toISOString();
  }

  function humanGrantPayload({ principal, role, expiry }) {
    if (!principal || !["account", "group", "everyone"].includes(principal.kind)) throw new Error("Choose a person or group before adding access.");
    if (!GRANT_ROLES.has(role)) throw new Error("Choose Viewer or Editor access.");
    const payload = { principal_kind: principal.kind, role };
    if (principal.kind !== "everyone") {
      if (!String(principal.ref || "").trim()) throw new Error("Choose a listed person or group before adding access.");
      payload.principal_ref = String(principal.ref);
    }
    const expiresAt = optionalExpiry(expiry);
    if (expiresAt) payload.expires_at = expiresAt;
    return payload;
  }

  function canonicalRootKey(root) {
    const workspace = root?.canonical_workspace_id || root?.workspace_id;
    const file = root?.canonical_root_id || root?.root_file_id || root?.file_id || root?.id;
    return workspace && file ? `${workspace}:${file}` : "";
  }

  function activeGuestLink(link, now = Date.now()) {
    if (!link || (link.uses_remaining != null && Number(link.uses_remaining) <= 0)) return false;
    if (!link.expires_at) return true;
    const expiresAt = Date.parse(link.expires_at);
    return Number.isFinite(expiresAt) && expiresAt > now;
  }

  function sharedByMeSummary(root, now = Date.now()) {
    let people = 0; let groups = 0; let everyone = false;
    for (const raw of Array.isArray(root?.grants) ? root.grants : []) {
      const grant = normalizeGrant(raw);
      if (!grant || !grantActive(grant, now)) continue;
      if (grant.principal.kind === "account") people += 1;
      else if (grant.principal.kind === "group") groups += 1;
      else if (grant.principal.kind === "everyone") everyone = true;
    }
    const guestLinks = (Array.isArray(root?.guest_links) ? root.guest_links : [])
      .filter((link) => activeGuestLink(link, now)).length;
    const parts = ["Shared"];
    if (people) parts.push(`${people} ${people === 1 ? "person" : "people"}`);
    if (groups) parts.push(`${groups} ${groups === 1 ? "group" : "groups"}`);
    if (everyone) parts.push("Everyone");
    if (guestLinks) parts.push(`${guestLinks} ${guestLinks === 1 ? "guest link" : "guest links"}`);
    return parts.join(" · ");
  }

  function normalizeRoot(raw, listKind) {
    const file = raw?.file && typeof raw.file === "object" ? raw.file : {};
    const id = raw?.canonical_root_id || raw?.root_file_id || raw?.file_id || raw?.id || file.id;
    const workspace = raw?.canonical_workspace_id || raw?.workspace_id || file.workspace_id;
    if (!id || !workspace) return null;
    const sharedByMe = listKind === "shared-by-me";
    const role = sharedByMe ? "owner" : GRANT_ROLES.has(raw?.effective_role) ? raw.effective_role : GRANT_ROLES.has(raw?.role) ? raw.role : "viewer";
    return {
      ...file, ...raw, id: String(id), canonical_root_id: String(id), canonical_workspace_id: String(workspace), workspace_id: String(workspace),
      name: String(raw?.display_label || raw?.label || raw?.name || raw?.root_name || file.name || "Shared item"), kind: (raw?.kind || file.kind) === "file" ? "file" : "folder", parent_id: null,
      owned_by_actor: sharedByMe || Boolean(raw?.owned_by_actor), effective_role: role,
      human_share_root: true, human_share_list: listKind, owner_label: String(raw?.owner_display_name || raw?.owner_label || raw?.owner_name || (sharedByMe ? "You" : "Owner")),
      workspace_name: String(raw?.workspace_name || raw?.owner_workspace_label || "My files"), grant_source: raw?.grant_source || raw?.source || (raw?.inherited ? "inherited" : "direct"),
      expires_at: raw?.expires_at || null, read_only: !sharedByMe && role === "viewer",
    };
  }

  function dedupeCanonicalRoots(roots, listKind) {
    const seen = new Set();
    return (Array.isArray(roots) ? roots : []).map((root) => normalizeRoot(root, listKind)).filter((root) => {
      if (["revoked", "expired", "removed"].includes(root?.access_state)) return false;
      if (root?.expires_at && Date.parse(root.expires_at) <= Date.now()) return false;
      const key = canonicalRootKey(root);
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function actionCapability(file, name) {
    const actions = file?.action_capabilities || file?.capabilities || file?.actions;
    return actions?.[name] === true;
  }

  function createAdapter(api, endpoints = {}) {
    const adminContent = endpoints.adminContent || "/admin/canonical-content";
    const adminDetail = endpoints.adminDetail || ((id) => `${adminContent}/${pathPart(id)}/share-details`);
    return {
      async principals({ fileId, kind, query, limit = 20 }) {
        if (!PRINCIPAL_KINDS.has(kind)) throw new Error("Choose people or groups.");
        if (!String(fileId || "").trim()) throw new Error("Select an owner-manageable item before searching people or groups.");
        const text = String(query || "").trim();
        if (!text) throw new Error("Type an email address or address prefix to search.");
        const params = new URLSearchParams({ file_id: String(fileId), kind, query: text, limit: String(Math.max(1, Math.min(MAX_PRINCIPAL_LIMIT, Number(limit) || 20))) });
        return api(`/share-principals?${params.toString()}`);
      },
      grants: (fileId) => api(`/files/${pathPart(fileId)}/human-grants`),
      capabilities: (fileId) => api(`/files/${pathPart(fileId)}/action-capabilities`),
      createGrant: (fileId, payload) => api(`/files/${pathPart(fileId)}/human-grants`, { method: "POST", body: JSON.stringify(payload) }),
      updateGrant: (id, payload) => api(`/human-grants/${pathPart(id)}`, { method: "PATCH", body: JSON.stringify(payload) }),
      revokeGrant: (id) => api(`/human-grants/${pathPart(id)}`, { method: "DELETE" }),
      sharedWithMe: ({ cursor = null, limit = 100 } = {}) => {
        const query = new URLSearchParams({ limit: String(limit) });
        if (cursor) query.set("cursor", cursor);
        return api(`/sharing/shared-with-me?${query}`);
      },
      sharedByMe: ({ cursor = null, limit = 100 } = {}) => {
        const query = new URLSearchParams({ limit: String(limit) });
        if (cursor) query.set("cursor", cursor);
        return api(`/sharing/shared-by-me?${query}`);
      },
      scopedRootManifest: (root) => {
        const subject = root?.sync_root_id || root?.root_subject_id || root?.grant_id;
        if (!subject) throw new Error("This shared root is no longer available.");
        const query = new URLSearchParams({ access_generation: accessGenerationPart(root?.access_generation) });
        return api(`/sync/roots/${pathPart(subject)}/manifest?${query.toString()}`);
      },
      revalidateScopedRoot: async (root) => {
        const subject = root?.sync_root_id || root?.root_subject_id || root?.grant_id;
        const data = await api("/sync/roots/revalidate", { method: "POST", body: JSON.stringify({ root_ids: [subject] }) });
        const fresh = data?.roots?.find((candidate) => candidate.id === subject)
          || data?.replacements?.find((candidate) => candidate.requested_id === subject)?.root;
        if (!fresh || (fresh.root_file_id && fresh.root_file_id !== root.id)) {
          throw Object.assign(new Error("Shared item unavailable"), { status: 404 });
        }
        return { ...root, sync_root_id: fresh.id, access_generation: fresh.access_generation, effective_role: fresh.role, action_capabilities: fresh.action_capabilities };
      },
      adminContent: ({ query = "", cursor = "", limit = ADMIN_PAGE_LIMIT } = {}) => {
        const params = new URLSearchParams({ limit: String(Math.max(1, Math.min(100, Number(limit) || ADMIN_PAGE_LIMIT))) });
        if (cursor) params.set("cursor", String(cursor));
        if (String(query).trim()) params.set("query", String(query).trim());
        return api(`${adminContent}?${params.toString()}`);
      },
      adminDetail: (id, { kind, cursor = "", limit = 25 } = {}) => {
        if (!["human", "guest", "ai"].includes(kind)) throw new Error("Choose human, guest, or AI share details.");
        const params = new URLSearchParams({ kind, limit: String(Math.max(1, Math.min(50, Number(limit) || 25))) });
        if (cursor) params.set("cursor", String(cursor));
        return api(`${adminDetail(id)}?${params.toString()}`);
      },
    };
  }

  window.ShellXDriveHumanSharingContract = {
    PRINCIPAL_KINDS, GRANT_ROLES, MAX_PRINCIPAL_LIMIT, ADMIN_PAGE_LIMIT, roleLabel, sourceLabel, displayExpiry, grantActive,
    normalizePrincipal, normalizeGrant, optionalExpiry, humanGrantPayload, canonicalRootKey, activeGuestLink, sharedByMeSummary, normalizeRoot, dedupeCanonicalRoots,
    actionCapability, accessGenerationPart, createAdapter,
  };
})();
