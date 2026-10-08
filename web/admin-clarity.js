(function attachAdminClarity(root) {
  "use strict";

  const EVENT_PRESENTATION = {
    "auth.logout": ["Browser signed out", "A browser session was ended.", "access"],
    "auth.session.revoke": ["Browser session revoked", "A signed-in browser was forced to sign out.", "access"],
    "session.revoke": ["Browser session revoked", "A signed-in browser was forced to sign out.", "access"],
    "auth.password.change": ["Password changed", "An account password was replaced.", "access"],
    "auth.user.create": ["Account created", "A person was given a Drive account.", "access"],
    "auth.user.update": ["Account updated", "Account access or security settings changed.", "access"],
    "auth.account.create": ["Account created", "A person was given a Drive account.", "access"],
    "auth.account.update": ["Account updated", "Account access or security settings changed.", "access"],
    "auth.account.disable": ["Account disabled", "Sign-in was stopped and existing account credentials were revoked.", "access"],
    "auth.account.enable": ["Account enabled", "Sign-in was restored for an account.", "access"],
    "auth.account.password_reset": ["Account password reset", "An administrator replaced the password and revoked existing account credentials.", "access"],
    "auth.account.2fa_reset": ["Account 2FA reset", "An administrator removed the account's authenticator setup and revoked existing credentials.", "access"],
    "auth.password_reset.link.create": ["Recovery link created", "A server administrator created a one-time password-recovery link.", "access"],
    "auth.password_reset.link.revoke": ["Recovery link revoked", "A server administrator invalidated an unused password-recovery link.", "access"],
    "workspace.create": ["Workspace created", "A new workspace was added to this server.", "files"],
    "workspace.update": ["Workspace updated", "Workspace details or lifecycle state changed.", "files"],
    "workspace.delete": ["Workspace deleted", "An empty archived workspace was permanently removed.", "files"],
    "file.create": ["File added", "A file was added to a workspace.", "files"],
    "file.update": ["File updated", "File content or metadata changed.", "files"],
    "file.delete": ["File deleted", "A file was moved to Trash or permanently removed.", "files"],
    "file.restore": ["File restored", "A file was restored from Trash.", "files"],
    "folder.create": ["Folder created", "A folder was added to a workspace.", "files"],
    "share.create": ["Guest link created", "Read-only guest access was created.", "sharing"],
    "share.update": ["Guest link updated", "A guest link rule changed.", "sharing"],
    "share.revoke": ["Guest link revoked", "Guest access was stopped.", "sharing"],
    "drop.create": ["Upload link created", "A guest upload destination was created.", "sharing"],
    "drop.revoke": ["Upload link revoked", "Guest uploads were stopped.", "sharing"],
    "backup.create.intent": ["Backup queued", "A full server snapshot was queued.", "backups"],
    "backup.create": ["Backup completed", "A full server snapshot finished.", "backups"],
    "backup.validate": ["Backup checked", "A backup archive passed or failed validation.", "backups"],
    "backup.restore": ["Backup restored", "The server was restored from a selected snapshot.", "backups"],
    "backup.delete": ["Backup deleted", "A snapshot was permanently removed from this server.", "backups"],
    "backup.download": ["Backup downloaded", "An administrator started an archive download.", "backups"],
    "backup.policy.update": ["Backup schedule changed", "Automatic backup frequency or retention changed.", "backups"],
    "maintenance.check": ["Host summary viewed", "An administrator opened the saved host summary; no update was run.", "host"],
    "maintenance.blob.gc": ["Storage cleanup run", "Unreferenced stored blobs were checked and removed when eligible.", "host"],
    "sandbox.profile.update": ["Host profile draft saved", "A deployment draft changed; the live host was not modified.", "host"],
    "sandbox.apply.intent": ["Host profile plan recorded", "An audit record was saved; Drive did not apply the profile.", "host"],
    "support_bundle.create": ["Support bundle created", "A redacted diagnostic bundle was prepared.", "host"],
  };

  const AUTH_SCOPE_LABELS = {
    password: "Password sign-in",
    auth_login_client: "Account sign-in",
    totp: "Authenticator code",
    password_change: "Password change",
    password_reset_client: "Password-reset request",
    password_reset_email: "Password-reset email",
    password_reset_consume_client: "Password-reset link",
    totp_setup_password: "2FA setup password",
    totp_security_mutation_factor: "2FA security change",
    share_password: "Guest-link password",
    drop_password: "Upload-link password",
    share_password_work: "Guest-link password work allowance",
    share_password_work_capability: "Guest-link shared work allowance",
    drop_password_work: "Upload-link password work allowance",
    drop_password_work_capability: "Upload-link shared work allowance",
  };

  const PASSWORD_WORK_SCOPES = new Set([
    "share_password_work",
    "share_password_work_capability",
    "drop_password_work",
    "drop_password_work_capability",
  ]);

  const CLIENT_SCOPES = new Set([
    "auth_login_client",
    "password_reset_client",
    "password_reset_consume_client",
  ]);

  function normalize(value) {
    return String(value || "").trim().toLocaleLowerCase();
  }

  function sessionReference(id) {
    const compact = String(id || "").replaceAll("-", "");
    return compact ? compact.slice(0, 8).toUpperCase() : "Unavailable";
  }

  function sessionIssuerLabel(issuer) {
    const labels = {
      "local-password": "Password sign-in",
      "local-sso": "Single sign-on",
      oidc: "Single sign-on",
    };
    return labels[issuer] || String(issuer || "Sign-in").replaceAll("-", " ");
  }

  function clientReference(fingerprint) {
    const value = String(fingerprint || "");
    if (!value) return "Client not recorded";
    const tail = value.split("-").at(-1)?.slice(-8).toUpperCase();
    return tail ? `Client ${tail}` : "Client recorded";
  }

  function browserDeviceLabel(userAgent) {
    const value = String(userAgent || "");
    if (!value) return "Browser not recorded";
    const browser = value.match(/Edg\/([\d.]+)/) ? "Edge"
      : value.match(/Firefox\/([\d.]+)/) ? "Firefox"
        : value.match(/(?:Chrome|CriOS)\/([\d.]+)/) ? "Chrome"
          : value.includes("Safari/") && value.includes("Version/") ? "Safari"
            : "Browser";
    const platform = /Windows/i.test(value) ? "Windows"
      : /Android/i.test(value) ? "Android"
        : /iPhone|iPad/i.test(value) ? "iPhone or iPad"
          : /Mac OS X|Macintosh/i.test(value) ? "macOS"
            : /Linux/i.test(value) ? "Linux"
              : "unknown device";
    return `${browser} on ${platform}`;
  }

  function filterSessions(sessions, query) {
    const needle = normalize(query);
    if (!needle) return sessions || [];
    return (sessions || []).filter((session) =>
      normalize([
        session.actor_email,
        session.issuer,
        sessionIssuerLabel(session.issuer),
        sessionReference(session.id),
        session.client_ip,
        session.user_agent,
        browserDeviceLabel(session.user_agent),
      ].join(" ")).includes(needle),
    );
  }

  function filterAuthAccounts(accounts, query, filter = "all") {
    const needle = normalize(query);
    return (accounts || []).filter((account) => {
      const matchesFilter = filter === "all"
        || (filter === "active" && !account.disabled)
        || (filter === "disabled" && account.disabled)
        || (filter === "admin" && account.is_admin)
        || (filter === "2fa" && account.totp_enabled);
      return matchesFilter && (!needle || normalize(account.email).includes(needle));
    });
  }

  function filterAuthAttempts(attempts, query, filter = "all", now = Date.now()) {
    const needle = normalize(query);
    return (attempts || []).filter((attempt) => {
      const locked = Boolean(attempt.locked_until && Date.parse(attempt.locked_until) > now);
      const matchesFilter = filter === "all"
        || (filter === "locked" && locked)
        || (filter === "counters" && !locked);
      const text = [
        attempt.actor_email,
        AUTH_SCOPE_LABELS[attempt.scope] || attempt.scope,
        clientReference(attempt.client_fingerprint),
      ].join(" ");
      return matchesFilter && (!needle || normalize(text).includes(needle));
    });
  }

  function authAttemptTargetLabel(attempt) {
    if (String(attempt.actor_email || "").startsWith("unknown:")) return "Unknown account sign-in";
    if (attempt.actor_email) return attempt.actor_email;
    if (CLIENT_SCOPES.has(attempt.scope)) return "This client reference";
    if (attempt.scope === "password_reset_email") return "Account recovery request";
    if (["share_password", "drop_password"].includes(attempt.scope) || PASSWORD_WORK_SCOPES.has(attempt.scope)) return "Public guest endpoint";
    return "Account not recorded";
  }

  function humanizeEventKind(kind) {
    if (EVENT_PRESENTATION[kind]) return EVENT_PRESENTATION[kind][0];
    const words = String(kind || "Activity").replace(/[._]+/g, " ").trim();
    return words.charAt(0).toUpperCase() + words.slice(1);
  }

  function buildActivityEvents(summary) {
    const grouped = new Map();
    const seen = new Set();
    for (const event of [...(summary?.recent_receipts || []), ...(summary?.recent_activity || [])]) {
      const exactKey = [event.kind, event.actor, event.target_id, event.created_at].join("|");
      if (seen.has(exactKey)) continue;
      seen.add(exactKey);
      const presentation = EVENT_PRESENTATION[event.kind] || [
        humanizeEventKind(event.kind),
        "A server action was recorded.",
        "other",
      ];
      const key = [event.kind, event.actor, event.target_id].join("|");
      const existing = grouped.get(key);
      if (existing) {
        existing.count += 1;
        if (Date.parse(event.created_at) > Date.parse(existing.at)) existing.at = event.created_at;
      } else {
        grouped.set(key, {
          actor: event.actor || "System",
          at: event.created_at,
          category: presentation[2],
          count: 1,
          description: presentation[1],
          label: presentation[0],
        });
      }
    }
    return [...grouped.values()].sort((left, right) => Date.parse(right.at) - Date.parse(left.at));
  }

  function filterActivity(events, query, category = "all") {
    const needle = normalize(query);
    return (events || []).filter((event) => {
      const matchesCategory = category === "all" || event.category === category;
      const text = [event.label, event.description, event.actor, event.category].join(" ");
      return matchesCategory && (!needle || normalize(text).includes(needle));
    });
  }

  function renderSessions(options) {
    const sessions = filterSessions(options.sessions, options.query);
    if (!sessions.length) {
      options.renderEmpty(
        options.element,
        options.query ? "No matching sessions" : "No active sessions",
        options.query ? "Try a different account or session reference." : "New browser sign-ins will appear here.",
      );
      return;
    }
    options.element.classList.remove("admin-skeleton", "admin-skeleton-tiles");
    options.element.replaceChildren(...sessions.map((session) => {
      const row = document.createElement("div");
      row.className = options.admin ? "admin-live-row admin-session-row" : "session-row";
      const current = Boolean(options.currentSessionId && session.id === options.currentSessionId);
      const title = options.admin ? session.actor_email : current ? "This browser" : "Another browser session";
      const currentLabel = options.admin && current ? "This browser · " : "";
      const client = `${browserDeviceLabel(session.user_agent)} · IP ${session.client_ip || "not recorded"}`;
      const lastSeen = session.last_seen_at
        ? ` · last seen ${options.relativeTime(session.last_seen_at)}`
        : "";
      const details = `${currentLabel}${client}${lastSeen} · ${sessionIssuerLabel(session.issuer)} · signed in ${options.relativeTime(session.created_at)} (${options.formatDate(session.created_at)}) · expires ${options.formatDate(session.expires_at)} · ref ${sessionReference(session.id)}`;
      const action = options.admin && current
        ? "<strong>Current</strong>"
        : `<button type="button" class="admin-inline-button" data-${options.admin ? "revoke-session" : "revoke-self-session"}="${options.escapeHtml(session.id)}">${current ? "Log out" : "Revoke"}</button>`;
      row.innerHTML = `<span><b>${options.escapeHtml(title)}</b><small>${options.escapeHtml(details)}</small></span>${action}`;
      return row;
    }));
  }

  function renderAuthAccounts(options) {
    const accounts = filterAuthAccounts(options.accounts, options.query, options.filter);
    if (!accounts.length) {
      options.renderEmpty(options.element, "No matching accounts", "Change the search or account filter.");
      return;
    }
    options.element.classList.remove("admin-skeleton", "admin-skeleton-tiles");
    options.element.replaceChildren(...accounts.map((account) => {
      const row = document.createElement("div");
      row.className = `admin-live-row admin-session-row${account.email === options.selectedEmail ? " active" : ""}`;
      const status = account.disabled ? "Disabled" : "Active";
      const recovery = Number(account.recovery_codes_remaining || 0);
      row.innerHTML = `<span><b>${options.escapeHtml(account.email)}</b><small>${options.escapeHtml(account.is_admin ? "Server admin" : "User")} · ${status} · ${account.totp_enabled ? "2FA enabled" : "2FA not enabled"} · ${recovery} recovery ${recovery === 1 ? "code" : "codes"}</small></span><button type="button" class="admin-inline-button" data-admin-auth-email="${options.escapeHtml(account.email)}">Manage</button>`;
      return row;
    }));
  }

  function renderAuthAttempts(options) {
    const attempts = filterAuthAttempts(options.attempts, options.query, options.filter);
    if (!attempts.length) {
      options.renderEmpty(
        options.element,
        options.query || options.filter !== "all" ? "No matching protection entries" : "No active protection counters",
        "Drive creates an entry after a protected request needs throttling or failure tracking.",
      );
      return;
    }
    options.element.classList.remove("admin-skeleton", "admin-skeleton-tiles");
    options.element.replaceChildren(...attempts.map((attempt) => {
      const row = document.createElement("div");
      row.className = "admin-live-row admin-session-row";
      const locked = Boolean(attempt.locked_until && Date.parse(attempt.locked_until) > Date.now());
      const target = authAttemptTargetLabel(attempt);
      const scope = AUTH_SCOPE_LABELS[attempt.scope] || humanizeEventKind(attempt.scope);
      const workAllowance = PASSWORD_WORK_SCOPES.has(attempt.scope);
      const count = Number(attempt.failures || 0);
      const countLabel = workAllowance
        ? `${count} password ${count === 1 ? "check" : "checks"}`
        : `${count} failed ${count === 1 ? "attempt" : "attempts"}`;
      const status = workAllowance
        ? (locked
          ? `Allowance full until ${options.formatDate(attempt.locked_until)}`
          : `Allowance active · last check ${options.relativeTime(attempt.updated_at)}`)
        : (locked
          ? `Blocked until ${options.formatDate(attempt.locked_until)}`
          : `Counter active · last failure ${options.relativeTime(attempt.updated_at)}`);
      row.innerHTML = `<span><b>${options.escapeHtml(target)}</b><small>${options.escapeHtml(scope)} · ${options.escapeHtml(countLabel)} · ${options.escapeHtml(clientReference(attempt.client_fingerprint))} · ${options.escapeHtml(status)}</small></span><button type="button" class="admin-inline-button" data-auth-attempt-unlock="${options.escapeHtml(attempt.key)}">${locked ? "Remove block" : "Clear counter"}</button>`;
      return row;
    }));
  }

  function renderActivity(options) {
    const events = filterActivity(buildActivityEvents(options.summary), options.query, options.category);
    if (!events.length) {
      options.renderEmpty(options.element, "No matching activity", "Change the search or activity type.");
      return;
    }
    options.element.classList.remove("admin-skeleton", "admin-skeleton-tiles");
    options.element.replaceChildren(...events.slice(0, 12).map((event) => {
      const row = document.createElement("div");
      row.className = "admin-live-row";
      const count = event.count > 1 ? ` · ${event.count} similar records grouped` : "";
      row.innerHTML = `<span><b>${options.escapeHtml(event.label)}</b><small>${options.escapeHtml(event.description)} · ${options.escapeHtml(event.actor)}${options.escapeHtml(count)}</small></span><strong>${options.escapeHtml(options.relativeTime(event.at))}</strong>`;
      return row;
    }));
  }

  root.ShellXDriveAdminClarity = Object.freeze({
    authAttemptTargetLabel,
    browserDeviceLabel,
    buildActivityEvents,
    clientReference,
    filterActivity,
    filterAuthAccounts,
    filterAuthAttempts,
    filterSessions,
    humanizeEventKind,
    renderActivity,
    renderAuthAccounts,
    renderAuthAttempts,
    renderSessions,
    sessionIssuerLabel,
    sessionReference,
  });
})(window);
