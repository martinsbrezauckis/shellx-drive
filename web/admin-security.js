(function attachAdminSecurity(root) {
  "use strict";

  const CATEGORY_LABELS = {
    login: "Sign-in",
    access: "Authenticated access",
    guest_access: "Guest-link access",
    command: "Server command",
  };

  const OUTCOME_LABELS = {
    success: "Allowed",
    challenge: "2FA requested",
    denied: "Denied",
    blocked: "Temporarily blocked",
    rejected: "Rejected",
    failed: "Server failure",
  };

  function eventTitle(event) {
    return `${CATEGORY_LABELS[event.category] || "Security event"} · ${OUTCOME_LABELS[event.outcome] || event.outcome}`;
  }

  function eventSubject(event) {
    if (event.actor_email) return event.actor_email;
    if (event.credential_kind === "guest") return "Guest visitor";
    if (event.credential_kind === "anonymous") return "Unauthenticated request";
    return String(event.credential_kind || "Unknown credential").replaceAll("_", " ");
  }

  function eventSearchText(event) {
    return [
      eventTitle(event),
      eventSubject(event),
      event.action,
      event.route,
      event.status_code,
      event.client_ip,
      event.user_agent,
      event.target_ref,
    ].join(" ").toLocaleLowerCase();
  }

  function renderSecurityEvents(options) {
    const events = options.events || [];
    if (!events.length) {
      options.renderEmpty(
        options.element,
        "No matching security activity",
        "Change the search or filters. New sign-ins, guest access, rejected requests, and authenticated commands appear here.",
      );
      return;
    }
    options.element.classList.remove("admin-skeleton", "admin-skeleton-tiles");
    options.element.replaceChildren(...events.map((event) => {
      const row = document.createElement("div");
      row.className = "admin-live-row admin-security-event-row";
      const device = options.browserDeviceLabel(event.user_agent);
      const target = event.target_ref ? ` · ${event.target_ref}` : "";
      const details = options.technicalDetails
        ? `${eventSubject(event)} · ${event.action} ${event.route} · HTTP ${event.status_code} · IP ${event.client_ip || "not recorded"} · ${device}${target}`
        : `${device} · IP ${event.client_ip || "not recorded"}`;
      row.innerHTML = `<span><b>${options.escapeHtml(eventTitle(event))}</b><small>${options.escapeHtml(details)}</small></span><strong>${options.escapeHtml(options.relativeTime(event.created_at))}</strong>`;
      return row;
    }));
  }

  function createController(options) {
    let debounceTimer = null;
    let hasMore = false;

    async function load({ append = false } = {}) {
      const params = new URLSearchParams({ limit: "200" });
      const query = options.els.adminSecurityEventsSearch?.value.trim();
      const category = options.els.adminSecurityEventsCategory?.value;
      const outcome = options.els.adminSecurityEventsOutcome?.value;
      if (query) params.set("query", query);
      if (category && category !== "all") params.set("category", category);
      if (outcome && outcome !== "all") params.set("outcome", outcome);
      if (append && options.state.securityEvents?.events?.length) {
        const last = options.state.securityEvents.events.at(-1);
        params.set("before", last.created_at);
        params.set("before_id", last.id);
      }
      const data = await options.api(`/admin/security-events?${params}`);
      hasMore = (data.events || []).length === 200;
      options.state.securityEvents = {
        ...data,
        events: append
          ? [...(options.state.securityEvents?.events || []), ...(data.events || [])]
          : data.events || [],
      };
      render();
      return data;
    }

    function render() {
      const data = options.state.securityEvents;
      if (!data) {
        options.renderSkeleton(options.els.adminSecurityEventsList, "rows", 4);
        return;
      }
      options.els.adminSecurityEventsPolicy.textContent = `Network metadata is visible only to server admins and the account owner for their own sessions and sign-in history. Security events are kept for ${data.retention_days} days, up to ${Number(data.maximum_events).toLocaleString()} records. Passwords, tokens, request bodies, file content, and raw capability URLs are never stored here.`;
      renderSecurityEvents({
        element: options.els.adminSecurityEventsList,
        events: data.events,
        browserDeviceLabel: options.browserDeviceLabel,
        escapeHtml: options.escapeHtml,
        relativeTime: options.relativeTime,
        renderEmpty: options.renderEmpty,
        technicalDetails: true,
      });
      options.els.adminSecurityEventsMore.disabled = !hasMore;
    }

    function reloadSoon() {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => load().catch(options.onError), 250);
    }

    options.els.adminSecurityEventsRefresh?.addEventListener("click", () => load().catch(options.onError));
    options.els.adminSecurityEventsSearch?.addEventListener("input", reloadSoon);
    options.els.adminSecurityEventsCategory?.addEventListener("change", () => load().catch(options.onError));
    options.els.adminSecurityEventsOutcome?.addEventListener("change", () => load().catch(options.onError));
    options.els.adminSecurityEventsMore?.addEventListener("click", () => load({ append: true }).catch(options.onError));

    return Object.freeze({ load, render });
  }

  function createSelfController(options) {
    async function load() {
      const data = await options.api("/auth/security-events");
      options.state.selfSecurityEvents = data.events || [];
      render();
      return options.state.selfSecurityEvents;
    }

    function render() {
      if (!options.state.selfSecurityEvents) {
        options.renderFallback([["Sign-in activity", "Not checked"]]);
        return;
      }
      renderSecurityEvents({
        element: options.element,
        events: options.state.selfSecurityEvents,
        browserDeviceLabel: options.browserDeviceLabel,
        escapeHtml: options.escapeHtml,
        relativeTime: options.relativeTime,
        renderEmpty: options.renderEmpty,
        technicalDetails: false,
      });
    }

    return Object.freeze({ load, render });
  }

  root.ShellXDriveAdminSecurity = Object.freeze({
    createController,
    createSelfController,
    eventSearchText,
    eventSubject,
    eventTitle,
    renderSecurityEvents,
  });
})(window);
