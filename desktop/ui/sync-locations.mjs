export function normalizeSyncLocations(rawLocations, activePairId, fallback = null) {
  const normalized = (Array.isArray(rawLocations) ? rawLocations : []).map((location) => ({
    id: String(location.id ?? ""),
    driveLocation: String(location.driveLocation ?? location.drive_location ?? ""),
    localRoot: String(location.localRoot ?? location.local_root ?? ""),
    active: Boolean(location.active),
    syncStatus: String(location.syncStatus ?? location.sync_status ?? location.status ?? ""),
    error: String(location.error ?? location.lastError ?? location.last_error ?? ""),
  })).filter((location) => location.id && location.driveLocation && location.localRoot);
  if (normalized.length) {
    return normalized.map((location) => ({
      ...location,
      active: activePairId ? location.id === activePairId : location.active,
    }));
  }
  return fallback?.driveLocation && fallback?.localRoot ? [{
    id: activePairId || "active-location",
    driveLocation: fallback.driveLocation,
    localRoot: fallback.localRoot,
    active: true,
    syncStatus: "",
    error: "",
  }] : [];
}

function rootStatusCopy(location) {
  const explicit = location.syncStatus.trim();
  if (explicit === "needs_review") return "Needs review";
  if (location.error) return "Error";
  if (explicit === "error") return "Error";
  if (explicit === "paused") return "Paused";
  if (explicit === "current") return "Current status details";
  if (explicit === "managed") return "Managed automatically";
  if (explicit) return explicit;
  return location.active ? "Current status details" : "Managed automatically";
}

export function filterSyncLocations(locations, query = "") {
  const needle = String(query).trim().toLocaleLowerCase();
  if (!needle) return locations;
  return locations.filter((location) => [
    location.driveLocation,
    location.localRoot,
    rootStatusCopy(location),
    location.error,
  ].some((value) => String(value ?? "").toLocaleLowerCase().includes(needle)));
}

export function renderSyncLocations(view, escapeHtml, filter = "") {
  if (!view.syncLocations.length) return "";
  const matching = filterSyncLocations(view.syncLocations, filter);
  const totalCopy = view.syncLocations.length === 1 ? "1 Drive root" : `${view.syncLocations.length} Drive roots`;
  const matchingCopy = matching.length === view.syncLocations.length
    ? `Showing all ${totalCopy}`
    : `Showing ${matching.length} of ${totalCopy}`;
  const rows = matching.map((location) => {
    const reviewDetailsBlocked = view.status === "syncing";
    const reviewDetails = !location.active && location.syncStatus === "needs_review"
      ? `<button class="button sync-location-review" type="button" data-action="review-location" data-pair-id="${escapeHtml(location.id)}" aria-label="Review issues for ${escapeHtml(location.driveLocation)}" ${reviewDetailsBlocked ? "disabled title=\"A sync pass is active. Review details will be available when it finishes.\"" : ""}>Review issues</button>`
      : "";
    return `<li class="sync-location${location.active ? " current-details" : ""}${location.error ? " has-error" : ""}" data-root-id="${escapeHtml(location.id)}">
    <div class="sync-location-copy">
      <strong>${escapeHtml(location.driveLocation)}</strong>
      <span>${escapeHtml(location.localRoot)}</span>
      ${location.error ? `<small class="sync-location-error">${escapeHtml(location.error)}</small>` : ""}
    </div>
    <div class="sync-location-state">
      <span class="root-status${location.error ? " root-status-error" : ""}">${escapeHtml(rootStatusCopy(location))}</span>
      ${reviewDetails}
    </div>
  </li>`;
  }).join("");
  return `<section class="settings-section" aria-labelledby="sync-locations-heading">
    <h3 id="sync-locations-heading" tabindex="-1">Managed Drive roots</h3><p class="when">Each server and account connection uses its own local Drive folder. Every configured owned or shared root syncs automatically in one serialized pass. “Current status details” summarizes the selected root.</p>
    <div class="sync-location-tools"><label>Find a Drive root<input type="search" data-sync-locations-filter autocomplete="off" placeholder="Name, local folder, status, or error" value="${escapeHtml(filter)}" /></label><output data-sync-locations-count role="status" aria-live="polite">${escapeHtml(matchingCopy)}</output></div>
    ${rows ? `<ul class="sync-location-list">${rows}</ul>` : `<p class="empty sync-location-empty">No configured Drive roots match “${escapeHtml(filter)}”.</p>`}
  </section>`;
}

export function renderDiscoveredRoots(locations, escapeHtml, selectedSyncRootId = "", inputName = "syncRootId") {
  const rows = locations.map((location) => `<li><label><input type="radio" name="${inputName}" value="${escapeHtml(location.syncRootId)}" ${location.syncRootId === selectedSyncRootId ? "checked" : ""} />${escapeHtml(location.label)}</label></li>`).join("");
  return `<ul class="discovered-root-list">${rows}</ul>`;
}

export function formatByteSize(bytes) {
  if (bytes === null || bytes === undefined || !Number.isFinite(Number(bytes)) || Number(bytes) < 0) return "Unavailable";
  const value = Number(bytes);
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let scaled = value;
  let unit = -1;
  do {
    scaled /= 1024;
    unit += 1;
  } while (scaled >= 1024 && unit < units.length - 1);
  return `${scaled >= 10 ? scaled.toFixed(1) : scaled.toFixed(2)} ${units[unit]}`;
}
