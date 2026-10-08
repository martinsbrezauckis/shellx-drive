/* Server-version polling and Settings > About presentation. */
const VERSION_POLL_MS = 60_000;
const versionWatch = {
  loadedBuild: null,
  dismissedBuild: null,
  info: null,
  timer: null,
  visibilityBound: false,
  controlsBound: false,
};

async function fetchVersionInfo() {
  try {
    return await publicApi("/version");
  } catch {
    return null;
  }
}

function stopVersionWatch() {
  if (versionWatch.timer !== null) {
    window.clearInterval(versionWatch.timer);
    versionWatch.timer = null;
  }
}

function shouldRunVersionWatch() {
  return hasAuthenticatedSession() && hasAdminTools() && document.visibilityState === "visible";
}

async function updateVersionWatchActivity({ poll = false } = {}) {
  if (!shouldRunVersionWatch()) {
    stopVersionWatch();
    hideUpdateBanner();
    if (!hasAdminTools()) {
      if (els.aboutServerUpdatePanel) els.aboutServerUpdatePanel.hidden = true;
      if (els.aboutUpdateStatus) {
        els.aboutUpdateStatus.hidden = true;
        els.aboutUpdateStatus.textContent = "";
      }
    }
    return;
  }
  if (!versionWatch.loadedBuild || poll) {
    await pollServerVersion();
  }
  if (versionWatch.timer === null && shouldRunVersionWatch()) {
    versionWatch.timer = window.setInterval(pollServerVersion, VERSION_POLL_MS);
  }
}

function startVersionWatch() {
  if (!versionWatch.visibilityBound) {
    document.addEventListener("visibilitychange", () => {
      updateVersionWatchActivity({ poll: document.visibilityState === "visible" });
    });
    versionWatch.visibilityBound = true;
  }
  if (!versionWatch.controlsBound) {
    els.updateBannerReload?.addEventListener("click", () => window.location.reload());
    els.updateBannerDismiss?.addEventListener("click", () => {
      versionWatch.dismissedBuild = versionWatch.info?.build || versionWatch.dismissedBuild;
      hideUpdateBanner();
    });
    els.aboutCheckUpdateButton?.addEventListener("click", checkForUpdate);
    versionWatch.controlsBound = true;
  }
  updateVersionWatchActivity();
}

async function pollServerVersion() {
  const info = await fetchVersionInfo();
  if (!shouldRunVersionWatch() || !info || !info.build) return;
  versionWatch.info = info;
  if (!versionWatch.loadedBuild) {
    versionWatch.loadedBuild = info.build;
    return;
  }
  if (info.build !== versionWatch.loadedBuild && info.build !== versionWatch.dismissedBuild) {
    showUpdateBanner(info);
  }
}

function showUpdateBanner(info) {
  if (!hasAdminTools()) {
    hideUpdateBanner();
    return;
  }
  if (!els.updateBanner) return;
  if (els.updateBannerDetail) {
    const from = versionWatch.loadedBuild || "";
    els.updateBannerDetail.textContent = info.version
      ? `v${info.version} · ${from} → ${info.build}`
      : `${from} → ${info.build}`;
  }
  els.updateBanner.hidden = false;
  els.updateBanner.classList.add("is-visible");
}

function hideUpdateBanner() {
  if (!els.updateBanner) return;
  els.updateBanner.hidden = true;
  els.updateBanner.classList.remove("is-visible");
}

function renderAbout() {
  const adminAllowed = hasAdminTools();
  if (els.aboutServerUpdatePanel) els.aboutServerUpdatePanel.hidden = !adminAllowed;
  if (!adminAllowed && els.aboutUpdateStatus) {
    els.aboutUpdateStatus.hidden = true;
    els.aboutUpdateStatus.textContent = "";
  }
  const info = versionWatch.info;
  if (info) {
    if (els.aboutVersion) els.aboutVersion.textContent = `v${info.version}`;
    if (els.aboutBuild) els.aboutBuild.textContent = info.build || "—";
    if (els.aboutBuiltAt) els.aboutBuiltAt.textContent = formatBuiltAt(info.built_at);
    return;
  }
  fetchVersionInfo().then((fresh) => {
    if (fresh) {
      versionWatch.info = fresh;
      renderAbout();
    }
  });
}

function formatBuiltAt(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

async function checkForUpdate() {
  if (!hasAdminTools()) return;
  const box = els.aboutUpdateStatus;
  if (!box) return;
  box.hidden = false;
  box.className = "about-update-status is-checking";
  box.textContent = "Checking for updates…";
  try {
    renderUpdateStatus(await api("/update/check"));
  } catch (error) {
    box.className = "about-update-status is-error";
    box.textContent = `Update check failed: ${error.message}`;
  }
}

function renderUpdateStatus(status) {
  const box = els.aboutUpdateStatus;
  if (!box) return;
  box.hidden = false;
  box.textContent = "";
  if (status.kind === "available") {
    box.className = "about-update-status is-available";
    const line = document.createElement("strong");
    line.textContent = `Version ${status.latest_version} is available`;
    box.appendChild(line);
    if (status.body) {
      const notes = document.createElement("p");
      notes.className = "about-release-notes";
      notes.textContent = status.body.slice(0, 600);
      box.appendChild(notes);
    }
    if (status.release_url) {
      const link = document.createElement("a");
      link.href = status.release_url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.className = "about-release-link";
      link.textContent = "View release on GitHub";
      box.appendChild(link);
    }
    if (status.download_url) {
      const download = document.createElement("a");
      download.href = status.download_url;
      download.target = "_blank";
      download.rel = "noopener noreferrer";
      download.className = "about-release-link";
      download.textContent = "Download Linux server package";
      box.appendChild(download);
    }
    if (status.checksum_url) {
      const checksum = document.createElement("a");
      checksum.href = status.checksum_url;
      checksum.target = "_blank";
      checksum.rel = "noopener noreferrer";
      checksum.className = "about-release-link";
      checksum.textContent = "Download SHA-256 checksum";
      box.appendChild(checksum);
    }
    const guidance = document.createElement("p");
    guidance.className = "about-release-notes";
    guidance.textContent = "Drive will not replace or restart this server automatically. Review the release, verify its checksum, take a backup, then follow the documented upgrade procedure.";
    box.appendChild(guidance);
  } else if (status.kind === "current") {
    box.className = "about-update-status is-current";
    box.textContent = status.latest_version
      ? `You’re up to date (latest release v${status.latest_version}).`
      : status.reason || "You’re up to date.";
  } else if (status.kind === "unconfigured") {
    box.className = "about-update-status is-muted";
    box.textContent = status.reason || "Automatic update checks are turned off.";
  } else {
    box.className = "about-update-status is-error";
    box.textContent = status.reason || "Could not check for updates.";
  }
}
