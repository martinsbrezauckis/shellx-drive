// ShellX Drive public-share media preview controller.
//
// Keeps guest preview lifecycle and protected ticket preparation outside the
// folder-browser renderer. Preview never changes the explicit Download action:
// opening media and saving media remain distinct.

(() => {
  const IMAGE_EXTENSIONS = new Set(["bmp", "gif", "jpeg", "jpg", "png", "webp"]);
  const VIDEO_EXTENSIONS = new Set(["mov", "mp4", "webm"]);

  function extensionFor(name) {
    const value = String(name || "");
    const separator = value.lastIndexOf(".");
    return separator >= 0 ? value.slice(separator + 1).toLowerCase() : "";
  }

  function previewKind(entry) {
    if (!entry || entry.kind !== "file") return "";
    const extension = extensionFor(entry.name);
    if (IMAGE_EXTENSIONS.has(extension)) return "image";
    if (VIDEO_EXTENSIONS.has(extension)) return "video";
    return "";
  }

  function contentUrl(shareId, path) {
    const base = `/pub/shares/${encodeURIComponent(shareId)}/content`;
    return path ? `${base}?${new URLSearchParams({ path })}` : base;
  }

  function createController({
    shareId,
    getAccessToken,
    onAccessTokenInvalid,
    modal,
    title,
    body,
    closeButton,
    downloadButton,
    previousButton,
    nextButton,
    position,
    getSequence,
    onDownload,
    onStatus,
  }) {
    let currentEntry = null;
    let abortController = null;
    let returnFocus = null;

    function mediaSequence() {
      const entries = typeof getSequence === "function" ? getSequence() : [];
      return entries.filter((entry) => previewKind(entry));
    }

    function currentIndex(entries) {
      return entries.findIndex((entry) => entry.path === currentEntry?.path);
    }

    function updateNavigation() {
      const entries = mediaSequence();
      const index = currentIndex(entries);
      const hasSequence = entries.length > 1 && index >= 0;
      previousButton.hidden = !hasSequence;
      nextButton.hidden = !hasSequence;
      previousButton.disabled = !hasSequence || index === 0;
      nextButton.disabled = !hasSequence || index === entries.length - 1;
      position.textContent = hasSequence ? `${index + 1} of ${entries.length}` : "";
    }

    function releaseMedia() {
      abortController?.abort();
      abortController = null;
      body.querySelector("video")?.pause();
      body.replaceChildren();
    }

    function close() {
      if (modal.hidden) return;
      releaseMedia();
      modal.hidden = true;
      document.body.classList.remove("share-preview-open");
      currentEntry = null;
      updateNavigation();
      if (returnFocus instanceof HTMLElement && returnFocus.isConnected) returnFocus.focus();
      returnFocus = null;
    }

    function loading(message) {
      const panel = document.createElement("div");
      panel.className = "share-preview-loading";
      panel.setAttribute("role", "status");
      const spinner = document.createElement("span");
      spinner.className = "share-preview-spinner";
      spinner.setAttribute("aria-hidden", "true");
      const copy = document.createElement("span");
      copy.textContent = message;
      panel.append(spinner, copy);
      body.replaceChildren(panel);
    }

    function failure(message) {
      const panel = document.createElement("div");
      panel.className = "share-preview-failure";
      const heading = document.createElement("strong");
      heading.textContent = "Preview unavailable";
      const copy = document.createElement("span");
      copy.textContent = message;
      panel.append(heading, copy);
      body.replaceChildren(panel);
    }

    function requestHeaders() {
      const accessToken = getAccessToken?.() || "";
      return {
        ...(accessToken ? { "x-share-access-token": accessToken } : {}),
      };
    }

    function requiresTicket() {
      return Boolean(getAccessToken?.());
    }

    async function prepareProtectedPreview(entry) {
      abortController?.abort();
      abortController = new AbortController();
      const response = await fetch(`/pub/shares/${encodeURIComponent(shareId)}/preview`, {
        method: "POST",
        headers: { "content-type": "application/json", ...requestHeaders() },
        body: JSON.stringify({ path: entry.path || null }),
        signal: abortController.signal,
      });
      if (!response.ok) {
        onAccessTokenInvalid?.(response);
        const error = new Error("The shared file could not be prepared.");
        error.status = response.status;
        throw error;
      }
      const prepared = await response.json();
      if (!/^\/downloads\/files\/[a-f0-9]{64}$/.test(prepared.content_url || "")) {
        throw new Error("Drive returned an invalid preview ticket.");
      }
      return prepared.content_url;
    }

    async function renderImage(entry) {
      loading("Loading full image…");
      try {
        const source = requiresTicket()
          ? await prepareProtectedPreview(entry)
          : contentUrl(shareId, entry.path || "");
        const image = document.createElement("img");
        image.src = source;
        image.alt = entry.name;
        image.addEventListener("error", () => failure("This image format could not be displayed."), {
          once: true,
        });
        body.replaceChildren(image);
      } catch (error) {
        if (error?.name !== "AbortError") failure(error?.message || "The image could not be loaded.");
      }
    }

    function renderVideoElement(entry, source, readyMessage) {
      const frame = document.createElement("div");
      frame.className = "share-video-frame";
      const video = document.createElement("video");
      video.src = source;
      video.controls = true;
      video.preload = "metadata";
      video.playsInline = true;
      video.autoplay = false;
      video.setAttribute("aria-label", `Preview ${entry.name}`);
      const state = document.createElement("span");
      state.className = "share-video-state";
      state.textContent = "Loading video preview…";
      video.addEventListener("loadeddata", () => {
        state.textContent = readyMessage;
      });
      video.addEventListener("error", () => {
        failure("This browser could not play the shared video format.");
      });
      frame.append(video, state);
      body.replaceChildren(frame);
    }

    async function prepareProtectedVideo(entry, button) {
      button.disabled = true;
      button.textContent = "Preparing…";
      try {
        const source = await prepareProtectedPreview(entry);
        renderVideoElement(entry, source, "Ready to play · streamed from Drive");
      } catch (error) {
        if (error?.name !== "AbortError") failure(error?.message || "The video could not be prepared.");
      }
    }

    function renderVideo(entry) {
      if (!getAccessToken?.()) {
        renderVideoElement(
          entry,
          contentUrl(shareId, entry.path || ""),
          "Ready to play · streamed from Drive",
        );
        return;
      }
      const panel = document.createElement("div");
      panel.className = "share-video-prepare";
      const heading = document.createElement("strong");
      heading.textContent = "Prepare protected video";
      const copy = document.createElement("span");
      copy.textContent =
        "Drive prepares a short-lived streaming URL for this protected video.";
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = "Prepare video preview";
      button.addEventListener("click", () => prepareProtectedVideo(entry, button));
      panel.append(heading, copy, button);
      body.replaceChildren(panel);
    }

    async function show(entry) {
      const kind = previewKind(entry);
      if (!kind) return false;
      releaseMedia();
      currentEntry = entry;
      title.textContent = entry.name;
      updateNavigation();
      if (kind === "image") await renderImage(entry);
      else renderVideo(entry);
      return true;
    }

    async function open(entry, opener = document.activeElement) {
      if (!previewKind(entry)) return false;
      returnFocus = opener;
      modal.hidden = false;
      document.body.classList.add("share-preview-open");
      closeButton.focus();
      return show(entry);
    }

    function navigate(offset) {
      const entries = mediaSequence();
      const index = currentIndex(entries);
      const destination = entries[index + offset];
      if (!destination) return;
      show(destination).catch((error) => {
        onStatus(error?.message || "The preview could not be opened.", "error");
      });
    }

    closeButton.addEventListener("click", close);
    modal.addEventListener("click", (event) => {
      if (event.target === modal) close();
    });
    downloadButton.addEventListener("click", () => {
      if (!currentEntry) return;
      Promise.resolve(onDownload(currentEntry, downloadButton)).catch((error) => {
        onStatus(error?.message || "The file could not be downloaded.", "error");
      });
    });
    previousButton.addEventListener("click", () => navigate(-1));
    nextButton.addEventListener("click", () => navigate(1));
    document.addEventListener("keydown", (event) => {
      if (modal.hidden) return;
      if (event.key === "Escape") close();
      if (event.target instanceof HTMLMediaElement) return;
      if (event.key === "ArrowLeft") {
        event.preventDefault();
        navigate(-1);
      }
      if (event.key === "ArrowRight") {
        event.preventDefault();
        navigate(1);
      }
    });

    return {
      canPreview: (entry) => Boolean(previewKind(entry)),
      close,
      open,
    };
  }

  window.ShellXPublicPreview = { createController, previewKind };
})();
