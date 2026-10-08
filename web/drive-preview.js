// Authenticated Drive preview controller.
//
// The sequence is snapshotted from the exact rendered folder/search order when
// the modal opens. Navigation filters only previewable files, never silently
// jumps across folders, and keeps media lifecycle code out of drive.js.

(() => {
  const MAX_TEXT_PREVIEW_BYTES = 256 * 1024;
  const MAX_MARKDOWN_LINES = 20_000;
  const MAX_MARKDOWN_RENDER_CHARS = MAX_TEXT_PREVIEW_BYTES * 6;

  function previewLimitError(message = "This file is too large to preview safely. Download it instead.") {
    const error = new Error(message);
    error.code = "TEXT_PREVIEW_LIMIT";
    return error;
  }

  function textPreviewRefusal(file) {
    const size = file?.size_bytes;
    if (!Number.isSafeInteger(size) || size < 0) {
      return {
        heading: "Preview unavailable",
        copy: "Drive could not verify this file's size. Download it instead.",
      };
    }
    if (size > MAX_TEXT_PREVIEW_BYTES) {
      return {
        heading: "Too large to preview",
        copy: "Text previews are limited to 256 KiB. Download this file instead.",
      };
    }
    return null;
  }

  function textPreviewRange(file) {
    return file?.size_bytes === 0 ? null : `bytes=0-${MAX_TEXT_PREVIEW_BYTES - 1}`;
  }

  function declaredResponseBytes(response) {
    const contentRange = response.headers?.get?.("content-range") || "";
    const rangeMatch = contentRange.match(/\/(\d+)$/);
    if (rangeMatch) return Number(rangeMatch[1]);
    const contentLength = response.headers?.get?.("content-length");
    return contentLength === null ? null : Number(contentLength);
  }

  async function readBoundedTextResponse(response, maximum = MAX_TEXT_PREVIEW_BYTES) {
    const declared = declaredResponseBytes(response);
    if (Number.isFinite(declared) && declared > maximum) {
      try { await response.body?.cancel?.(); } catch {}
      throw previewLimitError();
    }
    const reader = response.body?.getReader?.();
    if (!reader) {
      if (declared === 0) return "";
      throw new Error("This text preview could not be streamed safely.");
    }
    const decoder = new TextDecoder();
    const parts = [];
    let received = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maximum) {
        try { await reader.cancel(); } catch {}
        throw previewLimitError();
      }
      parts.push(decoder.decode(value, { stream: true }));
    }
    parts.push(decoder.decode());
    return parts.join("");
  }

  function previewSequence(files, fileInfo) {
    return (Array.isArray(files) ? files : []).filter((file) =>
      file?.kind === "file" && Boolean(fileInfo(file)?.previewable),
    );
  }

  function navigationState(sequence, fileId) {
    const files = Array.isArray(sequence) ? sequence : [];
    const index = files.findIndex((file) => file.id === fileId);
    return {
      index,
      count: files.length,
      position: index >= 0 ? `${index + 1} of ${files.length}` : "",
      hasPrevious: index > 0,
      hasNext: index >= 0 && index < files.length - 1,
    };
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function renderMarkdown(markdown) {
    const input = String(markdown ?? "");
    if (input.length > MAX_TEXT_PREVIEW_BYTES) throw previewLimitError();
    const escaped = escapeHtml(input);
    if (escaped.length > MAX_MARKDOWN_RENDER_CHARS) throw previewLimitError();
    const lines = escaped.split(/\r?\n/);
    if (lines.length > MAX_MARKDOWN_LINES) throw previewLimitError();
    const output = [];
    let outputLength = 0;
    let inList = false;
    let inCode = false;
    const append = (value) => {
      outputLength += value.length;
      if (outputLength > MAX_MARKDOWN_RENDER_CHARS) throw previewLimitError();
      output.push(value);
    };
    const closeList = () => {
      if (inList) {
        append("</ul>");
        inList = false;
      }
    };
    for (const raw of lines) {
      if (raw.trim().startsWith("```")) {
        if (inCode) {
          append("</pre>");
          inCode = false;
        } else {
          closeList();
          append('<pre class="text-preview">');
          inCode = true;
        }
        continue;
      }
      if (inCode) {
        append(`${raw}\n`);
        continue;
      }
      const line = raw
        .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
        .replace(/(^|[^*])\*([^*]+)\*/g, "$1<em>$2</em>")
        .replace(/`([^`]+)`/g, "<code>$1</code>");
      const heading = line.match(/^(#{1,6})\s+(.*)$/);
      if (heading) {
        closeList();
        const level = Math.min(heading[1].length, 6);
        append(`<h${level}>${heading[2]}</h${level}>`);
        continue;
      }
      const listItem = line.match(/^\s*[-*]\s+(.*)$/) || line.match(/^\s*\d+\.\s+(.*)$/);
      if (listItem) {
        if (!inList) {
          append("<ul>");
          inList = true;
        }
        append(`<li>${listItem[1]}</li>`);
        continue;
      }
      if (line.trim() === "") {
        closeList();
        continue;
      }
      closeList();
      append(`<p>${line}</p>`);
    }
    closeList();
    if (inCode) append("</pre>");
    return output.join("");
  }

  function createController({
    modal,
    title,
    body,
    closeButton,
    downloadButton,
    previousButton,
    nextButton,
    position,
    getSequence,
    fileInfo,
    prepareContentUrl,
    loadText,
    onDownload,
    onCurrentChange,
    onStatus,
  }) {
    let currentFile = null;
    let sequence = [];
    let renderGeneration = 0;
    let returnFocus = null;

    function updateNavigation() {
      const navigation = navigationState(sequence, currentFile?.id);
      previousButton.hidden = navigation.count <= 1;
      nextButton.hidden = navigation.count <= 1;
      previousButton.disabled = !navigation.hasPrevious;
      nextButton.disabled = !navigation.hasNext;
      position.textContent = navigation.position;
      position.setAttribute("aria-label", navigation.position ? `Preview ${navigation.position}` : "");
    }

    function releaseMedia() {
      renderGeneration += 1;
      body.querySelector("video")?.pause();
      body.querySelector("audio")?.pause();
      body.replaceChildren();
    }

    function statusPanel(heading, copy, className) {
      const panel = document.createElement("div");
      panel.className = className;
      const strong = document.createElement("strong");
      strong.textContent = heading;
      const detail = document.createElement("span");
      detail.textContent = copy;
      panel.append(strong, detail);
      body.replaceChildren(panel);
    }

    function unavailable(file) {
      statusPanel(
        "No preview available",
        `${fileInfo(file)?.label || "This file type"} can be downloaded instead.`,
        "preview-modal-empty",
      );
    }

    function failed(message) {
      statusPanel("Preview unavailable", message, "preview-modal-empty preview-modal-failure");
    }

    async function render(file) {
      releaseMedia();
      const generation = renderGeneration;
      const info = fileInfo(file) || {};
      if (!info.previewable) {
        unavailable(file);
        return;
      }
      let source = "";
      if (["image", "pdf", "video", "audio"].includes(info.preview)) {
        statusPanel("Preparing preview", "Authorizing a short-lived media stream…", "preview-modal-empty");
        try {
          source = await prepareContentUrl(file);
          if (generation !== renderGeneration || currentFile?.id !== file.id) return;
          body.replaceChildren();
        } catch (error) {
          if (generation === renderGeneration) {
            failed(error?.message || "This media preview could not be prepared.");
          }
          return;
        }
      }
      if (info.preview === "image") {
        const image = document.createElement("img");
        image.src = source;
        image.alt = file.name;
        image.addEventListener("error", () => failed("This image could not be displayed."), {
          once: true,
        });
        body.append(image);
        return;
      }
      if (info.preview === "pdf") {
        const frame = document.createElement("iframe");
        frame.src = source;
        frame.title = `${file.name} preview`;
        body.append(frame);
        return;
      }
      if (info.preview === "video") {
        const video = document.createElement("video");
        video.src = source;
        video.controls = true;
        video.preload = "metadata";
        video.playsInline = true;
        video.autoplay = false;
        video.setAttribute("aria-label", `Preview ${file.name}`);
        video.addEventListener("error", () => failed("This video could not be streamed."), {
          once: true,
        });
        body.append(video);
        return;
      }
      if (info.preview === "audio") {
        const audio = document.createElement("audio");
        audio.src = source;
        audio.controls = true;
        audio.preload = "metadata";
        audio.setAttribute("aria-label", `Preview ${file.name}`);
        body.append(audio);
        return;
      }
      if (info.preview === "text" || info.preview === "markdown") {
        const refusal = textPreviewRefusal(file);
        if (refusal) {
          statusPanel(refusal.heading, refusal.copy, "preview-modal-empty preview-modal-failure");
          return;
        }
        const container = document.createElement("div");
        container.className = info.preview === "markdown" ? "markdown-preview" : "text-preview";
        container.textContent = "Loading preview…";
        container.setAttribute("role", "status");
        body.append(container);
        try {
          const text = await loadText(file);
          if (generation !== renderGeneration || currentFile?.id !== file.id) return;
          container.removeAttribute("role");
          if (info.preview === "markdown") container.innerHTML = renderMarkdown(text);
          else container.textContent = String(text);
        } catch (error) {
          if (generation === renderGeneration) {
            if (error?.code === "TEXT_PREVIEW_LIMIT") {
              statusPanel(
                "Too large to preview",
                error.message,
                "preview-modal-empty preview-modal-failure",
              );
            } else failed(error?.message || "This text preview could not be loaded.");
          }
        }
        return;
      }
      unavailable(file);
    }

    async function show(file) {
      currentFile = file;
      title.textContent = file.name;
      onCurrentChange(file);
      updateNavigation();
      await render(file);
    }

    async function open(file, opener = document.activeElement) {
      if (!file || !fileInfo(file)?.previewable) return false;
      sequence = previewSequence(getSequence(), fileInfo);
      if (!sequence.some((entry) => entry.id === file.id)) sequence.unshift(file);
      returnFocus = opener;
      modal.hidden = false;
      document.body.classList.add("drive-preview-open");
      closeButton.focus();
      await show(file);
      return true;
    }

    function navigate(offset) {
      const navigation = navigationState(sequence, currentFile?.id);
      const destination = sequence[navigation.index + offset];
      if (!destination) return;
      show(destination).catch((error) => onStatus(error?.message || "Preview navigation failed."));
    }

    function close() {
      if (modal.hidden) return;
      releaseMedia();
      modal.hidden = true;
      document.body.classList.remove("drive-preview-open");
      currentFile = null;
      sequence = [];
      onCurrentChange(null);
      updateNavigation();
      if (returnFocus instanceof HTMLElement && returnFocus.isConnected) returnFocus.focus();
      returnFocus = null;
    }

    closeButton.addEventListener("click", close);
    modal.addEventListener("click", (event) => {
      if (event.target === modal) close();
    });
    downloadButton.addEventListener("click", () => {
      if (!currentFile) return;
      Promise.resolve(onDownload(currentFile)).catch((error) => {
        onStatus(error?.message || "Download failed.");
      });
    });
    previousButton.addEventListener("click", () => navigate(-1));
    nextButton.addEventListener("click", () => navigate(1));
    document.addEventListener("keydown", (event) => {
      if (modal.hidden) return;
      if (event.key === "Escape") {
        event.preventDefault();
        close();
        return;
      }
      if (event.target instanceof HTMLMediaElement || /^(INPUT|TEXTAREA|SELECT)$/.test(event.target?.tagName)) {
        return;
      }
      if (event.key === "ArrowLeft") {
        event.preventDefault();
        navigate(-1);
      }
      if (event.key === "ArrowRight") {
        event.preventDefault();
        navigate(1);
      }
    });

    return { close, navigate, open, current: () => currentFile };
  }

  const api = {
    MAX_TEXT_PREVIEW_BYTES,
    createController,
    navigationState,
    previewSequence,
    readBoundedTextResponse,
    renderMarkdown,
    textPreviewRange,
    textPreviewRefusal,
  };
  if (typeof window !== "undefined") window.ShellXDrivePreview = api;
  else globalThis.ShellXDrivePreview = api;
})();
