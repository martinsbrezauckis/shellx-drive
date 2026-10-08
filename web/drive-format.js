(function registerDriveFormat(global) {
  "use strict";

  function formatDate(value) {
    if (!value) return "Not synced";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString([], {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "numeric",
      minute: "2-digit",
    });
  }

  function humanBytes(value, emptyLabel) {
    if (value === null || value === undefined || value === "") return emptyLabel;
    const bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) return emptyLabel === "No limit" ? String(value) : "—";
    if (bytes < 1024) return `${bytes} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let scaled = bytes;
    let unit = "B";
    for (const nextUnit of units) {
      scaled /= 1024;
      unit = nextUnit;
      if (scaled < 1024) break;
    }
    return `${scaled.toFixed(scaled >= 10 ? 0 : 1)} ${unit}`;
  }

  function formatBytes(value) {
    return humanBytes(value, "No limit");
  }

  function formatFileSize(value) {
    return humanBytes(value, "—");
  }

  function logicalFileSize(file) {
    return file?.kind === "folder" ? file.folder_size_bytes : file?.size_bytes;
  }

  function displayFileSize(file) {
    const value = logicalFileSize(file);
    if (file?.kind === "folder" && (value === null || value === undefined || value === "")) {
      return "Unavailable";
    }
    return formatFileSize(value);
  }

  function exactFileSizeLabel(file) {
    const value = Number(logicalFileSize(file));
    if (!Number.isSafeInteger(value) || value < 0) return "Size unavailable";
    const exact = `${value.toLocaleString()} ${value === 1 ? "byte" : "bytes"}`;
    return file?.kind === "folder" ? `${exact} in folder contents` : exact;
  }

  function formatDurationSeconds(value) {
    const seconds = Number(value || 0);
    if (seconds % 86400 === 0) {
      const days = seconds / 86400;
      return `${days} ${days === 1 ? "day" : "days"}`;
    }
    if (seconds % 3600 === 0) {
      const hours = seconds / 3600;
      return `${hours} ${hours === 1 ? "hour" : "hours"}`;
    }
    return `${seconds} seconds`;
  }

  function compactDate(value) {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });
  }

  function formatShareExpiry(value) {
    return value ? formatDate(value) : "Never";
  }

  function compactShareExpiry(value) {
    return value ? compactDate(value) : "Never";
  }

  function fileExtension(file) {
    const name = String(file?.name || "");
    const match = name.match(/\.([^.]+)$/);
    return match ? match[1].toLowerCase() : "";
  }

  function emptyTrashToast(data) {
    const deleted = Number(data?.deleted || 0);
    const retained = Array.isArray(data?.retained_items) ? data.retained_items : [];
    const deletedLabel = `${deleted} eligible item${deleted === 1 ? "" : "s"} deleted`;
    if (!retained.length) return `Emptied trash — ${deletedLabel}.`;
    const names = retained.slice(0, 3).map((item) => `“${String(item?.name || "Unnamed item")}”`);
    const extra = retained.length > names.length ? ` and ${retained.length - names.length} more` : "";
    return `Emptied trash — ${deletedLabel}. Kept until retention: ${names.join(", ")}${extra}.`;
  }

  global.ShellXDriveFormat = Object.freeze({
    compactDate,
    compactShareExpiry,
    displayFileSize,
    emptyTrashToast,
    exactFileSizeLabel,
    fileExtension,
    formatBytes,
    formatDate,
    formatDurationSeconds,
    formatFileSize,
    formatShareExpiry,
    logicalFileSize,
  });
})(window);
