export const HISTORY_PAGE_SIZE = 5;
export const HISTORY_RANGES = new Set(["24h", "7d", "30d", "all"]);

export function emptyHistoryState() {
  return { query: "", range: "7d", page: 1 };
}

export function activityHistoryPage(entries, state, now = new Date()) {
  const query = String(state.query ?? "").trim().toLocaleLowerCase();
  const range = HISTORY_RANGES.has(state.range) ? state.range : "7d";
  const cutoff = rangeCutoff(range, now);
  const filtered = (Array.isArray(entries) ? entries : [])
    .filter((entry) => {
      const at = new Date(entry.at);
      if (Number.isNaN(at.valueOf()) || (cutoff && at < cutoff)) return false;
      if (!query) return true;
      return [entry.direction, entry.path, entry.relativePath, entry.relative_path, entry.result]
        .some((value) => String(value ?? "").toLocaleLowerCase().includes(query));
    })
    .sort((left, right) => new Date(right.at) - new Date(left.at));
  const pageCount = Math.max(1, Math.ceil(filtered.length / HISTORY_PAGE_SIZE));
  const requestedPage = Number.isFinite(Number(state.page)) ? Math.trunc(Number(state.page)) : 1;
  const page = Math.min(pageCount, Math.max(1, requestedPage));
  const start = (page - 1) * HISTORY_PAGE_SIZE;
  return {
    entries: filtered.slice(start, start + HISTORY_PAGE_SIZE),
    page,
    pageCount,
    total: filtered.length,
  };
}

export function renderActivityHistory(entries, state, escapeHtml) {
  const result = activityHistoryPage(entries, state);
  const rows = result.entries.length ? `<ul class="list history-list">${result.entries.map((entry) => `<li><span class="when">${escapeHtml(displayActivityTime(entry.at))}</span><span class="path">${escapeHtml(entry.path ?? entry.relativePath ?? entry.relative_path ?? entry.direction ?? "")}</span><span class="result">${escapeHtml(entry.result ?? "")}</span></li>`).join("")}</ul>` : `<div class="empty history-empty">${entries.length ? "No history matches these filters." : "History will appear after the first completed sync."}</div>`;
  const pagination = result.pageCount > 1 ? `<nav class="history-pagination" aria-label="History pages"><button class="button" type="button" data-action="history-previous" ${result.page === 1 ? "disabled" : ""}>Previous</button><span>Page ${result.page} of ${result.pageCount}</span><button class="button" type="button" data-action="history-next" ${result.page === result.pageCount ? "disabled" : ""}>Next</button></nav>` : "";
  return `<div class="history-controls">
    <form id="history-filter-form" class="history-filter">
      <label><span>Search history</span><input name="historyQuery" type="search" value="${escapeHtml(state.query)}" placeholder="File or result" /></label>
      <label><span>Time frame</span><select name="historyRange"><option value="24h" ${state.range === "24h" ? "selected" : ""}>Last 24 hours</option><option value="7d" ${state.range === "7d" ? "selected" : ""}>Last 7 days</option><option value="30d" ${state.range === "30d" ? "selected" : ""}>Last 30 days</option><option value="all" ${state.range === "all" ? "selected" : ""}>All retained</option></select></label>
      <button class="button" type="submit">Apply</button>
      ${state.query || state.range !== "7d" ? `<button class="button" type="button" data-action="history-clear">Clear</button>` : ""}
    </form>
    <span class="history-count" role="status">${result.total} ${result.total === 1 ? "event" : "events"}</span>
  </div>${rows}${pagination}`;
}

export function bindActivityHistory(root, state, onChange) {
  root.querySelector("#history-filter-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const range = String(data.get("historyRange"));
    onChange({
      query: String(data.get("historyQuery") ?? "").trim(),
      range: HISTORY_RANGES.has(range) ? range : "7d",
      page: 1,
    }, "#history-filter-form input[name='historyQuery']");
  });
  root.querySelector("[data-action='history-clear']")?.addEventListener("click", () => {
    onChange(emptyHistoryState(), "#history-filter-form input[name='historyQuery']");
  });
  root.querySelector("[data-action='history-previous']")?.addEventListener("click", () => {
    onChange({ ...state, page: Math.max(1, state.page - 1) }, "[data-action='history-next']");
  });
  root.querySelector("[data-action='history-next']")?.addEventListener("click", () => {
    onChange({ ...state, page: state.page + 1 }, "[data-action='history-previous']");
  });
}

function rangeCutoff(range, now) {
  const milliseconds = { "24h": 24 * 60 * 60 * 1000, "7d": 7 * 24 * 60 * 60 * 1000, "30d": 30 * 24 * 60 * 60 * 1000 }[range];
  return milliseconds ? new Date(now.valueOf() - milliseconds) : null;
}

function displayActivityTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "Unknown time";
  return date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
