// Native browser downloads backed by a short-lived server capability.
// The authorization request uses fetch, but each single-file or archive body
// is handed to a normal navigation so multi-gigabyte downloads never become
// JavaScript Blobs.

(() => {
  const DOWNLOAD_PATH = /^\/downloads\/(?:files\/)?[a-f0-9]{64}$/;

  async function start({ endpoint, body, headers = {} }) {
    const options = {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
    };
    const consume = async (response, signal) => {
      if (!response.ok) {
        const text = await response.text();
        const error = new Error(text || `${response.status} ${response.statusText}`);
        error.status = response.status;
        throw error;
      }
      const prepared = await response.json();
      if (!DOWNLOAD_PATH.test(prepared.download_url || "")) {
        throw new Error("Drive returned an invalid download ticket.");
      }
      signal?.throwIfAborted();
      const anchor = document.createElement("a");
      anchor.href = prepared.download_url;
      anchor.hidden = true;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      return prepared;
    };
    if (window.authenticatedFetch) return window.authenticatedFetch(endpoint, options, consume);
    return consume(await fetch(endpoint, options));
  }

  window.ShellXDownloadTickets = { start };
})();
