const authLifecycle = window.ShellXDriveAuthLifecycle.controller;

async function authenticatedFetch(path, options = {}, consume = (response) => response) {
  return authLifecycle.run(async (signal) => {
    const response = await fetch(path, {
      ...options,
      signal,
      headers: {
        ...(options.body ? { "content-type": "application/json" } : {}),
        ...(state.token ? { authorization: `Bearer ${state.token}` } : {}),
        ...(state.actor ? { "X-ShellX-Actor": state.actor } : {}),
        ...(options.headers || {}),
      },
    });
    return consume(response, signal);
  }, options.signal);
}

async function api(path, options = {}) {
  const method = options.method || "GET";
  let result;
  try {
    result = await authenticatedFetch(path, options, async (response) => {
      if (!response.ok) {
        const text = await response.text();
        let details = null;
        try { details = JSON.parse(text); } catch {}
        return { response, text, details };
      }
      const type = response.headers.get("content-type") || "";
      return { response, data: type.includes("application/json") ? await response.json() : await response.text() };
    });
  } catch (error) {
    if (window.ShellXDriveAuthLifecycle.isStale(error)) throw error;
    driveDebug?.recordFailure({ method, path, status: 0, responseText: "" });
    throw error;
  }
  if (!result.response.ok) {
    driveDebug?.recordFailure({ method, path, status: result.response.status, responseText: result.text });
    const error = new Error(result.details?.message || result.text || `${result.response.status} ${result.response.statusText}`);
    error.status = result.response.status;
    error.code = result.details?.error || "";
    error.responseText = result.text;
    throw error;
  }
  return result.data;
}

async function publicApi(path, options = {}) {
  const method = options.method || "GET";
  let response;
  try {
    response = await fetch(path, {
      ...options,
      headers: {
        ...(options.body ? { "content-type": "application/json" } : {}),
        ...(options.headers || {}),
      },
    });
  } catch (error) {
    driveDebug?.recordFailure({ method, path, status: 0, responseText: "" });
    throw error;
  }
  if (!response.ok && response.status !== 202) {
    const text = await response.text();
    driveDebug?.recordFailure({ method, path, status: response.status, responseText: text });
    let details = null;
    try { details = JSON.parse(text); } catch {}
    const error = new Error(details?.message || text || `${response.status} ${response.statusText}`);
    error.status = response.status;
    error.code = details?.error || "";
    error.responseText = text;
    throw error;
  }
  const type = response.headers.get("content-type") || "";
  if (type.includes("application/json")) {
    const data = await response.json();
    data.__status = response.status;
    return data;
  }
  return { text: await response.text(), __status: response.status };
}
