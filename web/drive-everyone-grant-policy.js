// Server-admin control for Drive-wide human item grants. It deliberately uses
// a separate endpoint: workspace owners cannot broaden this server policy.
(() => {
  function createController({ api, relativeTime, showToast } = {}) {
    const form = document.getElementById("admin-everyone-grant-policy-form");
    const enabled = document.getElementById("admin-everyone-grant-policy-enabled");
    const output = document.getElementById("admin-everyone-grant-policy-output");
    let policy = null;

    function render() {
      if (!policy) return;
      if (enabled) enabled.value = String(policy.everyone_grants_enabled === true);
      if (output) {
        const state = policy.everyone_grants_enabled ? "Allowed" : "Blocked";
        const updated = policy.updated_at ? ` Last changed ${relativeTime(policy.updated_at)}.` : "";
        output.textContent = `${state}. Turning this off keeps existing everyone access active until its owner removes it, but blocks new or changed everyone access.${updated}`;
      }
    }

    async function load() {
      const data = await api("/admin/human-sharing-policy");
      policy = data?.policy || null;
      render();
      return data;
    }

    async function save(event) {
      event?.preventDefault();
      const data = await api("/admin/human-sharing-policy", {
        method: "PATCH",
        body: JSON.stringify({ everyone_grants_enabled: enabled?.value === "true" }),
      });
      policy = data?.policy || null;
      render();
      showToast?.("Everyone access policy saved.");
      return data;
    }

    form?.addEventListener("submit", (event) => {
      save(event).catch((error) => {
        if (output) output.textContent = String(error?.message || "Could not save everyone access policy.");
      });
    });
    return Object.freeze({ load, save });
  }

  window.ShellXDriveEveryoneGrantPolicy = Object.freeze({ createController });
})();
