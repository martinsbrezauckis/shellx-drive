// Workspace-policy requests share one lease so a delayed response can never
// render or save policy data for a workspace that is no longer current.
(function attachDriveWorkspacePolicy(root) {
  "use strict";

  function createController(options) {
    let generation = 0;

    function invalidate() {
      generation += 1;
      return generation;
    }

    function begin(workspaceId) {
      return { workspaceId, generation: invalidate() };
    }

    function isCurrent(request) {
      return Boolean(
        request &&
        request.generation === generation &&
        options.getCurrentWorkspace()?.id === request.workspaceId,
      );
    }

    async function loadForWorkspace(workspaceId) {
      if (options.getCurrentWorkspace()?.id !== workspaceId) return null;
      const request = begin(workspaceId);
      let usage;
      let policyResponse;
      try {
        [usage, policyResponse] = await Promise.all([
          options.api(`/workspaces/${workspaceId}/usage`),
          options.api(`/workspaces/${workspaceId}/policy`),
        ]);
      } catch (error) {
        if (!isCurrent(request)) return null;
        throw error;
      }
      if (!isCurrent(request)) return null;
      const policy = policyResponse.policy;
      if (
        usage?.workspace_id !== request.workspaceId ||
        policy?.workspace_id !== request.workspaceId
      ) return null;
      options.setWorkspaceData({ usage, policy });
      options.render();
      return { usage, policy };
    }

    async function load() {
      const workspace = options.getCurrentWorkspace();
      if (!workspace) {
        invalidate();
        options.setWorkspaceData({ usage: null, policy: null });
        options.render();
        return null;
      }
      return loadForWorkspace(workspace.id);
    }

    async function save(patch) {
      const workspace = options.getCurrentWorkspace();
      if (!workspace) return null;
      const request = begin(workspace.id);
      let data;
      try {
        data = await options.api(`/workspaces/${request.workspaceId}/policy`, {
          method: "PATCH",
          body: JSON.stringify(patch),
        });
      } catch (error) {
        if (!isCurrent(request)) return null;
        throw error;
      }
      if (!isCurrent(request)) return null;
      if (data?.policy?.workspace_id !== request.workspaceId) return null;
      options.setWorkspaceData({ usage: options.getWorkspaceUsage(), policy: data.policy });
      options.render();
      const refreshed = await loadForWorkspace(request.workspaceId);
      if (!refreshed) return null;
      return { ...data, ...refreshed };
    }

    return Object.freeze({ invalidate, isCurrent, load, save });
  }

  root.ShellXDriveWorkspacePolicy = Object.freeze({ createController });
})(window);
