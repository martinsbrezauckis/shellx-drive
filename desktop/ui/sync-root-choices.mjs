export function rootLocationLabel(workspaceName, rootLabel, ownerLabel, role) {
  const roleCopy = role === "viewer"
    ? "Viewer · download only"
    : role === "editor"
      ? "Editor"
      : "Access pending";
  if (role === "owner") {
    const workspace = String(workspaceName ?? "").trim()
      || String(rootLabel ?? "").trim()
      || "My files";
    return `${workspace} / Workspace root`;
  }
  const owner = ownerLabel || "Unknown owner";
  return `Shared with me / ${owner} / ${rootLabel || "Shared root"} — ${roleCopy}`;
}

export function driveLocationChoices(workspaces) {
  return workspaces.flatMap((workspace) => {
    const locations = (workspace.locations ?? []).map((location) => {
      const remoteRootId = location.remoteRootId ?? location.remote_root_id ?? null;
      const syncRootId = String(location.syncRootId ?? location.sync_root_id ?? "");
      const ownerLabel = String(location.ownerLabel ?? location.owner_label ?? "");
      const role = String(location.role ?? "").toLowerCase();
      const rootLabel = String(location.label ?? "");
      return {
        ...location,
        workspaceId: workspace.id,
        remoteRootId,
        syncRootId,
        ownerLabel,
        role,
        label: syncRootId
          ? rootLocationLabel(workspace.name, rootLabel, ownerLabel, role)
          : remoteRootId === null
            ? `${workspace.name} — Entire workspace`
            : rootLabel,
      };
    });
    return locations.sort((left, right) => (
      Number(left.role !== "owner") - Number(right.role !== "owner")
      || left.label.localeCompare(right.label)
    ));
  });
}
