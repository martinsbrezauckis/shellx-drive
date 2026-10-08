use std::path::PathBuf;

use anyhow::{bail, Context};
use shellx_drive::sync_client::{SyncClient, SyncClientConfig};

const USAGE: &str = "ShellX Drive sync client\n\nUsage:\n  shellx-drive-sync sync-once --base-url <https-url> [--ca-file <pem>] [--token-file <path>] --cache-dir <path> [--profile <name>] [--adopt-existing-cache] [--actor <email>] [--workspace <id>] [--safe-space <id>]\n\nThe token may instead be supplied through SHELLX_DRIVE_SYNC_TOKEN. A private --ca-file is trusted only by this Drive client; it does not modify operating-system certificate settings.";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        bail!(USAGE);
    };
    if matches!(command.as_str(), "--help" | "-h" | "help") {
        println!("{USAGE}");
        return Ok(());
    }
    if matches!(command.as_str(), "--version" | "-V") {
        println!("shellx-drive-sync {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if command != "sync-once" {
        bail!("unknown command: {command}");
    }

    let mut base_url = None;
    let mut token = std::env::var("SHELLX_DRIVE_SYNC_TOKEN").ok();
    let mut cache_dir = None;
    let mut ca_file = None;
    let mut actor_email = None;
    let mut profile_name = None;
    let mut adopt_existing_cache = false;
    let mut selected_workspace_ids = Vec::new();
    let mut safe_space_workspace_ids = Vec::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--base-url" => base_url = Some(args.next().context("--base-url requires value")?),
            "--ca-file" => {
                ca_file = Some(PathBuf::from(
                    args.next().context("--ca-file requires path")?,
                ))
            }
            "--token-file" => {
                let path = PathBuf::from(args.next().context("--token-file requires path")?);
                token = Some(shellx_drive::secret_input::read_private_secret_file(
                    &path,
                    "sync token",
                )?);
            }
            "--actor" => actor_email = Some(args.next().context("--actor requires value")?),
            "--profile" => profile_name = Some(args.next().context("--profile requires value")?),
            "--adopt-existing-cache" => adopt_existing_cache = true,
            "--workspace" => {
                selected_workspace_ids.push(args.next().context("--workspace requires value")?)
            }
            "--safe-space" => {
                safe_space_workspace_ids.push(args.next().context("--safe-space requires value")?)
            }
            "--cache-dir" => {
                cache_dir = Some(PathBuf::from(
                    args.next().context("--cache-dir requires value")?,
                ))
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    let mut client = SyncClient::new(SyncClientConfig {
        base_url: base_url.context("--base-url is required")?,
        token: token.context("SHELLX_DRIVE_SYNC_TOKEN or --token-file is required")?,
        cache_dir: cache_dir.context("--cache-dir is required")?,
        actor_email,
        selected_workspace_ids,
        safe_space_workspace_ids,
    })?
    .with_profile(profile_name.as_deref(), adopt_existing_cache)?;
    if let Some(ca_file) = ca_file.as_deref() {
        client = client.with_additional_ca_file(ca_file)?;
    }
    let report = client.sync_once().await?;
    // Two-way totals across all synced workspaces.
    let downloaded: usize = report
        .workspaces
        .iter()
        .map(|workspace| workspace.downloaded_files)
        .sum();
    let uploaded_new: usize = report
        .workspaces
        .iter()
        .map(|workspace| workspace.uploaded_new)
        .sum();
    let uploaded_updated: usize = report
        .workspaces
        .iter()
        .map(|workspace| workspace.uploaded_updated)
        .sum();
    let resumable: usize = report
        .workspaces
        .iter()
        .map(|workspace| workspace.resumable_uploads)
        .sum();
    let skipped_conflicts: usize = report
        .workspaces
        .iter()
        .map(|workspace| workspace.skipped_conflicts)
        .sum();
    println!(
        "SHELLX_DRIVE_SYNC_OK workspaces={} downloaded_files={} uploaded_new={} uploaded_updated={} resumable_uploads={} skipped_conflicts={} conflicts_total={}",
        report.workspaces.len(),
        downloaded,
        uploaded_new,
        uploaded_updated,
        resumable,
        skipped_conflicts,
        report.conflicts.total,
    );
    Ok(())
}
