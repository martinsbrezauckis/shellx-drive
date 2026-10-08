// build.rs — embed build-time provenance so the running server can report a
// stable, per-build version id.
//
// Consumed by `crate::version` → `GET /version` (the web UI's "new version
// available" reload banner compares the live server build to the one the tab
// loaded) and the Settings ▸ About panel.
//
// Everything degrades gracefully outside a git checkout (e.g. a source tarball
// build): the SHA becomes "unknown" and the commit time is left empty, so the
// build never fails for lack of git.
use std::process::Command;

fn main() {
    track_git_provenance_inputs();

    let sha = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=SHELLX_DRIVE_GIT_SHA={sha}");

    // Commit time (RFC3339). Stable per commit and meaningful as "built from a
    // commit made at …"; empty when git is unavailable.
    let built_at = git(&["log", "-1", "--format=%cI"]).unwrap_or_default();
    println!("cargo:rustc-env=SHELLX_DRIVE_BUILT_AT={built_at}");
}

/// Track the actual Git files that can change the resolved `HEAD` revision.
///
/// `.git/HEAD` normally contains only `ref: refs/heads/<branch>`, so committing
/// on that branch changes the referenced file rather than `HEAD` itself. Git
/// worktrees also use a `.git` indirection file. Resolve every path through Git
/// so both layouts cause Cargo to rerun this build script when the commit moves.
fn track_git_provenance_inputs() {
    for git_path in ["HEAD", "index", "packed-refs"] {
        emit_rerun_if_git_path_changes(git_path);
    }
    if let Some(head_ref) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        emit_rerun_if_git_path_changes(&head_ref);
    }
}

fn emit_rerun_if_git_path_changes(git_path: &str) {
    if let Some(path) = git(&["rev-parse", "--git-path", git_path]) {
        println!("cargo:rerun-if-changed={path}");
    }
}

/// Run a git subcommand, returning its trimmed stdout when it succeeds and is
/// non-empty. Any failure (git missing, not a repo, empty output) yields `None`.
fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}
