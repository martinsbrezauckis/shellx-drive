use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use tempfile::TempDir;

use super::{decode_graphical_password, install_package_with, PrivilegePrograms};
use crate::error::Error;

struct Fixture {
    root: TempDir,
    trace: PathBuf,
    captured_stdin: PathBuf,
    programs: PrivilegePrograms,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let trace = root.path().join("trace");
        let captured_stdin = root.path().join("stdin");
        let programs = PrivilegePrograms {
            pkexec: root.path().join("pkexec"),
            zenity: root.path().join("zenity"),
            kdialog: root.path().join("kdialog"),
            sudo: root.path().join("sudo"),
        };
        Self {
            root,
            trace,
            captured_stdin,
            programs,
        }
    }

    fn package(&self) -> PathBuf {
        let package = self.root.path().join("package.deb");
        fs::write(&package, b"fixture package").unwrap();
        package
    }

    fn command(&self, name: &str, script: &str) {
        let path = self.root.path().join(name);
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{script}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn trace(&self) -> Vec<String> {
        fs::read_to_string(&self.trace)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn trace_path(&self) -> String {
        shell_quote(&self.trace)
    }

    fn stdin_path(&self) -> String {
        shell_quote(&self.captured_stdin)
    }
}

#[test]
fn system_privilege_programs_use_supported_absolute_paths() {
    let programs = PrivilegePrograms::system();

    assert_eq!(programs.pkexec, Path::new("/usr/bin/pkexec"));
    assert_eq!(programs.zenity, Path::new("/usr/bin/zenity"));
    assert_eq!(programs.kdialog, Path::new("/usr/bin/kdialog"));
    assert_eq!(programs.sudo, Path::new("/usr/bin/sudo"));
}

#[test]
fn started_pkexec_cancellation_does_not_open_another_prompt() {
    let fixture = Fixture::new();
    fixture.command(
        "pkexec",
        &format!("echo pkexec >> {}; exit 126", fixture.trace_path()),
    );
    fixture.command(
        "zenity",
        &format!("echo zenity >> {}; exit 0", fixture.trace_path()),
    );
    fixture.command(
        "kdialog",
        &format!("echo kdialog >> {}; exit 0", fixture.trace_path()),
    );
    fixture.command(
        "sudo",
        &format!("echo sudo >> {}; exit 0", fixture.trace_path()),
    );

    let result = install_package_with(&fixture.programs, &fixture.package(), "dpkg", "-i", false);

    assert!(matches!(result, Err(Error::AuthenticationFailed)));
    assert_eq!(fixture.trace(), ["pkexec"]);
}

#[test]
fn started_pkexec_install_failure_does_not_open_another_prompt() {
    let fixture = Fixture::new();
    fixture.command(
        "pkexec",
        &format!("echo pkexec >> {}; exit 1", fixture.trace_path()),
    );
    fixture.command(
        "zenity",
        &format!("echo zenity >> {}; exit 0", fixture.trace_path()),
    );
    fixture.command(
        "sudo",
        &format!("echo sudo >> {}; exit 0", fixture.trace_path()),
    );

    let result = install_package_with(&fixture.programs, &fixture.package(), "dpkg", "-i", false);

    assert!(matches!(result, Err(Error::PackageInstallFailed)));
    assert_eq!(fixture.trace(), ["pkexec"]);
}

#[test]
fn cancelled_graphical_dialog_does_not_open_terminal_sudo() {
    let fixture = Fixture::new();
    fixture.command(
        "zenity",
        &format!("echo zenity >> {}; exit 1", fixture.trace_path()),
    );
    fixture.command(
        "kdialog",
        &format!("echo kdialog >> {}; exit 0", fixture.trace_path()),
    );
    fixture.command(
        "sudo",
        &format!("echo sudo >> {}; exit 0", fixture.trace_path()),
    );

    let result = install_package_with(&fixture.programs, &fixture.package(), "dpkg", "-i", false);

    assert!(matches!(result, Err(Error::AuthenticationFailed)));
    assert_eq!(fixture.trace(), ["zenity"]);
}

#[test]
fn cancelled_kdialog_does_not_open_terminal_sudo() {
    let fixture = Fixture::new();
    fixture.command(
        "kdialog",
        &format!("echo kdialog >> {}; exit 1", fixture.trace_path()),
    );
    fixture.command(
        "sudo",
        &format!("echo sudo >> {}; exit 0", fixture.trace_path()),
    );

    let result = install_package_with(&fixture.programs, &fixture.package(), "dpkg", "-i", false);

    assert!(matches!(result, Err(Error::AuthenticationFailed)));
    assert_eq!(fixture.trace(), ["kdialog"]);
}

#[test]
fn unavailable_graphical_tools_use_noninteractive_terminal_sudo() {
    let fixture = Fixture::new();
    fixture.command(
        "sudo",
        &format!("echo \"sudo:$*\" >> {}; exit 0", fixture.trace_path()),
    );

    install_package_with(&fixture.programs, &fixture.package(), "dpkg", "-i", false).unwrap();

    assert_eq!(
        fixture.trace(),
        ["sudo:-n dpkg -i ".to_owned() + fixture.package().to_str().unwrap()]
    );
}

#[test]
fn available_terminal_preserves_the_interactive_sudo_fallback() {
    let fixture = Fixture::new();
    fixture.command(
        "sudo",
        &format!("echo \"sudo:$*\" >> {}; exit 0", fixture.trace_path()),
    );

    install_package_with(&fixture.programs, &fixture.package(), "dpkg", "-i", true).unwrap();

    assert_eq!(
        fixture.trace(),
        ["sudo:dpkg -i ".to_owned() + fixture.package().to_str().unwrap()]
    );
}

#[test]
fn graphical_password_preserves_spaces_and_only_removes_the_final_line_feed() {
    let fixture = Fixture::new();
    fixture.command(
        "zenity",
        &format!(
            "echo zenity >> {}; printf ' fixture value  \\n'",
            fixture.trace_path()
        ),
    );
    fixture.command(
        "sudo",
        &format!(
            "echo sudo >> {}; cat > {}; exit 0",
            fixture.trace_path(),
            fixture.stdin_path()
        ),
    );

    install_package_with(&fixture.programs, &fixture.package(), "dpkg", "-i", false).unwrap();

    assert_eq!(
        fs::read(&fixture.captured_stdin).unwrap(),
        b" fixture value  \n"
    );
    assert_eq!(fixture.trace(), ["zenity", "sudo"]);
}

#[test]
fn graphical_password_rejects_lossy_or_multiline_protocol_output() {
    assert!(matches!(
        decode_graphical_password(vec![0xff, b'\n']),
        Err(Error::AuthenticationFailed)
    ));
    assert!(matches!(
        decode_graphical_password(b"one\ntwo\n".to_vec()),
        Err(Error::AuthenticationFailed)
    ));
    assert_eq!(
        decode_graphical_password(b" value \r\n".to_vec()).unwrap(),
        b" value \r"
    );
}

#[test]
fn verbose_gui_sudo_completes_without_pipe_backpressure() {
    let fixture = Fixture::new();
    fixture.command("zenity", "printf 'fixture\\n'; exit 0");
    fixture.command(
        "sudo",
        &format!(
            "cat > {}; dd if=/dev/zero bs=131072 count=1; dd if=/dev/zero bs=131072 count=1 >&2; exit 0",
            fixture.stdin_path()
        ),
    );

    install_package_with(&fixture.programs, &fixture.package(), "dpkg", "-i", false).unwrap();

    assert_eq!(fs::read(&fixture.captured_stdin).unwrap(), b"fixture\n");
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\"'\"'"))
}
