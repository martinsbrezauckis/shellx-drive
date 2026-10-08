// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Privilege admission for Debian and RPM updates.
//!
//! A process that has started is authoritative: cancellation or failure must
//! not open another credential prompt. Only a missing executable permits the
//! next fallback.

use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
};

use crate::error::{Error, Result};

mod command_environment;
use command_environment::privileged_command;

const PASSWORD_TITLE: &str = "Authentication Required";
const PASSWORD_TEXT: &str = "Enter your password to install the update:";
#[cfg(target_os = "linux")]
mod sealed_package;

#[cfg(target_os = "linux")]
pub(super) fn install_package(
    bytes: &[u8],
    install_command: &str,
    install_argument: &str,
) -> Result<()> {
    // Keep this owner alive through the authorization dialog and installer exit.
    // sudo may close inherited descriptors, so the child opens the live parent's
    // sealed object through procfs instead of inheriting an fd or a mutable file.
    let package = sealed_package::SealedPackage::new(bytes)?;
    install_package_with(
        &PrivilegePrograms::system(),
        package.path(),
        install_command,
        install_argument,
        io::stdin().is_terminal(),
    )
}

#[cfg(not(target_os = "linux"))]
pub(super) fn install_package(_: &[u8], _: &str, _: &str) -> Result<()> {
    // These platforms have no supported immutable Deb/RPM admission route.
    Err(Error::UnsupportedOs)
}

#[derive(Clone)]
struct PrivilegePrograms {
    pkexec: PathBuf,
    zenity: PathBuf,
    kdialog: PathBuf,
    sudo: PathBuf,
}

impl PrivilegePrograms {
    fn system() -> Self {
        Self {
            pkexec: PathBuf::from("/usr/bin/pkexec"),
            zenity: PathBuf::from("/usr/bin/zenity"),
            kdialog: PathBuf::from("/usr/bin/kdialog"),
            sudo: PathBuf::from("/usr/bin/sudo"),
        }
    }
}

enum GraphicalPassword {
    Unavailable,
    Cancelled,
    Value(Vec<u8>),
}

fn install_package_with(
    programs: &PrivilegePrograms,
    package: &Path,
    install_command: &str,
    install_argument: &str,
    has_terminal: bool,
) -> Result<()> {
    match run_pkexec(&programs.pkexec, package, install_command, install_argument) {
        Ok(Some(status)) if status.success() => {
            log::debug!("installed {package:?} with pkexec");
            return Ok(());
        }
        Ok(Some(status)) => return Err(pkexec_error(status)),
        Ok(None) => {}
        Err(error) => return Err(error.into()),
    }

    match graphical_password(programs)? {
        GraphicalPassword::Value(password) => {
            if install_with_graphical_sudo(
                programs,
                package,
                install_command,
                install_argument,
                &password,
            )? {
                log::debug!("installed {package:?} with graphical sudo");
                Ok(())
            } else {
                Err(Error::PackageInstallFailed)
            }
        }
        GraphicalPassword::Cancelled => Err(Error::AuthenticationFailed),
        GraphicalPassword::Unavailable => install_with_terminal_sudo(
            programs,
            package,
            install_command,
            install_argument,
            has_terminal,
        ),
    }
}

fn pkexec_error(status: ExitStatus) -> Error {
    // pkexec reserves 126 for a dismissed authentication dialog and 127 for
    // authorization failure or a pkexec error. Other statuses are returned by
    // the installer after successful authorization.
    match status.code() {
        Some(126 | 127) => Error::AuthenticationFailed,
        _ => Error::PackageInstallFailed,
    }
}

fn graphical_password(programs: &PrivilegePrograms) -> Result<GraphicalPassword> {
    let title = format!("--title={PASSWORD_TITLE}");
    let text = format!("--text={PASSWORD_TEXT}");
    match run_password_dialog(&programs.zenity, &["--password", &title, &text])? {
        GraphicalPassword::Unavailable => {
            run_password_dialog(&programs.kdialog, &["--password", PASSWORD_TEXT])
        }
        outcome => Ok(outcome),
    }
}

fn run_password_dialog(program: &Path, arguments: &[&str]) -> Result<GraphicalPassword> {
    match privileged_command(program).args(arguments).output() {
        Ok(output) if output.status.success() => Ok(GraphicalPassword::Value(
            decode_graphical_password(output.stdout)?,
        )),
        Ok(_) => Ok(GraphicalPassword::Cancelled),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(GraphicalPassword::Unavailable),
        Err(error) => Err(error.into()),
    }
}

fn decode_graphical_password(mut output: Vec<u8>) -> Result<Vec<u8>> {
    // zenity and kdialog terminate their password response with one LF. Do
    // not use `trim`: leading/trailing spaces and a trailing carriage return
    // are password bytes, not a dialog protocol delimiter.
    if output.last() == Some(&b'\n') {
        output.pop();
    }
    if output.contains(&b'\n') || std::str::from_utf8(&output).is_err() {
        return Err(Error::AuthenticationFailed);
    }
    Ok(output)
}

fn install_with_graphical_sudo(
    programs: &PrivilegePrograms,
    package: &Path,
    install_command: &str,
    install_argument: &str,
    password: &[u8],
) -> Result<bool> {
    let mut child = privileged_command(&programs.sudo)
        .args(["-S", install_command, install_argument])
        .arg(package)
        .stdin(Stdio::piped())
        // The updater does not use installer output. Null descriptors prevent
        // a verbose dpkg/rpm from blocking child.wait() on a full pipe.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let write_result = child
        .stdin
        .as_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "sudo stdin is unavailable"))
        .and_then(|stdin| {
            stdin.write_all(password)?;
            stdin.write_all(b"\n")
        });
    drop(child.stdin.take());

    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error.into());
    }

    Ok(child.wait()?.success())
}

fn install_with_terminal_sudo(
    programs: &PrivilegePrograms,
    package: &Path,
    install_command: &str,
    install_argument: &str,
    has_terminal: bool,
) -> Result<()> {
    let mut command = privileged_command(&programs.sudo);
    if !has_terminal {
        // A desktop process has no trustworthy terminal to answer sudo's
        // prompt. Preserve the existing interactive fallback when a terminal
        // exists, but fail immediately instead of leaving a headless app hung.
        command.arg("-n");
    }
    let status = command
        .args([install_command, install_argument])
        .arg(package)
        .status()?;

    if status.success() {
        log::debug!("installed {package:?} with terminal sudo");
        Ok(())
    } else if has_terminal {
        Err(Error::PackageInstallFailed)
    } else {
        Err(Error::AuthenticationFailed)
    }
}

fn run_pkexec(
    program: &Path,
    package: &Path,
    install_command: &str,
    install_argument: &str,
) -> io::Result<Option<ExitStatus>> {
    match privileged_command(program)
        .arg(install_command)
        .arg(install_argument)
        .arg(package)
        .status()
    {
        Ok(status) => Ok(Some(status)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "linux_privileges_tests.rs"]
mod tests;
