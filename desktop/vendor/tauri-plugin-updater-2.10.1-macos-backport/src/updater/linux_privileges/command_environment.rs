// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Restricted environment for native privilege and password-dialog helpers.

use std::{
    ffi::{OsStr, OsString},
    path::Path,
    process::Command,
};

const PRIVILEGED_COMMAND_PATH: &str = "/usr/bin:/bin";
const INTERACTIVE_ENVIRONMENT: &[&str] = &[
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "LANG",
    "LC_CTYPE",
    "LC_MESSAGES",
    "TERM",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_CURRENT_DESKTOP",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
];

pub(super) fn privileged_command(program: &Path) -> Command {
    privileged_command_with_environment(program, std::env::vars_os())
}

fn privileged_command_with_environment<I>(program: &Path, environment: I) -> Command
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut command = Command::new(program);
    command.env_clear().env("PATH", PRIVILEGED_COMMAND_PATH);
    for (name, value) in environment {
        if INTERACTIVE_ENVIRONMENT
            .iter()
            .any(|allowed| name == OsStr::new(allowed))
        {
            command.env(name, value);
        }
    }
    command
}

#[cfg(test)]
#[path = "command_environment_tests.rs"]
mod tests;
