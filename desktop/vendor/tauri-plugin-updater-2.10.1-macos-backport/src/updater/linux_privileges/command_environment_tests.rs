use std::{collections::BTreeMap, ffi::OsString, path::Path, process::Command};

use super::privileged_command_with_environment;

#[test]
fn privileged_commands_reject_hostile_lookup_and_loader_environment() {
    let command = privileged_command_with_environment(
        Path::new("/usr/bin/sudo"),
        [
            (OsString::from("PATH"), OsString::from("/attacker/bin")),
            (
                OsString::from("LD_PRELOAD"),
                OsString::from("/attacker/lib.so"),
            ),
            (
                OsString::from("LD_LIBRARY_PATH"),
                OsString::from("/attacker/lib"),
            ),
            (OsString::from("BASH_ENV"), OsString::from("/attacker/env")),
            (OsString::from("HOME"), OsString::from("/attacker/home")),
            (OsString::from("DISPLAY"), OsString::from(":1")),
            (
                OsString::from("DBUS_SESSION_BUS_ADDRESS"),
                OsString::from("unix:path=/run/user/1000/bus"),
            ),
            (
                OsString::from("WAYLAND_DISPLAY"),
                OsString::from("wayland-0"),
            ),
            (
                OsString::from("XDG_RUNTIME_DIR"),
                OsString::from("/run/user/1000"),
            ),
            (
                OsString::from("XDG_CURRENT_DESKTOP"),
                OsString::from("GNOME"),
            ),
            (
                OsString::from("XDG_SESSION_TYPE"),
                OsString::from("wayland"),
            ),
            (
                OsString::from("XAUTHORITY"),
                OsString::from("/run/user/1000/Xauthority"),
            ),
            (OsString::from("LANG"), OsString::from("en_US.UTF-8")),
            (OsString::from("LC_CTYPE"), OsString::from("en_US.UTF-8")),
            (OsString::from("LC_MESSAGES"), OsString::from("en_US.UTF-8")),
            (OsString::from("TERM"), OsString::from("xterm-256color")),
        ],
    );
    let environment = command_environment(&command);

    assert_eq!(
        command.get_program(),
        Path::new("/usr/bin/sudo").as_os_str()
    );
    assert_eq!(environment.get("PATH"), Some(&"/usr/bin:/bin".to_owned()));
    for name in ["LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "HOME"] {
        assert!(!environment.contains_key(name));
    }
    for (name, value) in [
        ("DISPLAY", ":1"),
        ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
        ("WAYLAND_DISPLAY", "wayland-0"),
        ("XDG_RUNTIME_DIR", "/run/user/1000"),
        ("XDG_CURRENT_DESKTOP", "GNOME"),
        ("XDG_SESSION_TYPE", "wayland"),
        ("XAUTHORITY", "/run/user/1000/Xauthority"),
        ("LANG", "en_US.UTF-8"),
        ("LC_CTYPE", "en_US.UTF-8"),
        ("LC_MESSAGES", "en_US.UTF-8"),
        ("TERM", "xterm-256color"),
    ] {
        assert_eq!(environment.get(name), Some(&value.to_owned()));
    }
}

fn command_environment(command: &Command) -> BTreeMap<String, String> {
    command
        .get_envs()
        .filter_map(|(name, value)| {
            value.map(|value| {
                (
                    name.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
        })
        .collect()
}
