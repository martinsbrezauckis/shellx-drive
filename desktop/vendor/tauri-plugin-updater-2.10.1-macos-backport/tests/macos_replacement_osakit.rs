// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

#[cfg(target_os = "macos")]
use std::{fs, path::Path, process::Command};

#[cfg(target_os = "macos")]
const APPLESCRIPT: &str = include_str!("../src/updater/macos_replacement.applescript");

#[cfg(target_os = "macos")]
fn argument(path: &Path) -> osakit::Value {
    osakit::Value::String(
        path.to_str()
            .expect("the test paths are valid UTF-8")
            .to_string(),
    )
}

#[cfg(target_os = "macos")]
fn main() {
    let root = tempfile::tempdir().expect("temporary root");
    let parent = root.path().join("Drive's \"quoted\" \\ folder\n雪");
    fs::create_dir_all(&parent).expect("special path parent");
    let source = parent.join("source app");
    let incoming = parent.join("incoming app");
    let staging = parent.join("staging app");
    let output = parent.join("backup output");
    let arguments = [
        argument(&source),
        argument(&incoming),
        argument(&staging),
        argument(&output),
        osakit::Value::String("0".to_string()),
        osakit::Value::String(
            "/usr/bin/printf '%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$5\" > \"$4\"".to_string(),
        ),
    ];

    let mut script = osakit::Script::new_from_source(osakit::Language::AppleScript, APPLESCRIPT);
    script
        .compile()
        .expect("compile the fixed AppleScript on the process main thread");
    let command = match script
        .execute_function("replacement_command", arguments)
        .expect("render the quoted command without requesting authorization")
    {
        osakit::Value::String(command) => command,
        other => panic!("unexpected rendered command: {other:?}"),
    };
    assert!(Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .status()
        .expect("run the unprivileged round-trip command")
        .success());
    assert_eq!(
        fs::read_to_string(&output).expect("round-trip output"),
        format!(
            "{}\n{}\n{}\n{}\n0\n",
            source.display(),
            incoming.display(),
            staging.display(),
            output.display()
        )
    );
}

#[cfg(not(target_os = "macos"))]
fn main() {}
