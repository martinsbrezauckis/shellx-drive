use crate::{
    error::ApiResult,
    model::{SandboxPreviewResponse, SandboxProfile},
    storage::ensure_valid_sandbox_profile,
};

pub fn preview_for_profile(
    profile: SandboxProfile,
    public_base_url: &str,
) -> ApiResult<SandboxPreviewResponse> {
    ensure_valid_sandbox_profile(&profile)?;
    let read_write_paths = profile.read_write_paths.join(" ");
    let unit_preview = format!(
        "[Service]\nUser={}\nGroup={}\nEnvironmentFile=/etc/shellx-drive.env\nExecStart=/usr/local/bin/shellx-drive --bind ${{SHELLX_DRIVE_BIND}} --data-dir ${{SHELLX_DRIVE_DATA_DIR}}\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nPrivateDevices=true\nProtectClock=true\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectKernelLogs=true\nProtectControlGroups=true\nLockPersonality=true\nMemoryDenyWriteExecute=true\nRestrictRealtime=true\nRestrictSUIDSGID=true\nSystemCallArchitectures=native\nReadWritePaths={}\n",
        profile.service_user, profile.service_group, read_write_paths
    );
    let commands = vec![
        format!(
            "./scripts/install_systemd.sh --binary target/release/shellx-drive --sha256 \"$(sha256sum target/release/shellx-drive | awk '{{print $1}}')\" --sandbox-profile {} --bind {} --data-dir {} --public-base-url {}",
            shell_quote(&profile.mode),
            shell_quote(&profile.bind),
            shell_quote(&profile.data_dir),
            shell_quote(public_base_url),
        ),
        "systemctl status shellx-drive.service".to_string(),
    ];
    Ok(SandboxPreviewResponse {
        profile,
        commands,
        unit_preview,
    })
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> SandboxProfile {
        SandboxProfile {
            id: "default".to_string(),
            name: "Default ShellX Drive sandbox".to_string(),
            mode: "strict".to_string(),
            data_dir: "/var/lib/shellx-drive".to_string(),
            bind: "127.0.0.1:5758".to_string(),
            service_user: "shellx-drive".to_string(),
            service_group: "shellx-drive".to_string(),
            read_write_paths: vec!["/var/lib/shellx-drive".to_string()],
            read_only_paths: Vec::new(),
            network_policy: "loopback_default".to_string(),
            status: "preview".to_string(),
            last_checked_at: None,
        }
    }

    #[test]
    fn legitimate_profile_renders_quoted_shell_arguments() {
        let preview = preview_for_profile(profile(), "https://drive.example.test").unwrap();
        assert!(preview.commands[0].contains("--sandbox-profile 'strict'"));
        assert!(preview.commands[0].contains("--bind '127.0.0.1:5758'"));
        assert!(preview.commands[0].contains("--data-dir '/var/lib/shellx-drive'"));
        assert!(preview.commands[0].contains("--public-base-url 'https://drive.example.test'"));
    }

    #[test]
    fn command_and_systemd_injection_profiles_fail_closed() {
        let mut command = profile();
        command.data_dir = "/var/lib/shellx-drive;touch /tmp/pwned".to_string();
        assert!(preview_for_profile(command, "https://drive.example.test").is_err());

        let mut systemd = profile();
        systemd.service_user = "shellx-drive\nExecStart=/tmp/pwned".to_string();
        assert!(preview_for_profile(systemd, "https://drive.example.test").is_err());
    }
}
