use anyhow::Context;
use shellx_drive::{config::Config, fs_private, server};

const DEFAULT_TRACING_FILTER: &str = "shellx_drive=info";
const HELP: &str = "ShellX Drive server\n\nUsage: shellx-drive [OPTIONS]\n\nOptions:\n  --bind <ADDRESS>     Listen address (default: 127.0.0.1:5758)\n  --data-dir <PATH>    Private Drive data directory\n  --token-file <PATH> Private operator-token file (or SHELLX_DRIVE_TOKEN)\n  --hosted             Enable hosted-mode surfaces\n  --e2e                Enable loopback-only destructive test helpers\n  -h, --help           Print help\n  -V, --version        Print version\n\nEnvironment and deployment settings are documented in docs/public/CONFIG.md.\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EarlyCliAction {
    Help,
    Version,
}

fn early_cli_action(args: &[String]) -> Option<EarlyCliAction> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help"))
    {
        Some(EarlyCliAction::Help)
    } else if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-V" | "--version"))
    {
        Some(EarlyCliAction::Version)
    } else {
        None
    }
}

fn default_tracing_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::new(DEFAULT_TRACING_FILTER)
}

fn tracing_filter_from_rust_log(rust_log: Option<&str>) -> tracing_subscriber::EnvFilter {
    rust_log
        .and_then(|directive| tracing_subscriber::EnvFilter::try_new(directive).ok())
        .unwrap_or_else(default_tracing_filter)
}

fn tracing_filter() -> tracing_subscriber::EnvFilter {
    tracing_filter_from_rust_log(std::env::var("RUST_LOG").ok().as_deref())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fs_private::set_process_private_umask();
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match early_cli_action(&args) {
        Some(EarlyCliAction::Help) => {
            print!("{HELP}");
            return Ok(());
        }
        Some(EarlyCliAction::Version) => {
            println!("shellx-drive {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        None => {}
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_filter())
        .init();

    let config = Config::from_args(args)?;
    server::serve(config)
        .await
        .context("shellx-drive server failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracing_defaults_to_project_info_when_rust_log_is_absent() {
        assert_eq!(
            tracing_filter_from_rust_log(None).to_string(),
            DEFAULT_TRACING_FILTER
        );
    }

    #[test]
    fn tracing_honors_a_valid_explicit_rust_log_filter() {
        assert_eq!(
            tracing_filter_from_rust_log(Some("shellx_drive=debug")).to_string(),
            "shellx_drive=debug"
        );
    }

    #[test]
    fn help_and_version_are_available_without_configuration_or_secrets() {
        assert_eq!(
            early_cli_action(&["--help".to_string()]),
            Some(EarlyCliAction::Help)
        );
        assert_eq!(
            early_cli_action(&["-h".to_string()]),
            Some(EarlyCliAction::Help)
        );
        assert_eq!(
            early_cli_action(&["--version".to_string()]),
            Some(EarlyCliAction::Version)
        );
        assert_eq!(
            early_cli_action(&["-V".to_string()]),
            Some(EarlyCliAction::Version)
        );
        assert!(HELP.contains("SHELLX_DRIVE_TOKEN"));
        assert!(!HELP.contains("dev-token"));
        assert_eq!(early_cli_action(&["--hosted".to_string()]), None);
    }
}
