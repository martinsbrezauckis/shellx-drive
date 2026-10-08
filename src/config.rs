use std::{net::SocketAddr, path::PathBuf};

use anyhow::{bail, Context};
use reqwest::Url;

const DEFAULT_PUBLIC_ORIGIN: &str = "http://127.0.0.1:5758";

/// The one public browser origin for this Drive instance.
///
/// A public origin is deliberately narrower than a generic URL: it identifies
/// one scheme + host + optional non-default port, with no credentials, path,
/// query, or fragment. That lets every browser-facing boundary (links, CSRF,
/// hosted status, and redirect-adjacent helpers) compare and generate the same
/// canonical value rather than each accepting a differently parsed string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicOrigin(String);

impl PublicOrigin {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        let value = value.trim();
        let parsed = Url::parse(value).context("public origin must be an absolute URL")?;
        if !matches!(parsed.scheme(), "http" | "https") {
            bail!("public origin must use http or https");
        }
        if parsed.host_str().is_none() {
            bail!("public origin must have a host");
        }
        // `Url` represents an empty username as `""`, so checking its parsed
        // username alone would accept an explicitly present `https://@host`
        // authority. Any `@` in the authority is user-info and is forbidden.
        if public_origin_has_userinfo(value)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            bail!("public origin must not contain embedded credentials");
        }
        if parsed.path() != "/" {
            bail!("public origin must not contain a path");
        }
        if parsed.query().is_some() {
            bail!("public origin must not contain a query");
        }
        if parsed.fragment().is_some() {
            bail!("public origin must not contain a fragment");
        }
        if parsed.scheme() == "http" && !public_origin_is_loopback(&parsed) {
            bail!("public origin must use HTTPS unless it targets loopback");
        }
        Ok(Self(parsed.origin().ascii_serialization()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_loopback(&self) -> bool {
        // `Self` is constructed only by `parse`, which stores this canonical
        // absolute origin. Reparse instead of retaining a second derived field
        // so equality remains exactly the browser authority string.
        public_origin_is_loopback(
            &Url::parse(&self.0).expect("PublicOrigin stores a parsed, canonical origin"),
        )
    }

    /// Join a constant application-root route without allowing a caller to
    /// change the authority or smuggle query/fragment data into an origin.
    pub fn application_route(&self, route: &str) -> String {
        debug_assert!(route.starts_with('/'));
        debug_assert!(!route.contains('?'));
        debug_assert!(!route.contains('#'));
        format!("{}{route}", self.0)
    }
}

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub token: String,
    /// Optional first-run authority accepted only by the bootstrap routes.
    /// Once an account exists, storage rejects every further bootstrap attempt.
    pub bootstrap_token: Option<String>,
    pub e2e_enabled: bool,
    pub email_transport: String,
    pub email_from: String,
    pub public_origin: PublicOrigin,
    pub email_smtp_host_source: String,
    pub email_smtp_port: Option<u16>,
    pub email_smtp_user_source: String,
    pub maintenance_token_source: String,
    pub maintenance_sudo_source: String,
    pub local_session_ttl_seconds: i64,
    pub office_provider_name: String,
    pub office_provider_url: Option<String>,
    pub office_session_ttl_seconds: i64,
    pub hosted_mode: bool,
    pub hosted_billing_provider: String,
    pub hosted_public_rate_limit_per_minute: i64,
    /// Maximum bytes accepted or produced by one streamed v2 archive.
    pub backup_max_archive_bytes: u64,
    /// Whether Drive emits the production `__Host-shellx_drive_session` cookie
    /// with browser-enforced `Secure; Path=/` and no `Domain` attribute. Gated
    /// on config, not on the request scheme: Drive is expected to sit behind a
    /// TLS-terminating reverse proxy, so the request reaching the app is often
    /// plain `http` even though the browser<->proxy leg is HTTPS. Controlled by
    /// `SHELLX_DRIVE_SECURE_COOKIES` (`1/true/yes/on` = force on,
    /// `0/false/no/off` = force off). When the env var is unset the default is
    /// **on in production and off under `--e2e`**, so `http://127.0.0.1` local
    /// and end-to-end testing keeps working without an override.
    pub secure_cookies: bool,
    /// Trust reverse-proxy client-address headers only when the transport peer
    /// is loopback. Off by default so unrelated local processes cannot choose
    /// their own rate-limit identity.
    pub trust_proxy_headers: bool,

    /// Public GitHub `owner/repo` slug checked by administrator-only
    /// `GET /update/check` for a newer server release. The check is disabled
    /// unless `SHELLX_DRIVE_UPDATE_REPO` names a bare `owner/repo` slug.
    /// `None` = check disabled.
    pub update_repo: Option<String>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Config")
            .field("bind", &self.bind)
            .field("data_dir", &self.data_dir)
            .field("token", &"[REDACTED]")
            .field(
                "bootstrap_token_configured",
                &self.bootstrap_token.is_some(),
            )
            .field("e2e_enabled", &self.e2e_enabled)
            .field("hosted_mode", &self.hosted_mode)
            .field("secure_cookies", &self.secure_cookies)
            .field("trust_proxy_headers", &self.trust_proxy_headers)
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn from_args<I>(args: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut bind: SocketAddr = "127.0.0.1:5758".parse().unwrap();
        let mut data_dir = PathBuf::from(".shellx-drive-data");
        let token_from_env = std::env::var("SHELLX_DRIVE_TOKEN").ok();
        let mut token = token_from_env
            .clone()
            .unwrap_or_else(|| "dev-token".to_string());
        let mut token_explicit = token_from_env.is_some();
        let bootstrap_token = std::env::var("SHELLX_DRIVE_BOOTSTRAP_TOKEN").ok();
        let mut e2e_enabled = false;
        let email_transport =
            std::env::var("SHELLX_DRIVE_EMAIL_TRANSPORT").unwrap_or_else(|_| "capture".to_string());
        let email_from = std::env::var("SHELLX_DRIVE_EMAIL_FROM")
            .unwrap_or_else(|_| "ShellX Drive <noreply@shellx.local>".to_string());
        let email_smtp_host_source = safe_source_label("SHELLX_DRIVE_SMTP_HOST");
        let email_smtp_port = std::env::var("SHELLX_DRIVE_SMTP_PORT")
            .ok()
            .and_then(|port| port.parse::<u16>().ok());
        let email_smtp_user_source = safe_source_label("SHELLX_DRIVE_SMTP_USERNAME");
        let maintenance_token_source = safe_source_label("SHELLX_DRIVE_UBUNTU_PRO_TOKEN_SOURCE");
        let maintenance_sudo_source = safe_source_label("SHELLX_DRIVE_SUDO_SOURCE");
        let local_session_ttl_seconds = std::env::var("SHELLX_DRIVE_LOCAL_SESSION_TTL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(2_592_000)
            .clamp(3_600, 31_536_000);
        let office_provider_name = std::env::var("SHELLX_DRIVE_OFFICE_PROVIDER_NAME")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "Office editor".to_string());
        let office_provider_url = std::env::var("SHELLX_DRIVE_OFFICE_PROVIDER_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(validate_office_provider_url)
            .transpose()?;
        let office_session_ttl_seconds = std::env::var("SHELLX_DRIVE_OFFICE_SESSION_TTL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(900)
            .clamp(60, 3_600);
        let mut hosted_mode = env_bool("SHELLX_DRIVE_HOSTED_MODE");
        let hosted_billing_provider = std::env::var("SHELLX_DRIVE_HOSTED_BILLING_PROVIDER")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "none".to_string());
        let hosted_public_rate_limit_per_minute =
            std::env::var("SHELLX_DRIVE_HOSTED_PUBLIC_RATE_LIMIT_PER_MINUTE")
                .ok()
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(60)
                .max(1);
        let backup_max_archive_bytes = std::env::var("SHELLX_DRIVE_BACKUP_MAX_ARCHIVE_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(9 * 1024 * 1024 * 1024 * 1024)
            .clamp(1024 * 1024, 9 * 1024 * 1024 * 1024 * 1024);
        // Explicit override for the session-cookie `Secure` attribute, if the
        // operator set one. Resolved to a concrete bool *after* `--e2e` is known
        // so the unset default can depend on it (on in prod, off under e2e).
        let secure_cookies_override = env_bool_opt("SHELLX_DRIVE_SECURE_COOKIES")?;
        let trust_proxy_headers = env_bool("SHELLX_DRIVE_TRUST_PROXY_HEADERS");
        // Update-check repo: unset or empty → disabled; any value is validated
        // as a bare `owner/repo` slug (invalid → disabled). There is no release
        // coordinate until the project deliberately assigns one.
        let update_repo = match std::env::var("SHELLX_DRIVE_UPDATE_REPO") {
            Ok(value) if value.trim().is_empty() => None,
            Ok(value) => crate::version::normalize_repo_slug(&value),
            Err(_) => None,
        };

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--bind" => {
                    let value = args.next().context("--bind requires address")?;
                    bind = value.parse().context("invalid --bind address")?;
                }
                "--data-dir" => {
                    data_dir = PathBuf::from(args.next().context("--data-dir requires path")?);
                }
                "--token-file" => {
                    let path = PathBuf::from(args.next().context("--token-file requires path")?);
                    token =
                        crate::secret_input::read_private_secret_file(&path, "SHELLX_DRIVE_TOKEN")?;
                    token_explicit = true;
                }
                "--e2e" => e2e_enabled = true,
                "--hosted" => hosted_mode = true,
                other => bail!("unknown argument: {other}"),
            }
        }

        if e2e_enabled {
            validate_e2e_config(bind, &token)?;
        } else {
            if !token_explicit {
                bail!(
                    "SHELLX_DRIVE_TOKEN is not set. Set SHELLX_DRIVE_TOKEN or pass --token-file to a \
                     strong random secret of at least {MIN_TOKEN_LEN} characters, for example: \
                     `openssl rand -hex 32`. Pass --e2e only for local testing."
                );
            }
            if let Some(reason) = weak_token_reason(&token) {
                bail!(
                    "SHELLX_DRIVE_TOKEN is {reason}. Set SHELLX_DRIVE_TOKEN or pass --token-file to a \
                     strong random secret of at least {MIN_TOKEN_LEN} characters, for example: \
                     `openssl rand -hex 32`. Pass --e2e only for local testing."
                );
            }
        }
        validate_bootstrap_token(bootstrap_token.as_deref(), &token)?;

        let public_origin = resolve_public_origin()?;

        // Default: secure cookies ON in production, OFF under `--e2e` (so local
        // http testing works). An explicit `SHELLX_DRIVE_SECURE_COOKIES` wins,
        // except an insecure override may never weaken a production bind or
        // browser origin.
        let secure_cookies =
            resolve_secure_cookies(bind, &public_origin, e2e_enabled, secure_cookies_override)?;

        Ok(Self {
            bind,
            data_dir,
            token,
            bootstrap_token,
            e2e_enabled,
            email_transport,
            email_from,
            public_origin,
            email_smtp_host_source,
            email_smtp_port,
            email_smtp_user_source,
            maintenance_token_source,
            maintenance_sudo_source,
            local_session_ttl_seconds,
            office_provider_name,
            office_provider_url,
            office_session_ttl_seconds,
            hosted_mode,
            hosted_billing_provider,
            hosted_public_rate_limit_per_minute,
            backup_max_archive_bytes,
            secure_cookies,
            trust_proxy_headers,
            update_repo,
        })
    }
}

/// Keep destructive end-to-end helpers unreachable from any network other than
/// the local machine, and require the same minimum operator-token strength as
/// production so a separate local process cannot guess the authority value.
fn validate_e2e_config(bind: SocketAddr, token: &str) -> anyhow::Result<()> {
    if !bind.ip().is_loopback() {
        bail!(
            "--e2e requires a loopback --bind address; use 127.0.0.1:<port> or [::1]:<port>, \
             or remove --e2e before binding to {bind}"
        );
    }
    if let Some(reason) = weak_token_reason(token) {
        bail!(
            "--e2e operator token is {reason}. Set SHELLX_DRIVE_TOKEN or pass a private \
             --token-file with a strong random token of at least {MIN_TOKEN_LEN} characters and \
             keep --bind on loopback."
        );
    }
    Ok(())
}

fn resolve_public_origin() -> anyhow::Result<PublicOrigin> {
    // `SHELLX_DRIVE_EMAIL_BASE_URL` and `SHELLX_DRIVE_HOSTED_PUBLIC_BASE_URL`
    // were separate historical knobs. Keep them as migration aliases for one
    // release line, but make disagreement a startup error rather than letting
    // links, hosted status, and CSRF silently select different authorities.
    resolve_configured_public_origin([
        (
            "SHELLX_DRIVE_PUBLIC_ORIGIN",
            configured_env_value("SHELLX_DRIVE_PUBLIC_ORIGIN"),
        ),
        (
            "SHELLX_DRIVE_EMAIL_BASE_URL",
            configured_env_value("SHELLX_DRIVE_EMAIL_BASE_URL"),
        ),
        (
            "SHELLX_DRIVE_HOSTED_PUBLIC_BASE_URL",
            configured_env_value("SHELLX_DRIVE_HOSTED_PUBLIC_BASE_URL"),
        ),
    ])
}

fn resolve_configured_public_origin(
    configured: [(&str, Option<String>); 3],
) -> anyhow::Result<PublicOrigin> {
    let mut origins = configured.into_iter().filter_map(|(name, value)| {
        value.map(|value| PublicOrigin::parse(&value).with_context(|| format!("invalid {name}")))
    });
    let Some(origin) = origins.next().transpose()? else {
        return PublicOrigin::parse(DEFAULT_PUBLIC_ORIGIN);
    };
    for candidate in origins {
        let candidate = candidate?;
        if candidate != origin {
            bail!(
                "SHELLX_DRIVE_PUBLIC_ORIGIN, SHELLX_DRIVE_EMAIL_BASE_URL, and SHELLX_DRIVE_HOSTED_PUBLIC_BASE_URL must resolve to the same public origin"
            );
        }
    }
    Ok(origin)
}

fn resolve_secure_cookies(
    bind: SocketAddr,
    public_origin: &PublicOrigin,
    e2e_enabled: bool,
    secure_cookies_override: Option<bool>,
) -> anyhow::Result<bool> {
    let secure_cookies = secure_cookies_override.unwrap_or(!e2e_enabled);
    if e2e_enabled {
        return Ok(secure_cookies);
    }

    if !bind.ip().is_loopback() && public_origin.is_loopback() {
        bail!(
            "a network-reachable production --bind requires a non-loopback SHELLX_DRIVE_PUBLIC_ORIGIN; use the final HTTPS browser origin or keep --bind on loopback behind a trusted TLS reverse proxy"
        );
    }

    if secure_cookies_override == Some(false)
        && (!bind.ip().is_loopback() || !public_origin.is_loopback())
    {
        bail!(
            "SHELLX_DRIVE_SECURE_COOKIES=false is allowed only when both --bind and SHELLX_DRIVE_PUBLIC_ORIGIN are loopback, or under --e2e; remove the override for production"
        );
    }
    Ok(secure_cookies)
}

fn configured_env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn public_origin_is_loopback(origin: &Url) -> bool {
    origin.host_str().is_some_and(|host| {
        let host = host.trim_matches(['[', ']']);
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

fn public_origin_has_userinfo(value: &str) -> bool {
    let Some((_, after_scheme)) = value.split_once("://") else {
        return false;
    };
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    after_scheme[..authority_end].contains('@')
}

/// Minimum acceptable length for a production `SHELLX_DRIVE_TOKEN`.
const MIN_TOKEN_LEN: usize = 16;

/// Return a human-readable reason a production token is unacceptable, or `None`
/// if it is strong enough to boot with. Rejects empty tokens, well-known
/// placeholders (`dev-token`, `change-me`, `REPLACE_WITH_...`, etc.), and
/// anything shorter than [`MIN_TOKEN_LEN`]. Never echoes the token value.
fn weak_token_reason(token: &str) -> Option<&'static str> {
    if token.trim().is_empty() {
        return Some("empty");
    }
    if is_placeholder_token(token) {
        return Some("set to a known placeholder value");
    }
    if token.len() < MIN_TOKEN_LEN {
        return Some("shorter than the required minimum length");
    }
    None
}

fn validate_bootstrap_token(
    bootstrap_token: Option<&str>,
    operator_token: &str,
) -> anyhow::Result<()> {
    let Some(bootstrap_token) = bootstrap_token else {
        return Ok(());
    };
    if let Some(reason) = weak_token_reason(bootstrap_token) {
        bail!(
            "SHELLX_DRIVE_BOOTSTRAP_TOKEN is {reason}. Set it to a strong random secret of \
             at least {MIN_TOKEN_LEN} characters, for example: `openssl rand -hex 32`, or \
             leave it unset to use the operator token for legacy bootstrap."
        );
    }
    if crate::auth::constant_time_str_eq(bootstrap_token, operator_token) {
        bail!(
            "SHELLX_DRIVE_BOOTSTRAP_TOKEN must differ from SHELLX_DRIVE_TOKEN. The bootstrap \
             credential is setup-only; use two independently generated secrets, or leave \
             SHELLX_DRIVE_BOOTSTRAP_TOKEN unset for the legacy operator bootstrap."
        );
    }
    Ok(())
}

/// Detect obvious placeholder tokens that must never be used as a live secret.
/// Matches known exact defaults and common "replace me" markers case-insensitively.
fn is_placeholder_token(token: &str) -> bool {
    let lowered = token.trim().to_ascii_lowercase();
    const EXACT: [&str; 3] = ["dev-token", "change-me", "changeme"];
    if EXACT.contains(&lowered.as_str()) {
        return true;
    }
    const MARKERS: [&str; 6] = [
        "change-me",
        "changeme",
        "replace_with",
        "replace-with",
        "your-token",
        "example-token",
    ];
    MARKERS.iter().any(|marker| lowered.contains(marker))
}

fn env_bool(env_name: &str) -> bool {
    matches!(
        std::env::var(env_name)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Parse an optional boolean env var without silently turning an operator typo
/// into a security-sensitive `false` override.
fn env_bool_opt(env_name: &str) -> anyhow::Result<Option<bool>> {
    match std::env::var(env_name) {
        Ok(value) => parse_optional_bool(env_name, &value),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("{env_name} must be a valid UTF-8 boolean value")
        }
    }
}

fn parse_optional_bool(env_name: &str, value: &str) -> anyhow::Result<Option<bool>> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(None),
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => bail!("{env_name} must be one of 1, true, yes, on, 0, false, no, or off"),
    }
}

fn safe_source_label(env_name: &str) -> String {
    match std::env::var(env_name) {
        Ok(value) if !value.trim().is_empty() => "configured".to_string(),
        _ => "not_configured".to_string(),
    }
}

pub(crate) fn validate_office_provider_url(value: String) -> anyhow::Result<String> {
    let parsed = reqwest::Url::parse(&value).context("invalid Office provider URL")?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("Office provider URL must not contain embedded credentials");
    }
    if parsed.fragment().is_some() {
        bail!("Office provider URL must not contain a fragment");
    }
    let host = parsed
        .host_str()
        .context("Office provider URL must have a host")?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        bail!("Office provider URL must use HTTPS unless it targets loopback");
    }
    Ok(parsed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_token_file(value: &str) -> (tempfile::TempDir, String) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("operator-token");
        std::fs::write(&path, value).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (temp, path.to_string_lossy().into_owned())
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn e2e_rejects_non_loopback_bind_with_actionable_error() {
        let (_token_dir, token_path) = private_token_file("e2e-test-token-long-enough");
        for bind in ["0.0.0.0:5758", "[::]:5758"] {
            let error = Config::from_args(args(&[
                "--e2e",
                "--bind",
                bind,
                "--token-file",
                &token_path,
            ]))
            .unwrap_err();

            assert!(error
                .to_string()
                .contains("--e2e requires a loopback --bind address"));
            assert!(error.to_string().contains("remove --e2e"));
        }
    }

    #[test]
    fn e2e_rejects_the_documented_dev_token() {
        let (_token_dir, token_path) = private_token_file("dev-token");
        let error = Config::from_args(args(&[
            "--e2e",
            "--bind",
            "127.0.0.1:0",
            "--token-file",
            &token_path,
        ]))
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("--e2e operator token is set to a known placeholder value"));
        assert!(error.to_string().contains("strong random token"));
    }

    #[test]
    fn e2e_rejects_a_short_non_default_token() {
        let (_token_dir, token_path) = private_token_file("short-test");
        let error = Config::from_args(args(&[
            "--e2e",
            "--bind",
            "127.0.0.1:0",
            "--token-file",
            &token_path,
        ]))
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("shorter than the required minimum length"));
    }

    #[test]
    fn e2e_accepts_a_strong_token_on_ipv6_loopback() {
        let (_token_dir, token_path) = private_token_file("e2e-test-token-long-enough");
        let config = Config::from_args(args(&[
            "--e2e",
            "--bind",
            "[::1]:0",
            "--token-file",
            &token_path,
        ]))
        .expect("loopback e2e config");

        assert!(config.e2e_enabled);
        assert!(config.bind.ip().is_loopback());
    }

    #[test]
    fn production_keeps_loopback_bind_available_with_a_strong_token() {
        let (_token_dir, token_path) = private_token_file("production-token-is-long-enough");
        let config = Config::from_args(args(&[
            "--bind",
            "127.0.0.1:5758",
            "--token-file",
            &token_path,
        ]))
        .expect("production config");

        assert!(!config.e2e_enabled);
        assert_eq!(config.bind, "127.0.0.1:5758".parse().unwrap());
    }

    #[test]
    fn public_origin_normalizes_strict_browser_authorities() {
        let canonical_cases = [
            (
                "HTTPS://Drive.Example.Test:443/",
                "https://drive.example.test",
            ),
            ("https://münich.example/", "https://xn--mnich-kva.example"),
            ("http://127.0.0.1:80/", "http://127.0.0.1"),
            ("http://[::1]:5758", "http://[::1]:5758"),
            ("http://localhost:5758/", "http://localhost:5758"),
        ];
        for (input, expected) in canonical_cases {
            assert_eq!(PublicOrigin::parse(input).unwrap().as_str(), expected);
        }

        let origin = PublicOrigin::parse("HTTPS://Drive.Example.Test:443/").unwrap();
        assert_eq!(
            origin.application_route("/reset-password"),
            "https://drive.example.test/reset-password"
        );
    }

    #[test]
    fn public_origin_rejects_unsafe_or_non_origin_urls() {
        for value in [
            "http://drive.example.test",
            "ftp://drive.example.test",
            "https://user:secret@drive.example.test",
            "https://@drive.example.test",
            "https://drive.example.test/not-an-origin",
            "https://drive.example.test?surplus=query",
            "https://drive.example.test#fragment",
        ] {
            assert!(
                PublicOrigin::parse(value).is_err(),
                "expected {value:?} to be rejected"
            );
        }
    }

    #[test]
    fn public_origin_migration_aliases_must_agree_after_normalization() {
        let canonical = resolve_configured_public_origin([
            (
                "SHELLX_DRIVE_PUBLIC_ORIGIN",
                Some("HTTPS://Drive.Example.Test:443/".to_string()),
            ),
            (
                "SHELLX_DRIVE_EMAIL_BASE_URL",
                Some("https://drive.example.test".to_string()),
            ),
            (
                "SHELLX_DRIVE_HOSTED_PUBLIC_BASE_URL",
                Some("https://drive.example.test/".to_string()),
            ),
        ])
        .unwrap();
        assert_eq!(canonical.as_str(), "https://drive.example.test");

        let disagreement = resolve_configured_public_origin([
            (
                "SHELLX_DRIVE_PUBLIC_ORIGIN",
                Some("https://drive.example.test".to_string()),
            ),
            (
                "SHELLX_DRIVE_EMAIL_BASE_URL",
                Some("https://mail.example.test".to_string()),
            ),
            ("SHELLX_DRIVE_HOSTED_PUBLIC_BASE_URL", None),
        ])
        .unwrap_err();
        assert!(disagreement
            .to_string()
            .contains("must resolve to the same"));

        let legacy_only = resolve_configured_public_origin([
            ("SHELLX_DRIVE_PUBLIC_ORIGIN", None),
            (
                "SHELLX_DRIVE_EMAIL_BASE_URL",
                Some("https://drive.example.test".to_string()),
            ),
            ("SHELLX_DRIVE_HOSTED_PUBLIC_BASE_URL", None),
        ])
        .unwrap();
        assert_eq!(legacy_only.as_str(), "https://drive.example.test");
    }

    #[test]
    fn explicit_insecure_cookie_override_requires_a_fully_loopback_production_setup() {
        let network_bind = "0.0.0.0:5758".parse().unwrap();
        let loopback_bind = "127.0.0.1:5758".parse().unwrap();
        let loopback_origin = PublicOrigin::parse("http://127.0.0.1:5758").unwrap();
        let external_origin = PublicOrigin::parse("https://drive.example.test").unwrap();

        let error = resolve_secure_cookies(loopback_bind, &external_origin, false, Some(false))
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("both --bind and SHELLX_DRIVE_PUBLIC_ORIGIN are loopback"));
        assert!(
            !resolve_secure_cookies(loopback_bind, &loopback_origin, false, Some(false)).unwrap()
        );

        let error =
            resolve_secure_cookies(network_bind, &external_origin, false, Some(false)).unwrap_err();
        assert!(error
            .to_string()
            .contains("both --bind and SHELLX_DRIVE_PUBLIC_ORIGIN are loopback"));
        assert!(
            !resolve_secure_cookies(loopback_bind, &external_origin, true, Some(false)).unwrap()
        );
    }

    #[test]
    fn network_production_bind_requires_a_non_loopback_public_origin() {
        let network_bind = "0.0.0.0:5758".parse().unwrap();
        let loopback_origin = PublicOrigin::parse(DEFAULT_PUBLIC_ORIGIN).unwrap();
        let error =
            resolve_secure_cookies(network_bind, &loopback_origin, false, None).unwrap_err();
        assert!(error
            .to_string()
            .contains("requires a non-loopback SHELLX_DRIVE_PUBLIC_ORIGIN"));

        let external_origin = PublicOrigin::parse("https://drive.example.test").unwrap();
        assert!(resolve_secure_cookies(network_bind, &external_origin, false, None).unwrap());
    }

    #[test]
    fn configured_bootstrap_token_must_not_equal_resolved_operator_token() {
        let operator = "independent-operator-token-long-enough";
        let error = validate_bootstrap_token(Some(operator), operator).unwrap_err();
        assert!(error.to_string().contains("must differ"));
        assert!(validate_bootstrap_token(
            Some("independent-bootstrap-token-long-enough"),
            operator
        )
        .is_ok());
        assert!(validate_bootstrap_token(None, operator).is_ok());
    }

    #[test]
    fn token_value_flag_is_rejected_so_secrets_do_not_enter_argv() {
        let error = Config::from_args(args(&["--token", "must-not-be-accepted"])).unwrap_err();
        assert!(error.to_string().contains("unknown argument: --token"));
    }

    #[test]
    fn office_provider_requires_https_except_on_loopback() {
        assert!(
            validate_office_provider_url("https://office.example.test/edit".to_string()).is_ok()
        );
        assert!(validate_office_provider_url("http://127.0.0.1:9988/edit".to_string()).is_ok());
        assert!(
            validate_office_provider_url("http://office.example.test/edit".to_string())
                .unwrap_err()
                .to_string()
                .contains("HTTPS")
        );
        assert!(
            validate_office_provider_url("https://user:secret@example.test/edit".to_string())
                .unwrap_err()
                .to_string()
                .contains("embedded credentials")
        );
    }

    #[test]
    fn optional_security_boolean_rejects_typos_without_echoing_them() {
        assert_eq!(
            parse_optional_bool("SHELLX_DRIVE_SECURE_COOKIES", " yes ").unwrap(),
            Some(true)
        );
        assert_eq!(
            parse_optional_bool("SHELLX_DRIVE_SECURE_COOKIES", "OFF").unwrap(),
            Some(false)
        );
        assert_eq!(
            parse_optional_bool("SHELLX_DRIVE_SECURE_COOKIES", "  ").unwrap(),
            None
        );
        let error = parse_optional_bool("SHELLX_DRIVE_SECURE_COOKIES", "treu")
            .unwrap_err()
            .to_string();
        assert!(error.contains("SHELLX_DRIVE_SECURE_COOKIES"));
        assert!(!error.contains("treu"));
    }
}
