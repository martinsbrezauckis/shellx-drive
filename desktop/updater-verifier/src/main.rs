use base64::{engine::general_purpose::STANDARD, Engine};
use minisign_verify::{PublicKey, Signature};
use serde_json::Value;
use std::{env, fs, path::Path, path::PathBuf, process};

struct Arguments {
    config: PathBuf,
    installer: PathBuf,
    signature: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Probe {
    Help,
    Version,
}

enum Command {
    Probe(Probe),
    Verify(Arguments),
}

const VERIFICATION_SENTINEL: &str = "UPDATER_ARTIFACT_VERIFIED";
const HELP_MESSAGE: &str =
    "Usage: tauri-updater-verifier --config <path> --installer <path> --signature <path>";

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("FAIL: updater artifact verification: {}", message.as_ref());
    process::exit(1);
}

fn require_regular_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("cannot inspect {label}: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{label} must be a regular non-link file"));
    }
    fs::read(path).map_err(|error| format!("cannot read {label}: {error}"))
}

fn parse_arguments(arguments: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let arguments: Vec<_> = arguments.into_iter().collect();
    match arguments.as_slice() {
        [argument] if matches!(argument.as_str(), "--help" | "-h") => {
            return Ok(Command::Probe(Probe::Help));
        }
        [argument] if matches!(argument.as_str(), "--version" | "-V") => {
            return Ok(Command::Probe(Probe::Version));
        }
        _ => {}
    }

    let mut values = arguments.into_iter();
    let mut config = None;
    let mut installer = None;
    let mut signature = None;
    while let Some(argument) = values.next() {
        let destination = match argument.as_str() {
            "--config" => &mut config,
            "--installer" => &mut installer,
            "--signature" => &mut signature,
            _ => return Err(format!("unexpected argument: {argument}")),
        };
        let value = values
            .next()
            .ok_or_else(|| format!("{argument} requires a path"))?;
        if value.starts_with("--") {
            return Err(format!("{argument} requires a path"));
        }
        if destination.replace(PathBuf::from(value)).is_some() {
            return Err(format!("{argument} was supplied more than once"));
        }
    }
    Ok(Command::Verify(Arguments {
        config: config.ok_or("--config is required")?,
        installer: installer.ok_or("--installer is required")?,
        signature: signature.ok_or("--signature is required")?,
    }))
}

fn probe_message(probe: Probe) -> String {
    match probe {
        Probe::Help => HELP_MESSAGE.into(),
        Probe::Version => format!(
            "shellx-drive-updater-verifier {}",
            env!("CARGO_PKG_VERSION")
        ),
    }
}

fn config_public_key(config: &[u8]) -> Result<PublicKey, String> {
    let value: Value =
        serde_json::from_slice(config).map_err(|error| format!("invalid Tauri config: {error}"))?;
    let encoded = value
        .pointer("/plugins/updater/pubkey")
        .and_then(Value::as_str)
        .ok_or("Tauri updater public key is missing")?;
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| "Tauri updater public key is not base64")?;
    let decoded =
        std::str::from_utf8(&decoded).map_err(|_| "Tauri updater public key is not UTF-8")?;
    PublicKey::decode(decoded).map_err(|_| "Tauri updater public key is malformed".to_string())
}

fn decode_signature(encoded: &[u8]) -> Result<Signature, String> {
    let encoded = std::str::from_utf8(encoded).map_err(|_| "updater signature is not UTF-8")?;
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| "updater signature is not base64")?;
    let decoded =
        std::str::from_utf8(&decoded).map_err(|_| "updater signature payload is not UTF-8")?;
    Signature::decode(decoded).map_err(|_| "updater signature payload is malformed".to_string())
}

fn verify_artifact(config: &Path, installer: &Path, signature: &Path) -> Result<(), String> {
    let config = require_regular_file(config, "Tauri config")?;
    let installer = require_regular_file(installer, "installer")?;
    let signature = require_regular_file(signature, "updater signature")?;
    let public_key = config_public_key(&config)?;
    let signature = decode_signature(&signature)?;
    public_key
        .verify(&installer, &signature, true)
        .map_err(|_| {
            "updater signature does not verify the installer with the Tauri public key".to_string()
        })
}

fn main() {
    match parse_arguments(env::args().skip(1)).unwrap_or_else(|error| fail(error)) {
        Command::Probe(probe) => println!("{}", probe_message(probe)),
        Command::Verify(arguments) => {
            verify_artifact(
                &arguments.config,
                &arguments.installer,
                &arguments.signature,
            )
            .unwrap_or_else(|error| fail(error));
            println!("{VERIFICATION_SENTINEL}");
        }
    }
}

#[cfg(test)]
mod tests;
