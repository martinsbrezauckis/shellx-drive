use super::*;
use tempfile::tempdir;

const PUBLIC_KEY: &str = "untrusted comment: minisign public key E7620F1842B4E81F\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
const SIGNATURE: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1556193335\tfile:test\ny/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==";

fn fixture(
    public_key: &str,
    installer: &[u8],
    signature: &str,
) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let root = tempdir().unwrap();
    let config = root.path().join("tauri.conf.json");
    let installer_path = root.path().join("installer.exe");
    let signature_path = root.path().join("installer.exe.sig");
    let config_value = serde_json::json!({
        "plugins": { "updater": { "pubkey": STANDARD.encode(public_key) } }
    });
    fs::write(&config, config_value.to_string()).unwrap();
    fs::write(&installer_path, installer).unwrap();
    fs::write(&signature_path, STANDARD.encode(signature)).unwrap();
    (root, config, installer_path, signature_path)
}

#[test]
fn verifies_tauri_style_prehashed_signature() {
    let (_root, config, installer, signature) = fixture(PUBLIC_KEY, b"test", SIGNATURE);
    assert!(verify_artifact(&config, &installer, &signature).is_ok());
}

#[test]
fn rejects_a_signature_for_another_public_key() {
    let mut lines = PUBLIC_KEY.lines();
    let comment = lines.next().unwrap();
    let mut key = STANDARD.decode(lines.next().unwrap()).unwrap();
    key[2] ^= 1;
    let wrong_key = format!("{comment}\n{}", STANDARD.encode(key));
    let (_root, config, installer, signature) = fixture(&wrong_key, b"test", SIGNATURE);
    assert!(verify_artifact(&config, &installer, &signature).is_err());
}

#[test]
fn rejects_a_tampered_installer_and_malformed_signature() {
    let (_root, config, installer, signature) = fixture(PUBLIC_KEY, b"Test", SIGNATURE);
    assert!(verify_artifact(&config, &installer, &signature).is_err());
    fs::write(&signature, "not-base64").unwrap();
    assert!(verify_artifact(&config, &installer, &signature).is_err());
}

#[test]
fn rejects_duplicate_and_unknown_arguments() {
    assert!(parse_arguments([
        "--config".into(),
        "one".into(),
        "--config".into(),
        "two".into()
    ])
    .is_err());
    assert!(parse_arguments(["--unknown".into(), "one".into()]).is_err());
}

#[test]
fn accepts_only_standalone_probe_arguments() {
    for argument in ["--help", "-h"] {
        assert!(matches!(
            parse_arguments([argument.into()]),
            Ok(Command::Probe(Probe::Help))
        ));
    }
    for argument in ["--version", "-V"] {
        assert!(matches!(
            parse_arguments([argument.into()]),
            Ok(Command::Probe(Probe::Version))
        ));
    }
    assert_ne!(probe_message(Probe::Help), VERIFICATION_SENTINEL);
    assert_ne!(probe_message(Probe::Version), VERIFICATION_SENTINEL);
}

#[test]
fn rejects_probe_arguments_mixed_with_verification_arguments() {
    for probe in ["--help", "-h", "--version", "-V"] {
        assert!(parse_arguments([
            probe.into(),
            "--config".into(),
            "config.json".into(),
            "--installer".into(),
            "installer.AppImage".into(),
            "--signature".into(),
            "installer.AppImage.sig".into(),
        ])
        .is_err());
    }
}
