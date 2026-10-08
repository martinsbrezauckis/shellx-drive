use super::*;

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures.json")).unwrap()
}

fn release_url(entry: &serde_json::Value) -> Url {
    Url::parse(&entry["url"].as_str().unwrap().replace(
        "https://example.test/releases/v",
        "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v",
    ))
    .unwrap()
}

#[test]
fn authentic_new_release_is_accepted_on_every_shipped_platform() {
    let fixtures = fixtures();
    for entry in fixtures["releases"].as_array().unwrap() {
        verify(
            fixtures["bytes"].as_str().unwrap().as_bytes(),
            entry["signature"].as_str().unwrap(),
            fixtures["publicKey"].as_str().unwrap(),
            "1.0.0",
            "1.1.0",
            entry["platform"].as_str().unwrap(),
            &release_url(entry),
        )
        .unwrap();
    }
}

#[test]
fn github_normalized_urls_accept_the_same_original_signed_bytes_and_comment() {
    let fixtures = fixtures();
    for entry in fixtures["releases"].as_array().unwrap() {
        let url = Url::parse(&release_url(entry).as_str().replace("%20", ".")).unwrap();
        verify(
            fixtures["bytes"].as_str().unwrap().as_bytes(),
            entry["signature"].as_str().unwrap(),
            fixtures["publicKey"].as_str().unwrap(),
            "1.0.0",
            "1.1.0",
            entry["platform"].as_str().unwrap(),
            &url,
        )
        .unwrap();
    }
}

#[test]
fn normalized_transport_name_is_not_an_alias_for_the_signed_comment() {
    let comment = "timestamp:1\tfile:ShellX.Drive.Desktop_1.1.0_x64-setup.exe";
    let url = Url::parse("https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.1.0/ShellX.Drive.Desktop_1.1.0_x64-setup.exe").unwrap();
    assert!(
        verify_identity(comment, "1.0.0", "1.1.0", "windows-x86_64-nsis", &url)
            .unwrap_err()
            .contains("identity does not match")
    );
}

#[test]
fn authentic_signature_does_not_admit_foreign_or_noncanonical_transport_urls() {
    let fixtures = fixtures();
    let entry = &fixtures["releases"][0];
    for url in [
        "https://attacker.example/releases/download/v1.1.0/ShellX.Drive.Desktop_1.1.0_x64-setup.exe",
        "https://github.com/other/repository/releases/download/v1.1.0/ShellX.Drive.Desktop_1.1.0_x64-setup.exe",
        "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.2.0/ShellX.Drive.Desktop_1.1.0_x64-setup.exe",
        "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.1.0/ShellX.Drive.Desktop_1.1.0_aarch64.app.tar.gz",
        "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.1.0/ShellX%2EDrive%2EDesktop_1.1.0_x64-setup.exe",
        "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.1.0/ShellX.Drive.Desktop_1.1.0_x64-setup.exe?token=secret",
    ] {
        assert!(verify(
            fixtures["bytes"].as_str().unwrap().as_bytes(),
            entry["signature"].as_str().unwrap(),
            fixtures["publicKey"].as_str().unwrap(),
            "1.0.0", "1.1.0", "windows-x86_64-nsis", &Url::parse(url).unwrap(),
        ).is_err());
    }
}

#[test]
fn old_authentic_signature_cannot_be_relabelled_as_a_new_release() {
    let fixtures = fixtures();
    for entry in fixtures["releases"].as_array().unwrap() {
        let url = Url::parse(&release_url(entry).as_str().replace("1.1.0", "9.0.0")).unwrap();
        assert!(verify(
            fixtures["bytes"].as_str().unwrap().as_bytes(),
            entry["signature"].as_str().unwrap(),
            fixtures["publicKey"].as_str().unwrap(),
            "1.2.0",
            "9.0.0",
            entry["platform"].as_str().unwrap(),
            &url,
        )
        .unwrap_err()
        .contains("identity does not match"));
    }
}

#[test]
fn publisher_cannot_change_only_the_signed_comment() {
    let fixtures = fixtures();
    for entry in fixtures["releases"].as_array().unwrap() {
        let signature = base64::engine::general_purpose::STANDARD
            .decode(entry["signature"].as_str().unwrap())
            .unwrap();
        let changed = String::from_utf8(signature)
            .unwrap()
            .replace("1.1.0", "9.0.0");
        let changed = base64::engine::general_purpose::STANDARD.encode(changed);
        let url = Url::parse(&release_url(entry).as_str().replace("1.1.0", "9.0.0")).unwrap();
        assert!(verify(
            fixtures["bytes"].as_str().unwrap().as_bytes(),
            &changed,
            fixtures["publicKey"].as_str().unwrap(),
            "1.2.0",
            "9.0.0",
            entry["platform"].as_str().unwrap(),
            &url,
        )
        .unwrap_err()
        .contains("signature verification failed"));
    }
}

#[test]
fn altered_bytes_cannot_reuse_an_authentic_release_identity() {
    let fixtures = fixtures();
    let entry = &fixtures["releases"][0];
    assert!(verify(
        b"substituted installer",
        entry["signature"].as_str().unwrap(),
        fixtures["publicKey"].as_str().unwrap(),
        "1.0.0",
        "1.1.0",
        entry["platform"].as_str().unwrap(),
        &release_url(entry),
    )
    .is_err());
}

#[test]
fn direct_install_cannot_downgrade_or_reinstall_even_with_a_custom_comparator() {
    let fixtures = fixtures();
    let entry = &fixtures["releases"][0];
    for current in ["1.1.0", "1.1.0+installed", "1.2.0", "9.0.0"] {
        assert!(verify(
            fixtures["bytes"].as_str().unwrap().as_bytes(),
            entry["signature"].as_str().unwrap(),
            fixtures["publicKey"].as_str().unwrap(),
            current,
            "1.1.0",
            entry["platform"].as_str().unwrap(),
            &release_url(entry),
        )
        .unwrap_err()
        .contains("advance"));
    }
}

#[test]
fn exact_comment_grammar_rejects_ambiguous_or_foreign_identity() {
    let leaf = "ShellX Drive Desktop_1.1.0_x64-setup.exe";
    let url = Url::parse(&format!(
        "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.1.0/{leaf}"
    ))
    .unwrap();
    for comment in [
        format!("timestamp:1\tfile:{leaf}\tfile:{leaf}"),
        format!("timestamp:1\tfile:{leaf}\n"),
        format!("timestamp:1\tfile:../{leaf}"),
        format!("timestamp:-1\tfile:{leaf}"),
        "timestamp:1\tfile:OtherApp_1.1.0_x64-setup.exe".to_owned(),
        "timestamp:1\tfile:ShellX Drive Desktop_1.1.0_aarch64.app.tar.gz".to_owned(),
        "timestamp:1\tfile:ShellX Drive Desktop_01.1.0_x64-setup.exe".to_owned(),
    ] {
        assert!(verify_identity(&comment, "1.0.0", "1.1.0", "windows-x86_64-nsis", &url).is_err());
    }
    let comment = format!("timestamp:1\tfile:{leaf}");
    for platform in [
        "linux-x86_64-deb",
        "darwin-aarch64-app",
        "windows-aarch64-nsis",
        "windows-x86_64-msi",
    ] {
        assert!(verify_identity(&comment, "1.0.0", "1.1.0", platform, &url).is_err());
    }
    for version in ["v1.1.0", "01.1.0", "1.1", "1.1.0 "] {
        assert!(verify_identity(&comment, "1.0.0", version, "windows-x86_64-nsis", &url).is_err());
    }
}

#[test]
fn signed_leaf_must_match_the_selected_url_without_path_aliases() {
    let leaf = "ShellX Drive Desktop_1.1.0_x64-setup.exe";
    let comment = format!("timestamp:1\tfile:{leaf}");
    for leaf in [
        "different.exe",
        "subdir%2FShellX%20Drive%20Desktop_1.1.0_x64-setup.exe",
        "ShellX%2520Drive%2520Desktop_1.1.0_x64-setup.exe",
        "invalid%FF.exe",
    ] {
        assert!(verify_identity(
            &comment,
            "1.0.0",
            "1.1.0",
            "windows-x86_64-nsis",
            &Url::parse(&format!(
                "https://github.com/martinsbrezauckis/shellx-drive/releases/download/v1.1.0/{leaf}"
            ))
            .unwrap()
        )
        .is_err());
    }
}
