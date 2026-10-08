"""Native build, Apple checks, and unsigned observation under an admitted root."""

def run_worker(admission, admission_sha256):
    tools = verify_continuity(admission)
    output_root = admission["outputRoot"]
    os.mkdir(output_root, 0o700); os.chmod(output_root, 0o700)
    output_root_stat = physical(output_root, "candidate output root", "directory")
    require(mode4(output_root_stat.st_mode) == "0700" and output_root_stat.st_uid == os.geteuid(), "candidate output root must be caller-owned 0700")
    artifacts_dir, observations_dir, target_dir, tmp_dir, mount_dir = (os.path.join(output_root, name) for name in ("artifacts", "observations", "target", "tmp", "mounted-dmg"))
    for directory in (artifacts_dir, observations_dir, target_dir, tmp_dir, mount_dir): os.mkdir(directory, 0o700); os.chmod(directory, 0o700); physical(directory, "candidate private directory", "directory")
    stage_fd, desktop_fd, mounted = os.open(admission["stageRoot"]["path"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW), None, False
    try:
        require_runtime_contract(stage_fd)
        desktop_fd = os.open("desktop", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stage_fd)
        desktop_stat = os.fstat(desktop_fd)
        require(stat.S_ISDIR(desktop_stat.st_mode) and desktop_stat.st_uid == os.geteuid(), "admitted macOS desktop root identity is unsafe")
        macos_config, entitlements_contract = source_bytes(admission, "tauri-macos-config"), source_bytes(admission, "entitlements")
        require(b'"targets": ["app", "dmg"]' in macos_config and b"com.apple.security.cs.allow-jit" in entitlements_contract, "held macOS bundle configuration drifted")
        build_environment = {"APPLE_SIGNING_IDENTITY": EXPECTED_IDENTITY, "CARGO_TARGET_DIR": target_dir, "TAURI_SIGNING_PRIVATE_KEY": os.environ["TAURI_SIGNING_PRIVATE_KEY"], "TMPDIR": tmp_dir}
        if "TAURI_SIGNING_PRIVATE_KEY_PASSWORD" in os.environ: build_environment["TAURI_SIGNING_PRIVATE_KEY_PASSWORD"] = os.environ["TAURI_SIGNING_PRIVATE_KEY_PASSWORD"]
        keychain, notary_keychain = os.path.join(os.environ["HOME"], "Library/Keychains/shellx-build.keychain-db"), os.path.join(os.environ["HOME"], "Library/Keychains/login.keychain-db")
        physical(keychain, "maintained macOS build keychain", "file"); physical(notary_keychain, "maintained macOS notary keychain", "file")
        identity_raw = run_tool(tools, "security", ["find-identity", "-v", "-p", "codesigning", keychain], capture=True)
        require(EXPECTED_IDENTITY in identity_raw.decode("utf-8", "replace") and EXPECTED_CERTIFICATE_SHA1 in identity_raw.decode("utf-8", "replace"), "dedicated build keychain lacks the admitted Developer ID certificate")
        os.fchdir(desktop_fd)
        run_tool(tools, "tauri-cli", ["build", "--config", source_fd_path("tauri-macos-config"), "--target", TARGET, "--features", "desktop-shell", "--bundles", "app,dmg"], environment=build_environment, pass_fds=(stage_fd, desktop_fd))
        bundle = os.path.join(target_dir, TARGET, "release", "bundle")
        app, dmg = one_artifact(os.path.join(bundle, "macos"), ".app", "directory", "macOS bundle output"), one_artifact(os.path.join(bundle, "dmg"), ".dmg", "file", "DMG bundle output")
        updater_archive = one_artifact(os.path.join(bundle, "macos"), ".app.tar.gz", "file", "updater bundle output")
        run_tool(tools, "codesign", ["--verify", "--deep", "--strict", "--verbose=4", app], capture=True)
        code_details = run_tool(tools, "codesign", ["-d", "-r-", "--verbose=4", app], capture=True)
        entitlements, _ = run_tool(tools, "codesign", ["--display", "--entitlements", ":-", app], capture=True, separate=True)
        require(b"com.apple.security.cs.allow-jit" in entitlements and b"com.apple.security.app-sandbox" not in entitlements, "signed app hardened-runtime entitlements drifted")
        notary_raw, _ = run_tool(tools, "xcrun", ["notarytool", "submit", dmg, "--keychain-profile", NOTARY_PROFILE, "--keychain", notary_keychain, "--wait", "--output-format", "json"], capture=True, separate=True)
        try: notary = json.loads(notary_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error: fail(f"notarytool did not return JSON: {error}")
        submission_id = notary.get("id")
        require(notary.get("status") == "Accepted" and isinstance(submission_id, str) and re.fullmatch(r"[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}", submission_id), "notarytool did not report Accepted with a submission UUID")
        stapler_raw = run_tool(tools, "xcrun", ["stapler", "staple", dmg], capture=True) + run_tool(tools, "xcrun", ["stapler", "validate", dmg], capture=True)
        app_out, dmg_out = (os.path.join(artifacts_dir, safe_leaf(os.path.basename(item), "candidate artifact")) for item in (app, dmg))
        updater_out = os.path.join(artifacts_dir, f"ShellX Drive Desktop_{admission['version']}_aarch64.app.tar.gz")
        signature_out = updater_out + ".sig"
        run_tool(tools, "ditto", [app, app_out], pass_fds=(stage_fd,))
        for source, destination in ((dmg, dmg_out), (updater_archive, updater_out)): run_tool(tools, "cp", [source, destination], pass_fds=(stage_fd,))
        # Re-sign the archive under the admitted version-bearing filename: the
        # Minisign trusted comment authenticates this exact updater identity.
        run_tool(tools, "tauri-cli", ["signer", "sign", updater_out], environment=build_environment, pass_fds=(stage_fd, desktop_fd))
        stapler_raw += run_tool(tools, "xcrun", ["stapler", "validate", dmg_out], capture=True)
        app_tree = inspect_app_tree(app_out)
        plutil_raw, _ = run_tool(tools, "plutil", ["-extract", "CFBundleExecutable", "raw", "-o", "-", os.path.join(app_out, "Contents/Info.plist")], capture=True, separate=True)
        executable_name = plutil_raw.decode("utf-8", "strict").strip(); safe_leaf(executable_name, "CFBundleExecutable")
        executable_relative = f"Contents/MacOS/{executable_name}"; executable_file = artifact_file(os.path.join(app_out, executable_relative), "signed app executable")
        artifact_codesign = run_tool(tools, "codesign", ["--verify", "--deep", "--strict", "--verbose=4", app_out], capture=True)
        artifact_code_details = run_tool(tools, "codesign", ["-d", "-r-", "--verbose=4", app_out], capture=True); identity = parse_codesign(artifact_code_details + identity_raw)
        output_file(os.path.join(observations_dir, EVIDENCE_FILES["codesign"]), artifact_codesign + artifact_code_details + identity_raw + code_details)
        output_file(os.path.join(observations_dir, EVIDENCE_FILES["entitlements"]), entitlements); output_file(os.path.join(observations_dir, EVIDENCE_FILES["notarytool"]), notary_raw); output_file(os.path.join(observations_dir, EVIDENCE_FILES["stapler"]), stapler_raw)
        run_tool(tools, "hdiutil", ["attach", dmg_out, "-nobrowse", "-readonly", "-mountpoint", mount_dir], pass_fds=(stage_fd,)); mounted = True
        mounted_app = one_artifact(mount_dir, ".app", "directory", "mounted DMG"); require(os.path.basename(mounted_app) == os.path.basename(app_out), "mounted DMG app name differs from the signed app artifact")
        mounted_codesign = run_tool(tools, "codesign", ["--verify", "--deep", "--strict", "--verbose=4", mounted_app], capture=True); mounted_details = run_tool(tools, "codesign", ["-d", "-r-", "--verbose=4", mounted_app], capture=True)
        gatekeeper = run_tool(tools, "spctl", ["--assess", "--type", "execute", "--verbose=4", mounted_app], capture=True)
        mounted_tree, mounted_executable, mounted_identity = inspect_app_tree(mounted_app), artifact_file(os.path.join(mounted_app, executable_relative), "mounted app executable"), parse_codesign(mounted_details)
        require(mounted_tree["treeDigest"] == app_tree["treeDigest"] and mounted_executable["sha256"] == executable_file["sha256"] and mounted_identity["cdHash"] == identity["cdHash"], "mounted DMG differs from the signed app artifact")
        output_file(os.path.join(observations_dir, EVIDENCE_FILES["gatekeeper"]), gatekeeper + mounted_codesign + mounted_details)
        run_tool(tools, "hdiutil", ["detach", mount_dir, "-quiet"], pass_fds=(stage_fd,)); mounted = False
        updater_result = run_tool(tools, "tauri-updater-verifier", ["--config", source_fd_path("tauri-config"), "--installer", updater_out, "--signature", signature_out], capture=True, pass_fds=(stage_fd,))
        output_file(os.path.join(observations_dir, EVIDENCE_FILES["updaterVerifier"]), updater_result)
        tools_after = verify_continuity(admission); require(canonical_json(tools_after) == canonical_json(tools), "admitted tools changed during candidate build")
        run_tool(tools, "rm", ["-rf", target_dir, tmp_dir, mount_dir])
        output_canonical(os.path.join(output_root, EVIDENCE_FILES["workerComplete"]), {"fullStageDigest": admission["fullStageDigest"], "outputRoot": output_root, "schema": "shellx-drive.macos-worker-complete/v1", "source": admission["source"], "status": "pass"})
        raw_evidence = {kind: artifact_file(os.path.join(output_root if kind == "workerComplete" else observations_dir, name), f"raw evidence {name}") for kind, name in EVIDENCE_FILES.items()}
        observation = {"admissionSha256": admission_sha256, "artifacts": {"app": {"cdHash": identity["cdHash"], "executableRelativePath": executable_relative, "executableSha256": executable_file["sha256"], "name": os.path.basename(app_out), "treeDigest": app_tree["treeDigest"]}, "dmg": {"mountedAppTreeDigest": mounted_tree["treeDigest"], "mountedCdHash": mounted_identity["cdHash"], "mountedExecutableSha256": mounted_executable["sha256"], **artifact_file(dmg_out, "DMG artifact")}, "updaterArchive": artifact_file(updater_out, "updater archive"), "updaterSignature": artifact_file(signature_out, "updater signature")}, "checks": {"codesign": "pass", "gatekeeper": "pass", "notary": "pass", "staple": "pass", "updater": "pass"}, "fullStageDigest": admission["fullStageDigest"], "identity": {"bundleIdentifier": identity["bundleIdentifier"], "designatedRequirement": identity["designatedRequirement"], "signerFingerprint": EXPECTED_CERTIFICATE_SHA1, "teamIdentifier": identity["teamIdentifier"]}, "notarization": {"status": "Accepted", "submissionId": submission_id}, "platform": PLATFORM, "project": PROJECT, "rawEvidence": raw_evidence, "schema": OBSERVATION_SCHEMA, "source": admission["source"], "stageRoot": admission["stageRoot"], "status": "pass", "toolchainManifest": {"sha256": admission["toolchainManifest"]["sha256"]}, "tools": {"continuity": "pass", "digest": hashlib.sha256(f"{canonical_json(admission['tools'])}\n".encode()).hexdigest()}, "version": admission["version"]}
        output_canonical(os.path.join(output_root, "worker-observation.json"), observation)
        verify_continuity(admission)
        updater_candidate = os.path.join(output_root, "macos-updater-candidate.json")
        run_tool(tools, "node", [source_fd_path("updater-candidate-core"), "--platform", "darwin-aarch64", "--version", admission["version"], "--source-commit", admission["source"]["commit"], "--source-tree", admission["source"]["tree"], "--artifact", updater_out, "--signature", signature_out, "--identity-kind", "developer-id-notarized", "--identity-evidence", os.path.join(output_root, "worker-observation.json"), "--candidate-root", output_root, "--out", updater_candidate])
        verify_continuity(admission)
        require(set(os.listdir(output_root)) == {"artifacts", "observations", EVIDENCE_FILES["workerComplete"], "worker-observation.json", "macos-updater-candidate.json"}, "candidate output root contains build residue")
    finally:
        if mounted:
            try: run_tool(tools, "hdiutil", ["detach", mount_dir, "-quiet"], pass_fds=(stage_fd,))
            except Exception: pass
        if desktop_fd is not None: os.close(desktop_fd)
        os.close(stage_fd)
    return os.path.join(output_root, "worker-observation.json")
