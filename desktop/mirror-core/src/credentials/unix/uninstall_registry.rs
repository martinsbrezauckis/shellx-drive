use super::*;

/// Uninstall must never interpret a missing registry as an empty registry:
/// the provider may still hold credentials indexed by the deleted file.
pub fn uninstall_credential_registry_empty() -> Result<bool> {
    let data = ProjectDirs::from("com", "ShellX", "Drive Desktop")
        .ok_or_else(|| credential_error("could not determine application data directory"))?
        .data_local_dir()
        .to_path_buf();
    verify_registry_ancestry(&data)?;
    let directory = data.join(REGISTRY_DIRECTORY);
    verify_private_directory(&directory)?;
    let path = directory.join(REGISTRY_FILE);
    registry_file_empty_at(&path)
}

fn registry_file_empty_at(path: &Path) -> Result<bool> {
    verify_private_file(path)?;
    let bytes = fs::read(path)?;
    let file: RegistryFile = serde_json::from_slice(&bytes)
        .map_err(|_| credential_error("credential registry is malformed"))?;
    if file.version != REGISTRY_VERSION {
        return Err(credential_error(
            "credential registry version is unsupported",
        ));
    }
    for (service, keys) in &file.services {
        validate_service(service)?;
        if !keys.is_empty() {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(unix)]
fn verify_registry_ancestry(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let mut current = Some(path);
    while let Some(component) = current {
        let metadata = fs::symlink_metadata(component)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() })
            || metadata.mode() & 0o022 != 0
        {
            return Err(credential_error("credential registry ancestry is unsafe"));
        }
        current = component.parent();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninstall_registry_check_requires_an_existing_exact_empty_file() {
        let temporary = tempfile::tempdir().expect("temporary registry directory");
        let path = temporary.path().join(REGISTRY_FILE);
        assert!(
            registry_file_empty_at(&path).is_err(),
            "missing registry must fail"
        );

        let registry = CredentialRegistry::load_from_path(path.clone()).unwrap();
        registry.persist().unwrap();
        assert!(registry_file_empty_at(&path).unwrap());

        let mut occupied = CredentialRegistry::load_from_path(path.clone()).unwrap();
        occupied
            .insert(DESKTOP_AGENT_DISCONNECT_SERVICE, "pending")
            .unwrap();
        assert!(!registry_file_empty_at(&path).unwrap());

        fs::write(&path, br#"{"version":1,"services":{"unknown.service":[]}}"#).unwrap();
        assert!(registry_file_empty_at(&path).is_err());
        fs::write(&path, br#"{"version":1,"services":{},"unknown":true}"#).unwrap();
        assert!(registry_file_empty_at(&path).is_err());
    }
}
