use super::*;

#[test]
fn device_credentials_legacy_crash_resume_cannot_adopt_another_retained_owners_raw_slot() {
    // Cover admitted retained journals, a retired journal and a conflicting
    // scoped locator through the real manager/provider admission path.
    for reservation in [
        "journal",
        "retired_journal",
        "scoped_journal",
        "scoped_locator",
    ] {
        let harness = Harness::legacy();
        let owner_id = harness.add_legacy();
        let migrating = harness.manager.resolve(None).unwrap();
        let original = migrating.coordinator.snapshot();
        let pair = original.pair.as_ref().unwrap();
        let destination = desktop_agent_device_credential_key(
            &desktop_agent_enrollment_fingerprint(&pair.server_url, &pair.account_email),
            "device_shared",
        )
        .unwrap();
        let owner = harness.manager.resolve(Some(&owner_id)).unwrap();
        let mut owner_state = owner.coordinator.snapshot();
        if reservation == "scoped_locator" {
            owner_state.desktop_agent_control.device_id = Some("device_other".into());
            owner_state.desktop_agent_control.credential_key = Some(destination.clone());
        } else {
            owner_state.retire_desktop_agent_control();
            owner_state.pending_disconnect_cleanup = Some(
                DisconnectCleanupIntent::for_disconnect(
                    None,
                    vec![DisconnectCredentialSlot {
                        namespace: if reservation == "scoped_journal" {
                            DisconnectCredentialNamespace::DesktopAgentDeviceScoped
                        } else {
                            DisconnectCredentialNamespace::DesktopAgentDevice
                        },
                        account_key: destination.clone(),
                    }],
                )
                .unwrap(),
            );
        }
        owner.store.save(&owner_state).unwrap();
        owner
            .coordinator
            .begin_lifecycle_operation()
            .unwrap()
            .finish_state(owner_state.clone());
        if reservation == "retired_journal" {
            let mut catalog = harness.manager.catalog.lock().unwrap();
            catalog.connections.retain(|profile| profile.id != owner_id);
            catalog.retired_ids.push(owner_id.clone());
            harness.manager.store.save(&catalog).unwrap();
        }
        // Model delete-before-state-save crash for the migrating connection,
        // while another retained connection reserves its destination spelling.
        harness.credentials.values.delete("device_shared").unwrap();
        harness
            .credentials
            .values
            .set(&destination, "sxd_device_other_owner")
            .unwrap();
        harness.credentials.operations.lock().unwrap().clear();
        let restarted = harness.restart();
        assert!(
            harness.credentials.operations.lock().unwrap().is_empty(),
            "{reservation}: migration touched a protected slot before ownership admission"
        );
        let blocked = restarted.resolve(None).unwrap();
        assert_eq!(blocked.store.load().unwrap(), original);
        assert_eq!(owner.store.load().unwrap(), owner_state);
        assert!(device_credential(&blocked).is_err());
        assert!(scoped_device_cleanup_slot(&blocked.coordinator.snapshot()).is_err());
        assert!(harness.credentials.operations.lock().unwrap().is_empty());
        assert_eq!(
            harness
                .credentials
                .values
                .get(&destination)
                .unwrap()
                .as_deref(),
            Some("sxd_device_other_owner")
        );
        assert!(restarted
            .view()
            .connections
            .iter()
            .any(
                |connection| connection.id == super::super::super::LEGACY_CONNECTION_ID
                    && connection.view.error.as_deref() == Some(RECOVERY)
            ));
    }
}
