//! Admit migration source and destination ownership before provider access.

use super::*;

pub(super) fn credential_slot_claims(state: &DesktopState) -> BTreeSet<String> {
    device_claims(state)
        .into_iter()
        .chain(state.desktop_agent_control.credential_key.iter().cloned())
        .chain(
            state
                .pending_disconnect_cleanup
                .iter()
                .flat_map(|cleanup| &cleanup.credential_slots)
                .filter(|slot| {
                    slot.namespace == DisconnectCredentialNamespace::DesktopAgentDeviceScoped
                })
                .map(|slot| slot.account_key.clone()),
        )
        .collect()
}

pub(super) fn admit_destinations(
    state: &DesktopState,
    identity: &SessionIdentity,
    connection_id: &str,
    owners: &BTreeMap<String, BTreeSet<String>>,
) -> CoreResult<()> {
    let fingerprint = migration_fingerprint(state, identity)?;
    // Admit every destination before reading even the first source. A missing
    // source is not proof that an existing destination is this owner's crash
    // copy: another retained connection may reserve that locator in its saved
    // enrollment or cleanup metadata.
    for legacy in legacy_keys(state) {
        let scoped = desktop_agent_device_credential_key(&fingerprint, &legacy)?;
        if owners
            .get(&scoped)
            .is_some_and(|claims| claims.len() != 1 || !claims.contains(connection_id))
        {
            return Err(recovery_error());
        }
    }
    Ok(())
}

pub(super) fn migration_fingerprint(
    state: &DesktopState,
    identity: &SessionIdentity,
) -> CoreResult<String> {
    if let Some(pair) = &state.pair {
        if state_identity(state)?
            .as_ref()
            .map(|owner| owner.session().credential_key())
            != Some(identity.credential_key())
        {
            return Err(recovery_error());
        }
        // Lookup rederives from this retained spelling as well. Catalog URL
        // normalization must not strand a legitimate historical enrollment.
        Ok(desktop_agent_enrollment_fingerprint(
            &pair.server_url,
            &pair.account_email,
        ))
    } else {
        Ok(desktop_agent_enrollment_fingerprint(
            &identity.server_url,
            &identity.email,
        ))
    }
}
