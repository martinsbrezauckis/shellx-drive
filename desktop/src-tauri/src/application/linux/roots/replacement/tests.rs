use super::*;

fn pair(path: &str, workspace: &str) -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "person@example.test".to_string(),
        workspace_id: workspace.to_string(),
        workspace_name: workspace.to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: PathBuf::from(path),
        local_root_identity: None,
    }
}

fn activity(result: &str) -> shellx_drive_desktop_core::ActivityEntry {
    shellx_drive_desktop_core::ActivityEntry {
        at: Utc::now(),
        direction: "download".to_string(),
        relative_path: PathBuf::from("retained.txt"),
        result: result.to_string(),
    }
}

#[test]
fn fresh_candidate_preserves_auth_and_original_binding_until_publication() {
    let mut old = DesktopState::default();
    old.configure_pair(pair("/old/one", "one")).unwrap();
    old.activity.push(activity("one"));
    old.change_cursor = 71;
    old.paused = true;
    old.launch_at_login = false;
    old.active_remote_session = Some(
        shellx_drive_desktop_core::RemoteSessionRecord::new(
            "https://drive.example.test",
            "person@example.test",
            "session-one",
            Utc::now() + chrono::Duration::hours(1),
        )
        .unwrap(),
    );
    old.desktop_agent_control
        .enroll("device-one".to_string(), None, "a".repeat(64))
        .unwrap();
    let candidate = fresh_folder_state(&old, PathBuf::from("/new"));
    assert_eq!(
        old.pair.as_ref().unwrap().local_root,
        PathBuf::from("/old/one")
    );
    assert_eq!(old.change_cursor, 71);
    assert_eq!(old.activity.len(), 1);
    assert!(candidate.pair.is_none());
    assert_eq!(candidate.change_cursor, 0);
    assert_eq!(candidate.active_remote_session, old.active_remote_session);
    assert_eq!(candidate.desktop_agent_control, old.desktop_agent_control);
    assert!(candidate.paused);
    assert!(!candidate.launch_at_login);
}

#[test]
fn replacement_preserves_each_roots_history_pause_and_active_selection() {
    let mut old = DesktopState::default();
    old.configure_pair(pair("/old/one", "one")).unwrap();
    old.activity.push(activity("one"));
    old.paused = true;
    old.configure_pair(pair("/old/two", "two")).unwrap();
    old.activity.push(activity("two"));
    old.paused = false;
    let selected = old.pair.as_ref().map(remote_subject);
    let history = pair_history(&old);
    let mut candidate = fresh_folder_state(&old, PathBuf::from("/new"));
    candidate.configure_pair(pair("/new/two", "two")).unwrap();
    candidate.configure_pair(pair("/new/one", "one")).unwrap();
    restore_pair_history(&mut candidate, &history, selected).unwrap();
    assert_eq!(candidate.pair.as_ref().unwrap().workspace_id, "two");
    assert_eq!(candidate.activity[0].result, "two");
    assert!(!candidate.paused);
    assert_eq!(candidate.inactive_pairs[0].activity[0].result, "one");
    assert!(candidate.inactive_pairs[0].paused);
    assert_eq!(
        candidate.inactive_pairs[0].pair.local_root,
        PathBuf::from("/new/one")
    );
}
