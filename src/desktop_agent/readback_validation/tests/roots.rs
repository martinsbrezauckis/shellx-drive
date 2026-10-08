use serde_json::json;

use crate::desktop_agent::{
    parse_submit_request, validate_result_payload, DesktopAgentCommandKind,
    DesktopAgentCommandPayload, DesktopAgentResultPayload,
};

use super::request;

#[test]
fn discovered_roots_accept_opaque_server_cursor_and_sparse_continuation() {
    let first: DesktopAgentResultPayload = serde_json::from_value(json!({
        "kind": "roots_discovered", "workspace_count": 1, "candidate_count": 1,
        "requires_local_selection": true,
        "page": {"after": null, "limit": 1, "rows": [{
            "workspace_id": "workspace_01", "workspace_name": "My files",
            "sync_root_id": "workspace:workspace_01", "remote_root_id": null,
            "root_name": "My files", "owner_label": "Me", "role": "owner",
            "selection_status": "available"
        }]},
        "next_after": "opaque.page_1"
    }))
    .unwrap();
    let first_request = DesktopAgentCommandPayload::DiscoverRoots {
        after: None,
        limit: 1,
    };
    assert!(validate_result_payload(&first_request, &first).is_ok());

    let next_request = DesktopAgentCommandPayload::DiscoverRoots {
        after: Some("opaque.page_1".to_string()),
        limit: 1,
    };
    let empty: DesktopAgentResultPayload = serde_json::from_value(json!({
        "kind": "roots_discovered", "workspace_count": 0, "candidate_count": 0,
        "requires_local_selection": true,
        "page": {"after": "opaque.page_1", "limit": 1, "rows": []},
        "next_after": "opaque.page_2"
    }))
    .unwrap();
    assert!(validate_result_payload(&next_request, &empty).is_ok());
    let mut repeated = empty;
    if let DesktopAgentResultPayload::RootsDiscovered { next_after, .. } = &mut repeated {
        *next_after = Some("opaque.page_1".to_string());
    }
    assert!(validate_result_payload(&next_request, &repeated).is_err());
    assert!(parse_submit_request(request(
        DesktopAgentCommandKind::DiscoverRoots,
        json!({"after": "/local/path", "limit": 1})
    ))
    .is_err());
}
