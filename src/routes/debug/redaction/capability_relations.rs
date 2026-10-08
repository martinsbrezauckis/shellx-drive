use serde::Serialize;

use crate::{
    auth::opaque_audit_ref,
    model::{EmailOutboxItem, Notification},
};

#[derive(Serialize)]
pub(crate) struct DebugEmailResponse {
    pub(crate) service: String,
    pub(crate) transport: String,
    pub(crate) from: String,
    pub(crate) base_url: String,
    pub(crate) smtp_host_source: String,
    pub(crate) smtp_port: Option<u16>,
    pub(crate) smtp_user_source: String,
    pub(crate) emails: Vec<DebugEmailOutboxItem>,
}

#[derive(Serialize)]
pub(crate) struct DebugEmailOutboxItem {
    email_ref: String,
    kind: String,
    status: String,
    recipient_email: String,
    subject: String,
    related_type: Option<String>,
    related_ref: Option<String>,
    attempts: i64,
    last_error: Option<String>,
    created_at: String,
    updated_at: String,
    sent_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct DebugNotificationsResponse {
    pub(crate) service: String,
    pub(crate) unread_count: i64,
    pub(crate) notifications: Vec<DebugNotification>,
}

#[derive(Serialize)]
pub(crate) struct DebugNotification {
    notification_ref: String,
    recipient_email: String,
    workspace_id: Option<String>,
    file_id: Option<String>,
    kind: String,
    title: String,
    body: &'static str,
    related_type: Option<String>,
    related_ref: Option<String>,
    read_at: Option<String>,
    created_at: String,
}

pub(crate) fn emails(emails: Vec<EmailOutboxItem>, signing_key: &str) -> Vec<DebugEmailOutboxItem> {
    emails
        .into_iter()
        .map(|email| DebugEmailOutboxItem {
            email_ref: opaque_ref("email", &email.id, signing_key),
            kind: email.kind,
            status: email.status,
            recipient_email: email.recipient_email,
            subject: email.subject,
            related_ref: relation_ref(
                email.related_type.as_deref(),
                email.related_id.as_deref(),
                signing_key,
            ),
            related_type: email.related_type,
            attempts: email.attempts,
            last_error: email.last_error,
            created_at: email.created_at,
            updated_at: email.updated_at,
            sent_at: email.sent_at,
        })
        .collect()
}

pub(crate) fn notifications(
    notifications: Vec<Notification>,
    signing_key: &str,
) -> Vec<DebugNotification> {
    notifications
        .into_iter()
        .map(|notification| DebugNotification {
            notification_ref: opaque_ref("notification", &notification.id, signing_key),
            recipient_email: notification.recipient_email,
            workspace_id: notification.workspace_id,
            file_id: notification.file_id,
            kind: notification.kind,
            title: notification.title,
            body: "redacted",
            related_ref: relation_ref(
                notification.related_type.as_deref(),
                notification.related_id.as_deref(),
                signing_key,
            ),
            related_type: notification.related_type,
            read_at: notification.read_at,
            created_at: notification.created_at,
        })
        .collect()
}

fn relation_ref(
    related_type: Option<&str>,
    related_id: Option<&str>,
    signing_key: &str,
) -> Option<String> {
    related_id.map(|id| {
        opaque_ref(
            "relation",
            &format!("{}\0{id}", related_type.unwrap_or("untyped")),
            signing_key,
        )
    })
}

fn opaque_ref(kind: &str, value: &str, signing_key: &str) -> String {
    opaque_audit_ref(&format!("{kind}\0{value}"), signing_key).replacen(
        "target-v1-",
        &format!("{kind}-v1-"),
        1,
    )
}
