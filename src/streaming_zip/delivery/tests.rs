use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use axum::body::to_bytes;
use tokio_stream::StreamExt;

use super::*;
use crate::streaming_zip::{
    ArchiveTicket, ArchiveTickets, MAX_ARCHIVE_BYTES, MAX_CONCURRENT_ARCHIVES,
};

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn ticket(tickets: &ArchiveTickets, actor: &str, client: &str) -> ArchiveTicket {
    let token = tickets
        .issue(Vec::new(), "fixture.zip".to_string(), actor, client)
        .unwrap();
    tickets.redeem(&token, client, None).unwrap()
}

fn file(temp: &tempfile::TempDir) -> ArchiveEntry {
    let path = temp.path().join("blob");
    std::fs::write(&path, vec![7; 1024 * 1024]).unwrap();
    ArchiveEntry {
        path: "body.bin".to_string(),
        blob_path: Some(path),
        expected_size: 1024 * 1024,
        statistics_target: None,
        content_subject: None,
    }
}

async fn wait_for_capacity(tickets: &ArchiveTickets) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while tickets.permits.available_permits() != MAX_CONCURRENT_ARCHIVES {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the blocking ZIP producer must terminate and release its permits");
}

#[test]
fn archive_budget_includes_metadata_and_accepts_the_largest_supported_payload() {
    let small = ArchiveEntry::directory("folder".to_string());
    assert_eq!(archive_total_timeout(&[small]), Duration::from_secs(31));
    let mut large = ArchiveEntry::directory("large.bin".to_string());
    large.expected_size = 2 * 1024 * 1024 * 1024;
    assert_eq!(
        archive_total_timeout(&[large.clone()]),
        Duration::from_secs(16_415)
    );
    large.expected_size = MAX_ARCHIVE_BYTES;
    assert_eq!(
        archive_total_timeout(&[large]),
        Duration::from_secs(5 * 60 * 60)
    );
}

#[test]
fn successful_writes_cannot_extend_the_absolute_deadline() {
    let (sender, mut receiver) = mpsc::channel(1);
    let mut writer = ChannelWriter {
        sender,
        backpressure_timeout: Duration::from_secs(30),
        delivery_deadline: Instant::now() + Duration::from_secs(60),
    };
    for _ in 0..10 {
        writer.write_all(b"progress").unwrap();
        receiver.try_recv().unwrap().unwrap();
    }
    writer.delivery_deadline = Instant::now();
    let error = writer.write(b"still draining").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(receiver.try_recv().is_err());
}

#[tokio::test]
async fn trickle_progress_hits_the_deadline_and_returns_producer_capacity() {
    let temp = tempfile::tempdir().unwrap();
    let tickets = ArchiveTickets::default();
    let ticket = ticket(&tickets, "workspace-a", "client-a");
    let permit = tickets.try_acquire_producer(&ticket, "client-a").unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let mut stream = archive_body(
        vec![file(&temp)],
        permit,
        DropFlag(dropped.clone()),
        None,
        Duration::from_millis(150),
    )
    .into_data_stream();
    let mut bytes = 0;
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(chunk) = stream.next().await {
            bytes += chunk.unwrap().len();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("trickle progress must not reset the total deadline");
    assert!(bytes > 0 && bytes < 1024 * 1024);
    wait_for_capacity(&tickets).await;
    assert!(dropped.load(Ordering::SeqCst));
    assert!(tickets.try_acquire_producer(&ticket, "client-a").is_ok());
}

#[tokio::test]
async fn receiver_deadline_wakes_pending_reads_without_releasing_a_live_producer() {
    let tickets = ArchiveTickets::default();
    let active = ticket(&tickets, "workspace-a", "client-a");
    let other = ticket(&tickets, "workspace-b", "client-b");
    let permit = tickets.try_acquire_producer(&active, "client-a").unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let release_rx = std::sync::Mutex::new(release_rx);
    let revalidator: ArchiveEntryRevalidator = Arc::new(move |_| {
        started_tx.send(()).unwrap();
        release_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        Ok(())
    });
    let body = archive_body(
        vec![ArchiveEntry::directory("folder".to_string())],
        permit,
        DropFlag(dropped.clone()),
        Some(revalidator),
        Duration::from_millis(50),
    );
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let (drained_tx, drained_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = drained_tx.send(to_bytes(body, 1024).await);
    });
    let result = tokio::time::timeout(Duration::from_millis(250), drained_rx).await;
    assert!(!dropped.load(Ordering::SeqCst));
    assert!(tickets.try_acquire_producer(&active, "client-a").is_err());
    let other_permit = tickets.try_acquire_producer(&other, "client-b").unwrap();
    drop(other_permit);
    release_tx.send(()).unwrap();
    wait_for_capacity(&tickets).await;
    assert!(result
        .expect("the absolute deadline must wake a pending body poll")
        .unwrap()
        .unwrap()
        .is_empty());
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn body_disconnect_terminates_the_producer_and_releases_capacity() {
    let temp = tempfile::tempdir().unwrap();
    let tickets = ArchiveTickets::default();
    let ticket = ticket(&tickets, "workspace-a", "client-a");
    let permit = tickets.try_acquire_producer(&ticket, "client-a").unwrap();
    drop(archive_body(
        vec![file(&temp)],
        permit,
        (),
        None,
        Duration::from_secs(60),
    ));
    wait_for_capacity(&tickets).await;
    assert!(tickets.try_acquire_producer(&ticket, "client-a").is_ok());
}
