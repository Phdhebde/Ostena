use proptest::prelude::*;

use super::*;

fn write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

fn dir() -> tempdir::Dir {
    tempdir::Dir::new()
}

/// A temporary directory removed on drop (no dependency).
mod tempdir {
    pub(super) struct Dir(pub(super) std::path::PathBuf);

    impl Dir {
        pub(super) fn new() -> Self {
            let n: [u8; 8] = ostena_crypto::rand::array().unwrap();
            let path =
                std::env::temp_dir().join(format!("ostena-reports-{}", u64::from_be_bytes(n)));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn session(n: u8) -> Uuid {
    Uuid::from_bytes([n; 16])
}

fn ids(queue: &ReportQueue) -> Vec<u64> {
    queue
        .state
        .lock()
        .unwrap()
        .stored
        .reports
        .iter()
        .map(|r| r.id)
        .collect()
}

#[test]
fn reports_survive_a_restart_encrypted_until_acknowledged() {
    let d = dir();
    let queue = ReportQueue::open(&d.0, write).unwrap();
    assert_eq!(
        queue.push(session(1), "fin normale", 10, 20),
        Pushed::Queued
    );
    assert_eq!(queue.push(session(2), "coupée\u{7}", 0, 0), Pushed::Queued);
    let key = std::fs::read(d.0.join(KEY_FILE)).unwrap();
    assert_eq!(key.len(), 32);
    let file = std::fs::read(d.0.join(QUEUE_FILE)).unwrap();
    let text = String::from_utf8_lossy(&file);
    assert!(!text.contains(&session(1).to_string()) && !text.contains("fin normale"));
    drop(queue);

    let queue = ReportQueue::open(&d.0, write).unwrap();
    assert_eq!(queue.pending(), 2);
    let messages = queue.due(Instant::now());
    assert_eq!(messages.len(), 2);
    let AgentMessage::SessionClosed {
        report_id,
        session_id,
        reason,
        bytes_to_target,
        bytes_from_target,
        closed_at,
    } = &messages[0]
    else {
        panic!("{messages:?}");
    };
    assert_eq!(
        (
            session_id.as_str(),
            reason.as_str(),
            *bytes_to_target,
            *bytes_from_target
        ),
        (session(1).to_string().as_str(), "fin normale", 10, 20)
    );
    assert!(*closed_at > 1_700_000_000);
    messages[1].validate().unwrap();
    // Not sent again before RESEND, then sent again.
    assert_eq!(queue.due(Instant::now()).len(), 0);
    assert_eq!(queue.due(Instant::now() + RESEND).len(), 2);
    queue.ack(*report_id);
    queue.ack(*report_id);
    drop(queue);
    let queue = ReportQueue::open(&d.0, write).unwrap();
    assert_eq!(queue.pending(), 1);
    let AgentMessage::SessionClosed { reason, .. } = &queue.due(Instant::now())[0] else {
        panic!();
    };
    assert_eq!(reason, "coupée");
}

#[test]
fn a_full_queue_counts_and_reports_what_it_drops() {
    let d = dir();
    let queue = ReportQueue::open_bounded(&d.0, write, 2).unwrap();
    for n in 0..2 {
        assert_eq!(queue.push(session(n), "x", 0, 0), Pushed::Queued);
    }
    assert_eq!(queue.push(session(3), "x", 0, 0), Pushed::Dropped);
    assert_eq!(queue.push(session(4), "x", 0, 0), Pushed::Dropped);
    let lost = queue.lost().unwrap();
    assert_eq!((lost.count, lost.unreadable), (2, false));
    // The notice goes first, then the reports.
    let messages = queue.due(Instant::now());
    assert!(matches!(
        messages[0],
        AgentMessage::ReportsLost {
            count: 2,
            unreadable: false,
            ..
        }
    ));
    messages[0].validate().unwrap();
    // A drop while the notice is on its way stays, in a new notice.
    assert_eq!(queue.push(session(5), "x", 0, 0), Pushed::Dropped);
    queue.ack(lost.id);
    let next = queue.lost().unwrap();
    assert_ne!(next.id, lost.id);
    assert_eq!(next.count, 1);
    drop(queue);
    // Kept across a restart.
    let queue = ReportQueue::open_bounded(&d.0, write, 2).unwrap();
    assert_eq!(queue.lost(), Some(next));
    queue.ack(next.id);
    assert_eq!(queue.lost(), None);
    let first = ids(&queue)[0];
    queue.ack(first);
    assert_eq!(queue.push(session(6), "x", 0, 0), Pushed::Queued);
}

#[test]
fn an_unreadable_queue_is_set_aside_and_reported() {
    let d = dir();
    let queue = ReportQueue::open(&d.0, write).unwrap();
    queue.push(session(1), "x", 0, 0);
    drop(queue);
    let path = d.0.join(QUEUE_FILE);
    let mut bytes = std::fs::read(&path).unwrap();
    let end = bytes.len() - 1;
    bytes[end] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    let queue = ReportQueue::open(&d.0, write).unwrap();
    assert_eq!(queue.pending(), 0);
    let lost = queue.lost().unwrap();
    assert_eq!((lost.count, lost.unreadable), (0, true));
    let aside = std::fs::read_dir(&d.0)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("reports.queue.corrupt-")
        })
        .count();
    assert_eq!(aside, 1);
    // Another key: unreadable too.
    drop(queue);
    std::fs::remove_file(d.0.join(KEY_FILE)).unwrap();
    let queue = ReportQueue::open(&d.0, write).unwrap();
    assert!(queue.lost().unwrap().unreadable);
    // A key of another length refuses to start.
    std::fs::write(d.0.join(KEY_FILE), [0u8; 16]).unwrap();
    assert!(ReportQueue::open(&d.0, write).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Whatever is pushed and acknowledged, the queue stays bounded, every
    /// drop is counted, and a restart reads back the same queue.
    #[test]
    fn prop_bounded_counted_and_durable(ops in prop::collection::vec(any::<Option<u8>>(), 0..40)) {
        let d = dir();
        let queue = ReportQueue::open_bounded(&d.0, write, 5).unwrap();
        let (mut queued, mut dropped) = (0u64, 0u64);
        for op in ops {
            match op {
                Some(n) => match queue.push(session(n), "x", 0, 0) {
                    Pushed::Queued => queued += 1,
                    Pushed::Dropped => dropped += 1,
                },
                None => {
                    if let Some(&id) = ids(&queue).first() {
                        queue.ack(id);
                        queued -= 1;
                    }
                }
            }
            prop_assert!(queue.pending() <= 5);
            prop_assert_eq!(queue.pending() as u64, queued);
            prop_assert_eq!(queue.lost().map_or(0, |l| l.count), dropped);
        }
        let reports = queue.state.lock().unwrap().stored.clone();
        drop(queue);
        let again = ReportQueue::open_bounded(&d.0, write, 5).unwrap();
        prop_assert_eq!(&again.state.lock().unwrap().stored, &reports);
    }
}
