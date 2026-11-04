mod cancel;
mod dfile;
mod manifest;
mod opening_payload;
mod paths;

#[allow(unused_imports)]
use cancel::*;
#[allow(unused_imports)]
use dfile::*;
#[allow(unused_imports)]
use manifest::*;
#[allow(unused_imports)]
use opening_payload::*;
#[allow(unused_imports)]
use paths::*;

pub use cancel::{record_drained, request_cancel_recv};

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::channel::Channel;
use crate::{Error, Result};

const POLL: Duration = Duration::from_micros(500);

const DRAIN_LIMIT: usize = 64;
const DRAIN_BUDGET: Duration = Duration::from_millis(30);
const PEER_META_FRAME: u32 = 0xFFFF_0002;
const PEER_META_ACK_FRAME: u32 = 0xFFFF_0008;
const PEER_META_ACK_JSON: &[u8] = b"META_DEVICE_INFO_ACK\0";
const CHANNEL_BYTES: u32 = 0xFFFF_0004;

pub struct Session {
    pub file_count: u32,
    pub total_bytes: u64,
    pub session_key: [u8; 32],
    pub device_hash: Vec<u8>,
    pub peer: String,
    pub accepted: bool,
    pub peer_apple: bool,
}

pub struct ReceiveResult {
    pub saved: Vec<PathBuf>,
    pub bytes: u64,
}

pub fn accept_connection(
    channel: &mut Channel,
    private: &rsa::RsaPrivateKey,
    accept: bool,
    timeout: Duration,
) -> Result<Session> {
    let local = channel.local_ip().unwrap_or_default();
    if channel.label() == "chan" {
        channel.set_label("control");
    }
    let result = accept_connection_inner(channel, private, accept, timeout);
    match &result {
        Ok(session) => crate::trace::session_start(
            "recv",
            &session.peer,
            &local,
            session.file_count as usize,
            session.total_bytes,
        ),
        Err(e) => crate::trace::note("control", &format!("认证/握手失败: {e}")),
    }
    result
}

pub fn run_session(
    session: &Session,
    control: &mut Channel,
    destination: &Path,
    display_name: &str,
    timeout: Duration,
) -> Result<ReceiveResult> {
    let started = Instant::now();
    let progress = Arc::new(AtomicU64::new(0));
    let outcome = run_session_once(session, control, destination, display_name, timeout, &progress);
    let received = progress.load(Ordering::Relaxed);
    let outcome = outcome.map_err(|e| {
        let msg = e.to_string();
        if received == 0 || msg.contains("已收") || msg.contains("取消") {
            return e;
        }
        let suffix = format!("（已收 {:.1} MB）", received as f64 / 1048576.0);
        match e {
            Error::Io(m) => Error::Io(format!("{m}{suffix}")),
            other => Error::Protocol(format!("{other}{suffix}")),
        }
    });
    let files: Vec<(String, u64)> = match &outcome {
        Ok(result) => result
            .saved
            .iter()
            .filter_map(|p| {
                let name = p.file_name()?.to_string_lossy().to_string();
                let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                Some((name, size))
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    match &outcome {
        Ok(result) => crate::history::record(
            "recv",
            &session.peer,
            &files,
            result.bytes,
            started.elapsed(),
            true,
            "",
        ),
        Err(e) => crate::history::record(
            "recv",
            &session.peer,
            &files,
            received,
            started.elapsed(),
            false,
            &e.to_string(),
        ),
    }
    let names: Vec<String> = files.iter().map(|(n, _)| n.clone()).collect();
    let dur = started.elapsed().as_millis();
    match &outcome {
        Ok(result) if session.accepted => {
            crate::trace::session_end(true, result.bytes, &names, "done", dur)
        }
        Ok(_) => crate::trace::session_end(true, 0, &names, "rejected", dur),
        Err(e) => crate::trace::session_end(false, received, &names, &e.to_string(), dur),
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::tlv_encode;
    #[allow(unused_imports)]
    use crate::transfer;

    #[test]
    fn sanitize_strips_paths() {
        assert_eq!(sanitize("../../etc/passwd"), "passwd");
        assert_eq!(sanitize(r"C:\Windows\a.txt"), "a.txt");
        assert_eq!(sanitize("a<b>c.txt"), "a_b_c.txt");
        assert_eq!(sanitize(".."), "received.bin");
    }

    #[test]
    fn sanitize_handles_windows_quirks() {
        assert_eq!(sanitize("CON.txt"), "_CON.txt");
        assert_eq!(sanitize("com1"), "_com1");
        assert_eq!(sanitize("LPT9.log"), "_LPT9.log");
        assert_eq!(sanitize("A.TXT. "), "A.TXT");
        assert_eq!(sanitize("COM10.txt"), "COM10.txt", "两位数不是保留名");
        let long = "啊".repeat(300);
        assert_eq!(sanitize(&long).chars().count(), 120);
    }

    #[test]
    fn unique_path_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("hwshare-unique-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a.txt"));
        std::fs::write(dir.join("a.txt"), b"first").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (1).txt"));

        std::fs::write(part_path(&dir.join("a (1).txt")), b"half").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (2).txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_same_name_gets_distinct_parts() {
        use std::io::Write;

        let dir = std::env::temp_dir().join(format!("hwshare-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        const N: usize = 8;
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let d = dir.clone();
                std::thread::spawn(move || {
                    let (_target, part, mut f) =
                        create_part_atomic(&d, "same.txt").expect("抢占 .part 失败");
                    writeln!(f, "writer {i}").unwrap();
                    drop(f);
                    part
                })
            })
            .collect();

        let parts: std::collections::HashSet<_> = handles
            .into_iter()
            .map(|h| h.join().expect("子线程 panic"))
            .collect();

        assert_eq!(parts.len(), N, "不同会话抢到了同一个 .part：{:?}", parts);
        for p in &parts {
            let text = std::fs::read_to_string(p).unwrap();
            assert!(text.starts_with("writer "), "{:?} 内容被覆盖", p);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_caps_entry_count() {
        fn entry(id: u16, name: &str) -> Vec<u8> {
            let mut unit = Vec::new();
            unit.extend_from_slice(&id.to_be_bytes());
            unit.extend_from_slice(&100u64.to_be_bytes());
            unit.extend_from_slice(&(name.len() as u16).to_be_bytes());
            unit.extend_from_slice(name.as_bytes());
            unit
        }

        let mut payload = vec![0u8, 0u8];
        let total = MAX_MANIFEST + 50;
        for i in 0..total {
            let id = (i % 60000) as u16 + 1;
            payload.extend(entry(id, "f.txt"));
        }

        let mut expected = Vec::new();
        let mut empty = Vec::new();
        let added = merge_manifest(&mut expected, &mut empty, &payload);
        assert_eq!(expected.len(), MAX_MANIFEST, "必须停在 MAX_MANIFEST");
        assert_eq!(added, MAX_MANIFEST);
        assert!(expected.len() <= total);
    }

    #[test]
    fn manifest_merges_multiple_frames() {
        fn entry(id: u16, size: u64, name: &str) -> Vec<u8> {
            let mut unit = Vec::new();
            unit.extend_from_slice(&id.to_be_bytes());
            unit.extend_from_slice(&size.to_be_bytes());
            unit.extend_from_slice(&(name.len() as u16).to_be_bytes());
            unit.extend_from_slice(name.as_bytes());
            unit
        }
        let mut frame1 = vec![0u8, 2];
        frame1.extend(entry(1, 100, "a.txt"));
        let mut frame2 = vec![0u8, 2];
        frame2.extend(entry(1, 100, "dup.txt")); 
        frame2.extend(entry(2, 200, "b.bin"));
        frame2.extend(entry(3, 0, "empty.txt")); 
        frame2.extend(entry(4, 10, "  "));       

        let mut expected = Vec::new();
        let mut empty = Vec::new();
        assert_eq!(merge_manifest(&mut expected, &mut empty, &frame1), 1);
        assert_eq!(merge_manifest(&mut expected, &mut empty, &frame2), 1);
        assert_eq!(expected.len(), 2);
        assert_eq!(expected[1].0, 2);
        assert_eq!(expected[1].1, 200);
        assert_eq!(expected[1].2, "b.bin");
        assert_eq!(empty.len(), 1);
        assert_eq!(empty[0].0, 3);
    }

    #[test]
    fn describes_drained_cancel_frame() {
        let key = [7u8; 32];
        let body = tlv_encode(1, &tlv_encode(1, b"senderCancel").unwrap()).unwrap();
        let wire_frame = transfer::seal_encrypted_frame(&[0u8; 16], &key, &body, 1).unwrap();
        let text = describe_wire_frame(9, &wire_frame, &key);
        assert!(text.contains("senderCancel"), "没认出取消命令: {text}");
    }

    #[test]
    fn describing_garbage_never_panics() {
        let key = [0u8; 32];
        assert!(describe_wire_frame(21, &[0u8; 32], &key).contains("module=21"));
        let text = describe_control_body(b"not a tlv at all");
        assert!(text.starts_with("明文"), "{text}");
        assert!(hex_head(&[0xAB; 100]).ends_with('…'));
    }
}
