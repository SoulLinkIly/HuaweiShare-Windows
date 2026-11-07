//! 发送流程编排：收集文件 → 协商 → 逐文件传输 → 记历史。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;

use crate::{Error, ErrorKind, Result};

pub const DEVICE_TYPE_ID: u32 = 12;

const MAX_RETRY: u32 = 2;
const RETRY_BACKOFF: Duration = Duration::from_secs(2);
const FAST_FAIL: Duration = Duration::from_secs(3);

pub(crate) fn debug_io() -> bool {
    crate::env::present("HWSHARE_DEBUG")
}

macro_rules! dbg_frame {
    ($($arg:tt)*) => {
        if crate::outbound::debug_io() {
            eprintln!($($arg)*);
        }
    };
}

#[derive(Default)]
pub(super) struct PeerState {

    pub cancel_acked: AtomicBool,

    pub peer_pct_bits: AtomicU64,

    pub preview_ok: AtomicBool,
}

impl PeerState {
    pub fn new() -> Self {
        Self {
            cancel_acked: AtomicBool::new(false),
            peer_pct_bits: AtomicU64::new(u64::MAX),
            preview_ok: AtomicBool::new(false),
        }
    }
}

pub struct Outgoing {
    pub id: u16,

    pub name: String,
    pub size: u64,

    pub path: PathBuf,

    pub rel_path: String,
}

impl Clone for Outgoing {
    fn clone(&self) -> Self {
        Self { id: self.id, name: self.name.clone(), size: self.size, path: self.path.clone(), rel_path: self.rel_path.clone() }
    }
}

pub struct Report {
    pub files: Vec<String>,
    pub bytes: u64,
}

fn walk_dir(
    dir: &Path,
    prefix: &str,
    depth: usize,
    out: &mut Vec<Outgoing>,
    empty_dirs: &mut usize,
) -> Result<()> {
    if depth > 32 {
        return Ok(());
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return Ok(()) };
    let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();

    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        let Some(nm) = p.file_name().map(|s| s.to_string_lossy().to_string()) else {
            continue;
        };
        let rel = format!("{prefix}/{nm}");

        let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
        if md.is_dir() {
            let before = out.len();
            walk_dir(&p, &rel, depth + 1, out, empty_dirs)?;
            if out.len() == before {
                *empty_dirs += 1;
            }
        } else {

            let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            out.push(Outgoing {
                id: 0,
                name: nm,
                size,
                path: p,
                rel_path: rel,
            });
        }
    }
    Ok(())
}

/// `collect` 的结果。
///
/// 以前是个 4 元组，调用点大量出现 `(files, _, _, _)`，读代码时根本对不上号；
/// 这几个计数各有各的用途（提示用户跳过了什么），值得有名字。
pub struct Collected {
    pub files: Vec<Outgoing>,
    /// 被跳过的条目：空目录、非文件、取不到名字的路径。
    pub skipped: usize,
    /// 顶层文件夹个数（决定要不要按相对路径发）。
    pub top_dirs: usize,
    /// 无法表达的空文件夹个数——协议按文件传，装不下空目录。
    pub empty_dirs: usize,
}

pub fn collect(paths: &[PathBuf]) -> Result<Collected> {
    if paths.is_empty() {
        return Err(Error::Argument);
    }
    let mut out = Vec::new();
    let mut skipped = 0usize;
    let mut top_dirs = 0usize;
    let mut empty_dirs = 0usize;
    for path in paths {
        let meta = std::fs::metadata(path)
            .map_err(|e| Error::Io(format!("读取 {} 失败: {e}", path.display())))?;

        if meta.is_dir() {
            let Some(base) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
                skipped += 1;
                continue;
            };
            let mut found = Vec::new();
            walk_dir(path, &base, 0, &mut found, &mut empty_dirs)?;
            if found.is_empty() {

                skipped += 1;
                continue;
            }
            top_dirs += 1;
            for f in found {
                if out.len() >= crate::transfer::MAX_MANIFEST_ENTRIES {
                    return Err(Error::Protocol(format!(
                        "一次最多发 {} 个文件，请分批发",
                        crate::transfer::MAX_MANIFEST_ENTRIES
                    )));
                }
                out.push(Outgoing { id: (out.len() + 1) as u16, ..f });
            }
            continue;
        }

        if !meta.is_file() {
            skipped += 1;
            continue;
        }
        if meta.len() == 0 && !crate::env::unless_zero("HWSHARE_ALLOW_EMPTY") {

            return Err(Error::Protocol(format!(
                "空文件被 HWSHARE_ALLOW_EMPTY=0 拒绝: {}",
                path.display()
            )));
        }
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
            continue;
        };

        if out.len() >= crate::transfer::MAX_MANIFEST_ENTRIES {
            return Err(Error::Protocol(format!(
                "一次最多发 {} 个文件，请分批发",
                crate::transfer::MAX_MANIFEST_ENTRIES
            )));
        }
        out.push(Outgoing {

            id: (out.len() + 1) as u16,
            rel_path: name.clone(),
            name,
            size: meta.len(),
            path: path.clone(),
        });
    }
    if out.is_empty() {
        return Err(Error::Protocol(
            "选中的都是空文件夹，里面没有可发送的文件".to_string(),
        ));
    }
    Ok(Collected { files: out, skipped, top_dirs, empty_dirs })
}

fn local_ipv4(peer: &str) -> Result<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| Error::Io(e.to_string()))?;
    socket
        .connect((peer, 9))
        .map_err(|e| Error::Io(e.to_string()))?;
    let addr = socket.local_addr().map_err(|e| Error::Io(e.to_string()))?;
    Ok(addr.ip().to_string())
}

fn reserve_port(local: &str) -> Result<(u16, std::net::TcpListener)> {
    let listener =
        std::net::TcpListener::bind((local, 0)).map_err(|e| Error::Io(e.to_string()))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::Io(e.to_string()))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::Io(e.to_string()))?
        .port();
    Ok((port, listener))
}

fn rand_seq() -> u64 {
    rand::rngs::OsRng.next_u64()
}

pub fn transmit(
    peer_ip: &str,
    peer_port: u16,
    paths: &[PathBuf],
    display_name: &str,
    log: &dyn Fn(&str),
) -> Result<Report> {
    let started = Instant::now();

    // 这里只为进度条估个总量；真正的错误留给 send_once 里的 collect 去报。
    let planned: Vec<(String, u64)> = match collect(paths) {
        Ok(c) => c.files.iter().map(|f| (f.rel_path.clone(), f.size)).collect(),
        Err(_) => Vec::new(),
    };
    let planned_bytes: u64 = planned.iter().map(|(_, size)| *size).sum();
    let task = crate::progress::begin(true, "正在准备", planned.len(), planned_bytes);
    let _task_guard = crate::progress::Guard::new(task);
    let local = local_ipv4(peer_ip).map(|ip| ip.to_string()).unwrap_or_default();
    crate::trace::session_start("send", peer_ip, &local, planned.len(), planned_bytes);

    let progress = Arc::new(AtomicU64::new(0));
    // 每次发送一个独立令牌：多路并行互不牵连，也不会被上一批的取消点名。
    let cancel = cancel::CancelToken::new();

    let outcome = {
        let mut attempt = 0u32;
        loop {
            let started_at = Instant::now();
            let result =
                send_once(peer_ip, peer_port, paths, display_name, log, &progress, cancel.flag());
            let fast_fail = started_at.elapsed() < FAST_FAIL;
            match result {
                Err(e)
                    if e.retryable()
                        && attempt < MAX_RETRY
                        && progress.load(Ordering::Relaxed) == 0
                        && (e.kind() != ErrorKind::Network || fast_fail) =>
                {
                    attempt += 1;
                    let wait = RETRY_BACKOFF * attempt;
                    log(&format!(
                        "{e}；{} 秒后自动重试 {attempt}/{MAX_RETRY}",
                        wait.as_secs()
                    ));
                    std::thread::sleep(wait);
                    progress.store(0, Ordering::Relaxed);
                }
                other => break other,
            }
        }
    };
    let peer = format!("{peer_ip}:{peer_port}");
    let sent = progress.load(Ordering::Relaxed);
    match &outcome {
        Ok(report) => crate::history::record(
            "send",
            &peer,
            &planned,
            report.bytes,
            started.elapsed(),
            true,
            "",
        ),
        Err(e) => crate::history::record(
            "send",
            &peer,
            &planned,
            sent,
            started.elapsed(),
            false,
            &e.to_string(),
        ),
    }
    let names: Vec<String> = planned.iter().map(|(name, _)| name.clone()).collect();
    match &outcome {
        Ok(report) => crate::trace::session_end(
            true,
            report.bytes,
            &names,
            "done",
            started.elapsed().as_millis(),
        ),
        Err(e) => crate::trace::session_end(
            false,
            sent,
            &names,
            &e.to_string(),
            started.elapsed().as_millis(),
        ),
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::channel::Channel;
    use crate::transfer;
    use std::time::Duration;

    #[test]
    fn data_frame_size_accounts_for_header() {

        assert_eq!(data_frame_size(1422), 1472);
        assert_eq!(data_frame_size(32768), 32818);
        assert_eq!(data_frame_size(crate::transfer::DFILE_MAX_CONTENT), 65535);
    }

    #[test]
    fn collect_expands_directories() {
        let base = std::env::temp_dir().join(format!("hwshare-collect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("选中目录");
        std::fs::create_dir_all(root.join("子目录/深一层")).unwrap();
        std::fs::create_dir_all(root.join("空目录")).unwrap();
        std::fs::write(root.join("a.txt"), b"aaa").unwrap();
        std::fs::write(root.join("子目录/b.txt"), b"bbbb").unwrap();
        std::fs::write(root.join("子目录/深一层/c.txt"), b"ccccc").unwrap();

        let got = collect(&[root.clone()]).unwrap();
        let files = got.files;
        assert_eq!(got.top_dirs, 1, "选了一个顶层目录");
        assert_eq!(files.len(), 3, "空目录不该产生条目");
        assert_eq!(got.skipped, 0, "空目录已并入 top_dirs 的判断，不算 skipped");
        assert_eq!(got.empty_dirs, 1, "空目录要被单独计数，好提示用户");

        let mut rels: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
        rels.sort();
        assert_eq!(
            rels,
            vec![
                "选中目录/a.txt",
                "选中目录/子目录/b.txt",
                "选中目录/子目录/深一层/c.txt",
            ],
            "清单名必须是带顶层目录名的相对路径"
        );

        let a = files.iter().find(|f| f.rel_path.ends_with("a.txt")).unwrap();
        assert_eq!(a.name, "a.txt");

        let mut ids: Vec<u16> = files.iter().map(|f| f.id).collect();
        ids.sort();
        assert_eq!(ids, vec![1, 2, 3]);

        let _ = std::fs::remove_dir_all(&base);
    }

    fn tmp_image(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(name);

        std::fs::write(&path, b"fake-jpeg-body").unwrap();
        path
    }

    fn read_tlv(data: &[u8], want: u64) -> Option<Vec<u8>> {
        let mut off = 0usize;
        while off < data.len() {
            let tag = crate::varint_decode(data, &mut off).ok()?;
            let len = crate::varint_decode(data, &mut off).ok()? as usize;
            if off + len > data.len() {
                return None;
            }
            if tag == want {
                return Some(data[off..off + len].to_vec());
            }
            off += len;
        }
        None
    }

    #[test]
    fn preview_default_omits_meta_field() {
        let path = tmp_image("hwshare-preview-test.jpg");
        let files = vec![Outgoing {
            id: 1,
            name: "photo.jpg".into(),
            rel_path: "photo.jpg".into(),
            size: 1000,
            path: path.clone(),
        }];

        let wire_frame = build_preview_payload(&files).unwrap();

        let inner = read_tlv(&wire_frame, 8).expect("外层应为 tag 8");

        let names = read_tlv(&inner, 11).expect("应有字段 11");
        assert_eq!(String::from_utf8_lossy(&names), "photo.jpg");

        assert!(
            read_tlv(&inner, 12).is_none(),
            "默认不应发送字段 12（会让手机 MatchUtd 失败）"
        );

        let times = read_tlv(&inner, 13).expect("应有字段 13");
        let times_text = String::from_utf8_lossy(&times).to_string();
        assert!(times_text.contains("date_taken"), "缺 date_taken");
        assert!(!times_text.contains("-1"), "时间不应再是 -1 占位: {times_text}");
        assert!(times_text.contains("detail_time"), "缺 detail_time");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn control_watch_flags_receiver_cancel() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let key = [7u8; 32];
        let dev = b"0123456789ABCDEF".to_vec();
        let body =
            crate::tlv_encode(1, &crate::tlv_encode(1, b"receiverCancel").unwrap()).unwrap();
        let wire_frame = transfer::seal_encrypted_frame(&dev, &key, &body, 1).unwrap();
        assert_eq!(
            transfer::open_channel_frame(&wire_frame, &key).unwrap(),
            body,
            "测试帧本身应能解开"
        );
        assert_eq!(
            transfer::tlv_list(&body).unwrap()[0].0, 1,
            "外层应为 tag1"
        );

        let peer = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut chan = Channel::from_stream(stream, "test").unwrap();
            chan.transmit(&wire_frame).unwrap();
            std::thread::sleep(Duration::from_millis(300));
        });

        let client = Channel::connect("127.0.0.1", addr.port(), Duration::from_secs(3)).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let watch = spawn_control_watch(
            client,
            key,
            dev,
            "127.0.0.1".into(),
            0,
            cancel.clone(),
            stop.clone(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(PeerState::new()),
        );

        let deadline = Instant::now() + Duration::from_secs(2);
        while !cancel.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(cancel.load(Ordering::SeqCst), "应识别 receiverCancel");
        stop.store(true, Ordering::SeqCst);
        let _ = watch.join();
        let _ = peer.join();
    }

    #[test]
    fn preview_returns_when_cancel_set() {
        let path = std::env::temp_dir().join("wf-preview-cancel.bin");
        std::fs::write(&path, vec![0u8; 4096]).unwrap();
        let file = Outgoing {
            id: 1,
            name: "a.bin".into(),
            rel_path: "a.bin".into(),
            size: 4096,
            path: path.clone(),
        };

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut chan = Channel::from_stream(stream, "peer").unwrap();

            let _ = chan.read_channel_frame(Duration::from_secs(3));
            std::thread::sleep(Duration::from_millis(200));
        });

        let mut chan = Channel::connect("127.0.0.1", addr.port(), Duration::from_secs(3)).unwrap();
        let cancel = AtomicBool::new(true);
        let fb = PeerState::new();
        let t0 = Instant::now();
        let r = send_preview(
            &mut chan,
            &[9u8; 32],
            &[8u8; 32],
            b"0123456789ABCDEF",
            &[file],
            &|_| {},
            &cancel,
            &fb,
            true,
            15_000,
            true,
        );
        assert!(r.is_err(), "已取消时预览应直接失败");
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "不该等满 15 s，实际 {:?}",
            t0.elapsed()
        );
        let _ = std::fs::remove_file(path);
        let _ = peer.join();
    }
}

#[cfg(test)]
mod dump_tests {
    use super::*;

    use std::path::Path;

    #[test]
    fn dump_our_preview_frame() {
        let src = Path::new("E:/workbuddy/2026-10-27-14-27-19/_recv/IMG_20261027_164145.jpg");
        if !src.is_file() {
            return;
        }
        let files = vec![Outgoing {
            id: 1,
            name: "IMG_20261027_164145.jpg".into(),
            rel_path: "IMG_20261027_164145.jpg".into(),
            size: 14_706_054,
            path: src.to_path_buf(),
        }];
        let wire_frame = build_preview_payload(&files).unwrap();
        let out = std::env::temp_dir().join("hwshare-our-preview.bin");
        std::fs::write(&out, &wire_frame).unwrap();
        eprintln!("[dump] 我们的预览帧 {} 字节 → {}", wire_frame.len(), out.display());
    }
}

mod cancel;
mod dfile;
mod handshake;
mod preview;
mod session;

use cancel::{CANCEL_WAIT, cancel_error, cancelled, send_sender_cancel, spawn_byte_watch, spawn_control_watch, wait_cancel_ack};
use dfile::{SendOverlayGuard, data_frame_size, send_batch, settings_profile};
use handshake::{CHANNEL_BYTES, PEER_META_ACK_FRAME, PEER_META_FRAME, byte_handshake, file_channel_request, is_private_ipv4, logical_addr, send_meta};
use preview::{build_preview_payload, net_info_offer, net_info_reply, send_preview};
use session::send_once;


pub use cancel::request_cancel_send;
pub use dfile::chunk_size;
