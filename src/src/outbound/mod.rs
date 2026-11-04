use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use rand::RngCore;

use crate::{Error, Result};

pub const DEVICE_TYPE_ID: u32 = 12;

pub(crate) fn debug_io() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("HWSHARE_DEBUG").is_some())
}

macro_rules! dbg_frame {
    ($($arg:tt)*) => {
        if crate::outbound::debug_io() {
            eprintln!($($arg)*);
        }
    };
}

pub(super) static SEND_CANCEL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(super) static CANCEL_ACKED: AtomicBool = AtomicBool::new(false);

pub(super) static PEER_PCT_BITS: AtomicU64 = AtomicU64::new(u64::MAX);

pub(super) static PREVIEW_OK: AtomicBool = AtomicBool::new(false);

pub struct Outgoing {
    pub id: u16,
    pub name: String,
    pub size: u64,
    pub path: PathBuf,
}

impl Clone for Outgoing {
    fn clone(&self) -> Self {
        Self { id: self.id, name: self.name.clone(), size: self.size, path: self.path.clone() }
    }
}

pub struct Report {
    pub files: Vec<String>,
    pub bytes: u64,
}

pub fn collect(paths: &[PathBuf]) -> Result<(Vec<Outgoing>, usize)> {
    if paths.is_empty() {
        return Err(Error::Argument);
    }
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for path in paths {
        let meta = std::fs::metadata(path)
            .map_err(|e| Error::Io(format!("读取 {} 失败: {e}", path.display())))?;
        if !meta.is_file() {
            skipped += 1;
            continue;
        }
        if meta.len() == 0 {
            return Err(Error::Protocol(format!(
                "空文件暂不支持: {}",
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
            name,
            size: meta.len(),
            path: path.clone(),
        });
    }
    if out.is_empty() {
        return Err(Error::Protocol(
            "选中的都是文件夹，请选中里面的文件再发".to_string(),
        ));
    }
    Ok((out, skipped))
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
    clear_send_cancel();
    let planned = crate::transmit::collect(paths).unwrap_or_default().0;
    let planned_bytes: u64 = planned.iter().map(|(_, size)| *size).sum();
    let local = local_ipv4(peer_ip).map(|ip| ip.to_string()).unwrap_or_default();
    crate::trace::session_start("send", peer_ip, &local, planned.len(), planned_bytes);
    let progress = Arc::new(AtomicU64::new(0));
    let outcome = send_once(peer_ip, peer_port, paths, display_name, log, &progress);
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
    #[allow(unused_imports)]
    use crate::channel::Channel;
    #[allow(unused_imports)]
    use crate::transfer;
    #[allow(unused_imports)]
    use std::path::Path;
    #[allow(unused_imports)]
    use std::time::Duration;

    #[test]
    fn data_frame_size_accounts_for_header() {
        assert_eq!(data_frame_size(1422), 1472);
        assert_eq!(data_frame_size(32768), 32818);
        assert_eq!(data_frame_size(crate::transfer::DFILE_MAX_CONTENT), 65535);
    }

    fn tmp_image(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(name);
        let img = image::RgbImage::from_fn(1200, 800, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 128])
        });
        img.save(&path).unwrap();
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
    fn preview_meta_json_has_utd_and_thumbnail() {
        let path = tmp_image("hwshare-preview-meta-test.jpg");
        let files = vec![Outgoing {
            id: 1,
            name: "photo.jpg".into(),
            size: 1000,
            path: path.clone(),
        }];
        let meta = super::preview::preview_meta(&files);
        assert!(meta.starts_with('['), "应是 JSON 数组: {meta}");
        assert!(meta.contains(r#""utd":"general.jpeg""#), "缺 utd: {meta}");
        assert!(
            meta.contains(r#""thumbnail":"data:image/jpeg;base64,/9j/"#),
            "缩略图不是 JPEG data URL"
        );
        assert!(meta.contains(r#""category":5"#));
        assert!(meta.len() < 200_000, "缩略图过大: {} 字节", meta.len());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn utd_maps_common_extensions() {
        assert_eq!(utd_for("a.JPG"), "general.jpeg");
        assert_eq!(utd_for("a.png"), "general.png");
        assert_eq!(utd_for("a.mp4"), "general.mp4");
        assert_eq!(utd_for("noext"), "general.bin");
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
        let t0 = Instant::now();
        let r = send_preview(
            &mut chan,
            &[9u8; 32],
            &[8u8; 32],
            b"0123456789ABCDEF",
            &[file],
            &|_| {},
            &cancel,
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
    #[allow(unused_imports)]
    use crate::channel::Channel;
    #[allow(unused_imports)]
    use crate::transfer;
    #[allow(unused_imports)]
    use std::path::Path;
    #[allow(unused_imports)]
    use std::time::Duration;

    #[test]
    fn dump_our_preview_frame() {
        let src = Path::new("E:/workbuddy/2026-10-27-14-27-19/_recv/IMG_20261027_164145.jpg");
        if !src.is_file() {
            return;
        }
        let files = vec![Outgoing {
            id: 1,
            name: "IMG_20261027_164145.jpg".into(),
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

#[allow(unused_imports)]
use cancel::*;
#[allow(unused_imports)]
use dfile::*;
#[allow(unused_imports)]
use handshake::*;
#[allow(unused_imports)]
use preview::*;
#[allow(unused_imports)]
use session::*;

pub use cancel::request_cancel_send;
pub use dfile::chunk_size;
