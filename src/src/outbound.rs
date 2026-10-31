use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use rand::RngCore;

use crate::channel::Channel;
use crate::crypto;
use crate::send::{build_offer, load_or_create_identity};
use crate::transfer;
use crate::{auth, Error, Result};

const CHANNEL_BYTES: u32 = 0xFFFF_0004;
const META_INFO: u32 = 0xFFFF_0002;
const META_ACK: u32 = 0xFFFF_0008;
const META_ACK_TEXT: &[u8] = b"META_DEVICE_INFO_ACK\0";

fn debug_io() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("HWSHARE_DEBUG").is_some())
}

macro_rules! dbg_frame {
    ($($arg:tt)*) => {
        if debug_io() {
            eprintln!($($arg)*);
        }
    };
}

static SEND_CANCEL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

static CANCEL_ACKED: AtomicBool = AtomicBool::new(false);

static PEER_PCT_BITS: AtomicU64 = AtomicU64::new(u64::MAX);

pub fn request_cancel_send() {
    SEND_CANCEL.store(true, Ordering::SeqCst);
}

pub fn send_cancel_requested() -> bool {
    SEND_CANCEL.load(Ordering::SeqCst)
}

fn clear_send_cancel() {
    SEND_CANCEL.store(false, Ordering::SeqCst);
    CANCEL_ACKED.store(false, Ordering::SeqCst);
    PEER_PCT_BITS.store(u64::MAX, Ordering::SeqCst);
}

fn spawn_send_cancel_watch() {
    let Ok(raw) = std::env::var("HWSHARE_CANCEL_TRIGGER") else { return };
    if raw.trim().is_empty() {
        return;
    }
    let path = std::path::PathBuf::from(raw);
    std::thread::spawn(move || loop {
        if path.exists() {
            let _ = std::fs::remove_file(&path);
            crate::trace::note("control", "检测到取消触发文件，请求取消发送");
            request_cancel_send();
            return;
        }
        std::thread::sleep(Duration::from_millis(150));
    });
}

fn cancelled(cancel: &AtomicBool) -> bool {
    if cancel.load(Ordering::Relaxed) {
        return true;
    }
    if !send_cancel_requested() {
        return false;
    }
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline && !cancel.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(2));
    }
    true
}

fn cancel_mode() -> &'static str {
    static MODE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    MODE.get_or_init(|| std::env::var("HWSHARE_CANCEL_MODE").unwrap_or_default())
        .as_str()
}

fn cancel_wait() -> Duration {
    if let Some(ms) = std::env::var("HWSHARE_CANCEL_WAIT_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        return Duration::from_millis(ms.min(10_000));
    }
    match cancel_mode() {
        "a" => Duration::from_millis(500),
        "c" => Duration::from_millis(3_000),
        _ => Duration::from_millis(800),
    }
}

fn absorb_peer_frame(plain: &[u8], session_key: &[u8; 32]) {
    let Ok(frame) = crate::frame_encode_lenient(9, 0, 0, plain) else {
        return;
    };
    let Ok(body) = transfer::decrypt_frame(&frame, session_key) else {
        return;
    };
    let Ok(fields) = transfer::tlvs(&body) else {
        return;
    };
    for (tag, value) in fields {
        if tag != 1 {
            continue;
        }
        let Ok(inner) = transfer::tlvs(&value) else {
            continue;
        };
        for (ftag, data) in inner {
            match ftag {
                3 => {
                    if data == b"senderCancelACK" {
                        CANCEL_ACKED.store(true, Ordering::SeqCst);
                        crate::trace::note("byte", "收到对端 senderCancelACK（取消已确认）");
                    }
                }
                9 => {
                    let text = String::from_utf8_lossy(&data).to_string();
                    if let Some(rest) = text.strip_prefix("dfileRecvPercent#") {
                        if let Ok(pct) = rest.trim().parse::<f64>() {
                            PEER_PCT_BITS.store(pct.to_bits(), Ordering::SeqCst);
                        }
                    }
                    crate::trace::note("byte", &format!("对端已收：{text}"));
                }
                10 => crate::trace::note(
                    "byte",
                    &format!("对端报错：{}", String::from_utf8_lossy(&data)),
                ),
                _ => {}
            }
        }
    }
}

fn spawn_byte_watch(
    mut chan: Channel,
    bkey: [u8; 32],
    session_key: [u8; 32],
    stop: Arc<AtomicBool>,
) {
    std::thread::spawn(move || loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match transfer::try_read_bytes_frame(&mut chan, &bkey, Duration::from_millis(200)) {
            Ok(Some((_seq, plain))) => absorb_peer_frame(&plain, &session_key),
            Ok(None) => {}
            Err(_) => break,
        }
    });
}

fn wait_cancel_ack() {
    let deadline = Instant::now() + cancel_wait();
    while Instant::now() < deadline {
        if CANCEL_ACKED.load(Ordering::SeqCst) {
            crate::trace::note("byte", "已收到 senderCancelACK，立刻收尾（不用等满超时）");
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    crate::trace::note("byte", "等 senderCancelACK 超时，按原节奏收尾");
}

fn send_dfile_abort(chan: &mut Channel) -> bool {
    match transfer::dfile_packet(9, 0, 0, 0, b"") {
        Ok(pkt) => match chan.send(&pkt) {
            Ok(()) => {
                crate::trace::note("file#1", "已发送 DFile kind=9（数据面中止）");
                true
            }
            Err(e) => {
                crate::trace::note("file#1", &format!("DFile kind=9 发送失败：{e}"));
                false
            }
        },
        Err(e) => {
            crate::trace::note("file#1", &format!("DFile kind=9 构造失败：{e}"));
            false
        }
    }
}

fn cancel_error() -> Error {
    if send_cancel_requested() {
        Error::Protocol("已取消发送（本机操作）".into())
    } else {
        Error::Protocol("对方取消了本次分享".into())
    }
}

fn send_sender_cancel(
    channel: &mut Channel,
    device_hash: &[u8],
    key: &[u8; 32],
    sequence: &mut u64,
) -> bool {
    let tag = std::env::var("HWSHARE_CANCEL_TAG")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|t| *t <= 255)
        .unwrap_or(2);
    let payload =
        crate::tlv_encode(tag, b"senderCancel").and_then(|inner| crate::tlv_encode(1, &inner));
    let pkt = payload
        .and_then(|p| transfer::encrypted_frame(device_hash, key, &p, *sequence));
    match pkt {
        Ok(pkt) => match channel.send(&pkt) {
            Ok(()) => {
                *sequence = sequence.wrapping_add(1);
                crate::trace::note("control", "已向对端发送 senderCancel（内层 tag2）");
                true
            }
            Err(e) => {
                crate::trace::note("control", &format!("senderCancel 发送失败：{e}"));
                false
            }
        },
        Err(e) => {
            crate::trace::note("control", &format!("senderCancel 构造失败：{e}"));
            false
        }
    }
}
const BYTES_FLAG_REQUEST: u32 = 0x94;

const DFRAME_DEFAULT: usize = 1472;

const DFRAME_OVERHEAD: usize = 50;

const BATCH_BYTES: usize = 256 * 1024;

fn chunk_size() -> usize {
    let from_env = std::env::var("HWSHARE_CHUNK")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok());
    let chosen = from_env.or_else(crate::config::chunk);
    match chosen {
        Some(n) => n.clamp(512, crate::transfer::DFILE_MAX_CONTENT),

        None => DFRAME_DEFAULT - DFRAME_OVERHEAD,
    }
}

fn data_frame_size(chunk: usize) -> u16 {
    (chunk + DFRAME_OVERHEAD).min(u16::MAX as usize) as u16
}

fn mtu_size() -> u16 {
    std::env::var("HWSHARE_MTU")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|n| n.clamp(512, u16::MAX as u32) as u16)
        .unwrap_or(1472)
}

fn number_env(key: &str) -> Option<u32> {
    let raw = std::env::var(key).ok()?;
    let t = raw.trim();
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(rest) => u32::from_str_radix(rest, 16).ok(),
        None => t.parse::<u32>().ok(),
    }
}

fn tail_env() -> Option<(u32, u32)> {
    let raw = std::env::var("HWSHARE_TAIL").ok()?;
    let (a, b) = raw.split_once(',')?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
}

fn settings_profile(mtu: u16, frame_size: u16) -> transfer::SettingsProfile {
    let handset = std::env::var("HWSHARE_HWPROFILE")
        .ok()
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false);
    let mut p = if handset {
        transfer::SettingsProfile::handset(true)
    } else {
        transfer::SettingsProfile::verified(true, mtu, frame_size)
    };
    if let Some(n) = number_env("HWSHARE_CAP") {
        p.capability = n;
    }
    if let Some(n) = number_env("HWSHARE_ABM") {
        p.abm_capability = n;
    }
    if let Some(n) = number_env("HWSHARE_CAPS") {
        p.caps_check = n;
    }
    if let Some(n) = number_env("HWSHARE_DFS") {
        p.data_frame_size = n;
    }
    if let Some(t) = tail_env() {
        p.tail = t;
    }
    p
}

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

fn collect(paths: &[PathBuf]) -> Result<(Vec<Outgoing>, usize)> {
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
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .ok_or(Error::Argument)?;
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

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn private_ipv4(ip: &str) -> bool {
    match ip.parse::<std::net::Ipv4Addr>() {
        Ok(addr) => {
            let o = addr.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
        }
        Err(_) => false,
    }
}

fn byte_handshake(session_key: &[u8], identity: &str, byte_key: &[u8]) -> Result<Vec<u8>> {
    let payload = format!(
        r#"{{"CODE":1,"API_VERSION":2,"BUS_NAME":"IShareReceiverBytesSession","CLIENT_BUS_NAME":"IShareSenderBytesSession","PKG_NAME":"ohos.InterConnection.iShare","MTU_SIZE":4194304,"TRANS_CAPABILITY":0,"ROUTE_TYPE":2,"DEVICE_ID":"{identity}","BUSINESS_TYPE":1,"TRANS_FLAGS":2,"SESSION_KEY":"{key}"}}"#,
        key = b64(byte_key)
    );
    let mut body = payload.into_bytes();
    body.push(0);
    let frame = transfer::channel_frame(
        session_key,
        (crate::MAGIC, 6, rand_seq(), BYTES_FLAG_REQUEST, 0),
        &body,
        0,
    )?;
    Ok(frame[crate::FRAME_HEADER_SIZE..].to_vec())
}

fn file_handshake(local: &str, identity: &str, file_key: &[u8]) -> Result<Vec<u8>> {
    let payload = format!(
        r#"{{"MY_CHANNEL_ID":1,"MY_IP":"{local}","DEVICE_ID":"{identity}","CODE":1538,"API_VERSION":2,"BUSINESS_TYPE":3,"STREAM_TYPE":255,"CHANNEL_TYPE":1,"UDP_CONN_TYPE":1,"BUS_NAME":"IShareReceiverFileSession","CLIENT_BUS_NAME":"IShareSenderFileSession","PKG_NAME":"ohos.InterConnection.iShare","TRANS_CAPABILITY":0,"SESSION_KEY":"{key}"}}"#,
        key = b64(file_key)
    );
    let mut body = payload.into_bytes();
    body.push(0);
    Ok(body)
}

fn utd_for(name: &str) -> &'static str {
    match name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("jpg") | Some("jpeg") => "general.jpeg",
        Some("png") => "general.png",
        Some("gif") => "general.gif",
        Some("bmp") => "general.bmp",
        Some("webp") => "general.webp",
        Some("heic") | Some("heif") => "general.heic",
        Some("mp4") => "general.mp4",
        Some("pdf") => "general.pdf",
        Some("txt") | Some("log") | Some("md") => "general.plain-text",
        Some("zip") => "general.zip",
        Some("apk") => "general.android.package-archive",
        _ => "general.bin",
    }
}

const PREVIEW_THUMB_BUDGET: usize = 2 * 1024 * 1024;

const THUMB_SOURCE_MAX: u64 = 32 * 1024 * 1024;

fn thumbnail_data_url(path: &Path, budget: &mut usize) -> String {
    if *budget == 0 {
        return String::new();
    }

    if std::env::var("HWSHARE_THUMB_MARK").is_ok() {
        let mark = image::RgbImage::from_pixel(600, 400, image::Rgb([255, 0, 255]));
        let mut buf = Vec::new();
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, 70);
        if encoder
            .encode(
                mark.as_raw(),
                mark.width(),
                mark.height(),
                image::ExtendedColorType::Rgb8,
            )
            .is_ok()
        {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&buf);
            return format!("data:image/jpeg;base64,{b64}");
        }
    }

    match std::fs::metadata(path) {
        Ok(meta) if meta.len() <= THUMB_SOURCE_MAX => {}
        _ => return String::new(),
    }

    let Ok(reader) = image::ImageReader::open(path) else {
        return String::new();
    };
    let Ok(reader) = reader.with_guessed_format() else {
        return String::new();
    };
    let Ok(img) = reader.decode() else {
        return String::new();
    };

    let thumb = img.thumbnail(600, 600).to_rgb8();
    let mut buf = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, 70);
    if encoder
        .encode(
            thumb.as_raw(),
            thumb.width(),
            thumb.height(),
            image::ExtendedColorType::Rgb8,
        )
        .is_err()
    {
        return String::new();
    }
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&buf);
    *budget = budget.saturating_sub(b64.len());
    format!("data:image/jpeg;base64,{b64}")
}

fn preview_meta(files: &[Outgoing]) -> String {
    let mut budget = PREVIEW_THUMB_BUDGET;
    let items: Vec<String> = files
        .iter()
        .map(|f| {
            let utd = utd_for(&f.name);
            let thumb = thumbnail_data_url(&f.path, &mut budget);
            format!(
                r#"{{"utd":"{utd}","thumbnail":"{thumb}","thumbnailType":1,"properties":{{"duration":"0"}},"category":5}}"#
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

fn file_ms(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        })
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn format_detail_time(ms: u64) -> String {
    const OFFSET: i64 = 8 * 3600;
    let secs = (ms / 1000) as i64 + OFFSET;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}:{m:02}:{d:02} {:02}:{:02}:{:02}",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn net_info_reply(local: &str) -> Result<Vec<u8>> {
    let mut fields = Vec::new();
    fields.extend(crate::tlv_encode(1, b"")?);
    fields.extend(crate::tlv_encode(2, b"")?);
    fields.extend(crate::tlv_encode(3, b"true")?);
    fields.extend(crate::tlv_encode(4, local.as_bytes())?);
    crate::tlv_encode(5, &fields)
}

fn net_info_offer(local: &str) -> Result<Vec<u8>> {
    let mut fields = Vec::new();
    fields.extend(crate::tlv_encode(1, b"")?);
    fields.extend(crate::tlv_encode(2, b"")?);
    fields.extend(crate::tlv_encode(3, b"")?);
    fields.extend(crate::tlv_encode(4, local.as_bytes())?);
    crate::tlv_encode(4, &fields)
}

fn logical_addr(local: &str) -> Result<Vec<u8>> {
    crate::tlv_encode(10, &crate::tlv_encode(1, local.as_bytes())?)
}

fn file_preview(files: &[Outgoing]) -> Result<Vec<u8>> {
    let names: Vec<String> = files.iter().map(|f| f.name.clone()).collect();
    let joined = names.join("|");

    let stamps: Vec<String> = files.iter().map(|f| file_ms(&f.path).to_string()).collect();
    let details: Vec<String> = files
        .iter()
        .map(|f| format!("\"{}\"", format_detail_time(file_ms(&f.path))))
        .collect();
    let metadata = format!(
        r#"{{"date_added":[{}],"date_taken":[{}],"detail_time":[{}]}}"#,
        stamps.join(","),
        stamps.join(","),
        details.join(",")
    );
    let mut inner = crate::tlv_encode(11, joined.as_bytes())?;
    inner.extend(crate::tlv_encode(12, preview_meta(files).as_bytes())?);
    inner.extend(crate::tlv_encode(13, metadata.as_bytes())?);
    crate::tlv_encode(8, &inner)
}

pub fn send(
    peer_ip: &str,
    peer_port: u16,
    paths: &[PathBuf],
    display_name: &str,
    log: &dyn Fn(&str),
) -> Result<Report> {
    let started = Instant::now();

    clear_send_cancel();

    spawn_send_cancel_watch();

    let planned = crate::send::collect(paths).unwrap_or_default().0;
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

fn send_once(
    peer_ip: &str,
    peer_port: u16,
    paths: &[PathBuf],
    display_name: &str,
    log: &dyn Fn(&str),
    progress: &Arc<AtomicU64>,
) -> Result<Report> {
    let (files, skipped) = collect(paths)?;
    if skipped > 0 {
        log(&format!("已跳过 {skipped} 个文件夹（只发文件）"));
    }
    let total: u64 = files.iter().map(|f| f.size).sum();
    let names: Vec<String> = files.iter().map(|f| f.name.clone()).collect();

    let private = load_or_create_identity(None)?;
    let public_der = crypto::public_der(&private).map_err(Error::Crypto)?;
    let digest = crate::key_hash(&public_der)?;
    let device_hash: Vec<u8> = crate::hex_upper(&digest[..8]).into_bytes();
    let identity = crate::identity_v2(&public_der)?;
    let node_id = crate::meta_node_id(&public_der)?;
    let local = local_ipv4(peer_ip)?;

    let mut channel = Channel::connect(peer_ip, peer_port, Duration::from_secs(8))?;
    channel.set_label("control");
    channel.send(&auth::opening(&identity)?)?;
    if crate::trace::enabled() {
        crate::trace::note("control", "opening 已发，等 opening ACK");
    }
    let opening_ack = channel.read_frame(Duration::from_secs(10))?;
    let module = u32::from_le_bytes(opening_ack[4..8].try_into().unwrap());
    let flags = u32::from_le_bytes(opening_ack[16..20].try_into().unwrap());
    if module != 8 || flags != 1 {
        return Err(Error::Protocol("对方拒绝建立认证通道（可能正忙）".into()));
    }

    let machine = std::env::var("HWSHARE_MACHINE").unwrap_or_else(|_| "AMD64".to_string());
    channel.send(&auth::capabilities(&device_hash, "10.0", &machine)?)?;
    let capability_response = channel.read_frame(Duration::from_secs(8))?;
    let (cap_mode, cap_body) = auth::unpack_envelope(&capability_response)?;
    if cap_mode != 0 || !transfer::tlvs(&cap_body)?.iter().any(|(t, _)| *t == 3) {
        return Err(Error::Protocol("对方未回应能力协商".into()));
    }

    channel.send(&auth::send_public_key(&device_hash, &public_der)?)?;
    let peer_public_response = channel.read_frame(Duration::from_secs(15))?;
    let handshake = auth::challenge(
        &mut channel,
        &device_hash,
        &peer_public_response,
        &capability_response,
        &private,
        Duration::from_secs(10),
    )?;
    let key = handshake.session_key;

    let offer = build_offer(&names, total, display_name)?;
    channel.send(&transfer::encrypted_frame(&device_hash, &key, &offer, 5)?)?;
    if crate::trace::enabled() {
        crate::trace::note(
            "control",
            &format!("offer 已发：{} 个文件，共 {} 字节", names.len(), total),
        );
    }
    log(&format!(
        "已发出分享请求：{} 个文件，{:.1} MB",
        files.len(),
        total as f64 / 1048576.0
    ));

    let _wait_guard = SendOverlayGuard { done: false };

    ov::set_multi(files.len());

    ov::set_outgoing(true);
    ov::waiting(files.first().map(|f| f.name.as_str()).unwrap_or("正在发送"));

    let mut sequence = 6u64;
    let mut exchange_sent = false;
    let mut code3_sent = false;
    let mut file_request_sent = false;
    let mut byte_channel: Option<Channel> = None;
    let mut byte_key: Option<[u8; 32]> = None;
    let mut file_key: Option<[u8; 32]> = None;

    let deadline = Instant::now() + Duration::from_secs(120);

    while Instant::now() < deadline {
        let frame = match channel.try_read_frame(Duration::from_millis(200)) {
            Ok(Some(f)) => f,
            Ok(None) => {
                if send_cancel_requested() {
                    send_sender_cancel(&mut channel, &device_hash, &key, &mut sequence);

                    std::thread::sleep(cancel_wait());
                    crate::trace::note("control", "尚未开始传输时取消：已发 senderCancel，关闭控制通道");
                    return Err(Error::Protocol("已取消发送（对方尚未接收）".into()));
                }
                continue;
            }
            Err(_) => continue,
        };
        let module = u32::from_le_bytes(frame[4..8].try_into().unwrap());

        if module == 9 {
            let body = match transfer::decrypt_frame(&frame, &key) {
                Ok(b) => b,
                Err(_) => continue,
            };
            for (tag, value) in transfer::tlvs(&body)? {
                match tag {
                    1 => {
                        for (_, cmd) in transfer::tlvs(&value)? {
                            match cmd.as_slice() {
                                b"user_reject" | b"receiverCancel" => {
                                    return Err(Error::Protocol("对方拒绝了本次分享".into()))
                                }
                                b"user_confirm" => {
                                    log("对方已接受，正在建立数据通道");

                                    if !exchange_sent {
                                        channel.send(&transfer::encrypted_frame(
                                            &device_hash,
                                            &key,
                                            &net_info_offer(&local)?,
                                            sequence,
                                        )?)?;
                                        sequence += 1;
                                        channel.send(&transfer::encrypted_frame(
                                            &device_hash,
                                            &key,
                                            &logical_addr(&local)?,
                                            sequence,
                                        )?)?;
                                        sequence += 1;
                                        exchange_sent = true;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    4 => {
                        channel.send(&transfer::encrypted_frame(
                            &device_hash,
                            &key,
                            &net_info_reply(&local)?,
                            sequence,
                        )?)?;
                        sequence += 1;
                    }

                    10 => {
                        channel.send(&transfer::encrypted_frame(
                            &device_hash,
                            &key,
                            &logical_addr(&local)?,
                            sequence,
                        )?)?;
                        sequence += 1;
                    }
                    _ => {}
                }
            }
            continue;
        }

        let (header, plain) = match transfer::decode_channel(&frame, &key) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if header.0 == META_INFO {
            let device_type: u32 = std::env::var("HWSHARE_DEVICE_TYPE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(12);
            let info = format!(
                r#"{{"DEVICE_NAME":"{display_name}","DEVICE_TYPE_ID":{device_type},"META_NODE_ID":"{node_id}","FLAG":100}}"#
            );
            channel.send(&transfer::channel_frame(&key, header, info.as_bytes(), sequence)?)?;
            sequence += 1;
            channel.send(&transfer::channel_frame(
                &key,
                (META_ACK, 5, header.2, 0, 0),
                META_ACK_TEXT,
                sequence,
            )?)?;
            sequence += 1;
            continue;
        }

        if header.0 == META_ACK && !code3_sent {
            let (local_port, p2p_listener) = reserve_port(&local)?;

            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(180);
                while Instant::now() < deadline {
                    match p2p_listener.accept() {
                        Ok((sock, peer)) => {
                            if debug_io() {
                                eprintln!("[p2p] 收到回连 {peer}，已关闭");
                            }
                            drop(sock);
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(20)),
                    }
                }
            });
            let payload = format!(
                r#"{{"CODE":3,"P2P_IP":"{local}","P2P_PORT":{local_port},"PROTOCOL_TYPE":4}}"#
            );
            let mut body = payload.into_bytes();
            body.push(0);
            channel.send(&transfer::channel_frame(
                &key,
                (CHANNEL_BYTES, 16, rand_seq(), 0, 0),
                &body,
                sequence,
            )?)?;
            sequence += 1;
            code3_sent = true;
            continue;
        }

        let value: serde_json::Value = match serde_json::from_slice(
            plain.strip_suffix(&[0]).unwrap_or(&plain),
        ) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if header.0 == CHANNEL_BYTES && header.1 == 16 && header.3 == 1 {
            let ip = value["P2P_IP"].as_str().unwrap_or("").to_string();
            let port = value["P2P_PORT"].as_u64().unwrap_or(0) as u16;
            if !private_ipv4(&ip) || port == 0 {
                return Err(Error::Format);
            }
            let mut chan = Channel::connect(&ip, port, Duration::from_secs(8))?;
            chan.set_label("byte");
            let mut bkey = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bkey);

            #[cfg(feature = "diag")]
            {
                if std::env::var("HWSHARE_DEBUG_KEYS").is_ok() {
                    crate::trace::note(
                        "byte",
                        &format!(
                            "DEBUG byte_key={} session_key={}",
                            crate::hex_upper(&bkey),
                            crate::hex_upper(&key)
                        ),
                    );
                }
            }
            chan.send(&byte_handshake(&key, &identity, &bkey)?)?;

            let raw = chan.read_frame(Duration::from_secs(8))?;
            let wrapped = crate::frame_encode(21, 0, 0, &raw)?;
            let (ack_header, ack_plain) = transfer::decode_channel(&wrapped, &key)?;
            let ack: serde_json::Value = serde_json::from_slice(
                ack_plain.strip_suffix(&[0]).unwrap_or(&ack_plain),
            )
            .map_err(|_| Error::Format)?;

            if ack_header.1 != 6 || ack_header.3 != 0x95 || ack["CODE"] != 1 {
                return Err(Error::Protocol("byte 通道握手被拒绝".into()));
            }
            if ack.get("ERR_CODE").is_some() {
                return Err(Error::Protocol(format!("byte 通道返回错误: {ack}")));
            }
            byte_channel = Some(chan);
            byte_key = Some(bkey);
            log("预览通道已建立");

            let mut fkey = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut fkey);
            let payload = file_handshake(&local, &identity, &fkey)?;
            channel.send(&transfer::channel_frame(
                &key,
                (CHANNEL_BYTES, 17, rand_seq(), 0, 0),
                &payload,
                sequence,
            )?)?;
            sequence += 1;
            file_key = Some(fkey);
            file_request_sent = true;
            continue;
        }

        if header.0 == CHANNEL_BYTES && header.1 == 17 && header.3 == 1 && file_request_sent {
            let ip = value["MY_IP"].as_str().unwrap_or("").to_string();
            let port = value["P2P_PORT"].as_u64().unwrap_or(0) as u16;
            if !private_ipv4(&ip) || port == 0 {
                return Err(Error::Format);
            }
            let fkey = file_key.ok_or(Error::Format)?;

            let mut chan = Channel::connect(&ip, port, Duration::from_secs(8))?;
            chan.set_label("file#1");

            let chunk = chunk_size();
            let frame_size = data_frame_size(chunk);

            log(&format!("分块: {chunk} B（帧长 {frame_size}）"));
            let mtu = mtu_size();
            if mtu != 1472 {
                log(&format!("MTU: {mtu}"));
            }
            let profile = settings_profile(mtu, frame_size);
            if profile.capability != 0 || profile.caps_check != 0x100 || profile.tail != (0, 1) {
                log(&format!(
                    "settings 档位: cap=0x{:X} abm=0x{:X} caps=0x{:X} dfs={} tail=({},{})",
                    profile.capability,
                    profile.abm_capability,
                    profile.caps_check,
                    profile.data_frame_size,
                    profile.tail.0,
                    profile.tail.1
                ));
            }
            chan.send(&profile.encode())?;
            let reply = chan
                .try_read_dfile(Duration::from_secs(10))?
                .ok_or_else(|| Error::Protocol("对端未回应 DFile settings".into()))?;
            let (kind, _flags, _sess, _trans, size) = transfer::parse_dfile_header(&reply)?;
            if kind != 8 {
                return Err(Error::Protocol(format!("DFile settings 应答异常 kind={kind}")));
            }
            let payload = &reply[8..8 + size];
            if payload.len() < 100
                || u16::from_be_bytes([payload[2], payload[3]]) != 2
                || (u32::from_be_bytes([payload[96], payload[97], payload[98], payload[99]]) & 1) == 0
            {
                return Err(Error::Protocol("对端 DFile 能力不支持加密传输".into()));
            }

            {
                let mtu = u16::from_be_bytes([payload[0], payload[1]]);
                let ctype = u16::from_be_bytes([payload[2], payload[3]]);
                let version = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                let abm = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
                let cap = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
                let dfs = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
                let caps = u32::from_be_bytes([payload[20], payload[21], payload[22], payload[23]]);
                let hdr = payload[91];
                let tail1 = u32::from_be_bytes([payload[92], payload[93], payload[94], payload[95]]);
                let tail2 = u32::from_be_bytes([payload[96], payload[97], payload[98], payload[99]]);
                let note = format!(
                    "settings reply mtu={mtu} ctype={ctype} ver={version} abm=0x{abm:X} cap=0x{cap:X} dfs={dfs} caps=0x{caps:X} hdr={hdr} tail=({tail1},{tail2})"
                );
                log(&format!("[手机 settings] {note}"));
                crate::wire::mark("file#1", &note);
            }
            log("文件通道已建立");

            let want = channels_env();
            let mut pool: Vec<(Channel, [u8; 32])> = vec![(chan, fkey)];
            while pool.len() < want {
                let mut extra_key = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut extra_key);
                let payload = file_handshake(&local, &identity, &extra_key)?;
                channel.send(&transfer::channel_frame(
                    &key,
                    (CHANNEL_BYTES, 17, rand_seq(), 0, 0),
                    &payload,
                    sequence,
                )?)?;
                sequence += 1;

                let mut port_reply = None;
                let deadline = Instant::now() + Duration::from_secs(6);
                while Instant::now() < deadline {
                    let Ok(Some(frame)) = channel.try_read_frame(Duration::from_millis(200)) else {
                        continue;
                    };
                    let Ok((head, plain)) = transfer::decode_channel(&frame, &key) else {
                        continue;
                    };
                    if head.0 == CHANNEL_BYTES && head.1 == 17 && head.3 == 1 {
                        port_reply = Some(plain);
                        break;
                    }
                }
                let Some(plain) = port_reply else {
                    log("多通道：手机未再给端口，按当前通道数继续");
                    break;
                };
                let text = plain.strip_suffix(&[0]).unwrap_or(&plain);
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(text) else {
                    break;
                };
                let ip = value["MY_IP"].as_str().unwrap_or("").to_string();
                let port = value["P2P_PORT"].as_u64().unwrap_or(0) as u16;
                if !private_ipv4(&ip) || port == 0 {
                    break;
                }

                let mut extra = Channel::connect(&ip, port, Duration::from_secs(8))?;
                extra.set_label(&format!("file#{}", pool.len() + 1));
                crate::wire::mark("control", &format!("extra file channel port={port}"));
                extra.send(&profile.encode())?;
                let ok = extra
                    .try_read_dfile(Duration::from_secs(10))?
                    .map(|reply| transfer::parse_dfile_header(&reply).map(|h| h.0 == 8).unwrap_or(false))
                    .unwrap_or(false);
                if !ok {
                    log("多通道：附加通道 settings 未确认，忽略");
                    break;
                }
                log(&format!("第 {} 条文件通道已建立（:{}）", pool.len() + 1, port));
                pool.push((extra, extra_key));
            }

            let mut bchan_slot = Some(byte_channel.take().ok_or(Error::Format)?);
            let mut bkey_slot = Some(byte_key.ok_or(Error::Format)?);

            let cancel = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let watcher = spawn_control_watch(
                channel,
                key,
                device_hash.clone(),
                local.clone(),
                sequence,
                cancel.clone(),
                stop.clone(),
            );

            let result = (|| -> Result<u64> {
                let mut bchan = bchan_slot.take().ok_or(Error::Format)?;
                let bkey = bkey_slot.take().ok_or(Error::Format)?;
                send_preview(&mut bchan, &bkey, &key, &device_hash, &files, log, &cancel)?;
                if cancelled(&cancel) {
                    crate::trace::note("control", "预览阶段收到取消，停止发送");
                    return Err(cancel_error());
                }

                spawn_byte_watch(bchan, bkey, key, stop.clone());

                let used = pool.len().min(files.len()).max(1);
                if used <= 1 {
                    let (mut first, first_key) = pool.remove(0);
                    send_batch(&mut first, &first_key, &files, log, &cancel, progress)
                } else {
                    log(&format!("并行发送：{} 条通道 / {} 个文件", used, files.len()));
                    parallel_send(pool, &files, used, &cancel, progress)
                }
            })();

            stop.store(true, Ordering::SeqCst);
            let _ = watcher.join();
            let written = result?;
            return Ok(Report {
                files: files.iter().map(|f| f.name.clone()).collect(),
                bytes: written,
            });
        }
    }

    Err(Error::Protocol(if !code3_sent {
        "等待手机准备通道超时（对方可能未点接受）"
    } else {
        "通道协商超时"
    }
    .into()))
}

fn send_preview(
    chan: &mut Channel,
    byte_key: &[u8],
    session_key: &[u8],
    device_hash: &[u8],
    files: &[Outgoing],
    log: &dyn Fn(&str),
    cancel: &AtomicBool,
) -> Result<()> {
    let body = file_preview(files)?;

    let inner = transfer::encrypted_envelope(device_hash, session_key, &body)?;
    chan.send(&transfer::bytes_frame(byte_key, &inner, 0)?)?;

    for _ in 0..4 {
        let mut got = None;
        let wait = Instant::now() + Duration::from_secs(15);
        while Instant::now() < wait {
            if cancelled(&cancel) {
                crate::trace::note("byte", "预览等待中收到取消，停止发送");
                return Err(cancel_error());
            }
            if let Some(v) = transfer::try_read_bytes_frame(chan, byte_key, Duration::from_millis(200))? {
                got = Some(v);
                break;
            }
        }
        let Some((_seq, plain)) = got else {
            return Err(Error::Protocol("等待预览确认超时".into()));
        };
        let frame = crate::frame_encode_lenient(9, 0, 0, &plain)?;
        let Ok(body) = transfer::decrypt_frame(&frame, session_key) else {
            continue;
        };
        for (tag, value) in transfer::tlvs(&body)? {
            if tag != 1 {
                continue;
            }
            for (field, data) in transfer::tlvs(&value)? {
                if field == 8 && data == b"previewOK" {
                    log("预览已确认，开始传输");
                    return Ok(());
                }
            }
        }
    }
    Err(Error::Protocol("预览未获确认".into()))
}

fn parse_ids(inner: &[u8]) -> Result<Vec<u16>> {
    let data = inner.get(8..).ok_or(Error::Truncated)?;
    if data.len() % 2 != 0 {
        return Err(Error::Format);
    }
    Ok(data
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

fn draw_progress(written: u64, total: u64, t0: Instant) {
    use std::io::Write;
    let pct = if total == 0 { 0.0 } else { written as f64 * 100.0 / total as f64 };
    let width = 24usize;
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let bar = format!("{}{}", "#".repeat(filled.min(width)), "-".repeat(width - filled.min(width)));
    let mb = written as f64 / 1048576.0;
    let speed = mb / t0.elapsed().as_secs_f64().max(0.001);

    let peer = PEER_PCT_BITS.load(Ordering::Relaxed);
    if peer == u64::MAX {
        print!(
            "\r[{}] {:5.1}%  {:>7.1}/{:.1} MB  {:>5.1} MB/s",
            bar, pct, mb, total as f64 / 1048576.0, speed
        );
    } else {
        print!(
            "\r[{}] {:5.1}%  {:>7.1}/{:.1} MB  {:>5.1} MB/s  对方 {:5.1}%",
            bar,
            pct,
            mb,
            total as f64 / 1048576.0,
            speed,
            f64::from_bits(peer)
        );
    }
    let _ = std::io::stdout().flush();
}

mod ov {
    #[cfg(windows)]
    pub use crate::overlay::{fail, finish, hide, set_multi, set_outgoing, start, update, waiting};
    #[cfg(not(windows))]
    pub fn set_outgoing(_ours: bool) {}
    #[cfg(not(windows))]
    pub fn start(_name: &str) {}
    #[cfg(not(windows))]
    pub fn waiting(_name: &str) {}
    #[cfg(not(windows))]
    pub fn set_multi(_count: usize) {}
    #[cfg(not(windows))]
    pub fn update(_sent: u64, _total: u64) {}
    #[cfg(not(windows))]
    pub fn finish() {}
    #[cfg(not(windows))]
    pub fn fail() {}
    #[cfg(not(windows))]
    pub fn hide() {}
}

struct SendOverlayGuard {
    done: bool,
}

impl Drop for SendOverlayGuard {
    fn drop(&mut self) {
        if self.done {
            return;
        }

        ov::fail();
        ov::hide();
    }
}

fn send_file_chunks(
    chan: &mut Channel,
    key: &[u8],
    file: &Outgoing,
    written: &mut u64,
    done: &mut Vec<u16>,
    t0: Instant,
    total: u64,
    log: &dyn Fn(&str),
    cancel: &AtomicBool,
    progress: &AtomicU64,
) -> Result<()> {
    let mut handle = std::fs::File::open(&file.path)
        .map_err(|e| Error::Io(format!("打开 {} 失败: {e}", file.path.display())))?;
    let chunk = chunk_size();
    let mut buf = vec![0u8; chunk];
    let mut sequence: u32 = 0;
    let mut offset: u64 = 0;

    let mut batch: Vec<u8> = Vec::with_capacity(BATCH_BYTES + chunk + 64);

    let mut sent = 0u64;
    let mut batch_content = 0u64;
    let mut last_report = Instant::now();
    let mut last_draw = Instant::now();
    let mut unknown: std::collections::BTreeMap<u8, u32> = std::collections::BTreeMap::new();
    let mut flow_pauses = 0u32;
    loop {
        if cancelled(&cancel) {
            crate::trace::note(
                "file#1",
                &format!("取消时已发 {} 字节（file={}）", sent, file.name),
            );
            match cancel_mode() {
                "b" => {
                    send_dfile_abort(chan);
                    std::thread::sleep(Duration::from_millis(250));
                }
                _ => wait_cancel_ack(),
            }
            return Err(cancel_error());
        }
        let mut filled = 0usize;
        while filled < buf.len() {
            match handle.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) => return Err(Error::Io(format!("读取失败: {e}"))),
            }
        }
        if filled == 0 {
            break;
        }
        offset += filled as u64;

        let flag = if offset >= file.size {
            3
        } else if sequence == 0 {
            0
        } else {
            1
        };
        let frame = transfer::dfile_data_chunk(key, &buf[..filled], sequence, flag, file.id)?;
        batch.extend_from_slice(&frame);
        batch_content += filled as u64;
        let mut flushed = false;
        if batch.len() >= BATCH_BYTES {
            if cancelled(&cancel) {
                crate::trace::note(
                    "file#1",
                    &format!("取消时已发 {} 字节（本批未写）", sent),
                );
                return Err(cancel_error());
            }
            chan.send(&batch)?;
            batch.clear();
            sent += batch_content;
            progress.fetch_add(batch_content, Ordering::Relaxed);
            batch_content = 0;
            flushed = true;
        }
        *written += filled as u64;
        ov::update(*written, total);
        sequence += 1;

        if last_report.elapsed() >= Duration::from_secs(5) {
            let mb = *written as f64 / 1048576.0;
            log(&format!(
                "[速率] {:.1}/{:.1} MB  {:.1} MB/s  chunk={chunk}",
                mb,
                total as f64 / 1048576.0,
                mb / t0.elapsed().as_secs_f64().max(0.001)
            ));
            last_report = Instant::now();
        }

        if last_draw.elapsed() >= Duration::from_millis(120) {
            last_draw = Instant::now();
            draw_progress(*written, total, t0);
        }

        if flushed || sequence % 64 == 0 {
            while let Some(rx) = chan.try_read_dfile(Duration::from_micros(300))? {
                let (k, fl, s, tr, sz) = match transfer::parse_dfile_header(&rx) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!(
                            "[帧头异常·chunk] len={} hex={:02X?}",
                            rx.len(),
                            &rx[..rx.len().min(48)]
                        );
                        return Err(e);
                    }
                };
                let pl = &rx[8..8 + sz];
                match k {
                    5 => {
                        if let Ok(inner) =
                            transfer::dfile_decrypt_control(key, (k, fl, s, tr), pl)
                        {
                            dbg_frame!(
                                "[k5 {:>6.2}s] sent={:>8.2}MB seq={} hex={:02X?}",
                                t0.elapsed().as_secs_f64(),
                                *written as f64 / 1048576.0,
                                sequence,
                                inner
                            );
                            draw_progress(*written, total, t0);
                        }
                    }
                    6 => {
                        if let Ok(inner) =
                            transfer::dfile_decrypt_control(key, (k, fl, s, tr), pl)
                        {
                            for id in parse_ids(&inner)? {
                                if !done.contains(&id) {
                                    done.push(id);
                                }
                            }
                        }
                    }
                    9 => return Err(Error::Protocol("接收端中止了本次传输".into())),
                    22 => {
                        flow_pauses += 1;
                        if flow_pauses <= 3 {
                            log(&format!(
                                "[kind=22] 未知信号（第 {} 次，已发 {:.1} MB），暂停 20 ms",
                                flow_pauses,
                                *written as f64 / 1048576.0
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    other => {
                        dbg_frame!(
                            "[未知帧·chunk] kind={other} trans={tr} size={sz} hex={:02X?}",
                            &pl[..pl.len().min(24)]
                        );
                        let hits = unknown.entry(other).or_insert(0);
                        *hits += 1;
                        if *hits >= 3 {
                            return Err(Error::Protocol(format!(
                                "对端使用了未实现的控制帧 kind={other}"
                            )));
                        }
                    }
                }
            }
        }
        if offset >= file.size {
            break;
        }
    }

    if !batch.is_empty() {
        chan.send(&batch)?;
        progress.fetch_add(batch_content, Ordering::Relaxed);
    }
    Ok(())
}

fn channels_env() -> usize {
    std::env::var("HWSHARE_CHANNELS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, 4)
}

fn parallel_send(
    mut pool: Vec<(Channel, [u8; 32])>,
    files: &[Outgoing],
    used: usize,
    cancel: &AtomicBool,
    progress: &AtomicU64,
) -> Result<u64> {
    let mut total = 0u64;
    let mut failure: Option<Error> = None;
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for (index, (chan, key)) in pool.drain(..used).enumerate() {
            let subset: Vec<Outgoing> = files.iter().skip(index).step_by(used).cloned().collect();
            handles.push(scope.spawn(move || -> Result<u64> {
                let mut chan = chan;
                let quiet = |_: &str| {};
                let r = send_batch(&mut chan, &key, &subset, &quiet, cancel, progress);

                if r.is_err() {
                    cancel.store(true, Ordering::SeqCst);
                }
                r
            }));
        }
        for handle in handles {
            match handle.join() {
                Ok(Ok(bytes)) => total += bytes,
                Ok(Err(e)) => {
                    if failure.is_none() {
                        failure = Some(e);
                    }
                }
                Err(_) => {
                    if failure.is_none() {
                        failure = Some(Error::Protocol("并行发送线程异常退出".into()));
                    }
                    cancel.store(true, Ordering::SeqCst);
                }
            }
        }
    });
    match failure {
        Some(e) => Err(e),
        None => Ok(total),
    }
}

fn spawn_control_watch(
    mut channel: Channel,
    key: [u8; 32],
    device_hash: Vec<u8>,
    local: String,
    start_sequence: u64,
    cancel: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut sequence = start_sequence;
        let mut cancel_sent = false;
        while !stop.load(Ordering::Relaxed) {
            if !cancel_sent && send_cancel_requested() {
                cancel_sent = true;

                if cancel_mode() == "b" {
                    std::thread::sleep(Duration::from_millis(150));
                }
                send_sender_cancel(&mut channel, &device_hash, &key, &mut sequence);
                cancel.store(true, Ordering::SeqCst);
            }
            let frame = match channel.try_read_frame(Duration::from_millis(100)) {
                Ok(Some(f)) => f,
                Ok(None) => continue,
                Err(e) => {
                    crate::trace::note("control", &format!("控制通道断开：{e}"));
                    break;
                }
            };
            let Some(head) = frame.get(4..8) else { continue };
            let module = u32::from_le_bytes(head.try_into().unwrap());
            if module != 9 {
                continue;
            }
            let Ok(body) = transfer::decrypt_frame(&frame, &key) else {
                continue;
            };
            let Ok(fields) = transfer::tlvs(&body) else {
                continue;
            };
            for (tag, value) in fields {
                match tag {
                    1 => {
                        let Ok(cmds) = transfer::tlvs(&value) else { continue };
                        for (cmd_tag, cmd) in cmds {
                            crate::trace::note(
                                "control",
                                &format!(
                                    "收到控制命令 内层tag={cmd_tag} 值=\"{}\"",
                                    String::from_utf8_lossy(&cmd)
                                ),
                            );
                            match cmd.as_slice() {
                                b"user_reject" | b"receiverCancel" | b"senderCancel" => {
                                    crate::trace::note(
                                        "control",
                                        &format!(
                                            "收到取消/拒绝命令：{}",
                                            String::from_utf8_lossy(&cmd)
                                        ),
                                    );
                                    cancel.store(true, Ordering::SeqCst);
                                }
                                _ => {}
                            }
                        }
                    }
                    4 => {
                        if let Ok(payload) = net_info_reply(&local) {
                            if let Ok(pkt) =
                                transfer::encrypted_frame(&device_hash, &key, &payload, sequence)
                            {
                                if let Err(e) = channel.send(&pkt) {
                                    crate::trace::note(
                                        "control",
                                        &format!("控制通道应答 tag4 失败，监听线程退出：{e}"),
                                    );
                                    return;
                                }
                                sequence = sequence.wrapping_add(1);
                            }
                        }
                    }
                    10 => {
                        if let Ok(payload) = logical_addr(&local) {
                            if let Ok(pkt) =
                                transfer::encrypted_frame(&device_hash, &key, &payload, sequence)
                            {
                                if let Err(e) = channel.send(&pkt) {
                                    crate::trace::note(
                                        "control",
                                        &format!("控制通道应答 tag10 失败，监听线程退出：{e}"),
                                    );
                                    return;
                                }
                                sequence = sequence.wrapping_add(1);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    })
}

fn send_batch(
    chan: &mut Channel,
    key: &[u8],
    files: &[Outgoing],
    log: &dyn Fn(&str),
    cancel: &AtomicBool,
    progress: &AtomicU64,
) -> Result<u64> {
    let entries: Vec<(u16, u64, Vec<u8>)> = files
        .iter()
        .map(|f| (f.id, f.size, f.name.as_bytes().to_vec()))
        .collect();
    for packet in transfer::build_headers(&entries)? {
        chan.send(&transfer::dfile_encrypt_control(key, &packet)?)?;
    }
    log(&format!("已发送文件清单：{} 个", files.len()));

    let mut oguard = SendOverlayGuard { done: false };
    ov::set_outgoing(true);
    ov::start(files.first().map(|f| f.name.as_str()).unwrap_or("正在发送"));

    let mut sent: Vec<u16> = Vec::new();
    let mut done: Vec<u16> = Vec::new();
    let mut written: u64 = 0;
    let mut last_activity = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(3600);
    let mut next_log = 64u64 * 1024 * 1024;
    let t0 = Instant::now();
    let files_total: u64 = files.iter().map(|f| f.size).sum();
    let mut rx_kinds: std::collections::BTreeMap<u8, u32> = std::collections::BTreeMap::new();

    while Instant::now() < deadline {
        if cancelled(&cancel) {
            crate::trace::note(
                "file#1",
                &format!("取消时已发 {} 字节（等待 ACK 阶段）", written),
            );
            return Err(cancel_error());
        }

        let mut handled = false;
        while let Some(frame) = chan.try_read_dfile(Duration::from_millis(1))? {
            handled = true;
            let (kind, flags, sess, trans, size) = match transfer::parse_dfile_header(&frame) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!(
                        "[帧头异常·batch] len={} hex={:02X?}",
                        frame.len(),
                        &frame[..frame.len().min(48)]
                    );
                    return Err(e);
                }
            };
            let payload = &frame[8..8 + size];
            *rx_kinds.entry(kind).or_insert(0) += 1;
            dbg_frame!(
                "[rx {:>6.1}s] kind={} flags={} trans={} size={}",
                t0.elapsed().as_secs_f64(), kind, flags, trans, size
            );
            match kind {
                11 => {}
                2 | 3 => {
                    let inner =
                        transfer::dfile_decrypt_control(key, (kind, flags, sess, trans), payload)?;
                    for id in parse_ids(&inner)? {
                        if sent.contains(&id) {
                            continue;
                        }
                        let Some(file) = files.iter().find(|f| f.id == id) else {
                            continue;
                        };
                        crate::wire::mark(chan.label(), &format!("file req id={id} kind={kind}"));
                        send_file_chunks(
                            chan,
                            key,
                            file,
                            &mut written,
                            &mut done,
                            t0,
                            files_total,
                            log,
                            cancel,
                            progress,
                        )?;
                        sent.push(id);
                        if written >= next_log {
                            log(&format!(
                                "已发送 {:.1} MB / {:.1} MB",
                                written as f64 / 1048576.0,
                                files.iter().map(|f| f.size).sum::<u64>() as f64 / 1048576.0
                            ));
                            next_log += 64 * 1024 * 1024;
                        }
                        last_activity = Instant::now();
                    }
                }
                6 => {
                    let inner =
                        transfer::dfile_decrypt_control(key, (kind, flags, sess, trans), payload)?;
                    for id in parse_ids(&inner)? {
                        if !done.contains(&id) {
                            done.push(id);
                        }
                    }
                    if done.len() >= files.len() {
                        dbg_frame!("[rx 汇总] {:?}", rx_kinds);
                        let ack = transfer::dfile_packet(7, 0, 0, trans, b"")?;
                        chan.send(&transfer::dfile_encrypt_control(key, &ack)?)?;
                        println!();
                        ov::finish();
                        oguard.done = true;
                        return Ok(written);
                    }
                }
                9 => return Err(Error::Protocol("接收端中止了本次传输".into())),
                5 => {
                    let inner =
                        transfer::dfile_decrypt_control(key, (kind, flags, sess, trans), payload)?;
                    dbg_frame!("[k5] len={} hex={:02X?}", inner.len(), inner);
                }
                22 => {
                    dbg_frame!("[kind=22·batch] 未知信号，暂停 20 ms");
                    std::thread::sleep(Duration::from_millis(20));
                }
                other => {
                    dbg_frame!(
                        "[未知帧·batch] kind={other} trans={trans} size={size} hex={:02X?}",
                        &payload[..payload.len().min(24)]
                    );
                    if *rx_kinds.get(&other).unwrap_or(&0) >= 3 {
                        return Err(Error::Protocol(format!(
                            "对端使用了未实现的控制帧 kind={other}"
                        )));
                    }
                }
            }

            if matches!(kind, 2 | 3 | 5 | 6 | 7 | 11) {
                last_activity = Instant::now();
            }
        }
        if !handled {
            if last_activity.elapsed() > Duration::from_secs(60) {
                return Err(Error::Protocol("等待接收端响应超时".into()));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    Err(Error::Protocol("批量传输超时".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn preview_carries_utd_and_thumbnail() {
        let path = tmp_image("hwshare-preview-test.jpg");
        let files = vec![Outgoing {
            id: 1,
            name: "photo.jpg".into(),
            size: 1000,
            path: path.clone(),
        }];

        let frame = file_preview(&files).unwrap();

        let inner = read_tlv(&frame, 8).expect("外层应为 tag 8");

        let names = read_tlv(&inner, 11).expect("应有字段 11");
        assert_eq!(String::from_utf8_lossy(&names), "photo.jpg");

        let meta = read_tlv(&inner, 12).expect("应有字段 12（utd + thumbnail）");
        let text = String::from_utf8_lossy(&meta);
        assert!(text.starts_with('['), "字段 12 应是 JSON 数组: {text}");
        assert!(text.contains(r#""utd":"general.jpeg""#), "缺 utd: {text}");
        assert!(
            text.contains(r#""thumbnail":"data:image/jpeg;base64,/9j/"#),
            "缩略图不是 JPEG data URL"
        );
        assert!(text.contains(r#""category":5"#));

        let times = read_tlv(&inner, 13).expect("应有字段 13");
        let times_text = String::from_utf8_lossy(&times).to_string();
        assert!(times_text.contains("date_taken"), "缺 date_taken");
        assert!(!times_text.contains("-1"), "时间不应再是 -1 占位: {times_text}");
        assert!(times_text.contains("detail_time"), "缺 detail_time");

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
        let frame = transfer::encrypted_frame(&dev, &key, &body, 1).unwrap();
        assert_eq!(
            transfer::decrypt_frame(&frame, &key).unwrap(),
            body,
            "测试帧本身应能解开"
        );
        assert_eq!(
            transfer::tlvs(&body).unwrap()[0].0, 1,
            "外层应为 tag1"
        );

        let peer = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut chan = Channel::from_stream(stream, "test").unwrap();
            chan.send(&frame).unwrap();
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

            let _ = chan.read_frame(Duration::from_secs(3));
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
        let frame = file_preview(&files).unwrap();
        let out = std::env::temp_dir().join("hwshare-our-preview.bin");
        std::fs::write(&out, &frame).unwrap();
        eprintln!("[dump] 我们的预览帧 {} 字节 → {}", frame.len(), out.display());
    }
}
