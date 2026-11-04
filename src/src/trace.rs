use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

pub const FORMAT_VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    Skeleton,
    Frames,
    Bytes,
}

impl Scope {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "skeleton" | "session" | "1" => Some(Scope::Skeleton),
            "frame" | "frames" | "2" => Some(Scope::Frames),
            "bytes" | "all" | "full" | "3" => Some(Scope::Bytes),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Skeleton => "skeleton",
            Scope::Frames => "frames",
            Scope::Bytes => "bytes",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Scope::Skeleton => 0,
            Scope::Frames => 1,
            Scope::Bytes => 2,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub path: PathBuf,
    pub peer: Option<String>,
    pub local: Option<String>,
    pub scope: Scope,
    pub session_id: String,
    pub source: String,
    pub max_bytes: u64,
}

struct Sink {
    cfg: Config,
    out: BufWriter<File>,
    t0: Instant,
    wall0_ms: u128,
    captured: u64,
}

static SINK: OnceLock<Mutex<Option<Sink>>> = OnceLock::new();
static ON: AtomicBool = AtomicBool::new(false);
static SCOPE: AtomicU8 = AtomicU8::new(0);
static EVENTS: AtomicU64 = AtomicU64::new(0);
static FRAMES: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static LIMIT_HIT: AtomicBool = AtomicBool::new(false);
static LIMIT_REPORTED: AtomicBool = AtomicBool::new(false);

fn slot() -> &'static Mutex<Option<Sink>> {
    SINK.get_or_init(|| Mutex::new(None))
}

static CONN_SEQ: AtomicU64 = AtomicU64::new(1);

pub fn next_conn() -> u64 {
    CONN_SEQ.fetch_add(1, Ordering::Relaxed)
}

pub fn enabled() -> bool {
    ON.load(Ordering::Relaxed)
}

pub fn scope() -> Scope {
    match SCOPE.load(Ordering::Relaxed) {
        2 => Scope::Bytes,
        1 => Scope::Frames,
        _ => Scope::Skeleton,
    }
}

pub fn current_path() -> Option<PathBuf> {
    let guard = slot().lock().ok()?;
    guard.as_ref().map(|s| s.cfg.path.clone())
}

pub fn target_peer() -> Option<String> {
    let guard = slot().lock().ok()?;
    guard.as_ref().and_then(|s| s.cfg.peer.clone())
}

pub fn is_target(ip: &str) -> bool {
    match target_peer() {
        Some(p) => p == ip,
        None => true,
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn pid() -> u32 {
    std::process::id()
}

pub fn make_session_id() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = civil(secs as i64);
    let rnd: u16 = rand::random();
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}-{}-{rnd:04X}", pid())
}

fn civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, (rem / 3600) as u32, (rem % 3600 / 60) as u32, (rem % 60) as u32)
}

pub fn default_dir() -> PathBuf {
    match std::env::var_os("LOCALAPPDATA") {
        Some(base) => PathBuf::from(base).join("HWShareWin").join("sessions"),
        None => std::env::temp_dir().join("HWShareWin").join("sessions"),
    }
}

pub fn start(cfg: Config) -> std::io::Result<PathBuf> {
    if let Some(dir) = cfg.path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&cfg.path)?;
    let mut sink = Sink {
        cfg,
        out: BufWriter::with_capacity(256 * 1024, file),
        t0: Instant::now(),
        wall0_ms: now_ms(),
        captured: 0,
    };
    EVENTS.store(0, Ordering::Relaxed);
    FRAMES.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    LIMIT_HIT.store(false, Ordering::Relaxed);
    LIMIT_REPORTED.store(false, Ordering::Relaxed);
    let meta = json!({
        "v": FORMAT_VERSION,
        "ev": "capture.meta",
        "sid": sink.cfg.session_id.clone(),
        "tool": "hwshare",
        "source": sink.cfg.source.clone(),
        "pid": pid(),
        "wall": now_ms(),
        "wall_start": sink.wall0_ms,
        "host": std::env::var("COMPUTERNAME").unwrap_or_default(),
        "local": sink.cfg.local.clone(),
        "peer_filter": sink.cfg.peer.clone(),
        "scope": sink.cfg.scope.as_str(),
        "max_bytes": sink.cfg.max_bytes,
    });
    let path = sink.cfg.path.clone();
    sink.out.write_all(meta.to_string().as_bytes())?;
    sink.out.write_all(b"\n")?;
    sink.out.flush()?;
    let scope_rank = sink.cfg.scope.rank();
    if let Ok(mut guard) = slot().lock() {
        *guard = Some(sink);
    }
    SCOPE.store(scope_rank, Ordering::Relaxed);
    ON.store(true, Ordering::Relaxed);
    Ok(path)
}

pub fn init_from_env() {
    if enabled() {
        return;
    }
    if std::env::var("HWSHARE_TRACE").is_err() {
        return;
    }
    let sid = make_session_id();
    let default_scope = Scope::Frames;
    let scope = std::env::var("HWSHARE_TRACE_SCOPE")
        .ok()
        .and_then(|s| Scope::parse(&s))
        .unwrap_or(default_scope);
    let path = match std::env::var("HWSHARE_TRACE_OUT") {
        Ok(p) if !p.trim().is_empty() => PathBuf::from(p),
        _ => default_dir().join(format!("capture-{sid}.jsonl")),
    };
    let peer = std::env::var("HWSHARE_TRACE_PEER")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let local = std::env::var("HWSHARE_TRACE_LOCAL").ok().filter(|s| !s.is_empty());
    let max_bytes = std::env::var("HWSHARE_TRACE_MAX_MB")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(512)
        .saturating_mul(1024 * 1024);
    let cfg = Config {
        path,
        peer,
        local,
        scope,
        session_id: sid,
        source: "engine".into(),
        max_bytes,
    };
    if let Err(e) = start(cfg) {
        eprintln!("[trace] 采集文件创建失败: {e}");
    }
}

pub fn finish(reason: &str) {
    let Ok(mut guard) = slot().lock() else { return };
    let Some(sink) = guard.as_mut() else { return };
    let _ = sink.out.write_all(
        json!({
            "v": FORMAT_VERSION,
            "ev": "capture.end",
            "sid": sink.cfg.session_id.clone(),
            "t": sink.t0.elapsed().as_micros() as u64,
            "wall": now_ms(),
            "events": EVENTS.load(Ordering::Relaxed),
            "conns": CONN_SEQ.load(Ordering::Relaxed).saturating_sub(1),
            "frames": FRAMES.load(Ordering::Relaxed),
            "bytes": BYTES.load(Ordering::Relaxed),
            "limited": LIMIT_HIT.load(Ordering::Relaxed),
            "reason": reason,
        })
        .to_string()
        .as_bytes(),
    );
    let _ = sink.out.write_all(b"\n");
    let _ = sink.out.flush();
    ON.store(false, Ordering::Relaxed);
    *guard = None;
}

fn push(map: &mut Map<String, Value>, key: &str, value: Value) {
    map.insert(key.to_string(), value);
}

fn emit(ev: &str, peer: Option<&str>, mut fields: Map<String, Value>) {
    if !enabled() {
        return;
    }
    let Ok(mut guard) = slot().lock() else { return };
    let Some(sink) = guard.as_mut() else { return };
    if let (Some(want), Some(got)) = (sink.cfg.peer.as_deref(), peer) {
        if want != got {
            return;
        }
    }
    push(&mut fields, "v", json!(FORMAT_VERSION));
    push(&mut fields, "ev", json!(ev));
    push(&mut fields, "sid", json!(sink.cfg.session_id.clone()));
    push(&mut fields, "t", json!(sink.t0.elapsed().as_micros() as u64));
    push(&mut fields, "wall", json!(now_ms()));
    if let Some(p) = peer {
        push(&mut fields, "peer", json!(p));
    }
    let line = Value::Object(fields);
    let _ = sink.out.write_all(line.to_string().as_bytes());
    let _ = sink.out.write_all(b"\n");
    let _ = sink.out.flush();
    EVENTS.fetch_add(1, Ordering::Relaxed);
}

fn obj() -> Map<String, Value> {
    Map::new()
}

fn hex_text(data: &[u8], limit: usize) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let n = data.len().min(limit);
    let mut out = String::with_capacity(n * 2 + 2);
    for &b in &data[..n] {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0F) as usize] as char);
    }
    if n < data.len() {
        out.push_str("..");
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Babeface { module: u32, seq: u64, flags: u32, len: u32 },
    Dfile { kind: u8, flags: u8, session: u16, transaction: u16, size: u16 },
    Raw,
}

pub fn classify(data: &[u8]) -> FrameKind {
    if data.len() >= 24 {
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic == 0xBABE_FACE {
            let module = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            let seq = u64::from_le_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ]);
            let flags = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
            let len = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
            if 24 + len as usize <= data.len() {
                return FrameKind::Babeface { module, seq, flags, len };
            }
        }
    }
    if data.len() >= 8 {
        let kind = data[0];
        let size = u16::from_be_bytes([data[6], data[7]]);
        if (1..=14).contains(&kind) || kind == 22 {
            if 8 + size as usize == data.len() {
                return FrameKind::Dfile {
                    kind,
                    flags: data[1],
                    session: u16::from_be_bytes([data[2], data[3]]),
                    transaction: u16::from_be_bytes([data[4], data[5]]),
                    size,
                };
            }
        }
    }
    FrameKind::Raw
}

pub use crate::transfer::dfile_kind_name;

pub fn session_start(mode: &str, peer: &str, local: &str, files: usize, bytes: u64) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "dir", json!(mode));
    push(&mut f, "local", json!(local));
    push(&mut f, "files", json!(files));
    push(&mut f, "bytes", json!(bytes));
    emit("session.start", Some(peer), f);
}

pub fn session_end(ok: bool, bytes: u64, files: &[String], reason: &str, dur_ms: u128) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "ok", json!(ok));
    push(&mut f, "bytes", json!(bytes));
    push(&mut f, "files", json!(files));
    push(&mut f, "reason", json!(reason));
    push(&mut f, "dur_ms", json!(dur_ms as u64));
    emit("session.end", None, f);
}

pub fn channel_open(label: &str, role: &str, laddr: &str, raddr: &str, conn: u64) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "ch", json!(label));
    push(&mut f, "conn", json!(conn));
    push(&mut f, "role", json!(role));
    push(&mut f, "laddr", json!(laddr));
    push(&mut f, "raddr", json!(raddr));
    let peer = raddr.rsplit_once(':').map(|(ip, _)| ip.to_string());
    emit("channel.open", peer.as_deref(), f);
}

pub fn channel_close(label: &str, tx: u64, rx: u64, dur_ms: u128, reason: &str, conn: u64) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "ch", json!(label));
    push(&mut f, "conn", json!(conn));
    push(&mut f, "tx", json!(tx));
    push(&mut f, "rx", json!(rx));
    push(&mut f, "dur_ms", json!(dur_ms as u64));
    push(&mut f, "reason", json!(reason));
    emit("channel.close", None, f);
}

pub fn wire_frame(channel: &str, dir: &str, data: &[u8], conn: u64) {
    if !enabled() || scope() < Scope::Frames {
        return;
    }
    if !charge(channel, data.len() as u64) {
        return;
    }
    let mut f = obj();
    push(&mut f, "ch", json!(channel));
    push(&mut f, "conn", json!(conn));
    push(&mut f, "dir", json!(dir));
    push(&mut f, "n", json!(data.len()));
    match classify(data) {
        FrameKind::Babeface { module, seq, flags, len } => {
            push(&mut f, "proto", json!("babeface"));
            push(&mut f, "module", json!(module));
            push(&mut f, "seq", json!(seq));
            push(&mut f, "flags", json!(flags));
            push(&mut f, "len", json!(len));
        }
        FrameKind::Dfile { kind, flags, session, transaction, size } => {
            push(&mut f, "proto", json!("dfile"));
            push(&mut f, "kind", json!(kind));
            push(&mut f, "kind_name", json!(dfile_kind_name(kind)));
            push(&mut f, "flags", json!(flags));
            push(&mut f, "sess", json!(session));
            push(&mut f, "trans", json!(transaction));
            push(&mut f, "len", json!(size));
        }
        FrameKind::Raw => {
            push(&mut f, "proto", json!("raw"));
        }
    }
    let limit = if scope() == Scope::Bytes { data.len() } else { 64 };
    push(&mut f, "hex", json!(hex_text(data, limit)));
    emit("frame", None, f);
    FRAMES.fetch_add(1, Ordering::Relaxed);
}

pub fn bytes(channel: &str, dir: &str, data: &[u8], conn: u64) {
    if !enabled() || scope() != Scope::Bytes || data.is_empty() {
        return;
    }
    if !charge(channel, data.len() as u64) {
        return;
    }
    let mut f = obj();
    push(&mut f, "ch", json!(channel));
    push(&mut f, "conn", json!(conn));
    push(&mut f, "dir", json!(dir));
    push(&mut f, "n", json!(data.len()));
    push(&mut f, "hex", json!(hex_text(data, data.len())));
    emit("bytes", None, f);
    BYTES.fetch_add(data.len() as u64, Ordering::Relaxed);
}

fn charge(channel: &str, len: u64) -> bool {
    if LIMIT_HIT.load(Ordering::Relaxed) {
        return false;
    }
    let over = {
        let Ok(mut guard) = slot().lock() else { return false };
        let Some(sink) = guard.as_mut() else { return false };
        if sink.cfg.max_bytes > 0 && sink.captured.saturating_add(len) > sink.cfg.max_bytes {
            sink.captured = sink.cfg.max_bytes;
            true
        } else {
            sink.captured += len;
            false
        }
    };
    if !over {
        return true;
    }
    LIMIT_HIT.store(true, Ordering::Relaxed);
    if !LIMIT_REPORTED.swap(true, Ordering::Relaxed) {
        let limit = slot()
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.cfg.max_bytes))
            .unwrap_or(0);
        let mut f = obj();
        push(&mut f, "ch", json!(channel));
        push(&mut f, "limit", json!(limit));
        emit("capture.limit", None, f);
    }
    false
}

pub fn note(channel: &str, text: &str) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "ch", json!(channel));
    push(&mut f, "text", json!(text));
    emit("note", None, f);
}

pub fn note_conn(channel: &str, conn: u64, text: &str) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "ch", json!(channel));
    push(&mut f, "conn", json!(conn));
    push(&mut f, "text", json!(text));
    emit("note", None, f);
}

pub fn listen(label: &str, addr: &str) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "ch", json!(label));
    push(&mut f, "addr", json!(addr));
    let port = addr.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok());
    if let Some(p) = port {
        push(&mut f, "port", json!(p));
    }
    emit("listen", None, f);
}

pub fn discovery_build(local: &str, port: u16, name: &str, device_type: u32) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "src", json!(local));
    push(&mut f, "port", json!(port));
    push(&mut f, "name", json!(name));
    push(&mut f, "type", json!(device_type));
    emit("discovery.build", None, f);
}

pub fn discovery_tx(dst: &str, data: &[u8]) {
    if !enabled() {
        return;
    }
    let peer = dst.parse::<std::net::Ipv4Addr>().ok().map(|_| dst);
    let mut f = obj();
    push(&mut f, "dst", json!(dst));
    push(&mut f, "n", json!(data.len()));
    push(&mut f, "hex", json!(hex_text(data, 1024)));
    emit("discovery.tx", peer, f);
}

pub fn discovery_rx_raw(src: &str, data: &[u8]) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "src", json!(src));
    push(&mut f, "n", json!(data.len()));
    push(&mut f, "hex", json!(hex_text(data, 1024)));
    emit("discovery.rx.raw", Some(src), f);
}

pub fn channel_fail(peer: &str, port: u16, error: &str) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "port", json!(port));
    push(&mut f, "error", json!(error));
    emit("channel.fail", Some(peer), f);
}

pub fn frame_partial(channel: &str, dir: &str, data: &[u8], conn: u64) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "ch", json!(channel));
    push(&mut f, "conn", json!(conn));
    push(&mut f, "dir", json!(dir));
    push(&mut f, "n", json!(data.len()));
    push(&mut f, "hex", json!(hex_text(data, 256)));
    emit("frame.partial", None, f);
}

pub fn discovery_rx(peer: &crate::discovery::Peer) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "src", json!(peer.host));
    push(&mut f, "port", json!(peer.port));
    push(&mut f, "name", json!(peer.name));
    push(&mut f, "kind", json!(peer.kind));
    push(&mut f, "id", json!(peer.id));
    push(&mut f, "target", json!(is_target(&peer.host)));
    emit("discovery.rx", Some(&peer.host), f);
}

pub fn confirm_show(peer: &str, count: u32, bytes: u64) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "count", json!(count));
    push(&mut f, "bytes", json!(bytes));
    emit("confirm.show", Some(peer), f);
}

pub fn confirm_answer(peer: &str, accepted: bool, reason: &str) {
    if !enabled() {
        return;
    }
    let mut f = obj();
    push(&mut f, "accepted", json!(accepted));
    push(&mut f, "reason", json!(reason));
    emit("confirm.answer", Some(peer), f);
}

#[cfg(test)]
mod tests {
    use super::*;

    static LOCK: Mutex<()> = Mutex::new(());

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hwshare-trace-{tag}-{}-{}.jsonl",
            std::process::id(),
            now_ms()
        ))
    }

    fn start_at(path: &PathBuf, peer: Option<&str>, scope: Scope) {
        start_with(path, peer, scope, 0);
    }

    fn start_with(path: &PathBuf, peer: Option<&str>, scope: Scope, max_bytes: u64) {
        let cfg = Config {
            path: path.clone(),
            peer: peer.map(|s| s.to_string()),
            local: Some("127.0.0.1".into()),
            scope,
            session_id: "TEST".into(),
            source: "test".into(),
            max_bytes,
        };
        start(cfg).unwrap();
    }

    fn lines(path: &PathBuf) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .collect()
    }

    #[test]
    fn classify_both_protocols() {
        let mut b = Vec::new();
        b.extend_from_slice(&0xBABE_FACEu32.to_le_bytes());
        b.extend_from_slice(&8u32.to_le_bytes());
        b.extend_from_slice(&7u64.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&3u32.to_le_bytes());
        b.extend_from_slice(b"abc");
        assert_eq!(
            classify(&b),
            FrameKind::Babeface { module: 8, seq: 7, flags: 1, len: 3 }
        );

        let mut d = vec![8u8, 0, 0, 0, 0, 0, 0, 100];
        d.extend(std::iter::repeat(0u8).take(100));
        assert_eq!(
            classify(&d),
            FrameKind::Dfile { kind: 8, flags: 0, session: 0, transaction: 0, size: 100 }
        );

        assert_eq!(classify(b"hello"), FrameKind::Raw);
    }

    #[test]
    fn skeleton_drops_frames_and_bytes() {
        let _g = LOCK.lock().unwrap();
        let path = temp_path("skeleton");
        start_at(&path, None, Scope::Skeleton);
        session_start("recv", "10.0.0.2", "10.0.0.1", 1, 10);
        wire_frame("file#1", "rx", &[8, 0, 0, 0, 0, 0, 0, 0], 1);
        bytes("file#1", "rx", b"xyz", 1);
        note("control", "hello");
        finish("test");
        let all = lines(&path);
        assert!(all.iter().any(|v| v["ev"] == "session.start"));
        assert!(all.iter().any(|v| v["ev"] == "note"));
        assert!(!all.iter().any(|v| v["ev"] == "frame"));
        assert!(!all.iter().any(|v| v["ev"] == "bytes"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn peer_filter_keeps_only_target() {
        let _g = LOCK.lock().unwrap();
        let path = temp_path("filter");
        start_at(&path, Some("10.0.0.2"), Scope::Skeleton);
        session_start("recv", "10.0.0.2", "10.0.0.1", 1, 10);
        session_start("recv", "10.0.0.9", "10.0.0.1", 1, 10);
        channel_open("control", "connect", "10.0.0.1:5000", "10.0.0.2:5684", 1);
        channel_open("control", "connect", "10.0.0.1:5000", "10.0.0.9:5684", 2);
        finish("test");
        let all = lines(&path);
        let starts: Vec<_> = all.iter().filter(|v| v["ev"] == "session.start").collect();
        let opens: Vec<_> = all.iter().filter(|v| v["ev"] == "channel.open").collect();
        assert_eq!(starts.len(), 1);
        assert_eq!(opens.len(), 1);
        assert_eq!(starts[0]["peer"], "10.0.0.2");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn udp_and_failures_are_recorded_and_filtered() {
        let _g = LOCK.lock().unwrap();
        let path = temp_path("udp");
        start_with(&path, Some("192.168.1.9"), Scope::Skeleton, 0);
        discovery_build("192.168.1.5", 5684, "PC", 12);
        discovery_tx("broadcast", b"hey");
        discovery_tx("192.168.1.9", b"uni");
        discovery_tx("192.168.1.7", b"other");
        discovery_rx_raw("192.168.1.9", b"from-target");
        discovery_rx_raw("192.168.1.7", b"from-other");
        channel_fail("192.168.1.9", 5684, "refused");
        frame_partial("file#1", "rx", &[0xCE, 0xFA], 1);
        finish("test");
        let all = lines(&path);
        let count = |ev: &str| all.iter().filter(|v| v["ev"] == ev).count();
        assert_eq!(count("discovery.build"), 1);
        assert_eq!(count("discovery.tx"), 2, "broadcast + 目标单播；其它设备的不记");
        assert_eq!(count("discovery.rx.raw"), 1, "只留目标 IP 的 UDP");
        assert_eq!(count("channel.fail"), 1);
        assert_eq!(count("frame.partial"), 1);
        let tx = all.iter().find(|v| v["ev"] == "discovery.tx" && v["dst"] == "192.168.1.9").unwrap();
        assert_eq!(tx["hex"], "756E69", "uni 的 hex");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn byte_budget_stops_after_limit() {
        let _g = LOCK.lock().unwrap();
        let path = temp_path("limit");
        start_with(&path, None, Scope::Bytes, 100);
        bytes("control", "rx", &[1u8; 60], 1);
        bytes("control", "rx", &[2u8; 60], 1); 
        bytes("control", "rx", &[3u8; 60], 1);
        finish("test");
        let all = lines(&path);
        let recorded: Vec<_> = all.iter().filter(|v| v["ev"] == "bytes").collect();
        assert_eq!(recorded.len(), 1, "只应记录第一条 60 字节");
        assert_eq!(all.iter().filter(|v| v["ev"] == "capture.limit").count(), 1);
        assert_eq!(all.last().unwrap()["limited"], true);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn bytes_scope_writes_full_hex() {
        let _g = LOCK.lock().unwrap();
        let path = temp_path("bytes");
        start_at(&path, None, Scope::Bytes);
        bytes("file#1", "rx", &[0xAB; 128], 1);
        finish("test");
        let all = lines(&path);
        let b = all.iter().find(|v| v["ev"] == "bytes").expect("应有 bytes");
        let hex = b["hex"].as_str().unwrap();
        assert_eq!(hex.len(), 256);
        assert!(!hex.ends_with(".."));
        assert_eq!(classify(&[8, 0, 0, 0, 0, 0, 0, 0]), FrameKind::Dfile {
            kind: 8, flags: 0, session: 0, transaction: 0, size: 0
        });
        let _ = std::fs::remove_file(path);
    }
}
