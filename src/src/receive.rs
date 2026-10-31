use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;

use crate::auth;
use crate::channel::{Channel, Listener};
use crate::crypto;
use crate::transfer::{self, tlv_get, tlvs};
use crate::{aesgcm_encrypt_n16, frame_encode, tlv_encode, varint_encode, Error, Result,
            FRAME_HEADER_SIZE};

const POLL: Duration = Duration::from_millis(2);

const DRAIN_LIMIT: usize = 64;

const DRAIN_BUDGET: Duration = Duration::from_millis(30);
const META_INFO: u32 = 0xFFFF_0002;
const META_ACK: u32 = 0xFFFF_0008;
const META_ACK_TEXT: &[u8] = b"META_DEVICE_INFO_ACK\0";
const CHANNEL_BYTES: u32 = 0xFFFF_0004;

pub struct Session {
    pub file_count: u32,
    pub total_bytes: u64,
    pub session_key: [u8; 32],
    pub device_hash: Vec<u8>,
    pub peer: String,
    pub accepted: bool,
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

const MODULE_AUTH: u32 = 1;

const MAX_AUTH_ROUNDS: u32 = 6;

fn frame_module(frame: &[u8]) -> u32 {
    match frame.get(4..8) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthMode {
    Wait,
    Ack,
    Echo,
    Next,
    Close,
}

impl AuthMode {
    fn from_env() -> Self {
        match std::env::var("HWSHARE_AUTH_MODE")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "wait" | "probe" => AuthMode::Wait,
            "echo" => AuthMode::Echo,
            "next" => AuthMode::Next,
            "ack" => AuthMode::Ack,

            _ => AuthMode::Close,
        }
    }

    fn name(self) -> &'static str {
        match self {
            AuthMode::Wait => "wait",
            AuthMode::Ack => "ack",
            AuthMode::Echo => "echo",
            AuthMode::Next => "next",
            AuthMode::Close => "close",
        }
    }
}

fn build_opening_ack(private: &rsa::RsaPrivateKey) -> Result<Vec<u8>> {
    let public_der = crypto::public_der(private).map_err(Error::Crypto)?;
    let identity = crate::identity_v2(&public_der)?;
    let ack = format!(
        r#"{{"CODE":4,"DEVICE_ID":"{id}","PEER_NETWORK_ID":"{id}","API_VERSION":2,"PKG_NAME":"ohos.InterConnection.iShare","SRC_BUS_NAME":"ohos.InterConnection.iShare","DST_BUS_NAME":"IShareEcologyAuthSession","REQ_ID":"0","MTU_SIZE":39968,"ROUTE_TYPE":2}}"#,
        id = identity.to_lowercase()
    );
    let mut payload = ack.into_bytes();
    payload.push(0);
    frame_encode(8, 0, 1, &payload)
}

fn auth_reply(
    channel: &mut Channel,
    opening: &[u8],
    request: &serde_json::Value,
    round: u32,
    private: &rsa::RsaPrivateKey,
) -> Result<()> {
    let mode = AuthMode::from_env();
    crate::trace::note_conn(
        &channel.label().to_string(),
        channel.conn(),
        &format!(
            "认证帧应答策略={} (第 {round} 轮)，请求体: {}",
            mode.name(),
            String::from_utf8_lossy(&opening[FRAME_HEADER_SIZE..])
                .chars()
                .take(500)
                .collect::<String>()
        ),
    );

    match mode {
        AuthMode::Close => Err(Error::Protocol(
            "对方要求重新认证，当前版本未支持（HWSHARE_AUTH_MODE=close）".to_string(),
        )),
        AuthMode::Wait => {
            crate::trace::note_conn(
                "control",
                channel.conn(),
                "策略 wait：不应答，等手机后续帧",
            );
            Ok(())
        }
        AuthMode::Ack => {
            let ack = build_opening_ack(private)?;
            crate::trace::note_conn(
                "control",
                channel.conn(),
                &format!("策略 ack：回 opening ACK {} 字节", ack.len()),
            );
            channel.send(&ack)
        }
        AuthMode::Echo | AuthMode::Next => {
            let mut reply = request.clone();
            let state = reply["AUTH_START_STATE"].as_u64().unwrap_or(0);
            let next_state = if mode == AuthMode::Next { state + 1 } else { state };
            if let Some(obj) = reply.as_object_mut() {
                obj.insert("AUTH_START_STATE".into(), serde_json::json!(next_state));

                if let Ok(public_der) = crypto::public_der(private) {
                    if let Ok(hash) = crate::key_hash(&public_der) {
                        obj.insert(
                            "DevIpHash".into(),
                            serde_json::json!(crate::hex_upper(&hash)),
                        );
                    }
                }
            }
            let mut payload = serde_json::to_vec(&reply).map_err(|_| Error::Format)?;
            payload.push(0);
            let frame = frame_encode(MODULE_AUTH, 0, 1, &payload)?;
            crate::trace::note_conn(
                "control",
                channel.conn(),
                &format!(
                    "策略 {}：回认证帧 {} 字节，state {state}→{next_state}",
                    mode.name(),
                    frame.len()
                ),
            );
            channel.send(&frame)
        }
    }
}

fn accept_connection_inner(
    channel: &mut Channel,
    private: &rsa::RsaPrivateKey,
    accept: bool,
    timeout: Duration,
) -> Result<Session> {
    let debug = std::env::var("HWSHARE_DEBUG").is_ok();
    macro_rules! dbg_step {
        ($($arg:tt)*) => {
            if crate::trace::enabled() {
                crate::trace::note_conn("control", channel.conn(), &format!($($arg)*));
            }
            if debug { eprintln!("[rust-recv] {}", format!($($arg)*)); }
        };
    }

    dbg_step!("等待 opening");
    let mut opening = channel.read_frame(timeout)?;
    let mut auth_round = 0u32;

    let _request: serde_json::Value = loop {
        dbg_step!("收到 opening ({} 字节)", opening.len());
        let module = frame_module(&opening);
        let body = &opening[FRAME_HEADER_SIZE..];
        let text = body.strip_suffix(&[0]).unwrap_or(body);
        let req: serde_json::Value = match serde_json::from_slice(text) {
            Ok(v) => v,
            Err(_) => {
                let snippet: String =
                    String::from_utf8_lossy(text).chars().take(200).collect();
                dbg_step!("开场不是 JSON（module={module}）: {snippet}");
                return Err(Error::Format);
            }
        };

        if req["CODE"] == 4 {
            break req;
        }

        if req.get("AUTH_START_STATE").is_some() || module == MODULE_AUTH {
            auth_round += 1;
            dbg_step!(
                "认证帧 #{auth_round}（module={module}）: {}",
                String::from_utf8_lossy(text).chars().take(400).collect::<String>()
            );
            if auth_round > MAX_AUTH_ROUNDS {
                return Err(Error::Protocol(format!(
                    "认证握手重试 {MAX_AUTH_ROUNDS} 次仍未进入建链，已放弃"
                )));
            }
            auth_reply(channel, &opening, &req, auth_round, private)?;
            opening = channel.read_frame(timeout)?;
            continue;
        }

        let snippet: String = String::from_utf8_lossy(text).chars().take(200).collect();
        return Err(Error::Protocol(format!(
            "不支持的开场请求（{} 字节，module={module}）: {snippet}",
            opening.len()
        )));
    };

    let public_der = crypto::public_der(private).map_err(Error::Crypto)?;
    let ack_frame = build_opening_ack(private)?;
    dbg_step!("发 opening ACK: {} 字节, 头={:02X?}", ack_frame.len(), &ack_frame[..24]);
    channel.send(&ack_frame)?;

    let device_hash = crate::hex_upper(&crate::key_hash(&public_der)?[..8]).into_bytes();

    dbg_step!("已回 opening ACK，等能力协商");
    let capability_request = match channel.read_frame(timeout) {
        Ok(v) => { dbg_step!("能力帧 {} 字节", v.len()); v }
        Err(e) => { dbg_step!("能力帧读取失败: {e:?}"); return Err(e); }
    };
    dbg_step!("收到能力帧");
    let (mode, cap_body) = auth::unpack_envelope(&capability_request)?;
    if mode != 0 {
        return Err(Error::Format);
    }
    let _ = auth::unwrap_tlv(&cap_body, 2)?;
    channel.send(&auth::envelope_frame(&device_hash, &tlv_encode(3, &tlv_encode(1, b"")?)?, 0)?)?;

    dbg_step!("已回能力，等对端公钥");
    let public_request = channel.read_frame(timeout)?;
    dbg_step!("收到公钥帧");
    let (mode, pub_body) = auth::unpack_envelope(&public_request)?;
    if mode != 0 {
        return Err(Error::Format);
    }
    let peer_der = auth::unwrap_tlv(auth::unwrap_tlv(&pub_body, 6)?, 1)?;
    let peer_key = RsaPublicKey::from_public_key_der(peer_der)
        .map_err(|e| Error::Crypto(format!("对端公钥解析失败: {e}")))?;

    channel.send(&auth::envelope_frame(
        &device_hash,
        &tlv_encode(6, &tlv_encode(2, &public_der)?)?,
        0,
    )?)?;

    dbg_step!("已回公钥，等挑战");
    let challenge_frame = channel.read_frame(timeout)?;
    dbg_step!("收到挑战帧");
    let (mode, ciphertext) = auth::unpack_envelope(&challenge_frame)?;
    if mode != 3 {
        return Err(Error::Format);
    }
    let decrypted = crypto::oaep_decrypt(private, &ciphertext, false).map_err(Error::Crypto)?;
    let challenge = auth::unwrap_tlv(auth::unwrap_tlv(&decrypted, 6)?, 3)?;
    if challenge.len() != 48 {
        return Err(Error::Format);
    }

    let mut session_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut session_key);
    let encrypted = aesgcm_encrypt_n16(&challenge[16..48], &challenge[0..16], &session_key)?;
    let wrapped = crypto::oaep_encrypt(
        &peer_key,
        &tlv_encode(6, &tlv_encode(4, &encrypted)?)?,
        false,
    )
    .map_err(Error::Crypto)?;

    let mut meta_bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut meta_bytes);
    let metadata = tlv_encode(1, &meta_bytes)?;
    let mut envelope = Vec::new();
    envelope.extend_from_slice(&device_hash);
    envelope.extend_from_slice(&[0x81, 0xE5, 0x83]);
    envelope.extend(varint_encode(metadata.len() as u64)?);
    envelope.extend_from_slice(&metadata);
    envelope.extend(varint_encode(wrapped.len() as u64)?);
    envelope.extend_from_slice(&wrapped);
    channel.send(&frame_encode(9, 0, 0, &envelope)?)?;

    dbg_step!("已回挑战回应，等 offer");
    let offer_frame = channel.read_frame(Duration::from_secs(24))?;
    dbg_step!("收到 offer ({} 字节)", offer_frame.len());
    if debug {
        let offer_body = &offer_frame[FRAME_HEADER_SIZE..];
        eprintln!("[offer] 明文 {} 字节", offer_body.len());
        dump_tlvs("[offer] ", offer_body, 0);
    }
    let plain = transfer::decrypt_frame(&offer_frame, &session_key)?;
    let fields = tlvs(auth::unwrap_tlv(&plain, 7)?)?;
    let mut count = 0u32;
    let mut total = 0u64;
    for (tag, value) in fields {
        match tag {
            3 => count = String::from_utf8_lossy(&value).parse().unwrap_or(0),
            4 => total = String::from_utf8_lossy(&value).parse().unwrap_or(0),
            _ => {}
        }
    }

    Ok(Session {
        file_count: count,
        total_bytes: total,
        session_key,
        device_hash,
        peer: channel.peer().to_string(),
        accepted: accept,
    })
}

fn dump_tlvs(prefix: &str, data: &[u8], depth: usize) {
    let Ok(fields) = tlvs(data) else {
        eprintln!("{prefix}(非 TLV, {} 字节) {:02X?}", data.len(), &data[..data.len().min(48)]);
        return;
    };
    if fields.is_empty() {
        eprintln!("{prefix}(空 TLV) {:02X?}", &data[..data.len().min(48)]);
        return;
    }
    for (tag, value) in fields {
        let head = &value[..value.len().min(40)];
        let printable = std::str::from_utf8(&value)
            .ok()
            .filter(|s| s.chars().all(|c| !c.is_control() || c == '\n'))
            .filter(|s| s.len() <= 120);
        match printable {
            Some(s) => eprintln!("{prefix}{tag}: {}B = {s:?}", value.len()),
            None => eprintln!("{prefix}{tag}: {}B  {:02X?}", value.len(), head),
        }

        if depth < 3 {
            if let Ok(inner) = tlvs(&value) {
                if !inner.is_empty() {
                    let used: usize = inner.iter().map(|(_, v)| v.len() + 2).sum();
                    if used == value.len() {
                        dump_tlvs(&format!("{prefix}    "), &value, depth + 1);
                    }
                }
            }
        }
    }
}

const WRITE_BUF: usize = 64 * 1024;

#[cfg(windows)]
fn preallocate(file: &std::fs::File, size: u64, debug: bool) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileAllocationInfo, SetFileInformationByHandle, FILE_ALLOCATION_INFO,
    };
    if size == 0 {
        return;
    }
    let info = FILE_ALLOCATION_INFO { AllocationSize: size as i64 };
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as *mut core::ffi::c_void,
            FileAllocationInfo,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<FILE_ALLOCATION_INFO>() as u32,
        )
    };
    if ok == 0 && debug {
        eprintln!("[dfile] 预分配 {size} 字节失败（忽略，退化为边写边扩展）");
    }
}

#[cfg(not(windows))]
fn preallocate(_file: &std::fs::File, _size: u64, _debug: bool) {}

struct ActiveFile {
    file: BufWriter<std::fs::File>,
    path: PathBuf,
    part: PathBuf,
    written: u64,
}

fn part_path(target: &Path) -> PathBuf {
    let mut name = target.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    name.push(".part");
    target.with_file_name(name)
}

fn idle_limit() -> Duration {
    static LIMIT: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(|| {
        std::env::var("HWSHARE_IDLE_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|n| *n >= 5)
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(8))
    })
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

fn take_pending_cancel(control: &mut Channel, key: &[u8; 32]) -> Option<String> {
    let deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < deadline {
        match control.try_read_frame(Duration::from_millis(10)) {
            Ok(Some(frame)) => {
                let Some(head) = frame.get(4..8) else { continue };
                if u32::from_le_bytes(head.try_into().unwrap()) != 9 {
                    continue;
                }
                let Ok(body) = transfer::decrypt_frame(&frame, key) else {
                    continue;
                };
                let Ok(fields) = transfer::tlvs(&body) else {
                    continue;
                };
                for (tag, value) in fields {
                    if tag != 1 {
                        continue;
                    }
                    let Ok(cmds) = transfer::tlvs(&value) else {
                        continue;
                    };
                    for (_, cmd) in cmds {
                        if matches!(
                            cmd.as_slice(),
                            b"senderCancel" | b"receiverCancel" | b"user_reject"
                        ) {
                            return Some(String::from_utf8_lossy(&cmd).to_string());
                        }
                    }
                }
            }
            Ok(None) => continue,
            Err(_) => break,
        }
    }
    None
}

static RECV_CANCEL: AtomicBool = AtomicBool::new(false);

pub fn request_cancel_recv() {
    RECV_CANCEL.store(true, Ordering::SeqCst);
}

fn recv_cancel_requested() -> bool {
    RECV_CANCEL.load(Ordering::SeqCst)
}

fn clear_recv_cancel() {
    RECV_CANCEL.store(false, Ordering::SeqCst);
}

fn recv_cancel_tag() -> u64 {
    std::env::var("HWSHARE_RECV_CANCEL_TAG")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|t| *t <= 255)
        .unwrap_or(1)
}

fn recv_cancel_wait() -> Duration {
    std::env::var("HWSHARE_RECV_CANCEL_WAIT_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|ms| Duration::from_millis(ms.min(10_000)))
        .unwrap_or(Duration::from_millis(800))
}

fn spawn_recv_cancel_watch() {
    let Ok(raw) = std::env::var("HWSHARE_RECV_CANCEL_TRIGGER") else { return };
    if raw.trim().is_empty() {
        return;
    }
    let path = PathBuf::from(raw);
    std::thread::spawn(move || loop {
        if path.exists() {
            let _ = std::fs::remove_file(&path);
            crate::trace::note("control", "检测到取消触发文件，请求取消接收");
            request_cancel_recv();
            return;
        }
        std::thread::sleep(Duration::from_millis(150));
    });
}

pub fn record_drained(control: &mut Channel, session: &Session, drained: Vec<u8>) {
    if drained.is_empty() {
        return;
    }
    control.put_back(&drained);
    log_drained(&session.session_key, &drained);
}

fn log_drained(key: &[u8; 32], data: &[u8]) {
    if !crate::trace::enabled() {
        return;
    }
    let mut rest = data;
    let mut index = 0usize;
    while rest.len() >= FRAME_HEADER_SIZE {
        let header = crate::frame_decode(&rest[..FRAME_HEADER_SIZE]);
        let Ok((_magic, module, _seq, _flags, len)) = header else {
            crate::trace::note(
                "control",
                &format!(
                    "确认期间收到 {} 字节，帧头不合法（magic/长度）：{}",
                    rest.len(),
                    hex_head(rest)
                ),
            );
            return;
        };
        let total = FRAME_HEADER_SIZE + len as usize;
        if rest.len() < total {
            crate::trace::note(
                "control",
                &format!(
                    "确认期间收到半帧 {} / {} 字节：{}",
                    rest.len(),
                    total,
                    hex_head(rest)
                ),
            );
            return;
        }
        index += 1;
        let frame = &rest[..total];
        crate::trace::note(
            "control",
            &format!(
                "确认期间到达的帧#{index}：{} 字节，{}",
                total,
                describe_wire_frame(module, frame, key)
            ),
        );
        rest = &rest[total..];
    }
    if !rest.is_empty() {
        crate::trace::note(
            "control",
            &format!(
                "确认期间剩余 {} 字节（不足一个帧头）：{}",
                rest.len(),
                hex_head(rest)
            ),
        );
    }
}

fn describe_wire_frame(module: u32, frame: &[u8], key: &[u8; 32]) -> String {
    if module != 9 {
        return format!("module={module}（非控制模块）{}", hex_head(frame));
    }
    match transfer::decrypt_frame(frame, key) {
        Ok(body) => describe_control_body(&body),
        Err(e) => format!("解密失败（{e}），原文 {}", hex_head(frame)),
    }
}

fn describe_control_body(body: &[u8]) -> String {
    let Ok(fields) = transfer::tlvs(body) else {
        return format!("明文 {}", printable(body));
    };
    let mut parts: Vec<String> = Vec::new();
    for (tag, value) in fields {
        if tag == 1 {
            if let Ok(inner) = transfer::tlvs(&value) {
                for (tag2, value2) in inner {
                    parts.push(format!("命令 tag{tag2} = {}", printable(&value2)));
                }
                continue;
            }
        }
        parts.push(format!("tag{tag} = {}", printable(&value)));
    }
    if parts.is_empty() {
        format!("明文 {}", printable(body))
    } else {
        parts.join("；")
    }
}

fn printable(value: &[u8]) -> String {
    match std::str::from_utf8(value) {
        Ok(text) if text.chars().all(|c| !c.is_control()) => {
            format!("\"{text}\"（{} 字节）", value.len())
        }
        _ => format!("{}（{} 字节）", hex_head(value), value.len()),
    }
}

fn hex_head(value: &[u8]) -> String {
    const N: usize = 64;
    let n = value.len().min(N);
    let mut out = String::with_capacity(n * 3 + 4);
    for byte in &value[..n] {
        out.push_str(&format!("{byte:02X} "));
    }
    if value.len() > N {
        out.push('…');
    } else {
        out.pop();
    }
    out
}

fn send_progress_frame(
    chan: &mut Channel,
    byte_key: &[u8; 32],
    device_hash: &[u8],
    session_key: &[u8],
    declared_total: u64,
    received: u64,
    seq: &mut u32,
    warned: &mut bool,
) -> Result<()> {
    let total = declared_total.max(1);
    let pct = received as f64 * 100.0 / total as f64;
    let text = format!("dfileRecvPercent#{pct:.6}");
    let plain = crate::tlv_encode(1, &crate::tlv_encode(9, text.as_bytes())?)?;
    let env = transfer::encrypted_frame(device_hash, session_key, &plain, *seq as u64)?;
    let frame = transfer::bytes_frame(byte_key, &env[FRAME_HEADER_SIZE..], *seq)?;
    match chan.send(&frame) {
        Ok(()) => crate::trace::note("byte", &format!("已发进度帧 #{seq} {text}")),
        Err(e) => {
            if !*warned {
                *warned = true;
                crate::trace::note("byte", &format!("进度帧发送失败：{e}"));
            }
        }
    }
    *seq += 1;
    Ok(())
}

mod ov {
    #[cfg(windows)]
    pub use crate::overlay::{fail, finish, hide, set_multi, set_outgoing, start, update};
    #[cfg(not(windows))]
    pub fn set_outgoing(_ours: bool) {}
    #[cfg(not(windows))]
    pub fn start(_name: &str) {}
    #[cfg(not(windows))]
    pub fn set_multi(_count: usize) {}
    #[cfg(not(windows))]
    pub fn update(_received: u64, _total: u64) {}
    #[cfg(not(windows))]
    pub fn finish() {}
    #[cfg(not(windows))]
    pub fn fail() {}
    #[cfg(not(windows))]
    pub fn hide() {}
}

struct PartGuard {
    path: Option<PathBuf>,
    keep: bool,
}

impl PartGuard {
    fn new() -> Self {
        Self { path: None, keep: false }
    }
    fn track(&mut self, p: PathBuf) {
        self.path = Some(p);
    }
    fn clear(&mut self) {
        self.path = None;
    }
    fn commit(&mut self) {
        self.keep = true;
    }
}

impl Drop for PartGuard {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        if let Some(p) = self.path.take() {
            match std::fs::remove_file(&p) {
                Ok(()) => crate::trace::note("file#1", &format!("已删除未完成文件 {}", p.display())),
                Err(e) => crate::trace::note(
                    "file#1",
                    &format!("删除未完成文件失败 {}：{e}", p.display()),
                ),
            }
        }
    }
}

struct OverlayGuard {
    done: bool,
}
impl Drop for OverlayGuard {
    fn drop(&mut self) {
        if self.done {
            return;
        }

        ov::fail();
        ov::hide();
    }
}

fn merge_manifest(expected: &mut Vec<(u16, u64, String)>, data: &[u8]) -> usize {
    if data.len() < 2 {
        return 0;
    }
    let mut offset = 2usize;
    let mut added = 0usize;
    while offset + 12 <= data.len() {
        let id = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let size_bytes: [u8; 8] = match data[offset + 2..offset + 10].try_into() {
            Ok(v) => v,
            Err(_) => break,
        };
        let fsize = u64::from_be_bytes(size_bytes);
        let nlen = u16::from_be_bytes([data[offset + 10], data[offset + 11]]) as usize;
        offset += 12;
        if offset + nlen > data.len() {
            break;
        }
        let name = String::from_utf8_lossy(&data[offset..offset + nlen]).to_string();
        offset += nlen;
        if expected.iter().any(|(eid, _, _)| *eid == id) {
            crate::trace::note("file#1", &format!("清单里 id={id} 重复，忽略后一条"));
            continue;
        }
        if fsize == 0 {
            crate::trace::note(
                "file#1",
                &format!("清单里 {name} 是 0 字节，跳过（不参与收尾计数）"),
            );
            continue;
        }
        if name.trim().is_empty() {
            crate::trace::note("file#1", &format!("清单里 id={id} 没有文件名，忽略"));
            continue;
        }
        expected.push((id, fsize, name));
        added += 1;
    }
    added
}

fn ack_manifest(
    chan: &mut Channel,
    key: &[u8],
    trans: u16,
    expected: &[(u16, u64, String)],
) -> Result<()> {
    let mut ids: Vec<u8> = Vec::with_capacity(expected.len() * 2);
    for (id, _, _) in expected {
        ids.extend_from_slice(&id.to_be_bytes());
    }
    let ack = transfer::dfile_packet(2, 0, 0, trans, &ids)?;
    chan.send(&transfer::dfile_encrypt_control(key, &ack)?)
}

fn run_session_once(
    session: &Session,
    control: &mut Channel,
    destination: &Path,
    display_name: &str,
    timeout: Duration,
    progress: &AtomicU64,
) -> Result<ReceiveResult> {
    let key = session.session_key;

    #[cfg(feature = "diag")]
    {
        if std::env::var("HWSHARE_DEBUG_KEYS").is_ok() {
            crate::trace::note(
                "control",
                &format!("DEBUG session_key={}", crate::hex_upper(&key)),
            );
        }
    }
    let sess_t0 = Instant::now();
    let local_ip = control
        .local_ip()
        .unwrap_or_else(|| "0.0.0.0".to_string());

    if session.accepted {
        if let Some(ms) = confirm_delay_ms() {
            eprintln!("[实验] user_confirm 延时 {ms} ms 再发");
            std::thread::sleep(Duration::from_millis(ms));
        }
    }
    let verdict: &[u8] = if session.accepted { b"user_confirm" } else { b"user_reject" };
    let verdict_frame = transfer::encrypted_frame(
        &session.device_hash,
        &key,
        &tlv_encode(1, &tlv_encode(1, verdict)?)?,
        6,
    )?;
    if session.accepted {
        control.send(&verdict_frame)?;
        if crate::trace::enabled() {
            crate::trace::note("control", "已回 user_confirm，进入三路轮询");
        }
    } else {
        let _ = control.send(&verdict_frame);
        if crate::trace::enabled() {
            crate::trace::note("control", "已回 user_reject（发送失败也按拒绝收尾）");
        }
        return Ok(ReceiveResult { saved: Vec::new(), bytes: 0 });
    }

    if std::env::var("HWSHARE_PHONE_ROLE").is_ok() {
        let addr = local_ip.as_bytes();
        let mut fields = Vec::new();
        fields.extend(tlv_encode(1, b"")?);
        fields.extend(tlv_encode(2, b"")?);
        fields.extend(tlv_encode(3, b"")?);
        fields.extend(tlv_encode(4, addr)?);
        control.send(&transfer::encrypted_frame(
            &session.device_hash,
            &key,
            &tlv_encode(4, &fields)?,
            7,
        )?)?;
        control.send(&transfer::encrypted_frame(
            &session.device_hash,
            &key,
            &tlv_encode(10, &tlv_encode(1, addr)?)?,
            8,
        )?)?;
        let node = crate::hex_upper(&crate::sha256(&session.device_hash));
        let device_type = meta_device_type();
        let info = format!(
            r#"{{"DEVICE_NAME":"{display_name}","DEVICE_TYPE_ID":{device_type},"META_NODE_ID":"{node}","FLAG":100}}"#
        );
        control.send(&transfer::channel_frame(
            &key,
            (META_INFO, 5, 0, 0, 0),
            info.as_bytes(),
            0,
        )?)?;
    }

    std::fs::create_dir_all(destination).map_err(|e| Error::Io(format!("创建目录失败: {e}")))?;

    let debug = std::env::var("HWSHARE_DEBUG").is_ok();
    if debug { eprintln!("[rust-recv] 已发 user_confirm，进入三路轮询"); }

    let mut deadline = Instant::now() + timeout;
    let mut byte_channel: Option<Channel> = None;
    let mut file_channel: Option<Channel> = None;

    let mut file_port: Option<u16> = None;
    #[allow(unused_assignments)]
    let mut byte_listener: Option<Listener> = None;
    let mut file_listener: Option<Listener> = None;
    let mut byte_key: Option<[u8; 32]> = None;
    let mut file_key: Option<[u8; 32]> = None;
    let mut preview_acked = false;

    let mut byte_errors: u32 = 0;

    let eco_byte_on = std::env::var("HWSHARE_ECO_BYTE").ok().as_deref() != Some("0");

    let mut eco_byte_last = Instant::now() - Duration::from_secs(2);
    let mut eco_byte_seq: u32 = 1;
    let mut eco_byte_err = false;

    let mut expected_files: Vec<(u16, u64, String)> = Vec::new();
    let mut settings_seen = false;
    let mut header_seen = false;
    let mut transaction: Option<u16> = None;
    let mut active: Option<u16> = None;

    let mut active_file: Option<ActiveFile> = None;
    let mut current_declared: u64 = 0;
    let mut current_name = String::new();
    let mut done_sent = false;
    let mut done_acked = false;
    let mut saved: Vec<PathBuf> = Vec::new();

    let mut done_ids: Vec<u16> = Vec::new();
    let _ = &file_port;
    let mut total_received: u64 = 0;

    let mut overlay_started = false;
    let mut oguard = OverlayGuard { done: false };
    let mut part_guard = PartGuard::new();

    let mut dframe_count: u64 = 0;

    let ack5_enabled = std::env::var("HWSHARE_ACK5").ok().as_deref() == Some("1");

    let mut ack5_last = Instant::now();
    let mut ack5_counter: u16 = 0;

    let mut last_progress = Instant::now();
    let mut last_bytes = 0u64;

    let mut idle_warned = false;
    let mut last_report = Instant::now();
    let mut last_status = Instant::now();

    let eco_enabled = std::env::var("HWSHARE_ECO").ok().as_deref() == Some("1");
    let mut eco_last = Instant::now();
    let mut eco_seq: u64 = 0;

    clear_recv_cancel();
    spawn_recv_cancel_watch();
    while Instant::now() < deadline {
        if recv_cancel_requested() {
            let tag = recv_cancel_tag();
            let payload = tlv_encode(tag, b"receiverCancel")
                .and_then(|inner| tlv_encode(1, &inner));
            match payload.and_then(|p| {
                transfer::encrypted_frame(&session.device_hash, &key, &p, 7)
            }) {
                Ok(pkt) => match control.send(&pkt) {
                    Ok(()) => crate::trace::note(
                        "control",
                        &format!("已向对端发送 receiverCancel（内层 tag{tag}）"),
                    ),
                    Err(e) => crate::trace::note(
                        "control",
                        &format!("receiverCancel 发送失败：{e}"),
                    ),
                },
                Err(e) => crate::trace::note(
                    "control",
                    &format!("receiverCancel 构造失败：{e}"),
                ),
            }
            std::thread::sleep(recv_cancel_wait());
            return Err(Error::Protocol("已取消接收".to_string()));
        }
        if debug && last_status.elapsed() >= Duration::from_secs(3) {
            last_status = Instant::now();
            eprintln!(
                "[状态] settings={} preview={} 清单={}({} 个) 已收 {} 字节 已存 {} 个",
                settings_seen, preview_acked, header_seen, expected_files.len(),
                total_received, saved.len()
            );
        }

        if eco_enabled && total_received > 0 && eco_last.elapsed() >= Duration::from_secs(1) {
            eco_last = Instant::now();
            eco_seq += 1;
            let variant = ((eco_seq - 1) / 10) % 6;
            let mut payload: Vec<u8> = Vec::new();
            match variant {
                0 => payload.extend_from_slice(&total_received.to_be_bytes()),
                1 => payload.extend_from_slice(&(total_received as u32).to_be_bytes()),
                2 => {
                    payload.extend_from_slice(&total_received.to_be_bytes());
                    payload.extend_from_slice(&session.total_bytes.to_be_bytes());
                }
                3 => {
                    let pct = if session.total_bytes == 0 {
                        0
                    } else {
                        (total_received as f64 * 100.0 / session.total_bytes as f64) as u32
                    };
                    payload.extend_from_slice(&pct.to_be_bytes());
                }
                4 => {}
                _ => payload.extend_from_slice(total_received.to_string().as_bytes()),
            }
            let body = tlv_encode(1, &tlv_encode(9, &payload)?)?;
            let frame =
                transfer::encrypted_frame(&session.device_hash, &key, &body, 1000 + eco_seq)?;
            if let Err(e) = control.send(&frame) {
                eprintln!("[eco] 发送失败: {e}");
            } else {
                eprintln!(
                    "[eco] #{eco_seq} variant={variant} payload={}B recv={total_received}",
                    payload.len()
                );
            }
        }

        if done_acked && !saved.is_empty() && saved.len() >= expected_files.len() {
            if debug { eprintln!("[dfile] 全部完成，退出轮询"); }
            break;
        }
        let mut progressed = false;

        if total_received != last_bytes {
            last_bytes = total_received;
            last_progress = Instant::now();
            idle_warned = false;

            deadline = Instant::now() + timeout;
        }
        if last_report.elapsed() >= Duration::from_secs(5) && total_received > 0 {
            last_report = Instant::now();
            println!(
                "[进度] {:.1} / {:.1} MB",
                total_received as f64 / 1048576.0,
                session.total_bytes as f64 / 1048576.0
            );
        }
        let idle = last_progress.elapsed();

        if idle >= idle_limit() / 3 && !idle_warned {
            idle_warned = true;
            eprintln!(
                "[等待] 已 {:.0} 秒没有新数据，对方可能已取消或锁屏",
                idle.as_secs_f64()
            );

            #[cfg(windows)]
            if crate::tray::active() {
                crate::tray::notify(
                    "传输暂停",
                    &format!(
                        "已 {:.0} 秒没有新数据，对方可能取消了分享",
                        idle.as_secs_f64()
                    ),
                );
            }
            if crate::trace::enabled() {
                crate::trace::note(
                    "file#1",
                    &format!("数据停顿 {:.0} 秒，进入等待", idle.as_secs_f64()),
                );
            }
        }
        if idle >= idle_limit() {
            let pct = if session.total_bytes == 0 {
                0.0
            } else {
                total_received as f64 * 100.0 / session.total_bytes as f64
            };
            let partial = active_file
                .as_ref()
                .map(|f| f.part.display().to_string())
                .unwrap_or_default();

            let file_state = file_channel
                .as_ref()
                .map(|c| c.close_reason())
                .unwrap_or("none");
            let byte_state = byte_channel
                .as_ref()
                .map(|c| c.close_reason())
                .unwrap_or("none");
            let peer_closed = file_state == "eof" || byte_state == "eof";
            crate::trace::note(
                "file#1",
                &format!(
                    "空闲 {:.1}s 判中断：file#1={} byte={} 已收 {:.1} MB",
                    idle.as_secs_f64(),
                    file_state,
                    byte_state,
                    total_received as f64 / 1048576.0
                ),
            );
            let headline = if peer_closed {
                format!(
                    "对方结束了传输（已关闭数据通道，最后一份数据在 {:.0} 秒前）",
                    idle.as_secs_f64()
                )
            } else {
                format!("传输中断：{:.0} 秒没有收到数据", idle.as_secs_f64())
            };
            let _ = (&headline, &partial, pct);

            return Err(Error::Protocol(
                "传输中断：对方可能已锁屏或离开".to_string(),
            ));
        }

        if byte_channel.is_none() {
            if let Some(listener) = byte_listener.as_ref() {
                if let Some(mut chan) = listener.try_accept() {
                    chan.set_label("byte");
                    if debug { eprintln!("[byte] 通道已接入 ({})", chan.peer()); }
                    byte_channel = Some(chan);
                    byte_listener = None;
                    progressed = true;
                }
            }
        }
        if file_channel.is_none() {
            if let Some(listener) = file_listener.as_ref() {
                if let Some(mut chan) = listener.try_accept() {
                    chan.set_label("file#1");
                    if debug { eprintln!("[file] 通道已接入 ({})", chan.peer()); }
                    file_channel = Some(chan);
                    file_listener = None;
                    progressed = true;
                }
            }
        }

        if let (Some(chan), Some(fkey)) = (file_channel.as_mut(), file_key) {
            let mut drained = 0usize;
            let drain_start = Instant::now();
            while drained < DRAIN_LIMIT && drain_start.elapsed() < DRAIN_BUDGET {
                let wait = if drained == 0 { POLL } else { Duration::from_millis(1) };
                let frame = match chan.try_read_dfile(wait) {
                    Ok(Some(f)) => f,
                    Ok(None) => {
                        if chan.close_reason() == "eof" {
                            let done_now = !expected_files.is_empty()
                                && saved.len() >= expected_files.len();
                            if !done_now {
                                let pct = if session.total_bytes == 0 {
                                    0.0
                                } else {
                                    total_received as f64 * 100.0 / session.total_bytes as f64
                                };

                                if let Some(cmd) = take_pending_cancel(control, &key) {
                                    crate::trace::note(
                                        "control",
                                        &format!("文件通道 EOF 前读到取消命令：{cmd}"),
                                    );
                                    let _ = (pct, total_received);
                                    return Err(Error::Protocol(
                                        "对方取消了本次传输".to_string(),
                                    ));
                                }
                                return Err(Error::Protocol(format!(
                                    "对方中断了传输（关闭了文件通道），已收 {:.1} MB / {:.1} MB（{:.0}%）",
                                    total_received as f64 / 1048576.0,
                                    session.total_bytes as f64 / 1048576.0,
                                    pct
                                )));
                            }
                        }
                        break;
                    }
                    Err(e) => {
                        let done_now =
                            !expected_files.is_empty() && saved.len() >= expected_files.len();
                        if done_now {
                            if debug {
                                eprintln!("[dfile] 传输已完成，对端关闭连接（{e}），按成功处理");
                            }
                            break;
                        }
                        return Err(e);
                    }
                };
                drained += 1;
                progressed = true;
                let (kind, flags, sess, trans, size) = transfer::parse_dfile_header(&frame)?;

                if frame.len() < 8 + size {
                    return Err(Error::Truncated);
                }
                let payload: &[u8] = &frame[8..8 + size];
                dframe_count += 1;
                if debug && (kind != 4 || dframe_count % 512 == 0) {
                    eprintln!("[dfile] #{dframe_count} kind={kind} flags={flags} trans={trans} size={size}");
                }

                match kind {
                    8 if !settings_seen => {
                        let ok = payload.len() >= 100
                            && u16::from_be_bytes([payload[2], payload[3]]) == 2
                            && (u32::from_be_bytes([payload[20], payload[21], payload[22], payload[23]]) & 0x100) != 0
                            && payload[91] == 1
                            && (u32::from_be_bytes([payload[96], payload[97], payload[98], payload[99]]) & 1) != 0;
                        if !ok && debug {
                            eprintln!("[dfile] settings 字段与预期不同（继续）: {:02X?}", &payload[..payload.len().min(32)]);
                        }

                        if payload.len() >= 100 {
                            let mtu = u16::from_be_bytes([payload[0], payload[1]]);
                            let ctype = u16::from_be_bytes([payload[2], payload[3]]);
                            let ver = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                            let abm = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
                            let cap = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
                            let dfs = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
                            let caps = u32::from_be_bytes([payload[20], payload[21], payload[22], payload[23]]);
                            let hdr = payload[91];
                            let t1 = u32::from_be_bytes([payload[92], payload[93], payload[94], payload[95]]);
                            let t2 = u32::from_be_bytes([payload[96], payload[97], payload[98], payload[99]]);
                            let note = format!(
                                "[手机 settings·发送端] mtu={mtu} ctype={ctype} ver={ver} abm=0x{abm:X} cap=0x{cap:X} dfs={dfs} caps=0x{caps:X} hdr={hdr} tail=({t1},{t2})"
                            );
                            eprintln!("{note}");
                            crate::wire::mark("file#1", &note);
                            #[cfg(windows)]
                            crate::tray::log_line(&note);
                            if crate::trace::enabled() {
                                crate::trace::note("file#1", &note);
                            }
                        }

                        let mine = transfer::dfile_settings(true);
                        chan.send(&mine)?;
                        settings_seen = true;
                        if crate::trace::enabled() {
                            crate::trace::note(
                                "file#1",
                                &format!("已回 settings（{} 字节，明文）", mine.len()),
                            );
                        }
                        if debug {
                            eprintln!("[dfile] 已明文回 settings ({} 字节) 头={:02X?}", mine.len(), &mine[..16]);
                            eprintln!("[dfile] settings 内容 {} 字节: {:02X?}", payload.len(),
                                      &payload[..payload.len().min(110)]);
                        }
                    }

                    11 => {}

                    1 if settings_seen && !header_seen => {
                        let inner = transfer::dfile_decrypt_control(&fkey, (kind, flags, sess, trans), &payload)
                            .map_err(|e| { eprintln!("[dfile] 清单帧解密失败: {e}"); e })?;
                        let data = &inner[8..];
                        if debug {
                            eprintln!(
                                "[dfile] ===== 清单帧 {}, 明文 {} 字节 =====",
                                payload.len(), data.len()
                            );
                            eprintln!("[dfile] 前 160 字节: {:02X?}", &data[..data.len().min(160)]);
                            let dump = std::env::temp_dir().join("hwshare-header.bin");
                            if std::fs::write(&dump, data).is_ok() {
                                eprintln!("[dfile] 清单已落盘 {}", dump.display());
                            }
                        }
                        merge_manifest(&mut expected_files, data);
                        if expected_files.is_empty() {
                            return Err(Error::Protocol(
                                "对端发来的文件清单为空，无法继续".to_string(),
                            ));
                        }
                        transaction = Some(trans);
                        header_seen = true;

                        ack_manifest(chan, &fkey, trans, &expected_files)?;
                        if crate::trace::enabled() {
                            let list: Vec<String> = expected_files
                                .iter()
                                .map(|(id, size, name)| format!("{id}:{name}:{size}"))
                                .collect();
                            crate::trace::note("file#1", &format!("清单已确认 {}", list.join(",")));
                        }
                        if debug {
                            eprintln!("[dfile] 已回清单 ACK（{} 个文件）", expected_files.len());
                        }
                    }

                    1 if header_seen => {
                        let inner = transfer::dfile_decrypt_control(&fkey, (kind, flags, sess, trans), &payload)
                            .map_err(|e| { eprintln!("[dfile] 清单续帧解密失败: {e}"); e })?;
                        let added = merge_manifest(&mut expected_files, &inner[8..]);

                        ack_manifest(chan, &fkey, trans, &expected_files)?;
                        if added > 0 {
                            if crate::trace::enabled() {
                                crate::trace::note(
                                    "file#1",
                                    &format!(
                                        "清单续帧 +{added} 个，累计 {} 个",
                                        expected_files.len()
                                    ),
                                );
                            }
                        }
                    }

                    4 if header_seen && Some(trans) == transaction => {
                        let (fid, _seq, content) = transfer::dfile_parse_chunk(&fkey, &payload)
                            .map_err(|e| {
                                let n = payload.len().min(16);
                                eprintln!(
                                    "[dfile] 数据块解密失败: {e} | payload={}B flags={} trans={} size={} head={:02X?}",
                                    payload.len(), flags, trans, size, &payload[..n]
                                );
                                e
                            })?;
                        if active != Some(fid) {
                            if let Some(old) = active_file.as_ref() {
                                crate::trace::note(
                                    "file#1",
                                    &format!(
                                        "上一个文件未收完就切到 id={fid}（{} 已停写，保留 .part）",
                                        old.path.display()
                                    ),
                                );
                            }
                            active = Some(fid);
                            let entry = expected_files.iter().find(|(id, _, _)| *id == fid);
                            current_declared = entry.map(|(_, s, _)| *s).unwrap_or(0);
                            current_name = entry
                                .map(|(_, _, n)| n.clone())
                                .unwrap_or_else(|| format!("file-{fid}.bin"));
                            if !overlay_started {
                                overlay_started = true;

                                ov::set_multi(expected_files.len());

                                ov::set_outgoing(false);
                                ov::start(&current_name);
                            }

                            let target = unique_path(destination, &sanitize(&current_name));

                            let part = part_path(&target);
                            let raw = std::fs::File::create(&part).map_err(|e| {
                                Error::Io(format!("创建 {} 失败: {e}", part.display()))
                            })?;

                            preallocate(&raw, current_declared, debug);
                            let file = BufWriter::with_capacity(WRITE_BUF, raw);
                            if debug {
                                eprintln!("[dfile] 开始落盘 {}", target.display());
                            }
                            part_guard.track(part.clone());
                            active_file = Some(ActiveFile {
                                file,
                                path: target,
                                part,
                                written: 0,
                            });
                        }

                        {
                            let slot = active_file
                                .as_mut()
                                .ok_or_else(|| Error::Protocol("目标文件未打开".into()))?;
                            slot.file
                                .write_all(&content)
                                .map_err(|e| Error::Io(format!("写入失败: {e}")))?;
                            slot.written += content.len() as u64;
                            total_received += content.len() as u64;
                            if overlay_started {
                                ov::update(total_received, session.total_bytes);
                            }
                            progress.store(total_received, Ordering::Relaxed);
                            if ack5_enabled && ack5_last.elapsed() >= Duration::from_millis(140) {
                                ack5_last = Instant::now();
                                ack5_counter = ack5_counter.wrapping_add(20);

                                let mut body = vec![5u8, 0];
                                body.extend_from_slice(&1u32.to_be_bytes());
                                body.extend_from_slice(&6u16.to_be_bytes());
                                body.extend_from_slice(&ack5_counter.to_be_bytes());
                                body.extend_from_slice(&0u32.to_be_bytes());
                                let pkt = transfer::dfile_packet(5, 0, 0, trans, &body)?;
                                chan.send(&transfer::dfile_encrypt_control(&fkey, &pkt)?)?;
                            }
                        }

                        let written = active_file.as_ref().map(|f| f.written).unwrap_or(0);
                        let complete = current_declared > 0 && written >= current_declared;
                        if flags == 3 || complete {
                            let finished_id = active.unwrap_or(1);

                            if flags == 3
                                && current_declared > 0
                                && written < current_declared
                                && !allow_short_file()
                            {
                                let part = active_file
                                    .as_ref()
                                    .map(|f| f.part.display().to_string())
                                    .unwrap_or_default();

                                part_guard.clear();
                                return Err(Error::Protocol(format!(
                                    "文件不完整：{} 声明 {current_declared} 字节，只收到 {written} 字节（残包保留在 {part}）",
                                    current_name
                                )));
                            }
                            let (target, written) = match active_file.take() {
                                Some(slot) => {
                                    let ActiveFile { mut file, path, part, written } = slot;
                                    file.flush().map_err(|e| {
                                        Error::Io(format!("刷新落盘失败: {e}"))
                                    })?;

                                    drop(file);
                                    part_guard.clear();
                                    std::fs::rename(&part, &path).map_err(|e| {
                                        Error::Io(format!("改名 {} 失败: {e}", path.display()))
                                    })?;
                                    (path, written)
                                }
                                None => (destination.join(sanitize(&current_name)), 0),
                            };
                            if debug {
                                eprintln!("[dfile] 已保存 {} ({} 字节)", target.display(), written);
                            }
                            if crate::trace::enabled() {
                                crate::trace::note(
                                    "file#1",
                                    &format!(
                                        "文件完成 id={finished_id} bytes={written} path={}",
                                        target.display()
                                    ),
                                );
                            }
                            saved.push(target);
                            done_ids.push(finished_id);

                            let all_done = saved.len() >= expected_files.len().max(1);
                            let per_file = std::env::var("HWSHARE_DONE")
                                .map(|v| v.trim().eq_ignore_ascii_case("per"))
                                .unwrap_or(false);
                            if all_done || per_file {
                                let mut payload = Vec::with_capacity(done_ids.len() * 2);
                                for id in &done_ids {
                                    payload.extend_from_slice(&id.to_be_bytes());
                                }
                                let done = transfer::dfile_packet(6, 0, 0, trans, &payload)?;
                                chan.send(&transfer::dfile_encrypt_control(&fkey, &done)?)?;
                                done_sent = true;
                            }
                            active = None;
                            current_declared = 0;
                            current_name.clear();
                        }
                    }

                    9 => {
                        return Err(Error::Protocol(format!(
                            "对方中止了传输（DFile kind=9），已收 {:.1} MB",
                            total_received as f64 / 1048576.0
                        )))
                    }
                    7 if done_sent => {
                        let inner = transfer::dfile_decrypt_control(&fkey, (kind, flags, sess, trans), &payload)
                            .map_err(|e| { eprintln!("[dfile] DONE ACK 解密失败: {e}"); e })?;
                        if debug {
                            eprintln!("[dfile] DONE ACK，明文 {} 字节", inner.len().saturating_sub(8));
                        }
                        done_acked = true;
                        ov::finish();
                        oguard.done = true;
                        part_guard.commit();
                        if crate::trace::enabled() {
                            crate::trace::note("file#1", "收到 DONE ACK，会话可正常收尾");
                        }
                    }
                    _ => {
                        if debug {
                            eprintln!(
                                "[dfile] 未处理帧 kind={kind}({}) flags={flags} trans={trans} size={size} 头 {:02X?}",
                                transfer::dfile_kind_name(kind),
                                &payload[..payload.len().min(48)]
                            );
                        }
                    }
                }
            }
        }

        let mut byte_broken = false;
        if let Some(chan) = byte_channel.as_mut() {
            if eco_byte_on && preview_acked {
                if let Some(bk) = byte_key {
                    if eco_byte_last.elapsed() >= Duration::from_millis(1000) {
                        eco_byte_last = Instant::now();
                        send_progress_frame(
                            chan,
                            &bk,
                            &session.device_hash,
                            &key,
                            session.total_bytes,
                            total_received,
                            &mut eco_byte_seq,
                            &mut eco_byte_err,
                        )?;
                    }
                }
            }
            if byte_key.is_none() {
                if let Some(raw) = chan.try_read_frame(POLL)? {
                    progressed = true;
                    let wrapped = frame_encode(21, 0, 0, &raw)?;
                    let (header, plain) = transfer::decode_channel(&wrapped, &key)
                        .map_err(|e| { eprintln!("[byte] 握手帧解码失败: {e}"); e })?;
                    let value: serde_json::Value =
                        serde_json::from_slice(plain.strip_suffix(&[0]).unwrap_or(&plain))
                            .map_err(|_| { eprintln!("[byte] 握手 JSON 解析失败: {:?}", String::from_utf8_lossy(&plain[..plain.len().min(120)])); Error::Format })?;
                    if value["CODE"] != 1 || value["BUS_NAME"] != "IShareReceiverBytesSession" {
                        return Err(Error::Protocol("不支持的 byte 通道请求".into()));
                    }
                    use base64::Engine;
                    let raw_key = base64::engine::general_purpose::STANDARD
                        .decode(value["SESSION_KEY"].as_str().unwrap_or(""))
                        .map_err(|_| Error::Format)?;
                    if raw_key.len() != 32 {
                        return Err(Error::Format);
                    }
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&raw_key);
                    byte_key = Some(k);
                    if debug { eprintln!("[byte] 握手完成，byte 会话密钥已就绪"); }

                    let node = crate::hex_upper(&crate::sha256(&session.device_hash));
                    let response = format!(
                        r#"{{"CODE":1,"API_VERSION":2,"MTU_SIZE":1048576,"DEVICE_ID":"{node}","PKG_NAME":"ohos.InterConnection.iShare","TRANS_CAPABILITY":0,"AUTH_STATE":""}}"#
                    );
                    let mut body = response.into_bytes();
                    body.push(0);
                    let frame = transfer::channel_frame(
                        &key,
                        (header.0, 6, header.2, header.3 | 1, 0),
                        &body,
                        0,
                    )?;
                    let inner = &frame[FRAME_HEADER_SIZE..];
                    if debug {
                        eprintln!("[byte] 回 ACK {} 字节, 内层头={:02X?}", inner.len(), &inner[..24.min(inner.len())]);
                    }
                    chan.send(inner)?;
                }
            } else if let Some(bkey) = byte_key {
                match transfer::try_read_bytes_frame(chan, &bkey, POLL) {
                    Ok(Some((_seq, plain))) => {
                    progressed = true;
                    byte_errors = 0;

                    if debug {
                        eprintln!("[byte-rx] len={} hex={:02X?}", plain.len(), plain);
                    }

                    if let Ok(raw) = crate::frame_encode_lenient(9, 0, 0, &plain) {
                        match transfer::decrypt_frame(&raw, &key) {
                            Ok(b) if debug => {
                                eprintln!("[预览] ===== 预览帧 {} 字节 =====", b.len());
                                dump_tlvs("[预览] ", &b, 0);

                                let dump = std::env::temp_dir().join("hwshare-preview.bin");
                                if std::fs::write(&dump, &b).is_ok() {
                                    eprintln!("[预览] 已落盘 {}", dump.display());
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                if debug { eprintln!("[预览] 解密失败（应答不受影响）: {e}"); }
                            }
                        }
                    }
                    if !preview_acked {
                        let reply = transfer::encrypted_frame(
                            &session.device_hash,
                            &key,
                            &tlv_encode(1, &tlv_encode(8, b"previewOK")?)?,
                            0,
                        )?;
                        chan.send(&transfer::bytes_frame(
                            &bkey,
                            &reply[FRAME_HEADER_SIZE..],
                            0,
                        )?)?;
                        preview_acked = true;
                        if crate::trace::enabled() {
                            crate::trace::note("byte", "已回 previewOK");
                        }
                        if debug { eprintln!("[byte] 已回 previewOK"); }
                    }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        byte_errors += 1;
                        if byte_errors <= 3 {
                            if debug {
                                eprintln!("[byte] 预览帧异常（第 {byte_errors} 次）: {e}");
                            }
                            crate::trace::note(
                                "byte",
                                &format!("预览帧异常（第 {byte_errors} 次）：{e}"),
                            );
                        }
                        if byte_errors >= 8 {
                            byte_broken = true;
                        }
                    }
                }
            }
        }
        if byte_broken {
            crate::trace::note("byte", "byte 通道连续 8 次解码失败，已关闭（数据面不受影响）");
            byte_channel = None;
            byte_key = None;
            byte_errors = 0;
        }

        if done_acked && !saved.is_empty() && saved.len() >= expected_files.len() {
            if debug { eprintln!("[dfile] 已收齐并 ACK，跳过主通道尾部"); }
            break;
        }

        let ctl_frame = match control.try_read_frame(POLL) {
            Ok(f) => f,
            Err(e) => {
                let done_now =
                    !expected_files.is_empty() && saved.len() >= expected_files.len();
                if done_now {
                    if debug { eprintln!("[ctl] 传输已完成，对端关闭连接（{e}），按成功处理"); }
                    None
                } else {
                    return Err(e);
                }
            }
        };

        if ctl_frame.is_none() && control.close_reason() == "eof" {
            let done_now = !expected_files.is_empty() && saved.len() >= expected_files.len();
            if !done_now {
                let pct = if session.total_bytes == 0 {
                    0.0
                } else {
                    total_received as f64 * 100.0 / session.total_bytes as f64
                };

                if control.buffered_len() > 0 {
                    if let Some(cmd) = take_pending_cancel(control, &key) {
                        crate::trace::note(
                            "control",
                            &format!("控制通道 EOF 前读到取消命令：{cmd}"),
                        );
                        return Err(Error::Protocol("对方取消了本次传输".to_string()));
                    }
                }
                crate::trace::note(
                    "control",
                    &format!(
                        "控制通道 EOF，判定对方结束传输，已收 {:.1} MB",
                        total_received as f64 / 1048576.0
                    ),
                );
                return Err(Error::Protocol(format!(
                    "对方中断了本次分享（关闭了控制通道），已收 {:.1} MB / {:.1} MB（{:.0}%）",
                    total_received as f64 / 1048576.0,
                    session.total_bytes as f64 / 1048576.0,
                    pct
                )));
            }
        }

        if let Some(frame) = ctl_frame {
            let module = u32::from_le_bytes(frame[4..8].try_into().unwrap());

            if module == 9 {
                let body = transfer::decrypt_frame(&frame, &key)
                    .map_err(|e| { eprintln!("[ctrl] 控制帧解密失败: {e} (len={})", frame.len()); e })?;

                if debug {
                    if let Ok(list) = tlvs(&body) {
                        let tags: Vec<(u64, usize)> =
                            list.iter().map(|(t, v)| (*t, v.len())).collect();
                        eprintln!(
                            "[ctl {:>6.2}s recv={:>7.1}MB] tags={:?}",
                            sess_t0.elapsed().as_secs_f64(),
                            total_received as f64 / 1048576.0,
                            tags
                        );
                    }
                }

                let Ok(fields) = tlvs(&body) else {
                    crate::trace::note("control", "控制帧 TLV 解析失败，已忽略该帧");
                    continue;
                };
                for (tag, value) in fields {
                    if tag == 4 {
                        let mut fields = Vec::new();
                        fields.extend(tlv_encode(1, b"")?);
                        fields.extend(tlv_encode(2, b"")?);
                        fields.extend(tlv_encode(3, b"true")?);
                        let reply = tlv_encode(5, &fields)?;
                        control.send(&transfer::encrypted_frame(
                            &session.device_hash,
                            &key,
                            &reply,
                            0,
                        )?)?;
                    } else if tag == 10 {
                        let addr = tlv_get(&value, 1)?.unwrap_or_default();
                        let reply = tlv_encode(10, &tlv_encode(1, &addr)?)?;
                        control.send(&transfer::encrypted_frame(
                            &session.device_hash,
                            &key,
                            &reply,
                            0,
                        )?)?;
                    } else if tag == 1 {
                        if let Ok(cmds) = transfer::tlvs(&value) {
                            for (cmd_tag, field) in cmds {
                                if crate::trace::enabled() {
                                    crate::trace::note(
                                        "control",
                                        &format!(
                                            "对端控制命令 内层tag={cmd_tag} 值=\"{}\"（已收 {} 字节）",
                                            String::from_utf8_lossy(&field),
                                            total_received
                                        ),
                                    );
                                }

                                if field == b"senderCancel" {
                                    if let (Some(bc), Some(bk)) = (byte_channel.as_mut(), byte_key) {
                                        let ack = tlv_encode(3, b"senderCancelACK")
                                            .and_then(|inner| tlv_encode(1, &inner))
                                            .and_then(|p| {
                                                transfer::encrypted_frame(
                                                    &session.device_hash,
                                                    &key,
                                                    &p,
                                                    eco_byte_seq as u64,
                                                )
                                            })
                                            .and_then(|env| {
                                                transfer::bytes_frame(
                                                    &bk,
                                                    &env[FRAME_HEADER_SIZE..],
                                                    eco_byte_seq,
                                                )
                                            });
                                        match ack {
                                            Ok(pkt) => match bc.send(&pkt) {
                                                Ok(()) => {
                                                    crate::trace::note(
                                                        "byte",
                                                        &format!(
                                                            "已回 senderCancelACK（seq={eco_byte_seq}）"
                                                        ),
                                                    );
                                                    eco_byte_seq += 1;
                                                }
                                                Err(e) => crate::trace::note(
                                                    "byte",
                                                    &format!("回 senderCancelACK 失败：{e}"),
                                                ),
                                            },
                                            Err(e) => crate::trace::note(
                                                "byte",
                                                &format!("构造 senderCancelACK 失败：{e}"),
                                            ),
                                        }
                                    }
                                }
                                if field == b"senderCancel"
                                    || field == b"receiverCancel"
                                    || field == b"user_reject"
                                {
                                    let _ = &field;
                                    return Err(Error::Protocol(
                                        "对方取消了本次传输".to_string(),
                                    ));
                                }
                            }
                        }
                    }
                }
                continue;
            }

            let (header, plain) = transfer::decode_channel(&frame, &key)
                .map_err(|e| { eprintln!("[chan] 通道帧解码失败: {e}"); e })?;

            crate::trace::note(
                "control",
                &format!(
                    "通道帧 hdr=({:#X},{},{},{},{}) n={} body={}",
                    header.0,
                    header.1,
                    header.2,
                    header.3,
                    header.4,
                    plain.len(),
                    String::from_utf8_lossy(&plain[..plain.len().min(240)])
                ),
            );

            if header.0 == META_INFO {
                if debug {
                    let info = String::from_utf8_lossy(plain.strip_suffix(&[0]).unwrap_or(&plain));
                    eprintln!("[meta] 手机 META_INFO {} 字节: {info}", plain.len());
                }
                let node = crate::hex_upper(&crate::sha256(&session.device_hash));
                let device_type = meta_device_type();
                let info = format!(
                    r#"{{"DEVICE_NAME":"{display_name}","DEVICE_TYPE_ID":{device_type},"META_NODE_ID":"{node}","FLAG":100}}"#
                );
                control.send(&transfer::channel_frame(
                    &key,
                    (META_INFO, 5, 0, 0, 0),
                    info.as_bytes(),
                    0,
                )?)?;
                control.send(&transfer::channel_frame(
                    &key,
                    (META_ACK, 5, header.2, 0, 0),
                    META_ACK_TEXT,
                    0,
                )?)?;
                continue;
            }
            if header.0 == META_ACK && plain == META_ACK_TEXT {
                continue;
            }

            let text = String::from_utf8_lossy(plain.strip_suffix(&[0]).unwrap_or(&plain)).to_string();
            if debug {
                eprintln!("[chan] hdr=({:#X},{},{},{},{}) plain={:?}",
                          header.0, header.1, header.2, header.3, header.4,
                          &text[..text.len().min(160)]);
            }

            let value: serde_json::Value = match serde_json::from_slice(
                plain.strip_suffix(&[0]).unwrap_or(&plain),
            ) {
                Ok(v) => v,
                Err(_) => {
                    let brief: String = text.chars().take(160).collect();
                    let hex: String =
                        plain.iter().take(96).map(|b| format!("{b:02X}")).collect();
                    crate::trace::note(
                        "control",
                        &format!(
                            "非 JSON 通道帧 hdr=({:#X},{},{},{},{}) n={} text={:?} hex={}",
                            header.0, header.1, header.2, header.3, header.4,
                            plain.len(), brief, hex
                        ),
                    );
                    if brief.to_ascii_uppercase().contains("CANCEL") || brief.contains("取消") {
                        return Err(Error::Protocol(
                            "对方取消了本次传输".to_string(),
                        ));
                    }
                    continue;
                }
            };

            if header.0 == CHANNEL_BYTES && header.1 == 16 && header.3 == 0 {
                if value["CODE"] != 3 {
                    return Err(Error::Format);
                }
                let listener = Listener::bind(&local_ip, 0)?;
                let port = listener.port;
                let reply = format!(
                    r#"{{"CODE":3,"P2P_IP":"{local_ip}","P2P_PORT":{port},"PROTOCOL_TYPE":4}}"#
                );
                let mut body = reply.into_bytes();
                body.push(0);
                control.send(&transfer::channel_frame(
                    &key,
                    (header.0, 16, header.2, 1, 0),
                    &body,
                    0,
                )?)?;
                byte_listener = Some(listener);
                continue;
            }

            if header.0 == CHANNEL_BYTES && header.1 == 17 && header.3 == 0 {
                if value["CODE"] != 1538 {
                    return Err(Error::Format);
                }
                let brief: String = text.chars().take(260).collect();
                crate::trace::note(
                    "control",
                    &format!(
                        "file 通道请求 hdr=({:#X},{},{},{},{}) n={} json={}",
                        header.0, header.1, header.2, header.3, header.4,
                        plain.len(), brief
                    ),
                );

                if file_channel.is_some() || file_listener.is_some() {
                    let brief: String = text.chars().take(240).collect();
                    crate::trace::note(
                        "control",
                        &format!(
                            "重复的 file 通道请求 hdr=({:#X},{},{},{},{}) n={} json={}",
                            header.0, header.1, header.2, header.3, header.4,
                            plain.len(), brief
                        ),
                    );

                    let ch2_mode = std::env::var("HWSHARE_CH2").unwrap_or_default();
                    let peer_ch = value["MY_CHANNEL_ID"].as_u64().unwrap_or(0);

                    if ch2_mode.eq_ignore_ascii_case("new") {
                        let listener = Listener::bind(&local_ip, 0)?;
                        let port = listener.port;

                        let bin = crate::trace::current_path()
                            .and_then(|p| p.parent().map(|d| d.join("ch2.bin")))
                            .unwrap_or_else(|| std::path::PathBuf::from("ch2.bin"));
                        std::thread::spawn(move || {
                            crate::trace::note("control", "通道2 探针启动，等手机接入");
                            let Ok(mut chan) = listener.accept(Duration::from_secs(15)) else {
                                crate::trace::note("control", "通道2 探针：15 秒内没等到接入");
                                return;
                            };
                            chan.set_label("file#2");
                            crate::trace::note("control", "通道2 已接入，开始 dump");
                            let mut out = match std::fs::File::create(&bin) {
                                Ok(f) => f,
                                Err(e) => {
                                    crate::trace::note("control", &format!("通道2 dump 创建失败: {e}"));
                                    return;
                                }
                            };
                            let mut total = 0u64;
                            loop {
                                match chan.read_frame(Duration::from_secs(5)) {
                                    Ok(f) => {
                                        use std::io::Write;
                                        let _ = out.write_all(&f);
                                        total += f.len() as u64;
                                    }
                                    Err(e) => {
                                        crate::trace::note(
                                            "control",
                                            &format!("通道2 dump 结束：{total} 字节（{e}）"),
                                        );
                                        break;
                                    }
                                }
                            }
                            crate::trace::note(
                                "control",
                                &format!("通道2 dump: {} 共 {total} 字节", bin.display()),
                            );
                        });
                        let reply = format!(
                            r#"{{"MY_CHANNEL_ID":2,"PEER_CHANNEL_ID":{peer_ch},"P2P_PORT":{port},"MY_IP":"{local_ip}","CODE":1538,"STREAM_TYPE":255,"PKG_NAME":"ohos.InterConnection.iShare","BUSINESS_TYPE":3,"API_VERSION":0,"TRANS_CAPABILITY":0,"UDP_CHANNEL_CAPABILITY":0}}"#
                        );
                        let mut body = reply.into_bytes();
                        body.push(0);
                        control.send(&transfer::channel_frame(
                            &key,
                            (header.0, 17, header.2, 1, 0),
                            &body,
                            0,
                        )?)?;
                        crate::trace::note(
                            "control",
                            &format!("通道握手第二步 → 应答「新通道 2 / 端口 {port}」并起探针"),
                        );
                    } else if let Some(port) = file_port {
                        let reply = format!(
                            r#"{{"MY_CHANNEL_ID":1,"PEER_CHANNEL_ID":{peer_ch},"P2P_PORT":{port},"MY_IP":"{local_ip}","CODE":1538,"STREAM_TYPE":255,"PKG_NAME":"ohos.InterConnection.iShare","BUSINESS_TYPE":3,"API_VERSION":0,"TRANS_CAPABILITY":0,"UDP_CHANNEL_CAPABILITY":0}}"#
                        );
                        let mut body = reply.into_bytes();
                        body.push(0);
                        control.send(&transfer::channel_frame(
                            &key,
                            (header.0, 17, header.2, 1, 0),
                            &body,
                            0,
                        )?)?;
                        crate::trace::note(
                            "control",
                            &format!(
                                "通道握手第二步 → 已应答（通道 1 / 端口 {port} / 对端通道 {peer_ch}）"
                            ),
                        );
                    } else {
                        crate::trace::note(
                            "control",
                            "重复的 file 通道请求：没有可用端口，无法应答",
                        );
                    }
                    continue;
                }
                use base64::Engine;
                let raw_key = base64::engine::general_purpose::STANDARD
                    .decode(value["SESSION_KEY"].as_str().unwrap_or(""))
                    .map_err(|_| Error::Format)?;
                if raw_key.len() != 32 {
                    return Err(Error::Format);
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(&raw_key);
                file_key = Some(k);

                let listener = Listener::bind(&local_ip, 0)?;
                let port = listener.port;
                file_port = Some(port);
                let _ = file_port;
                let reply = format!(
                    r#"{{"MY_CHANNEL_ID":1,"P2P_PORT":{port},"MY_IP":"{local_ip}","CODE":1538,"STREAM_TYPE":255,"PKG_NAME":"ohos.InterConnection.iShare","BUSINESS_TYPE":3,"API_VERSION":0,"TRANS_CAPABILITY":0,"UDP_CHANNEL_CAPABILITY":0}}"#
                );
                let mut body = reply.into_bytes();
                body.push(0);
                control.send(&transfer::channel_frame(
                    &key,
                    (header.0, 17, header.2, 1, 0),
                    &body,
                    0,
                )?)?;
                file_listener = Some(listener);
                continue;
            }

            let brief: String = text.chars().take(240).collect();
            crate::trace::note(
                "control",
                &format!(
                    "未识别通道帧 hdr=({:#X},{},{},{},{}) json={}",
                    header.0, header.1, header.2, header.3, header.4, brief
                ),
            );
            if brief.to_ascii_uppercase().contains("CANCEL") || brief.contains("取消") {
                return Err(Error::Protocol("对方取消了本次传输".to_string()));
            }
            continue;
        }

        if !progressed {
            std::thread::sleep(Duration::from_millis(10));
        }

        if !saved.is_empty() && saved.len() >= expected_files.len().max(1) && active.is_none() {
            break;
        }
    }

    let expected = expected_files.len();
    if saved.is_empty() {
        return Err(Error::Protocol(if expected == 0 {
            format!(
                "等待对端开始传输超时（{} 秒内没收到文件清单）",
                timeout.as_secs()
            )
        } else {
            format!("传输超时：清单 {expected} 个文件，一个都没收完")
        }));
    }
    if saved.len() < expected {
        return Err(Error::Protocol(format!(
            "传输超时：清单 {expected} 个文件，只收完 {} 个（共 {:.1} MB）",
            saved.len(),
            total_received as f64 / 1048576.0
        )));
    }

    ov::finish();
    oguard.done = true;
    Ok(ReceiveResult { saved, bytes: total_received })
}

fn meta_device_type() -> u32 {
    std::env::var("HWSHARE_META_TYPE")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|n| *n <= 255)
        .unwrap_or(12)
}

fn confirm_delay_ms() -> Option<u64> {
    std::env::var("HWSHARE_CONFIRM_DELAY_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(|ms| ms.min(30_000))
}

#[allow(dead_code)]
fn tlv4(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + value.len());
    v.extend_from_slice(&tag.to_be_bytes());
    v.extend_from_slice(&(value.len() as u16).to_be_bytes());
    v.extend_from_slice(value);
    v
}

fn sanitize(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
    let cleaned: String = base
        .chars()
        .map(|c| if c.is_control() || "<>:\"|?*".contains(c) { '_' } else { c })
        .collect();
    let cleaned = cleaned.trim_end_matches(['.', ' ']).to_string();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return "received.bin".to_string();
    }
    if is_reserved_device_name(&cleaned) {
        return truncate_chars(&format!("_{cleaned}"), 120);
    }
    truncate_chars(&cleaned, 120)
}

fn is_reserved_device_name(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim()
        .to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    let bytes = stem.as_bytes();
    bytes.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && bytes[3].is_ascii_digit()
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        text.chars().take(max).collect()
    }
}

fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !occupied(&first) {
        return first;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, format!(".{ext}")),
        _ => (name, String::new()),
    };
    for n in 1..=9999u32 {
        let candidate = dir.join(format!("{stem} ({n}){ext}"));
        if !occupied(&candidate) {
            return candidate;
        }
    }

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    dir.join(format!("{stem}-{stamp}{ext}"))
}

fn occupied(target: &Path) -> bool {
    target.exists() || part_path(target).exists()
}

fn allow_short_file() -> bool {
    std::env::var("HWSHARE_ALLOW_SHORT")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(merge_manifest(&mut expected, &frame1), 1);
        assert_eq!(merge_manifest(&mut expected, &frame2), 1);
        assert_eq!(expected.len(), 2);
        assert_eq!(expected[1].0, 2);
        assert_eq!(expected[1].1, 200);
        assert_eq!(expected[1].2, "b.bin");
    }

    #[test]
    fn describes_drained_cancel_frame() {
        let key = [7u8; 32];
        let body = tlv_encode(1, &tlv_encode(1, b"senderCancel").unwrap()).unwrap();
        let frame = transfer::encrypted_frame(&[0u8; 16], &key, &body, 1).unwrap();
        let text = describe_wire_frame(9, &frame, &key);
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
