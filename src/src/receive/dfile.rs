use super::*;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::channel::{Channel, Listener};
use crate::transfer::{self, tlv_get, tlv_list};
use crate::{frame_encode, tlv_encode, Error, Result,
            FRAME_HEADER_SIZE};

pub(super) fn dump_tlvs(prefix: &str, data: &[u8], depth: usize) {
    let Ok(fields) = tlv_list(data) else {
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
            if let Ok(inner) = tlv_list(&value) {
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

pub(super) fn idle_limit() -> Duration {
    static RECV_GUARD_LIMIT: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *RECV_GUARD_LIMIT.get_or_init(|| {
        std::env::var("HWSHARE_IDLE_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|n| *n >= 5)
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(8))
    })
}

pub(super) fn send_progress_frame(
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
    let env = transfer::seal_encrypted_frame(device_hash, session_key, &plain, *seq as u64)?;
    let wire_frame = transfer::bytes_frame(byte_key, &env[FRAME_HEADER_SIZE..], *seq)?;
    match chan.transmit(&wire_frame) {
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

pub(super) struct PartGuard {
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

pub(super) struct OverlayGuard {
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

pub(super) fn run_session_once(
    session: &Session,
    control: &mut Channel,
    destination: &Path,
    display_name: &str,
    timeout: Duration,
    progress: &AtomicU64,
) -> Result<ReceiveResult> {
    let key = session.session_key;
    let sess_t0 = Instant::now();
    let local_ip = control
        .local_ip()
        .unwrap_or_else(|| "0.0.0.0".to_string());

    let verdict: &[u8] = if session.accepted { b"user_confirm" } else { b"user_reject" };
    let verdict_frame = transfer::seal_encrypted_frame(
        &session.device_hash,
        &key,
        &tlv_encode(1, &tlv_encode(1, verdict)?)?,
        6,
    )?;
    if session.accepted {
        control.transmit(&verdict_frame)?;
        if crate::trace::enabled() {
            crate::trace::note("control", "已回 user_confirm，进入三路轮询");
        }
    } else {
        let _ = control.transmit(&verdict_frame);
        if crate::trace::enabled() {
            crate::trace::note("control", "已回 user_reject（发送失败也按拒绝收尾）");
        }
        return Ok(ReceiveResult { saved: Vec::new(), bytes: 0 });
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
    let mut meta_sent = false;
    let mut my_meta_seq: Option<u64> = None;
    let mut tag10_replied = false;
    let mut peer_meta_seq: Option<u64> = None;
    let device_type = crate::outbound::DEVICE_TYPE_ID;
    let mut byte_key: Option<[u8; 32]> = None;
    let mut file_key: Option<[u8; 32]> = None;
    let mut preview_acked = false;
    let mut byte_errors: u32 = 0;
    let mut eco_byte_last = Instant::now() - Duration::from_secs(2);
    let mut eco_byte_seq: u32 = 1;
    let mut eco_byte_err = false;

    let mut expected_files: Vec<(u16, u64, String)> = Vec::new();
    let mut empty_files: Vec<(u16, String)> = Vec::new();
    let total_expected = session.file_count as usize;
    let mut base_saved: usize = 0;
    let mut pending_more = false;
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
    let mut last_progress = Instant::now();
    let mut last_bytes = 0u64;
    let mut idle_warned = false;
    let mut last_report = Instant::now();
    let mut last_status = Instant::now();
    clear_recv_cancel();
    while Instant::now() < deadline {
        if recv_cancel_requested() {
            let tag = RECV_CANCEL_TAG;
            let payload = tlv_encode(tag, b"receiverCancel")
                .and_then(|inner| tlv_encode(1, &inner));
            match payload.and_then(|p| {
                transfer::seal_encrypted_frame(&session.device_hash, &key, &p, 7)
            }) {
                Ok(pkt) => match control.transmit(&pkt) {
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
            std::thread::sleep(RECV_CANCEL_WAIT);
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
        if done_acked && !pending_more && !expected_files.is_empty()
            && saved.len() - base_saved >= expected_files.len() {
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
                let wire_frame = match chan.try_read_dfile(wait) {
                    Ok(Some(f)) => f,
                    Ok(None) => {
                        if chan.close_reason() == "eof" {
                            let done_now = !pending_more && !expected_files.is_empty()
                                && saved.len() - base_saved >= expected_files.len();
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
                        let done_now = !pending_more && !expected_files.is_empty()
                            && saved.len() - base_saved >= expected_files.len();
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
                let (kind, flags, sess, trans, size) = transfer::parse_dfile_header(&wire_frame)?;
                if wire_frame.len() < 8 + size {
                    return Err(Error::Truncated);
                }
                let payload: &[u8] = &wire_frame[8..8 + size];
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
                            let note = format!(
                                "[对端 settings·发送端] mtu={mtu} ctype={ctype} ver={ver} abm=0x{abm:X} cap=0x{cap:X} dfs={dfs} caps=0x{caps:X} len={}",
                                payload.len()
                            );
                            eprintln!("{note}");
                            crate::trace::note("file#1", &note);
                            let cipher = transfer::negotiate_cipher(
                                transfer::settings_cipher_caps(payload),
                            );
                            crate::trace::note("file#1", &format!("会话密码 → {cipher:?}"));
                        }
                        let mine = transfer::build_settings_payload(true);
                        chan.transmit(&mine)?;
                        let mut congest = Vec::with_capacity(32);
                        congest.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 24]);
                        congest.extend_from_slice(&[
                            0x00, 0x00, 0x01, 0xb0, 0x00, 0x00, 0x01, 0xb0, 0xff, 0xff, 0xff, 0xea,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ]);
                        chan.transmit(&congest)?;
                        crate::trace::note("file#1", "已回 CONGEST（11/32，接收端版本）");
                        settings_seen = true;
                        if crate::trace::enabled() {
                            crate::trace::note(
                                "file#1",
                                &format!("已回 settings（{} 字节，明文）", mine.len()),
                            );
                        }
                        if debug {
                            eprintln!("[dfile] 已明文回 settings ({} 字节) 头={:02X?}", mine.len(), &mine[..16]);
                            eprintln!("[dfile] 官方 settings 内容 {} 字节: {:02X?}", payload.len(),
                                      &payload[..payload.len().min(110)]);
                        }
                    }
                    11 => {}
                    1 if settings_seen && !header_seen => {
                        let inner = transfer::open_control_block(&fkey, (kind, flags, sess, trans), &payload)
                            .map_err(|e| { eprintln!("[dfile] 清单帧解密失败: {e}"); e })?;
                        let data = &inner[8..];
                        if debug {
                            eprintln!(
                                "[dfile] ===== 官方清单帧 {}, 明文 {} 字节 =====",
                                payload.len(), data.len()
                            );
                            eprintln!("[dfile] 前 160 字节: {:02X?}", &data[..data.len().min(160)]);
                            let dump = std::env::temp_dir().join("hwshare-header.bin");
                            if std::fs::write(&dump, data).is_ok() {
                                eprintln!("[dfile] 清单已落盘 {}", dump.display());
                            }
                        }
                        pending_more = false;
                        done_acked = false;
                        done_sent = false;
                        base_saved = saved.len();
                        merge_manifest(&mut expected_files, &mut empty_files, data);
                        if expected_files.is_empty() {
                            return Err(Error::Protocol(
                                "对端发来的文件清单为空，无法继续".to_string(),
                            ));
                        }
                        transaction = Some(trans);
                        header_seen = true;
                        ack_manifest(chan, &fkey, trans, &expected_files, &empty_files)?;
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
                        let inner = transfer::open_control_block(&fkey, (kind, flags, sess, trans), &payload)
                            .map_err(|e| { eprintln!("[dfile] 清单续帧解密失败: {e}"); e })?;
                        let added = merge_manifest(&mut expected_files, &mut empty_files, &inner[8..]);
                        ack_manifest(chan, &fkey, trans, &expected_files, &empty_files)?;
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
                            let safe_name = sanitize(&current_name);
                            let (target, part, raw) = create_part_atomic(destination, &safe_name)
                                .map_err(|e| {
                                    Error::Io(format!(
                                        "创建接收文件失败（目录 {}）: {e}",
                                        destination.display()
                                    ))
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
                        }

                        let written = active_file.as_ref().map(|f| f.written).unwrap_or(0);
                        let complete = current_declared > 0 && written >= current_declared;
                        if flags == 3 || complete {
                            let finished_id = active.unwrap_or(1);
                            if flags == 3 && current_declared > 0 && written < current_declared {
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
                                    let path = if path.exists() {
                                        unique_path(destination, &sanitize(&current_name))
                                    } else {
                                        path
                                    };
                                    std::fs::rename(&part, &path).map_err(|e| {
                                        Error::Io(format!("改名 {} 失败: {e}", path.display()))
                                    })?;
                                    (Some(path), written)
                                }
                                None => {
                                    crate::trace::note(
                                        "file#1",
                                        &format!(
                                            "结束帧到达但文件从未打开：{current_name}，跳过记录"
                                        ),
                                    );
                                    (None, 0)
                                }
                            };
                            if let Some(target) = target {
                                if debug {
                                    eprintln!(
                                        "[dfile] 已保存 {} ({} 字节)",
                                        target.display(),
                                        written
                                    );
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
                            }
                            done_ids.push(finished_id);
                            let all_done =
                                saved.len() - base_saved >= expected_files.len().max(1);
                            if all_done {
                                if !empty_files.is_empty() {
                                    for (_, name) in empty_files.drain(..) {
                                        let safe = sanitize(&name);
                                        if safe.trim().is_empty() {
                                            continue;
                                        }
                                        match create_part_atomic(destination, &safe) {
                                            Ok((target, part, raw)) => {
                                                drop(raw);
                                                if let Err(e) = std::fs::rename(&part, &target) {
                                                    crate::trace::note(
                                                        "file#1",
                                                        &format!("空文件改名失败 {name}: {e}"),
                                                    );
                                                    continue;
                                                }
                                                crate::trace::note(
                                                    "file#1",
                                                    &format!("空文件已创建 {}", target.display()),
                                                );
                                                saved.push(target);
                                            }
                                            Err(e) => crate::trace::note(
                                                "file#1",
                                                &format!("空文件创建失败 {name}: {e}"),
                                            ),
                                        }
                                    }
                                }
                                let mut payload = Vec::with_capacity(done_ids.len() * 2);
                                for id in &done_ids {
                                    payload.extend_from_slice(&id.to_be_bytes());
                                }
                                let done = transfer::assemble_dfile_packet(6, 0, 0, trans, &payload)?;
                                chan.transmit(&transfer::dfile_seal_control(&fkey, &done)?)?;
                                done_sent = true;
                                if saved.len() < total_expected {
                                    pending_more = true;
                                    expected_files.clear();
                                    empty_files.clear();
                                    done_ids.clear();
                                    header_seen = false;
                                    transaction = None;
                                    done_sent = false;
                                    done_acked = false;
                                    base_saved = saved.len();
                                    crate::trace::note(
                                        "file#1",
                                        &format!(
                                            "事务 {trans} 完成，累计 {}/{}，等待下一个事务",
                                            saved.len(),
                                            total_expected
                                        ),
                                    );
                                }
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
                        let inner = transfer::open_control_block(&fkey, (kind, flags, sess, trans), &payload)
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
            if preview_acked {
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
                    let (header, plain) = transfer::parse_channel_frame(&wrapped, &key)
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

                    let node = crate::hex_lower(&crate::sha256(&session.device_hash));
                    let response = if session.peer_apple {
                        r#"{"API_VERSION":2,"CODE":1,"DEVICE_ID":"","MTU_SIZE":4194304,"PKG_NAME":"ohos.InterConnection.iShare","TRANS_CAPABILITY":0}"#.to_string()
                    } else {
                        format!(
                            r#"{{"CODE":1,"API_VERSION":2,"MTU_SIZE":1048576,"DEVICE_ID":"{node}","PKG_NAME":"ohos.InterConnection.iShare","TRANS_CAPABILITY":0,"AUTH_STATE":""}}"#
                        )
                    };
                    let mut body = response.into_bytes();
                    body.push(0);
                    let wire_frame = transfer::seal_channel_frame(
                        &key,
                        (header.0, 6, header.2, header.3 | 1, 0),
                        &body,
                        0,
                    )?;
                    let inner = &wire_frame[FRAME_HEADER_SIZE..];
                    if debug {
                        eprintln!("[byte] 回 ACK {} 字节, 内层头={:02X?}", inner.len(), &inner[..24.min(inner.len())]);
                    }
                    chan.transmit(inner)?;
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
                        match transfer::open_channel_frame(&raw, &key) {
                            Ok(b) if debug => {
                                eprintln!("[预览] ===== 官方预览帧 {} 字节 =====", b.len());
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
                        let reply = transfer::seal_encrypted_frame(
                            &session.device_hash,
                            &key,
                            &tlv_encode(1, &tlv_encode(8, b"previewOK")?)?,
                            0,
                        )?;
                        chan.transmit(&transfer::bytes_frame(
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

        if done_acked && !pending_more && !expected_files.is_empty()
            && saved.len() - base_saved >= expected_files.len() {
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
            let done_now = !pending_more && !expected_files.is_empty()
                && saved.len() - base_saved >= expected_files.len();
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

        if let Some(wire_frame) = ctl_frame {
            let module = u32::from_le_bytes(wire_frame[4..8].try_into().unwrap());

            if module == 9 {
                let body = transfer::open_channel_frame(&wire_frame, &key)
                    .map_err(|e| { eprintln!("[ctrl] 控制帧解密失败: {e} (len={})", wire_frame.len()); e })?;
                if debug {
                    if let Ok(list) = tlv_list(&body) {
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
                let Ok(fields) = tlv_list(&body) else {
                    crate::trace::note("control", "控制帧 TLV 解析失败，已忽略该帧");
                    continue;
                };
                for (tag, value) in fields {
                    if tag == 4 {
                        let mut fields = Vec::new();
                        fields.extend(tlv_encode(1, b"")?);
                        fields.extend(tlv_encode(2, b"")?);
                        fields.extend(tlv_encode(3, b"true")?);
                        if !local_ip.is_empty() {
                            fields.extend(tlv_encode(4, local_ip.as_bytes())?);
                        }
                        let reply = tlv_encode(5, &fields)?;
                        if debug {
                            eprintln!(
                                "[trace] tag4→tag5 local_ip={:?} 回复 {} 字节",
                                local_ip,
                                reply.len()
                            );
                        }
                        control.transmit(&transfer::seal_encrypted_frame(
                            &session.device_hash,
                            &key,
                            &reply,
                            0,
                        )?)?;
                    } else if tag == 10 {
                        if debug {
                            eprintln!(
                                "[trace] tag10 收到 value={:02X?} tag10_replied={} meta_sent={} my_meta_seq={:?}",
                                value, tag10_replied, meta_sent, my_meta_seq
                            );
                        }
                        if !tag10_replied {
                            tag10_replied = true;

                            let addr = tlv_get(&value, 1)?.unwrap_or_default();
                            let reply = tlv_encode(10, &tlv_encode(1, &addr)?)?;
                            control.transmit(&transfer::seal_encrypted_frame(
                                &session.device_hash,
                                &key,
                                &reply,
                                0,
                            )?)?;
                            if debug {
                                eprintln!(
                                    "[trace] tag10 已回 addr={:?} meta_sent={}，接下来{}发 META",
                                    String::from_utf8_lossy(&addr),
                                    meta_sent,
                                    if meta_sent { "不" } else { "" }
                                );
                            }
                            if !meta_sent {
                                meta_sent = true;
                                let node = crate::hex_lower(&crate::sha256(&session.device_hash));
                                let info = format!(
                                    r#"{{"DEVICE_NAME":"{display_name}","DEVICE_TYPE_ID":{device_type},"FLAG":100,"META_AUTH_CAPA":1,"META_NODE_ID":"{node}","TOKEN_ID":"0000000000000000000000000000000000000000000000000000000000000001"}}"#
                                );
                                let meta_seq = rand::random::<u64>();
                                my_meta_seq = Some(meta_seq);
                                control.transmit(&transfer::seal_channel_frame(
                                    &key,
                                    (PEER_META_FRAME, 5, meta_seq, 0, 0),
                                    info.as_bytes(),
                                    0,
                                )?)?;
                                control.transmit(&transfer::seal_channel_frame(
                                    &key,
                                    (PEER_META_ACK_FRAME, 5, meta_seq, 0, 0),
                                    PEER_META_ACK_JSON,
                                    0,
                                )?)?;
                                if debug {
                                    eprintln!(
                                        "[trace] 已发 META_INFO(module=0x{PEER_META_FRAME:08X} seq={meta_seq} {}B) + META_ACK(0x{PEER_META_ACK_FRAME:08X})",
                                        info.len()
                                    );
                                }
                                crate::trace::note("control", "已主动发 META_INFO + META_ACK");
                            }
                        }
                    } else if tag == 1 {
                        if let Ok(cmds) = transfer::tlv_list(&value) {
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
                                                transfer::seal_encrypted_frame(
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
                                            Ok(pkt) => match bc.transmit(&pkt) {
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

            let (header, plain) = match transfer::parse_channel_frame(&wire_frame, &key) {
                Ok(v) => v,
                Err(e) => {
                    if wire_frame.len() == crate::FRAME_HEADER_SIZE {
                        crate::trace::note("control", "收到空通道帧（len=0，按确认忽略）");
                        continue;
                    }
                    match transfer::decode_channel_headerless(&wire_frame, &key) {
                        Ok((_h, p)) => {
                            crate::trace::note("control", "通道帧无内层头，已按回退布局解码");
                            ((0xFFFF_0004u32, 16u32, 0u64, 0u32, 0u32), p)
                        }
                        Err(_) => {
                            eprintln!("[chan] 通道帧解码失败: {e}");
                            continue;
                        }
                    }
                }
            };

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
                    String::from_utf8_lossy(&plain[..plain.len().min(700)])
                ),
            );

            if header.0 == PEER_META_FRAME {
                if debug {
                    let info = String::from_utf8_lossy(plain.strip_suffix(&[0]).unwrap_or(&plain));
                    eprintln!("[meta] 手机 META_INFO {} 字节: {info}", plain.len());
                }
                let peer_repeated = peer_meta_seq == Some(header.2);
                peer_meta_seq = Some(header.2);
                if debug {
                    eprintln!(
                        "[trace] 收到手机 META_INFO seq={} repeated={} my_meta_seq={:?} → {}",
                        header.2,
                        peer_repeated,
                        my_meta_seq,
                        match my_meta_seq {
                            Some(_) if peer_repeated => "补 ACK",
                            Some(_) => "不回（自己的已发过）",
                            None => "发自己的 INFO+ACK",
                        }
                    );
                }
                match my_meta_seq {
                    Some(seq) => {
                        if peer_repeated {
                            control.transmit(&transfer::seal_channel_frame(
                                &key,
                                (PEER_META_ACK_FRAME, 5, seq, 0, 0),
                                PEER_META_ACK_JSON,
                                0,
                            )?)?;
                        }
                    }
                    None => {
                        let node = crate::hex_lower(&crate::sha256(&session.device_hash));
                        let device_type = crate::outbound::DEVICE_TYPE_ID;
                        let info = format!(
                            r#"{{"DEVICE_NAME":"{display_name}","DEVICE_TYPE_ID":{device_type},"FLAG":100,"META_AUTH_CAPA":1,"META_NODE_ID":"{node}","TOKEN_ID":"0000000000000000000000000000000000000000000000000000000000000001"}}"#
                        );
                        let meta_seq = rand::random::<u64>();
                        my_meta_seq = Some(meta_seq);
                        meta_sent = true;
                        control.transmit(&transfer::seal_channel_frame(
                            &key,
                            (PEER_META_FRAME, 5, meta_seq, 0, 0),
                            info.as_bytes(),
                            0,
                        )?)?;
                        control.transmit(&transfer::seal_channel_frame(
                            &key,
                            (PEER_META_ACK_FRAME, 5, meta_seq, 0, 0),
                            PEER_META_ACK_JSON,
                            0,
                        )?)?;
                    }
                }
                continue;
            }
            if header.0 == PEER_META_ACK_FRAME && plain == PEER_META_ACK_JSON {
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
                control.transmit(&transfer::seal_channel_frame(
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
                let brief: String = text.chars().take(700).collect();
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
                    let peer_ch = value["MY_CHANNEL_ID"].as_u64().unwrap_or(0);

                    if let Some(port) = file_port {
                        let reply = format!(
                            r#"{{"MY_CHANNEL_ID":1,"PEER_CHANNEL_ID":{peer_ch},"P2P_PORT":{port},"MY_IP":"{local_ip}","CODE":1538,"STREAM_TYPE":255,"PKG_NAME":"ohos.InterConnection.iShare","BUSINESS_TYPE":3,"API_VERSION":0,"TRANS_CAPABILITY":0,"UDP_CHANNEL_CAPABILITY":0}}"#
                        );
                        let mut body = reply.into_bytes();
                        body.push(0);
                        control.transmit(&transfer::seal_channel_frame(
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
                control.transmit(&transfer::seal_channel_frame(
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

        if !pending_more && !saved.is_empty()
            && saved.len() - base_saved >= expected_files.len().max(1) && active.is_none() {
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
