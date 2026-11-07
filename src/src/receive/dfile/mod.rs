//! 接收侧数据帧：解密、落盘、空文件与空目录处理。
//!
//! 拆成三块：`wire` 是纯函数（按协议拼应答帧、打诊断）；`cleanup` 管
//! 「失败也要把现场收拾干净」——未完成文件、空文件、浮窗守卫；本文件只剩
//! 那个必须整体读才看得懂的三路轮询状态机。

pub(super) mod cleanup;
pub(super) mod wire;

use super::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::channel::{Channel, Listener};
use crate::transfer::{self, tlv_get, tlv_list};
use crate::{frame_encode, tlv_encode, Error, Result, FRAME_HEADER_SIZE};

use cleanup::{materialize_empty_files, OverlayGuard, PartGuard};
use wire::*;

mod ov {
    pub use crate::overlay::{abort, finish, set_batch, set_outgoing, start, update};
}

const MB: f64 = 1048576.0;

/// 接收一个 dfile 会话：回执 → 三路轮询 → 落盘。
///
/// 协议把一次传输拆成三条 TCP 通道，各有分工，必须同时轮询（任何一条堵住都会拖死另两条）：
///
/// | 通道 | 作用 |
/// |---|---|
/// | `control` | 首帧回执、通道握手应答、取消与控制命令 |
/// | `byte` | 预览载荷（图片缩略图等）、接收端主动上报的进度帧 |
/// | `file#1` | 文件清单、真正的数据块、收尾 ACK |
///
/// 这是一个显式状态机，状态却都放在局部变量里（`settings_seen` / `header_seen` /
/// `active_file` / `done_sent` ……），靠主循环每轮重新判断该做什么。改之前先看清
/// 某个变量在哪些段落被读写——它们之间有隐含顺序（例如没有 `header_seen` 就不该有
/// `active_file`）。各段边界在下面用 `──` 标出。

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
    // 接收侧只有对端地址；能从发现表反查到设备名就显示设备名，否则显示地址。
    let target = crate::peers::name_for_host(&session.peer)
        .unwrap_or_else(|| session.peer.clone());
    crate::progress::set_target(&target);
    let task = crate::progress::begin(
        false,
        "接收中",
        session.file_count as usize,
        session.total_bytes,
    );
    let _task_guard = crate::progress::Guard::new(task);
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
        return Ok(ReceiveResult { saved: Vec::new(), bytes: 0, clip: None });
    }

    std::fs::create_dir_all(destination).map_err(|e| Error::Io(format!("创建目录失败: {e}")))?;

    let debug = crate::env::present("HWSHARE_DEBUG");
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
    let mut base_done: usize = 0;
    let mut pending_more = false;
    let mut settings_seen = false;
    let mut header_seen = false;

    let mut manifest_count: usize = 0;
    let mut transaction: Option<u16> = None;
    let mut active: Option<u16> = None;

    let mut active_file: Option<ActiveFile> = None;
    let mut current_declared: u64 = 0;
    let mut current_name = String::new();
    let mut done_sent = false;
    let mut done_acked = false;
    let mut saved: Vec<PathBuf> = Vec::new();
    // 已完成的条目数（落盘文件 + 剪贴板文本）。`saved` 只装真文件，剪贴板那条
    // 永远进不来，所以「收完没有」不能再看 `saved.len()`，否则会话会等到超时。
    let mut done_count: usize = 0;
    let mut clip_info: Option<ClipInfo> = None;

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
    // ══ 主循环 ══════════════════════════════════════════════════════
    // 三路通道并行推进：control 管命令、byte 管预览/对端进度、file#1 管清单与数据。
    // 每轮顺序固定：先看「该不该退」，再收数据，最后处理控制帧。
    while Instant::now() < deadline {

        // ── 取消请求：回 receiverCancel 再退出 ─────────────────────
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
            return Err(Error::Cancelled("你取消了接收".to_string()));
        }
        if debug && last_status.elapsed() >= Duration::from_secs(3) {
            last_status = Instant::now();
            eprintln!(
                "[状态] settings={} preview={} 清单={}({} 个) 已收 {} 字节 已存 {} 个",
                settings_seen, preview_acked, header_seen, expected_files.len(),
                total_received, saved.len()
            );
        }

        // ── 收尾判定：清单里的都落了盘、对端也 ACK 了就直接退 ──────
        if done_acked && !pending_more && !expected_files.is_empty()
            && done_count - base_done >= expected_files.len() {
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
                total_received as f64 / MB,
                session.total_bytes as f64 / MB
            );
        }
        let idle = last_progress.elapsed();

        // ── 空闲与超时：先警告一次，再判中断 ───────────────────────
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
            let file_state = file_channel
                .as_ref()
                .map(|c| c.close_reason())
                .unwrap_or("none");
            let byte_state = byte_channel
                .as_ref()
                .map(|c| c.close_reason())
                .unwrap_or("none");
            crate::trace::note(
                "file#1",
                &format!(
                    "空闲 {:.1}s 判中断：file#1={} byte={} 已收 {:.1} MB",
                    idle.as_secs_f64(),
                    file_state,
                    byte_state,
                    total_received as f64 / MB
                ),
            );
            // 对方主动关通道（eof）和我们自己等不到数据是两回事：
            // 前者是「它发完了 / 它走了」，后者才像「卡住了」。
            // 以前这句更准的话算完就 `let _ =` 丢掉，用户永远只看到笼统的「可能已锁屏」。
            let peer_closed = file_state == "eof" || byte_state == "eof";
            return Err(Error::Protocol(if peer_closed {
                format!(
                    "对方结束了传输（已关闭数据通道，最后一份数据在 {:.0} 秒前）",
                    idle.as_secs_f64()
                )
            } else {
                format!(
                    "传输中断：{:.0} 秒没有收到数据，对方可能已锁屏或离开",
                    idle.as_secs_f64()
                )
            }));
        }

        // ── 接入对端后来才连上的 byte / file 通道 ───────────────────
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

        // ── 文件通道：清单帧、数据帧、文件收尾 ─────────────────────
        if let (Some(chan), Some(fkey)) = (file_channel.as_mut(), file_key) {

            macro_rules! finish_tx {
                ($tr:expr) => {{
                    let tr = $tr;
                    let mut payload = Vec::with_capacity(done_ids.len() * 2);
                    for id in &done_ids {
                        payload.extend_from_slice(&id.to_be_bytes());
                    }
                    let done = transfer::assemble_dfile_packet(6, 0, 0, tr, &payload)?;
                    chan.transmit(&transfer::dfile_seal_control(&fkey, &done)?)?;
                    done_sent = true;

                    let more = if total_expected == 0 {
                        session.total_bytes > 0 && total_received < session.total_bytes
                    } else {
                        done_count < total_expected
                    };
                    if more {
                        pending_more = true;
                        expected_files.clear();
                        empty_files.clear();
                        done_ids.clear();
                        header_seen = false;
                        transaction = None;
                        done_sent = false;
                        done_acked = false;
                        base_done = done_count;

                        crate::trace::note(
                            "file#1",
                            &format!(
                                "事务 {tr} 完成，累计 {}/{}，等待下一个事务",
                                saved.len(),
                                if total_expected == 0 {
                                    "?".to_string()
                                } else {
                                    total_expected.to_string()
                                }
                            ),
                        );
                    }
                }};
            }

            let mut drained = 0usize;
            let drain_start = Instant::now();
            while drained < DRAIN_LIMIT && drain_start.elapsed() < DRAIN_BUDGET {
                let wait = if drained == 0 { POLL } else { Duration::from_millis(1) };
                let wire_frame = match chan.try_read_dfile(wait) {
                    Ok(Some(f)) => f,
                    Ok(None) => {

                        if chan.close_reason() == "eof" {
                            let done_now = !pending_more && !expected_files.is_empty()
                                && done_count - base_done >= expected_files.len();
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
                                    return Err(Error::Protocol(
                                        "对方取消了本次传输".to_string(),
                                    ));
                                }
                                return Err(Error::Protocol(format!(
                                    "对方中断了传输（关闭了文件通道），已收 {:.1} MB / {:.1} MB（{:.0}%）",
                                    total_received as f64 / MB,
                                    session.total_bytes as f64 / MB,
                                    pct
                                )));
                            }
                        }
                        break;
                    }
                    Err(e) => {

                        let done_now = !pending_more && !expected_files.is_empty()
                            && done_count - base_done >= expected_files.len();
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

                        log_settings(payload, debug);

                        let recv_dfs: u16 = crate::env::num("HWSHARE_RECV_DFS", 65485);
                        let mine = transfer::dfile_settings_with(true, recv_dfs);
                        chan.transmit(&mine)?;

                        let congest = build_congest_frame();
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
                        base_done = done_count;
                        merge_manifest(&mut expected_files, &mut empty_files, data);
                        if expected_files.is_empty() && empty_files.is_empty() {
                            return Err(Error::Protocol(
                                "对端发来的文件清单为空，无法继续".to_string(),
                            ));
                        }
                        manifest_count = if data.len() >= 2 {
                            u16::from_be_bytes([data[0], data[1]]) as usize
                        } else {
                            0
                        };
                        transaction = Some(trans);
                        header_seen = true;

                        if manifest_count == 0
                            || expected_files.len() + empty_files.len() >= manifest_count
                        {
                            ack_manifest(chan, &fkey, trans, &expected_files, &empty_files)?;

                            if debug {
                                eprintln!("[dfile] 已回清单 ACK（{} 个文件）", expected_files.len());
                            }

                            if expected_files.is_empty() && !empty_files.is_empty() {
                                crate::trace::note(
                                    "file#1",
                                    "清单里全是 0 字节文件，直接创建并收尾",
                                );
                                materialize_empty_files(
                                    destination,
                                    &mut empty_files,
                                    &mut done_ids,
                                    &mut saved,
                                    &mut done_count,
                                    &mut clip_info,
                                );
                                finish_tx!(trans);
                            }
                        } else if debug {
                            eprintln!(
                                "[dfile] 清单未收齐（{}/{}），暂不 ACK",
                                expected_files.len() + empty_files.len(),
                                manifest_count
                            );
                        }
                        if crate::trace::enabled() {
                            crate::trace::note("file#1", &format!("清单已确认 {}", format_manifest_list(&expected_files)));
                        }
                    }

                    1 if header_seen => {
                        let inner = transfer::open_control_block(&fkey, (kind, flags, sess, trans), &payload)
                            .map_err(|e| { eprintln!("[dfile] 清单续帧解密失败: {e}"); e })?;
                        let added = merge_manifest(&mut expected_files, &mut empty_files, &inner[8..]);

                        let got = expected_files.len() + empty_files.len();
                        if manifest_count == 0 || got >= manifest_count {
                            ack_manifest(chan, &fkey, trans, &expected_files, &empty_files)?;
                            if debug {
                                eprintln!("[dfile] 已回清单 ACK（{got} 个文件）");
                            }
                            if expected_files.is_empty() && !empty_files.is_empty() {
                                crate::trace::note(
                                    "file#1",
                                    "清单里全是 0 字节文件，直接创建并收尾",
                                );
                                materialize_empty_files(
                                    destination,
                                    &mut empty_files,
                                    &mut done_ids,
                                    &mut saved,
                                    &mut done_count,
                                    &mut clip_info,
                                );
                                finish_tx!(trans);
                            }
                        } else if debug {
                            eprintln!("[dfile] 清单未收齐（{got}/{manifest_count}），暂不 ACK");
                        }
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

                                ov::set_batch(expected_files.len());

                                ov::set_outgoing(false);
                                ov::start(&current_name);
                            }

                            // 打开写入目标：普通文件落盘，`Huawei Share.txt` 只留在内存。
                            // `part` 为空就是「没有临时文件」，别往 PartGuard 里登记——
                            // 否则 Drop 时会去删一个不存在的路径。
                            let slot = ActiveFile::open(
                                destination,
                                &current_name,
                                current_declared,
                                debug,
                            )
                            .map_err(|e| {
                                Error::Io(format!(
                                    "创建接收文件失败（目录 {}）: {e}",
                                    destination.display()
                                ))
                            })?;
                            if !slot.part.as_os_str().is_empty() {
                                part_guard.track(slot.part.clone());
                            }
                            active_file = Some(slot);
                        }

                        {
                            let slot = active_file
                                .as_mut()
                                .ok_or_else(|| Error::Protocol("目标文件未打开".into()))?;
                            slot.write(&content)
                                .map_err(|e| Error::Io(format!("写入失败: {e}")))?;
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
                            // 收尾分两种归宿：落盘的进 `saved`，剪贴板文本进 `clip_info`。
                            // 两者都算「完成」，所以统一走 `done_count`。
                            let finished = match active_file.take() {
                                Some(slot) => {
                                    part_guard.clear();
                                    Some(
                                        slot.finish(destination)
                                            .map_err(|e| Error::Io(e.to_string()))?,
                                    )
                                }

                                None => {
                                    crate::trace::note(
                                        "file#1",
                                        &format!(
                                            "结束帧到达但文件从未打开：{current_name}，跳过记录"
                                        ),
                                    );
                                    None
                                }
                            };
                            let mut completed = false;
                            match finished {
                                Some(Finished::Saved(target)) => {
                                    completed = true;
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

                                Some(Finished::Text { buf, overflow }) => {
                                    completed = true;
                                    clip_info = Some(clip::deliver(&buf, overflow, written));
                                }
                                None => {}
                            }
                            if completed {
                                done_count += 1;
                            }
                            done_ids.push(finished_id);

                            let all_done =
                                done_count - base_done >= expected_files.len().max(1);
                            if all_done {
                                materialize_empty_files(
                                    destination,
                                    &mut empty_files,
                                    &mut done_ids,
                                    &mut saved,
                                    &mut done_count,
                                    &mut clip_info,
                                );
                                finish_tx!(trans);
                            }
                            active = None;
                            current_declared = 0;
                            current_name.clear();
                        }
                    }

                    9 => {
                        return Err(Error::Protocol(format!(
                            "对方中止了传输（DFile kind=9），已收 {:.1} MB",
                            total_received as f64 / MB
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
        // ── 字节通道：预览载荷与对端回报的进度 ─────────────────────
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
                    byte_key = Some(decode_session_key(&value)?);
                    if debug { eprintln!("[byte] 握手完成，byte 会话密钥已就绪"); }

                    let node = crate::hex_lower(&crate::sha256(&session.device_hash));
                    let pkg = crate::auth::PKG_NAME;

                    let body = build_byte_handshake_ack(session.peer_apple, pkg, &node);

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

                    let mut handled_as_list = false;
                    if let Ok(raw) = crate::frame_encode_lenient(9, 0, 0, &plain) {
                        match transfer::open_channel_frame(&raw, &key) {
                            Ok(b) => {
                                if debug {
                                    eprintln!("[预览] ===== 官方预览帧 {} 字节 =====", b.len());
                                    dump_tlvs("[预览] ", &b, 0);

                                    let dump = std::env::temp_dir().join("hwshare-preview.bin");
                                    if std::fs::write(&dump, &b).is_ok() {
                                        eprintln!("[预览] 已落盘 {}", dump.display());
                                    }
                                }
                                if is_name_list_frame(&b) {
                                    handled_as_list = true;
                                    preview_acked = true;
                                    match transfer::seal_encrypted_frame(
                                        &session.device_hash,
                                        &key,
                                        &tlv_encode(1, &tlv_encode(8, b"previewOK")?)?,
                                        0,
                                    ) {
                                        Ok(f) => {
                                            let _ = control.transmit(&f);
                                            crate::trace::note(
                                                "control",
                                                &format!("名单帧 -> previewOK（{} 字节名单）", b.len()),
                                            );
                                        }
                                        Err(e) => crate::trace::note(
                                            "control",
                                            &format!("名单帧回 previewOK 失败：{e}"),
                                        ),
                                    }
                                } else if debug && b.len() > 1000 {

                                    eprintln!("[预览] {} 字节，判定为非名单帧", b.len());
                                }
                            }
                            Err(e) => {
                                if debug { eprintln!("[预览] 解密失败（应答不受影响）: {e}"); }
                            }
                        }
                    }

                    if !handled_as_list && !preview_acked {
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
            && done_count - base_done >= expected_files.len() {
            if debug { eprintln!("[dfile] 已收齐并 ACK，跳过主通道尾部"); }
            break;
        }

        // ── 控制通道：取消、设置、收尾命令 ─────────────────────────
        let ctl_frame = match control.try_read_frame(POLL) {
            Ok(f) => f,
            Err(e) => {

                let done_now =
                    !expected_files.is_empty() && done_count >= expected_files.len();
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
                && done_count - base_done >= expected_files.len();
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
                        total_received as f64 / MB
                    ),
                );
                return Err(Error::Protocol(format!(
                    "对方中断了本次分享（关闭了控制通道），已收 {:.1} MB / {:.1} MB（{:.0}%）",
                    total_received as f64 / MB,
                    session.total_bytes as f64 / MB,
                    pct
                )));
            }
        }

        if let Some(wire_frame) = ctl_frame {

            let module = crate::u32_at(&wire_frame, 4).ok_or(Error::Truncated)?;

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
                            total_received as f64 / MB,
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
                        let reply = build_tag5_reply(&local_ip)?;
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

                            if !meta_sent && session.peer_apple {
                                meta_sent = true;
                                let info = build_meta_info_json(display_name, &session.device_hash);
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
                        let info = build_meta_info_json(display_name, &session.device_hash);

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
                    use std::fmt::Write;
                    let brief: String = take_chars(&text, 160);
                    let mut hex = String::with_capacity(96 * 2);
                    for b in plain.iter().take(96) {
                        let _ = write!(hex, "{b:02X}");
                    }
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

                let body = build_p2p_reply(&local_ip, port);
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
                let brief: String = take_chars(&text, 700);
                crate::trace::note(
                    "control",
                    &format!(
                        "file 通道请求 hdr=({:#X},{},{},{},{}) n={} json={}",
                        header.0, header.1, header.2, header.3, header.4,
                        plain.len(), brief
                    ),
                );

                if file_channel.is_some() || file_listener.is_some() {

                    let brief: String = take_chars(&text, 240);
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
                        let reply = file_channel_reply(port, &local_ip, Some(peer_ch));
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
                file_key = Some(decode_session_key(&value)?);

                let listener = Listener::bind(&local_ip, 0)?;
                let port = listener.port;
                file_port = Some(port);
                let _ = file_port;
                let reply = file_channel_reply(port, &local_ip, None);
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

            let brief: String = take_chars(&text, 240);
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

        if !pending_more && done_count > 0
            && done_count - base_done >= expected_files.len().max(1) && active.is_none() {
            break;
        }
    }

    let expected = expected_files.len();
    if done_count == 0 {
        return Err(Error::Protocol(if expected == 0 {
            format!(
                "等待对端开始传输超时（{} 秒内没收到文件清单）",
                timeout.as_secs()
            )
        } else {
            format!("传输超时：清单 {expected} 个文件，一个都没收完")
        }));
    }
    if done_count < expected {
        return Err(Error::Protocol(format!(
            "传输超时：清单 {expected} 个文件，只收完 {} 个（共 {:.1} MB）",
            done_count,
            total_received as f64 / MB
        )));
    }

    ov::finish();
    oguard.done = true;
    Ok(ReceiveResult { saved, bytes: total_received, clip: clip_info })
}
