use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::channel::Channel;
use crate::transfer;
use crate::{Error, Result};
use super::*;

pub(super) const DFRAME_DEFAULT: usize = 1472;

pub(super) const DFRAME_OVERHEAD: usize = 50;

pub(super) const BATCH_BYTES: usize = 256 * 1024;

pub(super) fn batch_bytes() -> usize {
    std::env::var("HWSHARE_BATCH_BYTES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(BATCH_BYTES)
}

pub fn chunk_size() -> usize {
    let from_env = std::env::var("HWSHARE_CHUNK")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok());
    let chosen = from_env.or_else(crate::config::chunk);
    match chosen {
        Some(n) => n.clamp(512, crate::transfer::DFILE_MAX_CONTENT),
        None => DFRAME_DEFAULT - DFRAME_OVERHEAD,
    }
}

pub(super) fn data_frame_size(chunk: usize) -> u16 {
    (chunk + DFRAME_OVERHEAD).min(u16::MAX as usize) as u16
}

pub(super) fn settings_profile(kind: transfer::PeerKind, frame_size: u16) -> transfer::SettingsProfile {
    if kind.is_apple() {
        transfer::SettingsProfile::phone_exact_with(frame_size)
    } else {
        transfer::SettingsProfile::sender_baseline(1472, frame_size)
    }
}

pub(super) fn parse_ids(inner: &[u8]) -> Result<Vec<u16>> {
    let data = inner.get(8..).ok_or(Error::Truncated)?;
    if data.len() % 2 != 0 {
        return Err(Error::Format);
    }
    Ok(data
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

pub(super) fn draw_progress(written: u64, total: u64, t0: Instant) {
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

pub(super) mod ov {
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

fn finish_batch(
    chan: &mut Channel,
    key: &[u8],
    trans: u16,
    apple: bool,
    written: u64,
    oguard: &mut SendOverlayGuard,
) -> Result<u64> {
    let ack = transfer::dfile_seal_control(key, &transfer::assemble_dfile_packet(7, 0, 0, trans, b"")?)?;
    let times = match std::env::var("HWSHARE_DONE_ACK").ok().as_deref() {
        Some("0") | Some("none") => 0,
        Some(v) => v.parse::<u32>().unwrap_or(3),
        None => 3,
    };
    let _ = apple;
    for i in 0..times {
        match chan.transmit(&ack) {
            Ok(()) => {}
            Err(e) if i > 0 => {
                dbg_frame!("[tx] 补偿 DONE_ACK 写失败（对端已收尾）：{e}");
                break;
            }
            Err(e) => return Err(e),
        }
        if i + 1 < times {
            std::thread::sleep(Duration::from_millis(15));
        }
    }
    println!();
    ov::finish();
    oguard.done = true;
    Ok(written)
}

pub(super) struct SendOverlayGuard {
    pub(super) done: bool,
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

pub(super) fn send_file_chunks(
    chan: &mut Channel,
    key: &[u8],
    file: &Outgoing,
    written: &mut u64,
    done: &mut Vec<u16>,
    done_trans: &mut Option<u16>,
    trans: u16,
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
    let batch_limit = batch_bytes();
    let mut batch: Vec<u8> = Vec::with_capacity(batch_limit + chunk + 64);
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
            wait_cancel_ack();
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
        let wire_frame = transfer::build_data_block(key, &buf[..filled], sequence, flag, file.id, trans)?;
        batch.extend_from_slice(&wire_frame);
        batch_content += filled as u64;
        let mut flushed = false;
        if batch.len() >= batch_limit {
            if cancelled(&cancel) {
                crate::trace::note(
                    "file#1",
                    &format!("取消时已发 {} 字节（本批未写）", sent),
                );
                return Err(cancel_error());
            }
            chan.transmit(&batch)?;
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
                            transfer::open_control_block(key, (k, fl, s, tr), pl)
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
                            transfer::open_control_block(key, (k, fl, s, tr), pl)
                        {
                            for id in parse_ids(&inner)? {
                                if !done.contains(&id) {
                                    done.push(id);
                                }
                            }
                            if !done.is_empty() {
                                *done_trans = Some(tr);
                            }
                            if let Ok(ack) = transfer::assemble_dfile_packet(7, 0, 0, tr, b"")
                                .and_then(|p| transfer::dfile_seal_control(key, &p))
                            {
                                let _ = chan.transmit(&ack);
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
                    13 => {
                        dbg_frame!("[kind=13·chunk] 对端收尾通知 trans={tr} size={sz}");
                    }
                    other => {
                        dbg_frame!(
                            "[未知帧·chunk] kind={other} trans={tr} size={sz} hex={:02X?}",
                            &pl[..pl.len().min(24)]
                        );
                        let hits = unknown.entry(other).or_insert(0);
                        *hits += 1;
                        if *hits == 1 {
                            log(&format!("[未知帧] kind={other}（发送中），已忽略"));
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
        chan.transmit(&batch)?;
        progress.fetch_add(batch_content, Ordering::Relaxed);
    }
    Ok(())
}
pub(super) fn send_batch(
    chan: &mut Channel,
    key: &[u8],
    peer: transfer::PeerKind,
    trans: u16,
    files: &[Outgoing],
    log: &dyn Fn(&str),
    cancel: &AtomicBool,
    progress: &AtomicU64,
) -> Result<u64> {
    if peer.is_apple() {
        let mut congest = Vec::with_capacity(8 + 24);
        congest.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 24]);
        congest.extend_from_slice(&[
            0x00, 0x00, 0x01, 0xb0, 0x00, 0x00, 0x01, 0xb0, 0xff, 0xff, 0xff, 0xea, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        chan.transmit(&congest)?;
        log("已发 CONGEST（窗口 432/432）");
    }

    let entries: Vec<(u16, u64, Vec<u8>)> = files
        .iter()
        .map(|f| (f.id, f.size, f.name.as_bytes().to_vec()))
        .collect();
    for packet in transfer::build_headers(&entries, trans)? {
        chan.transmit(&transfer::dfile_seal_control(key, &packet)?)?;
    }
    log(&format!("已发送文件清单：{} 个", files.len()));

    let mut oguard = SendOverlayGuard { done: false };
    ov::set_outgoing(true);
    ov::start(files.first().map(|f| f.name.as_str()).unwrap_or("正在发送"));

    let mut sent: Vec<u16> = Vec::new();
    let mut done: Vec<u16> = Vec::new();
    let mut done_trans: Option<u16> = None;
    let mut written: u64 = 0;
    let mut last_activity = Instant::now();
    let mut last_progress = (0u64, 0usize, 0usize);
    let mut dup_requests: std::collections::BTreeMap<u16, u32> = std::collections::BTreeMap::new();
    let mut backpressure = 0u32;
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
        while let Some(wire_frame) = chan.try_read_dfile(Duration::from_millis(1))? {
            handled = true;
            let (kind, flags, sess, trans, size) = match transfer::parse_dfile_header(&wire_frame) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!(
                        "[帧头异常·batch] len={} hex={:02X?}",
                        wire_frame.len(),
                        &wire_frame[..wire_frame.len().min(48)]
                    );
                    return Err(e);
                }
            };
            let payload = &wire_frame[8..8 + size];
            *rx_kinds.entry(kind).or_insert(0) += 1;
            dbg_frame!(
                "[rx {:>6.1}s] kind={} flags={} trans={} size={}",
                t0.elapsed().as_secs_f64(), kind, flags, trans, size
            );
            match kind {
                11 => {}
                2 | 3 => {
                    let inner =
                        transfer::open_control_block(key, (kind, flags, sess, trans), payload)?;
                    for id in parse_ids(&inner)? {
                        if sent.contains(&id) {
                            let n = dup_requests.entry(id).or_insert(0);
                            *n += 1;
                            if *n == 3 {
                                log(&format!(
                                    "[警告] 对端重复请求 id={id}（已发过），上一份可能未被接受"
                                ));
                            }
                            if *n > 20 {
                                return Err(Error::Protocol(format!(
                                    "对端反复请求同一个文件 id={id}（{n} 次），放弃本次传输"
                                )));
                            }
                            continue;
                        }
                        let Some(file) = files.iter().find(|f| f.id == id) else {
                            log(&format!("[AES 对照] 对端对 id={id} 回了 kind={kind}"));
                            continue;
                        };
                        crate::trace::note(chan.label(), &format!("file req id={id} kind={kind}"));
                        send_file_chunks(
                            chan,
                            key,
                            file,
                            &mut written,
                            &mut done,
                            &mut done_trans,
                            trans,
                            t0,
                            files_total,
                            log,
                            cancel,
                            progress,
                        )?;
                        sent.push(id);
                        if done.len() >= files.len() {
                            let tr = done_trans.unwrap_or(trans);
                            return finish_batch(chan, key, tr, peer.is_apple(), written, &mut oguard);
                        }
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
                        transfer::open_control_block(key, (kind, flags, sess, trans), payload)?;
                    let ids = parse_ids(&inner)?;
                    let before = done.len();
                    for id in &ids {
                        if !done.contains(id) {
                            done.push(*id);
                        }
                    }
                    log(&format!(
                        "[DONE] 收到 {} 个 id，新增 {}，累计 {}/{}",
                        ids.len(),
                        done.len() - before,
                        done.len(),
                        files.len()
                    ));
                    if done.len() >= files.len() {
                        dbg_frame!("[rx 汇总] {:?}", rx_kinds);
                        return finish_batch(chan, key, trans, peer.is_apple(), written, &mut oguard);
                    }
                    if let Ok(ack) = transfer::assemble_dfile_packet(7, 0, 0, trans, b"")
                        .and_then(|p| transfer::dfile_seal_control(key, &p))
                    {
                        let _ = chan.transmit(&ack);
                    }
                    last_activity = Instant::now();
                }
                9 => return Err(Error::Protocol("接收端中止了本次传输".into())),
                5 => {
                    let inner =
                        transfer::open_control_block(key, (kind, flags, sess, trans), payload)?;
                    dbg_frame!("[k5] len={} hex={:02X?}", inner.len(), inner);
                }
                22 => {
                    dbg_frame!("[kind=22·batch] 未知信号，暂停 20 ms");
                    std::thread::sleep(Duration::from_millis(20));
                }
                13 => {
                    backpressure = backpressure.saturating_add(1);
                    if backpressure <= 3 {
                        log(&format!(
                            "[背压] 对端要求减速（第 {} 次），暂停 50 ms",
                            backpressure
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                other => {
                    dbg_frame!(
                        "[未知帧·batch] kind={other} trans={trans} size={size} hex={:02X?}",
                        &payload[..payload.len().min(24)]
                    );
                    log(&format!(
                        "[未知帧] kind={other} trans={trans} size={size}，已忽略"
                    ));
                }
            }
        }
        let progress = (written, sent.len(), done.len());
        if progress != last_progress {
            last_progress = progress;
            last_activity = Instant::now();
        }
        if last_activity.elapsed() > Duration::from_secs(60) {
            return Err(Error::Protocol(format!(
                "等待接收端响应超时：已发 {}/{} 个文件、{} 字节，已收 {} 个 DONE{}",
                sent.len(),
                files.len(),
                written,
                done.len(),
                if dup_requests.is_empty() {
                    String::new()
                } else {
                    format!("，{} 个文件被重复请求", dup_requests.len())
                }
            )));
        }
        if !handled {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    Err(Error::Protocol("批量传输超时".into()))
}
