use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::channel::Channel;
use crate::transfer;
use crate::Error;
use super::*;

pub fn request_cancel_send() {
    SEND_CANCEL.store(true, Ordering::SeqCst);
}

pub fn send_cancel_requested() -> bool {
    SEND_CANCEL.load(Ordering::SeqCst)
}

pub(super) fn clear_send_cancel() {
    SEND_CANCEL.store(false, Ordering::SeqCst);
    CANCEL_ACKED.store(false, Ordering::SeqCst);
    PEER_PCT_BITS.store(u64::MAX, Ordering::SeqCst);
    PREVIEW_OK.store(false, Ordering::SeqCst);
}

pub(super) fn cancelled(cancel: &AtomicBool) -> bool {
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

pub(super) const CANCEL_WAIT: Duration = Duration::from_millis(800);

pub(super) fn absorb_peer_frame(plain: &[u8], session_key: &[u8; 32]) {
    let Ok(wire_frame) = crate::frame_encode_lenient(9, 0, 0, plain) else {
        return;
    };
    let Ok(body) = transfer::open_channel_frame(&wire_frame, session_key) else {
        return;
    };
    let Ok(fields) = transfer::tlv_list(&body) else {
        return;
    };
    for (tag, value) in fields {
        if tag != 1 {
            continue;
        }
        let Ok(inner) = transfer::tlv_list(&value) else {
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

pub(super) fn spawn_byte_watch(
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

pub(super) fn wait_cancel_ack() {
    let deadline = Instant::now() + CANCEL_WAIT;
    while Instant::now() < deadline {
        if CANCEL_ACKED.load(Ordering::SeqCst) {
            crate::trace::note("byte", "已收到 senderCancelACK，立刻收尾（不用等满超时）");
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    crate::trace::note("byte", "等 senderCancelACK 超时，按原节奏收尾");
}

pub(super) fn cancel_error() -> Error {
    if send_cancel_requested() {
        Error::Protocol("已取消发送（本机操作）".into())
    } else {
        Error::Protocol("对方取消了本次分享".into())
    }
}

pub(super) fn send_sender_cancel(
    channel: &mut Channel,
    device_hash: &[u8],
    key: &[u8; 32],
    sequence: &mut u64,
) -> bool {
    const TAG: u64 = 2;
    let tag = TAG;
    let payload =
        crate::tlv_encode(tag, b"senderCancel").and_then(|inner| crate::tlv_encode(1, &inner));
    let pkt = payload
        .and_then(|p| transfer::seal_encrypted_frame(device_hash, key, &p, *sequence));
    match pkt {
        Ok(pkt) => match channel.transmit(&pkt) {
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
pub(super) fn spawn_control_watch(
    mut channel: Channel,
    key: [u8; 32],
    device_hash: Vec<u8>,
    local: String,
    start_sequence: u64,
    cancel: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    peer_closed: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut sequence = start_sequence;
        let mut cancel_sent = false;
        while !stop.load(Ordering::Relaxed) {
            if !cancel_sent && send_cancel_requested() {
                cancel_sent = true;
                send_sender_cancel(&mut channel, &device_hash, &key, &mut sequence);
                cancel.store(true, Ordering::SeqCst);
            }
            let wire_frame = match channel.try_read_frame(Duration::from_millis(100)) {
                Ok(Some(f)) => f,
                Ok(None) => continue,
                Err(e) => {
                    crate::trace::note("control", &format!("控制通道断开：{e}"));
                    peer_closed.store(true, Ordering::SeqCst);
                    break;
                }
            };
            let Some(head) = wire_frame.get(4..8) else { continue };
            let module = u32::from_le_bytes(head.try_into().unwrap());
            if std::env::var("HWSHARE_DEBUG").is_ok() {
                let inner = wire_frame
                    .get(24..28)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0);
                eprintln!(
                    "[ctl] module={module:#x} inner={inner:#x} len={}",
                    wire_frame.len()
                );
            }

            if module == 0x15 {
                if std::env::var("HWSHARE_DEBUG").is_ok() {
                    if let Ok(body) = transfer::open_channel_frame(&wire_frame, &key) {
                        let text = String::from_utf8_lossy(&body);
                        eprintln!("[ctl0x15] len={} body={}", body.len(), &text[..text.len().min(600)]);
                    }
                }
                let inner_mod = wire_frame
                    .get(24..28)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()));
                if inner_mod == Some(0xFFFF_0004) {
                    crate::trace::note("control", "收到内层 0xFFFF0004，回 24 字节空帧");
                    if let Ok(ack) = crate::frame_encode(0x15, sequence, 0, &[]) {
                        let _ = channel.transmit(&ack);
                        sequence = sequence.wrapping_add(1);
                    }
                }
                continue;
            }

            if module != 9 {
                continue;
            }
            let Ok(body) = transfer::open_channel_frame(&wire_frame, &key) else {
                continue;
            };
            let Ok(fields) = transfer::tlv_list(&body) else {
                continue;
            };
            for (tag, value) in fields {
                match tag {
                    1 => {
                        let Ok(cmds) = transfer::tlv_list(&value) else { continue };
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
                                    cancel.store(true, Ordering::SeqCst);
                                }
                                b"previewOK" => PREVIEW_OK.store(true, Ordering::SeqCst),
                                _ => {}
                            }
                        }
                    }
                    4 | 10 => {
                        let payload = if tag == 4 {
                            net_info_reply(&local)
                        } else {
                            logical_addr(&local)
                        };
                        let Ok(payload) = payload else { continue };
                        let Ok(pkt) =
                            transfer::seal_encrypted_frame(&device_hash, &key, &payload, sequence)
                        else {
                            continue;
                        };
                        if let Err(e) = channel.transmit(&pkt) {
                            crate::trace::note(
                                "control",
                                &format!("控制通道应答 tag{tag} 失败，监听线程退出：{e}"),
                            );
                            return;
                        }
                        sequence = sequence.wrapping_add(1);
                    }
                    _ => {}
                }
            }
        }
        channel.graceful_close(std::time::Duration::from_millis(800));
    })
}
