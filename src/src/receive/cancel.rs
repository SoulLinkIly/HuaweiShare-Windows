//! 接收侧取消：解析控制通道上的取消指令，维护取消标志与排空帧记录。

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::channel::Channel;
use crate::transfer::{self};
use crate::FRAME_HEADER_SIZE;

fn is_cancel_command(cmd: &[u8]) -> bool {
    matches!(cmd, b"senderCancel" | b"receiverCancel" | b"user_reject")
}

pub(super) fn take_pending_cancel(control: &mut Channel, key: &[u8; 32]) -> Option<String> {
    let deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < deadline {
        match control.try_read_frame(Duration::from_millis(10)) {
            Ok(Some(wire_frame)) => {
                if crate::u32_at(&wire_frame, 4) != Some(9) {
                    continue;
                }
                let Ok(body) = transfer::open_channel_frame(&wire_frame, key) else {
                    continue;
                };
                let Ok(fields) = transfer::tlv_list(&body) else {
                    continue;
                };
                for (tag, value) in fields {
                    if tag != 1 {
                        continue;
                    }
                    let Ok(cmds) = transfer::tlv_list(&value) else {
                        continue;
                    };
                    for (_, cmd) in cmds {
                        if is_cancel_command(cmd.as_slice()) {
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

pub(super) static RECV_CANCEL: AtomicBool = AtomicBool::new(false);

pub fn request_cancel_recv() {
    RECV_CANCEL.store(true, Ordering::SeqCst);
}

pub(super) fn recv_cancel_requested() -> bool {
    RECV_CANCEL.load(Ordering::SeqCst)
}

pub(super) fn clear_recv_cancel() {
    RECV_CANCEL.store(false, Ordering::SeqCst);
}

pub(super) const RECV_CANCEL_TAG: u64 = 1;

pub(super) const RECV_CANCEL_WAIT: Duration = Duration::from_millis(800);

pub fn record_drained(control: &mut Channel, session: &Session, drained: Vec<u8>) {
    if drained.is_empty() {
        return;
    }
    control.put_back(&drained);
    log_drained(&session.session_key, &drained);
}

pub(super) fn log_drained(key: &[u8; 32], data: &[u8]) {
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
        let wire_frame = &rest[..total];
        crate::trace::note(
            "control",
            &format!(
                "确认期间到达的帧#{index}：{} 字节，{}",
                total,
                describe_wire_frame(module, wire_frame, key)
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

pub(super) fn describe_wire_frame(module: u32, wire_frame: &[u8], key: &[u8; 32]) -> String {
    if module != 9 {
        return format!("module={module}（非控制模块）{}", hex_head(wire_frame));
    }
    match transfer::open_channel_frame(wire_frame, key) {
        Ok(body) => describe_control_body(&body),
        Err(e) => format!("解密失败（{e}），原文 {}", hex_head(wire_frame)),
    }
}

pub(super) fn describe_control_body(body: &[u8]) -> String {
    let Ok(fields) = transfer::tlv_list(body) else {
        return format!("明文 {}", printable(body));
    };
    let mut parts: Vec<String> = Vec::new();
    for (tag, value) in fields {
        if tag == 1 {
            if let Ok(inner) = transfer::tlv_list(&value) {
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

pub(super) fn printable(value: &[u8]) -> String {
    match std::str::from_utf8(value) {
        Ok(text) if text.chars().all(|c| !c.is_control()) => {
            format!("\"{text}\"（{} 字节）", value.len())
        }
        _ => format!("{}（{} 字节）", hex_head(value), value.len()),
    }
}

pub(super) fn hex_head(value: &[u8]) -> String {
    use std::fmt::Write;
    const N: usize = 64;
    let n = value.len().min(N);
    let mut out = String::with_capacity(n * 3 + 4);
    for byte in &value[..n] {
        let _ = write!(out, "{byte:02X} ");
    }
    if value.len() > N {
        out.push('…');
    } else {
        out.pop();
    }
    out
}
