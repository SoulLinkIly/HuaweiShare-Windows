//! 发送侧取消：发出 cancel 帧，并盯住控制通道等对端确认。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use crate::channel::Channel;
use crate::transfer;
use crate::Error;
use super::*;

/// 还在跑的所有发送会话的令牌（弱引用，会话结束自动失效）。
///
/// 以前这里是一个全局 `AtomicBool`，多路并行时有两个连带问题：
/// ① 任何一路取消都会把**其它几路**一起停掉；
/// ② `transmit()` 里那句 `if active()==0 { clear() }` 在多路时永远不成立，
///    于是这个标志一直挂着，**之后新开的任务一跑就被判"已取消"**。
static TOKENS: Mutex<Vec<Weak<AtomicBool>>> = Mutex::new(Vec::new());

/// 一次发送会话的取消令牌。`transmit()` 创建，活到会话结束。
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        if let Ok(mut list) = TOKENS.lock() {
            prune(&mut list);
            list.push(Arc::downgrade(&flag));
        }
        Self(flag)
    }

    /// 各阶段共享的同一面旗。
    pub fn flag(&self) -> Arc<AtomicBool> {
        self.0.clone()
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

fn prune(list: &mut Vec<Weak<AtomicBool>>) {
    list.retain(|w| w.strong_count() > 0);
}

/// 用户点了「取消」：置位当前**所有**在跑的会话。
///
/// 并行时界面上是一个聚合视图，用户按的也是"这一批"，所以不是只停某一路；
/// 但已经结束的会话不会留在表里，新任务也不会被旧请求命中。
pub fn request_cancel_send() {
    let Ok(mut list) = TOKENS.lock() else {
        return;
    };
    prune(&mut list);
    for w in list.iter() {
        if let Some(flag) = w.upgrade() {
            flag.store(true, Ordering::SeqCst);
        }
    }
}

/// 只认本会话的令牌。
///
/// 以前这里还要再查一遍全局标志，并 sleep 300 ms 等控制线程把旗子插到自己身上；
/// 现在 `request_cancel_send` 直接置位每个令牌，不用等传播。
pub(super) fn cancelled(cancel: &AtomicBool) -> bool {
    cancel.load(Ordering::Relaxed)
}

pub(super) const CANCEL_WAIT: Duration = Duration::from_millis(800);

pub(super) fn absorb_peer_frame(plain: &[u8], session_key: &[u8; 32], peer: &PeerState) {
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
                        peer.cancel_acked.store(true, Ordering::SeqCst);
                        crate::trace::note("byte", "收到对端 senderCancelACK（取消已确认）");
                    }
                }
                9 => {
                    let text = String::from_utf8_lossy(&data).to_string();

                    let pct = text
                        .strip_prefix("dfileRecvPercent#")
                        .or_else(|| text.strip_prefix("fileRecvPercent#"));
                    if let Some(rest) = pct {
                        if let Ok(pct) = rest.trim().parse::<f64>() {
                            peer.peer_pct_bits.store(pct.to_bits(), Ordering::SeqCst);
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
    peer: Arc<PeerState>,
) {
    std::thread::spawn(move || loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match transfer::try_read_bytes_frame(&mut chan, &bkey, Duration::from_millis(200)) {
            Ok(Some((_seq, plain))) => absorb_peer_frame(&plain, &session_key, &peer),
            Ok(None) => {}
            Err(_) => break,
        }
    });
}

pub(super) fn wait_cancel_ack(fb: &PeerState) {
    let deadline = Instant::now() + CANCEL_WAIT;
    while Instant::now() < deadline {
        if fb.cancel_acked.load(Ordering::SeqCst) {
            crate::trace::note("byte", "已收到 senderCancelACK，立刻收尾（不用等满超时）");
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    crate::trace::note("byte", "等 senderCancelACK 超时，按原节奏收尾");
}

pub(super) fn cancel_error(cancel: &AtomicBool) -> Error {
    if cancel.load(Ordering::SeqCst) {
        Error::Cancelled("你取消了发送".into())
    } else {
        Error::Rejected("对方取消了这次分享".into())
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
    peer: Arc<PeerState>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut sequence = start_sequence;
        let mut cancel_sent = false;
        while !stop.load(Ordering::Relaxed) {

            // 令牌由 UI 直接置位，这里只负责把 senderCancel 发出去。
            if !cancel_sent && cancel.load(Ordering::Relaxed) {
                cancel_sent = true;
                send_sender_cancel(&mut channel, &device_hash, &key, &mut sequence);
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
            let Some(module) = crate::u32_at(&wire_frame, 4) else { continue };
            if crate::env::present("HWSHARE_DEBUG") {
                let inner = crate::u32_at(&wire_frame, 24).unwrap_or(0);
                eprintln!(
                    "[ctl] module={module:#x} inner={inner:#x} len={}",
                    wire_frame.len()
                );
            }

            if module == 0x15 {

                if crate::env::present("HWSHARE_DEBUG") {
                    if let Ok(body) = transfer::open_channel_frame(&wire_frame, &key) {
                        let text = String::from_utf8_lossy(&body);
                        eprintln!("[ctl0x15] len={} body={}", body.len(), &text[..text.len().min(600)]);
                    }
                }
                let inner_mod = crate::u32_at(&wire_frame, 24);
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
                                b"previewOK" => peer.preview_ok.store(true, Ordering::SeqCst),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `TOKENS` 是全局表，用例之间会互相置位，必须串行。
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn cancel_reaches_every_live_session() {
        let _g = serial();
        let a = CancelToken::new();
        let b = CancelToken::new();
        request_cancel_send();
        assert!(cancelled(&a.flag()), "并行时点一次取消要停掉所有在跑的会话");
        assert!(cancelled(&b.flag()));
    }

    #[test]
    fn new_session_is_not_hit_by_an_old_cancel() {
        let _g = serial();
        {
            let old = CancelToken::new();
            request_cancel_send();
            assert!(cancelled(&old.flag()));
        } // 会话结束，令牌随之释放
        let next = CancelToken::new();
        assert!(
            !cancelled(&next.flag()),
            "上一批的取消不能传染给之后新开的任务（全局标志的旧实现正是这样）"
        );
    }

    #[test]
    fn dead_tokens_are_pruned() {
        let _g = serial();
        let keep = CancelToken::new();
        {
            let gone = CancelToken::new();
            request_cancel_send();
            assert!(cancelled(&gone.flag()));
        }
        // 这一轮应该把已释放的弱引用清掉，否则表会随会话数一直涨。
        request_cancel_send();
        let list = TOKENS.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            list.iter().all(|w| w.strong_count() > 0),
            "失效令牌必须被清掉"
        );
        drop(list);
        assert!(cancelled(&keep.flag()));
    }
}
