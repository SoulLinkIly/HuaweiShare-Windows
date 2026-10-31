#![allow(unused_variables)]
#[inline]
pub fn init_from_env() {}

#[inline]
pub fn finish(reason: &str) {}

#[inline]
pub fn enabled() -> bool {
    false
}

#[inline]
pub fn current_path() -> Option<std::path::PathBuf> {
    None
}

pub fn session_start(mode: &str, peer: &str, local: &str, files: usize, bytes: u64) {}

pub fn session_end(ok: bool, bytes: u64, files: &[String], reason: &str, dur_ms: u128) {}

#[inline]
pub fn next_conn() -> u64 {
    0
}

pub fn channel_open(label: &str, role: &str, laddr: &str, raddr: &str, conn: u64) {}

pub fn channel_close(label: &str, tx: u64, rx: u64, dur_ms: u128, reason: &str, conn: u64) {}

pub fn frame(channel: &str, dir: &str, data: &[u8], conn: u64) {}

pub fn bytes(channel: &str, dir: &str, data: &[u8], conn: u64) {}

pub fn note(channel: &str, text: &str) {}

pub fn note_conn(channel: &str, conn: u64, text: &str) {}

pub fn listen(label: &str, addr: &str) {}

pub fn discovery_build(local: &str, port: u16, name: &str, device_type: u32) {}

pub fn discovery_tx(dst: &str, data: &[u8]) {}

pub fn discovery_rx_raw(src: &str, data: &[u8]) {}

pub fn discovery_rx(peer: &crate::discovery::Peer) {}

pub fn channel_fail(peer: &str, port: u16, error: &str) {}

pub fn frame_partial(channel: &str, dir: &str, data: &[u8], conn: u64) {}

pub fn confirm_show(peer: &str, count: u32, bytes: u64) {}

pub fn confirm_answer(peer: &str, accepted: bool, reason: &str) {}
