//! 进度浮窗门面，全部转发到 `progress`。
//!
//! 协议层（`outbound` / `receive`）只通过这里碰界面，不直接依赖 `card`：
//! CLI 构建里 `card` 整个不存在，这一层就是那段差异的唯一落点。
//!
//! 收尾只有 `abort()` 一个入口：`fail()` 把「正在传输」切成失败态，
//! `abort()` 额外保证已结束的任务不会被重复处理（Drop 守卫直接调它）。

#[cfg(windows)]
pub use crate::progress::{
    abort, finish, preparing, set_batch, set_outgoing, start, update, waiting,
};

#[cfg(not(windows))]
mod stubs {
    pub fn set_outgoing(_ours: bool) {}
    pub fn start(_name: &str) {}
    pub fn waiting(_name: &str) {}
    pub fn preparing(_name: &str) {}
    pub fn set_batch(_files: usize) {}
    pub fn update(_received: u64, _total: u64) {}
    pub fn finish() {}
    pub fn abort() {}
}

#[cfg(not(windows))]
pub use stubs::{abort, finish, preparing, set_batch, set_outgoing, start, update, waiting};
