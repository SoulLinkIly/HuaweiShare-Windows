//! UI 基础设施：跨卡片共享的视觉常量与字符串工具。
//!
//! 之前 `card` / `confirm` / `notice` 各写一套调色板、各写一份 `wide()`，
//! 数值一旦漂移（例如 0x938E8E 与 0x808080、圆角 20 与 22）就会在界面上露馅。
//! 现在只有这一处定义。

pub mod draw;
pub mod font;
#[cfg(windows)]
pub mod popup;
pub mod text;
pub mod theme;
