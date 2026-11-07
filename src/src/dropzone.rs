//! 投放面板的门面，供托盘线程调用。

#![cfg(windows)]

pub use crate::card::{hide_drop as hide, show_drop as show, toggle_drop as toggle};
