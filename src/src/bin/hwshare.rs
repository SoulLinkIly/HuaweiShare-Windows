//! GUI 入口：隐藏控制台，把消息循环交给 `tray`。

#![cfg_attr(windows, windows_subsystem = "windows")]

#[path = "shared/app.rs"]
#[allow(dead_code)]
mod app;

fn main() -> std::process::ExitCode {
    app::run_gui()
}
