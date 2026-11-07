//! 命令行入口：discover / send / send --to-all / serve / listen。

#[path = "shared/app.rs"]
#[allow(dead_code)]
mod app;

fn main() -> std::process::ExitCode {
    app::run_cli()
}
