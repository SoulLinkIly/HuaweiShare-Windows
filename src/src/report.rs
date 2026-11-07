//! 统一的事件出口：日志行与文本进度条。
//!
//! 协议层（`outbound` / `receive`）不直接 `print!`：谁在跑这个进程，就由谁决定
//! 事件去哪里。GUI 装一个「写托盘日志、不画文本进度」的 sink；CLI 不装，
//! 默认 sink 就直接打到 stderr / stdout。
//!
//! 以前这件事靠一个全局开关 `outbound::set_progress_lines(false)`：库自己默认
//! 往 stdout 画进度条，调用方必须"知道"要关，否则托盘进程里会攒下一堆没人看的
//! 输出。现在只有装 sink 这一个动作，而且发生在进程入口。

use std::sync::OnceLock;

/// 一次进度上报。`peer_pct` 是对端回报的百分比（只有部分设备会给）。
pub struct Progress {
    pub written: u64,
    pub total: u64,
    pub speed_mb: f64,
    pub peer_pct: Option<f64>,
}

type Logger = fn(&str);
type Painter = fn(&Progress);
type Ender = fn();

struct Sinks {
    log: Logger,
    paint: Painter,
    end: Ender,
}

static SINKS: OnceLock<Sinks> = OnceLock::new();

fn sinks() -> &'static Sinks {
    SINKS.get_or_init(|| Sinks {
        log: default_log,
        paint: default_paint,
        end: default_end,
    })
}

/// 装一次 sink。已经装过（或默认 sink 已被用过）时返回 `false`，不覆盖。
pub fn install(log: Logger, paint: Painter, end: Ender) -> bool {
    SINKS.set(Sinks { log, paint, end }).is_ok()
}

pub fn log(line: &str) {
    (sinks().log)(line);
}

pub fn progress(p: &Progress) {
    (sinks().paint)(p);
}

/// 一批传完：默认 sink 补一个换行，别让下一行输出接在进度条后面。
pub fn end_line() {
    (sinks().end)();
}

fn default_log(line: &str) {
    eprintln!("{line}");
}

fn default_paint(p: &Progress) {
    use std::io::Write;
    let pct = if p.total == 0 {
        0.0
    } else {
        p.written as f64 * 100.0 / p.total as f64
    };
    const WIDTH: usize = 24;
    let filled = (((pct / 100.0) * WIDTH as f64).round() as usize).min(WIDTH);
    let bar = format!("{}{}", "#".repeat(filled), "-".repeat(WIDTH - filled));
    let mb = p.written as f64 / 1_048_576.0;
    let total_mb = p.total as f64 / 1_048_576.0;
    match p.peer_pct {
        None => print!("\r[{bar}] {pct:5.1}%  {mb:>7.1}/{total_mb:.1} MB  {:>5.1} MB/s", p.speed_mb),
        Some(peer) => print!(
            "\r[{bar}] {pct:5.1}%  {mb:>7.1}/{total_mb:.1} MB  {:>5.1} MB/s  对方 {peer:5.1}%",
            p.speed_mb
        ),
    }
    let _ = std::io::stdout().flush();
}

fn default_end() {
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_sinks_are_usable_without_install() {
        // 测试进程不装 sink：这里只是确认默认实现不会 panic。
        progress(&Progress {
            written: 1,
            total: 2,
            speed_mb: 0.5,
            peer_pct: None,
        });
        end_line();
        log("");
    }
}
