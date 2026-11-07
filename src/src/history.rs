//! 传输历史：每次收发往 `transfers.log` 记一行，超过 1 MB 轮转。
//!
//! 这份文件就是给用户直接打开的：制表符分隔，一行一次传输，首行是表头。
//! 想看「几点、发给谁、几个文件、多大」不需要程序另做界面——记事本打开即可，
//! 或者直接拖进 Excel。

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

const MAX_LOG: u64 = 1024 * 1024;

/// 首行表头。新文件（含轮转后的新文件）第一次写入时补上。
const HEADER: &str = "时间\t方向\t设备\t结果\t文件数\t大小\t耗时\t速度\t文件列表\t备注\n";

fn log_path() -> PathBuf {
    crate::store::path("transfers.log")
}

/// 日志文件位置。托盘菜单「打开传输日志」用它。
pub fn log_file() -> PathBuf {
    log_path()
}

/// 一行的方向列：日志里给人看，写中文。
fn direction_label(raw: &str) -> &str {
    match raw {
        "send" => "发送",
        "recv" => "接收",
        other => other,
    }
}

fn describe_transfer(files: &[(String, u64)]) -> String {
    if files.is_empty() {
        return "-".to_string();
    }
    let shown: Vec<&str> = files.iter().take(5).map(|(n, _)| n.as_str()).collect();
    let mut text = shown.join("; ");
    if files.len() > 5 {
        text.push_str(&format!("; 等 {} 个", files.len()));
    }
    text.replace('\t', " ")
}

/// 大小列。一律按 MB 写的话，一段剪贴板文本、一张小图都会显示成 `0.0 MB`，
/// 看着像「什么也没传」。按量级换单位（实现见 [`crate::human::bytes`]），
/// 让这一列自己就能读懂。
fn size_text(bytes: u64) -> String {
    crate::human::bytes(bytes)
}

/// 一次传输 → 日志里的一行（含换行）。
fn format_line(
    stamp: &str,
    direction: &str,
    peer: &str,
    files: &[(String, u64)],
    bytes: u64,
    elapsed: Duration,
    ok: bool,
    note: &str,
) -> String {
    let secs = elapsed.as_secs_f64().max(0.001);
    let speed = bytes as f64 / 1_048_576.0 / secs;
    format!(
        "{stamp}\t{}\t{peer}\t{}\t{} 个\t{}\t{secs:.1} s\t{speed:.1} MB/s\t{}\t{}\n",
        direction_label(direction),
        if ok { "成功" } else { "失败" },
        files.len(),
        size_text(bytes),
        describe_transfer(files),
        note.replace('\t', " ")
    )
}

pub fn record(
    direction: &str,
    peer: &str,
    files: &[(String, u64)],
    bytes: u64,
    elapsed: Duration,
    ok: bool,
    note: &str,
) {
    let path = log_path();

    static WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > MAX_LOG {
            let old = path.with_extension("log.1");
            let _ = std::fs::remove_file(&old);
            let _ = std::fs::rename(&path, &old);
        }
    }

    let line = format_line(
        &crate::clock::format_unix(crate::clock::now_secs()),
        direction,
        peer,
        files,
        bytes,
        elapsed,
        ok,
        note,
    );

    // 多路并行时（最多 4 路发送 + 16 路接收）会有多个线程同时往这一份文件追加。
    // 单行超过 4 KiB 时系统不保证一次写入的原子性，可能两行交错成一条乱码，
    // 所以这里用一把进程内的锁把"打开 + 写整行"串起来。
    let _ = migrate_legacy(&path);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        // 空文件（新建或刚轮转）先补表头，用记事本打开就能看懂列。
        if file.metadata().map(|m| m.len()).unwrap_or(1) == 0 {
            let _ = file.write_all(HEADER.as_bytes());
        }
        let _ = file.write_all(line.as_bytes());
    }
}

/// 老版本写的日志没有表头、方向列是 `send` / `recv`。
///
/// 直接把表头补在末尾是没有意义的，只能整份重写一次；只动方向列的那一格，
/// 其余字节（含文件列表里的英文单词）一个不碰。每进程只试一次，失败就算了——
/// 日志格式不统一不该影响收发本身。
fn migrate_legacy(path: &std::path::Path) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(()); // 还没有日志，交给正常写入去建。
    };
    if !has_legacy_token(&text) {
        return Ok(());
    }

    let out = rewrite_legacy(&text);
    let tmp = path.with_extension("log.tmp");
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, path)
}

/// 整份重写：补表头 + 把旧英文列换成中文。纯函数，方便直接测。
fn rewrite_legacy(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + HEADER.len());
    out.push_str(HEADER);
    for line in text.lines() {
        // 旧表头（如果有）丢掉，下面统一只写一份。
        if line.starts_with("时间\t") {
            continue;
        }
        let mut cols: Vec<&str> = line.split('\t').collect();
        if cols.len() == 10 {
            match cols[1] {
                "send" => cols[1] = "发送",
                "recv" => cols[1] = "接收",
                _ => {}
            }
            match cols[3] {
                "OK" => cols[3] = "成功",
                "FAIL" => cols[3] = "失败",
                _ => {}
            }
        }
        out.push_str(&cols.join("\t"));
        out.push('\n');
    }
    out
}

/// 这份日志里还有没有旧格式的英文列（`send` / `recv` / `OK` / `FAIL`）。
///
/// 用「有没有旧记号」而不是「有没有表头」判断：上一次迁移可能中途失败或只改了一半，
/// 那样文件既有表头又留着英文列，只认表头就永远修不好了。
fn has_legacy_token(text: &str) -> bool {
    ["\tsend\t", "\trecv\t", "\tOK\t", "\tFAIL\t"]
        .iter()
        .any(|token| text.contains(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_is_readable() {

        let text = crate::clock::format_at(1_793_116_800, 8 * 3600);
        assert_eq!(text.len(), 19, "{text}");
        assert_eq!(&text[4..5], "-");
        assert_eq!(&text[10..11], " ");
        assert_eq!(&text[13..14], ":");
    }

    #[test]
    fn summarize_truncates() {
        let files: Vec<(String, u64)> = (0..8).map(|i| (format!("f{i}.jpg"), 1)).collect();
        let text = describe_transfer(&files);
        assert!(text.contains("等 8 个"), "{text}");
    }

    #[test]
    fn line_is_readable_without_a_ui() {
        let files = vec![
            ("a.jpg".to_string(), 5 * 1_048_576),
            ("b.jpg".to_string(), 7 * 1_048_576),
        ];
        let line = format_line(
            "2026-11-07 14:20:31",
            "send",
            "192.168.1.7:38999",
            &files,
            12 * 1_048_576,
            Duration::from_secs(4),
            true,
            "",
        );
        // 只去掉换行：备注为空时行尾仍留一个制表符，那是一个空列，不是多余字符。
        let cols: Vec<&str> = line.trim_end_matches('\n').split('\t').collect();
        assert_eq!(cols.len(), 10, "列数要跟表头一致：{line}");
        assert_eq!(cols[0], "2026-11-07 14:20:31", "要能看出几点");
        assert_eq!(cols[1], "发送", "方向写中文，别让人猜 send/recv");
        assert_eq!(cols[2], "192.168.1.7:38999", "发给谁/谁发来的");
        assert_eq!(cols[3], "成功");
        assert_eq!(cols[4], "2 个", "几个文件");
        assert_eq!(cols[5], "12.0 MB", "多大");
        assert_eq!(cols[8], "a.jpg; b.jpg");

        let recv = format_line(
            "2026-11-07 14:21:00",
            "recv",
            "192.168.1.9:12345",
            &files,
            1024,
            Duration::from_secs(1),
            false,
            "对端取消",
        );
        assert!(recv.contains("接收"), "{recv}");
        assert!(recv.contains("失败") && recv.contains("对端取消"), "{recv}");
    }

    #[test]
    fn size_column_switches_units_by_magnitude() {
        assert_eq!(size_text(0), "0 B", "空文件别写成 0.0 MB");
        assert_eq!(size_text(60), "60 B", "一段剪贴板文本");
        assert_eq!(size_text(1536), "1.5 KB");
        assert_eq!(size_text(1_048_576), "1.0 MB");
        assert_eq!(size_text(12_582_912), "12.0 MB", "MB 以上保持原来的写法");

        let line = format_line(
            "2026-11-07 14:20:31",
            "recv",
            "192.168.1.9",
            &[("Huawei Share.txt".to_string(), 60)],
            60,
            Duration::from_secs(1),
            true,
            "已复制到剪贴板（22 字）",
        );
        let cols: Vec<&str> = line.trim_end_matches('\n').split('\t').collect();
        assert_eq!(cols[5], "60 B", "文本这一行要能看出真的收到了东西：{line}");
        assert!(cols[9].contains("已复制"), "{line}");
    }

    #[test]
    fn header_matches_column_count() {
        let cols: Vec<&str> = HEADER.trim_end().split('\t').collect();
        assert_eq!(cols.len(), 10, "{HEADER}");
    }

    #[test]
    fn legacy_log_is_migrated_once_and_stays_put() {
        let legacy = "2026-11-01 09:00:00\tsend\t1.2.3.4:5\tOK\t3 个\t12.5 MB\t4.0 s\t3.1 MB/s\ta.jpg\t\n\
                      2026-11-01 09:05:00\trecv\t1.2.3.9:6\tFAIL\t1 个\t0.0 MB\t0.0 s\t0.0 MB/s\tx.zip\t对方取消\n";
        assert!(has_legacy_token(legacy), "旧文件应该被判成旧格式");

        let new = rewrite_legacy(legacy);
        assert!(new.starts_with("时间\t方向\t"), "表头必须在第一行");
        assert!(new.contains("\t发送\t"), "{new}");
        assert!(new.contains("\t接收\t"), "{new}");
        assert!(new.contains("\t成功\t") && new.contains("\t失败\t"), "{new}");
        assert!(new.contains("对方取消"), "备注不能丢");
        assert!(!has_legacy_token(&new), "改完就不该再有英文列");

        // 再跑一次必须原样：否则每次启动都要重写一遍日志。
        assert_eq!(rewrite_legacy(&new), new, "迁移要幂等");
    }
}
