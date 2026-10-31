use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::peers::PeerInfo;

static BUSY: AtomicBool = AtomicBool::new(false);
static STATUS: Mutex<Option<String>> = Mutex::new(None);

pub fn busy() -> bool {
    BUSY.load(Ordering::Relaxed)
}

pub fn status() -> Option<String> {
    STATUS.lock().ok().and_then(|slot| slot.clone())
}

fn set_status(text: impl Into<String>) {
    if let Ok(mut slot) = STATUS.lock() {
        *slot = Some(text.into());
    }
}

#[cfg(windows)]
fn toast(title: &str, body: &str) {
    crate::tray::notify(title, body);
}

#[cfg(not(windows))]
fn toast(_title: &str, _body: &str) {}

pub fn send_to(peer: PeerInfo, paths: Vec<PathBuf>, display_name: String) -> Result<usize, String> {
    if paths.is_empty() {
        return Err("没有选中文件".to_string());
    }
    if BUSY.swap(true, Ordering::SeqCst) {
        return Err("上一个发送还没结束，稍等一下".to_string());
    }

    let count = paths.len();
    let total: u64 = paths
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    set_status(format!(
        "正在发送 {count} 个文件 · {:.1} MB → {}",
        total as f64 / 1048576.0,
        peer.name
    ));

    std::thread::spawn(move || {
        #[cfg(windows)]
        let log = |line: &str| crate::tray::log_line(line);
        #[cfg(not(windows))]
        let log = |_line: &str| {};
        let outcome = crate::outbound::send(&peer.host, peer.port, &paths, &display_name, &log);
        match outcome {
            Ok(report) => {
                let message = format!(
                    "已发送 {} 个文件 · {:.1} MB",
                    report.files.len(),
                    report.bytes as f64 / 1048576.0
                );
                set_status(message.clone());
                toast("发送完成", &message);
            }
            Err(e) => {
                let message = format!("失败：{e}");
                set_status(message.clone());
                toast("发送失败", &message);
            }
        }
        BUSY.store(false, Ordering::SeqCst);
    });

    Ok(count)
}
