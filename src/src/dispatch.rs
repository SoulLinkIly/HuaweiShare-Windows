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

struct BusyGuard;

impl BusyGuard {
    fn acquire() -> Option<Self> {
        if BUSY.swap(true, Ordering::SeqCst) {
            None
        } else {
            Some(Self)
        }
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::SeqCst);
    }
}

pub fn send_to(peer: PeerInfo, paths: Vec<PathBuf>, display_name: String) -> Result<usize, String> {
    if paths.is_empty() {
        return Err("没有选中文件".to_string());
    }
    let Some(busy) = BusyGuard::acquire() else {
        return Err("上一个发送还没结束，稍等一下".to_string());
    };

    let count = paths.len();
    set_status(format!("正在发送 {count} 个文件 → {}", peer.name));

    let spawned = std::thread::Builder::new()
        .name("hwshare-send".to_string())
        .spawn(move || {
            let _busy = busy;
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
            #[cfg(windows)]
            let log = |line: &str| crate::tray::log_line(line);
            #[cfg(not(windows))]
            let log = |_line: &str| {};
            let outcome =
                crate::outbound::transmit(&peer.host, peer.port, &paths, &display_name, &log);
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
        });
    if let Err(e) = spawned {
        set_status(format!("无法创建发送线程：{e}"));
        return Err(format!("无法创建发送线程：{e}"));
    }

    Ok(count)
}
