//! 发送调度：按设备占槽、最多 4 路真并发，并把失败归并回 UI。

use std::path::PathBuf;
use std::sync::Mutex;

use crate::peers::PeerInfo;

const MAX_PARALLEL: usize = 4;
const PENDING_MAX: usize = 4;

static ACTIVE: Mutex<Vec<String>> = Mutex::new(Vec::new());
static PENDING: Mutex<Vec<(PeerInfo, Vec<PathBuf>, String)>> = Mutex::new(Vec::new());

pub fn active_count() -> usize {
    ACTIVE.lock().map(|l| l.len()).unwrap_or(0)
}

/// 发送过程的用户可见状态。以前它塞在一个全局 `Option<String>` 里，
/// 只有托盘自己读，CLI 完全看不到，浮窗还各记一份。现在统一走日志出口。
fn note(text: impl Into<String>) {
    crate::report::log(&text.into());
}

#[cfg(windows)]
fn toast(title: &str, body: &str) {
    crate::tray::notify(title, body);
}

#[cfg(not(windows))]
fn toast(_title: &str, _body: &str) {}

struct Slot {
    key: String,
}

impl Slot {
    fn acquire(peer: &PeerInfo) -> Option<Self> {
        let key = peer.host.clone();
        let mut list = ACTIVE.lock().ok()?;
        if list.iter().any(|k| *k == key) {
            return None;
        }
        if list.len() >= MAX_PARALLEL {
            return None;
        }
        list.push(key.clone());
        Some(Self { key })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Ok(mut list) = ACTIVE.lock() {
            list.retain(|k| *k != self.key);
        }
    }
}

pub fn send_to(peer: PeerInfo, paths: Vec<PathBuf>, display_name: String) -> Result<usize, String> {
    start(peer, paths, display_name, true)
}

fn start(
    peer: PeerInfo,
    paths: Vec<PathBuf>,
    display_name: String,
    allow_queue: bool,
) -> Result<usize, String> {
    if paths.is_empty() {
        return Err("没有选中文件".to_string());
    }
    let count = paths.len();
    let Some(slot) = Slot::acquire(&peer) else {
        if !allow_queue {
            return Err("目标正忙".to_string());
        }
        let queued = match PENDING.lock() {
            Ok(mut q) if q.len() < PENDING_MAX => {
                q.push((peer, paths, display_name));
                Ok(q.len())
            }
            Ok(_) => Err("排队太多了（最多 4 个），等前面发完再拖"),
            Err(_) => Err("排队的内部状态出错，请稍后重试"),
        };
        return match queued {
            Ok(n) => {
                note(format!(
                    "已排队 {count} 个文件（同一目标在发 / 前面还有 {} 个任务）",
                    n - 1
                ));
                // 拖进去的文件没立刻开始发，屏幕上必须先说一句「收到，排队了」；
                // 否则用户看到的就是「拖了但没反应」，很容易再拖一遍变成重复发送。
                toast(
                    "已排队",
                    &format!(
                        "{count} 个文件在等前一批发完（前面还有 {} 个）",
                        n - 1
                    ),
                );
                Ok(count)
            }
            Err(e) => Err(e.to_string()),
        };
    };

    note(format!(
        "正在发送 {count} 个文件 → {}（并发 {}）",
        peer.name,
        active_count()
    ));

    let spawned = std::thread::Builder::new()
        .name("hwshare-send".to_string())
        .spawn(move || {
            let _slot = slot;

            let total: u64 = paths
                .iter()
                .filter_map(|p| std::fs::metadata(p).ok())
                .map(|m| m.len())
                .sum();
            note(format!(
                "正在发送 {count} 个文件 · {:.1} MB → {}",
                total as f64 / 1048576.0,
                peer.name
            ));

            #[cfg(windows)]
            let log = |line: &str| {
                crate::tray::log_line(line);

                let brief: String = line.chars().take(48).collect();
                note(brief);
            };
            #[cfg(not(windows))]
            let log = |_line: &str| {};
            // 浮窗显示「发给谁」而不是文件名；begin() 会取走这个线程里的名字。
            crate::progress::set_target(&peer.name);
            let outcome =
                crate::outbound::transmit(&peer.host, peer.port, &paths, &display_name, &log);
            match outcome {
                Ok(report) => {
                    crate::peers::mark_verdict(&peer.host, crate::peers::Verdict::Open);
                    // 与接收侧的「收到 N 个文件 · X · 来自 设备」对称：
                    // 数量、体积、对端，一眼看完。体积按量级换单位，
                    // 五百 KB 的图不会写成「0.0 MB」。
                    let message = format!(
                        "已发送 {} 个文件 · {} → {}",
                        report.files.len(),
                        crate::human::bytes(report.bytes),
                        peer.name
                    );
                    note(message.clone());
                    toast("发送完成", &message);
                }
                Err(e) => {
                    crate::tray::log_line(&format!("发送失败（{}）：{e}", peer.name));
                    let mut message = format!("{}：{}", peer.name, e.user_message());
                    if e.kind() == crate::ErrorKind::Rejected {
                        crate::peers::mark_verdict(
                            &peer.host,
                            crate::peers::Verdict::Closed,
                        );
                        if peer.kind != "computer" {
                            message.push_str(
                                "（对方没打开华为分享，或控制中心里没设成\"所有人可见\"）",
                            );
                        }
                    }
                    note(message.clone());
                    toast(e.kind().title(), &message);
                }
            }

            drop(_slot);
            drain_pending();
        });

    if let Err(e) = spawned {
        note(format!("无法创建发送线程：{e}"));
        return Err(format!("无法创建发送线程：{e}"));
    }

    Ok(count)
}

fn drain_pending() {
    loop {
        if active_count() >= MAX_PARALLEL {
            break;
        }
        let next = match PENDING.lock() {
            Ok(mut q) if !q.is_empty() => Some(q.remove(0)),
            _ => None,
        };
        let Some((peer, paths, display)) = next else {
            break;
        };
        crate::tray::log_line(&format!(
            "[排队] 开始发送之前排队的 {} 个文件 → {}",
            paths.len(),
            peer.name
        ));
        // 取出来之后先留一份：如果这一轮起不来（目标还忙、或线程创不出来），
        // 要原样放回队首。以前这里是"取出即丢"，起不来那笔发送就静默消失了。
        let backup = (peer.clone(), paths.clone(), display.clone());
        match start(peer, paths, display, false) {
            Ok(_) => continue,
            Err(e) => {
                if let Ok(mut q) = PENDING.lock() {
                    q.insert(0, backup);
                }
                crate::tray::log_line(&format!("[排队] 这一轮起不来（{e}），任务留在队列里"));
                break;
            }
        }
    }
}

/// 同时发往多台设备（「发送目标」里可以勾多台）。
///
/// 每台一个线程，由 [`Slot`] 保证同设备不并行、总路数不超过上限；
/// 起不来的进队列，[`drain_pending`] 会接着发。
pub fn send_many(
    targets: Vec<PeerInfo>,
    paths: Vec<PathBuf>,
    display_name: String,
) -> Result<usize, String> {
    if paths.is_empty() {
        return Err("没有选中文件".to_string());
    }
    let count = paths.len();
    let total = targets.len();
    let mut started = 0usize;
    let mut first_error: Option<String> = None;
    for peer in targets {
        match send_to(peer, paths.clone(), display_name.clone()) {
            Ok(_) => started += 1,
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }
    if started == 0 {
        return Err(first_error.unwrap_or_else(|| "没有可发送的目标".to_string()));
    }
    note(format!(
        "正在同时发送 {count} 个文件 → {started}/{total} 台设备"
    ));
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 三个用例都在动全局槽位表，而 `cargo test` 默认多线程跑：
    /// 不串行的话 `active_count()` 会被另一个用例的占位污染（偶发失败）。
    static SLOT_LOCK: Mutex<()> = Mutex::new(());

    fn lock_slots() -> std::sync::MutexGuard<'static, ()> {
        SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn peer(name: &str, host: &str) -> PeerInfo {
        PeerInfo {
            name: name.to_string(),
            host: host.to_string(),
            port: 1,
            kind: "phone".to_string(),
            seen: std::time::Instant::now(),
            accepts: true,
        }
    }

    #[test]
    fn same_peer_cannot_run_twice_but_other_peer_can() {
        let _guard = lock_slots();
        let a = peer("A", "10.0.0.1");
        let first = Slot::acquire(&a).expect("第一路应拿到槽位");
        assert!(Slot::acquire(&a).is_none(), "同一台设备不能并发两路");
        let b = peer("B", "10.0.0.2");
        let second = Slot::acquire(&b).expect("另一台设备应能并发");
        assert_eq!(active_count(), 2);
        drop(first);
        assert_eq!(active_count(), 1);
        drop(second);
        assert_eq!(active_count(), 0);
    }

    #[test]
    fn parallel_limit_is_enforced() {
        let _guard = lock_slots();
        let mut held = Vec::new();
        for i in 0..MAX_PARALLEL {
            let p = peer("x", &format!("10.1.0.{i}"));
            held.push(Slot::acquire(&p).expect("未到上限都应成功"));
        }
        let extra = peer("y", "10.1.0.99");
        assert!(Slot::acquire(&extra).is_none(), "超过上限必须拒绝");
        held.clear();
        assert_eq!(active_count(), 0);
    }

    #[test]
    fn send_many_rejects_empty_file_list() {
        let _guard = lock_slots();
        let err = send_many(vec![peer("只有一台", "10.0.0.1")], Vec::new(), "本机".into());
        assert_eq!(err, Err("没有选中文件".to_string()), "空文件列表不该起线程");
    }
}
