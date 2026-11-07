//! 已发现设备表：发送目标（可多选）、在线判定、被拒记忆。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub kind: String,
    pub seen: Instant,
    /// 最近一次发现包说「我接收分享」。false 时列表里提示对方关了华为分享。
    pub accepts: bool,
}

static PEERS: Mutex<Vec<PeerInfo>> = Mutex::new(Vec::new());

/// 用户勾选的发送目标，可以有多台，顺序 = 勾选顺序。
static TARGETS: Mutex<Vec<PeerInfo>> = Mutex::new(Vec::new());

static REVISION: AtomicU64 = AtomicU64::new(0);

/// 勾选过「自动代选」的目标：界面上要明示，用户也能一键关掉。
static AUTO_PICKED: AtomicBool = AtomicBool::new(false);

/// 磁盘上的目标表已经读过一次没有。
static LOADED: AtomicBool = AtomicBool::new(false);

fn targets_path() -> std::path::PathBuf {
    crate::store::path("targets.json")
}

/// 目标表 → 磁盘格式。只存名字和地址：端口、类型、在线状态都是发现阶段的
/// 临时信息，落盘等于把过期的端口当成下次连接的依据。
fn targets_json(list: &[PeerInfo]) -> String {
    let items: Vec<serde_json::Value> = list
        .iter()
        .map(|p| serde_json::json!({ "name": p.name, "host": p.host }))
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({ "targets": items }))
        .unwrap_or_else(|_| "{\"targets\":[]}".to_string())
}

/// 磁盘格式 → 目标表。坏条目整条跳过，不因为一行坏了就丢掉其余目标。
fn parse_targets(text: &str) -> Vec<PeerInfo> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(items) = value.get("targets").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let now = Instant::now();
    items
        .iter()
        .filter_map(|item| {
            let host = item.get("host")?.as_str()?.trim().to_string();
            if host.is_empty() {
                return None;
            }
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .unwrap_or(&host)
                .to_string();
            Some(PeerInfo {
                name,
                host,
                port: 0,
                kind: String::new(),
                // 落盘的目标没有「最后见到」的时间：给一次完整 TTL 的宽限，
                // 真下线了，`targets()` 里那条 5 分钟规则会把它清掉。
                seen: now,
                accepts: true,
            })
        })
        .collect()
}

/// 把勾选的目标写盘。失败只静默（下次勾选会再写一次）：目标表是小事，
/// 不能因为它写不进去就让一次发送失败。
fn save_targets() {
    // 单测跑在设计机上，不能去改用户的真实配置：`cargo test` 跑完把
    // 托盘的目标表清成测试里造的假设备，那是真事故。
    if cfg!(test) {
        return;
    }
    let Ok(list) = TARGETS.lock() else { return };
    let text = targets_json(&list);
    drop(list);
    let path = targets_path();
    // 先写临时文件再改名：写一半崩掉，读回来还是上一份完整的表。
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// 读回上次勾选的目标。
fn load_saved_targets() -> Vec<PeerInfo> {
    if cfg!(test) {
        return Vec::new();
    }
    match std::fs::read_to_string(targets_path()) {
        Ok(text) => parse_targets(&text),
        Err(_) => Vec::new(),
    }
}

/// 首次用到目标表时把磁盘上的读回来（只读一次）。
fn ensure_loaded() {
    if LOADED.swap(true, Ordering::SeqCst) {
        return;
    }
    let saved = load_saved_targets();
    if saved.is_empty() {
        return;
    }
    if let Ok(mut list) = TARGETS.lock() {
        if list.is_empty() {
            *list = saved;
        }
    }
    bump();
}

/// 当前目标是「替用户代选」的，还是他自己勾的。
pub fn auto_picked() -> bool {
    AUTO_PICKED.load(Ordering::SeqCst)
}

/// 用户明确表达过「不要目标」：清空过、或把最后一台取消勾选过。
/// 有它就不再自动代选，免得设备下线后文件被悄悄发给另一台。
static USER_CLEARED: AtomicBool = AtomicBool::new(false);

fn bump() {
    REVISION.fetch_add(1, Ordering::SeqCst);
}

/// 多久没回发现包就算离线。对齐官方 `DeviceAgingTimeout`。
pub const ONLINE_WINDOW: Duration = Duration::from_secs(15);

/// 离线设备在菜单里还能留多久，超过就彻底清掉。
pub const LIST_TTL: Duration = Duration::from_secs(300);

pub fn upsert(name: &str, host: &str, port: u16, kind: &str, accepts: bool) {
    if crate::env::present("HWSHARE_DEBUG") {
        use std::io::Write;
        let line = format!("{name}\t{host}:{port}\t{kind}\n");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(std::env::temp_dir().join("hwshare-peers.log"))
        {
            let _ = file.write_all(line.as_bytes());
        }
    }
    let Ok(mut list) = PEERS.lock() else { return };
    if let Some(slot) = list.iter_mut().find(|p| p.host == host) {
        // 发现包每 1~2 秒就来一个，内容绝大多数时候完全一样。
        // 只有真变了才 bump：否则 revision 每秒抖一次，UI 那套
        // 「revision 没变就不重建视图」的短路就白做了（排序 + clone 整个列表）。
        let mut changed = false;
        if slot.name != name {
            slot.name.clear();
            slot.name.push_str(name);
            changed = true;
        }
        if slot.port != port {
            slot.port = port;
            changed = true;
        }
        if slot.kind != kind {
            slot.kind.clear();
            slot.kind.push_str(kind);
            changed = true;
        }
        if slot.accepts != accepts {
            slot.accepts = accepts;
            changed = true;
        }
        slot.seen = Instant::now();
        if changed {
            bump();
        }
        return;
    }
    if list.len() >= 32 {
        list.remove(0);
    }
    list.push(PeerInfo {
        name: name.to_string(),
        host: host.to_string(),
        port,
        kind: kind.to_string(),
        seen: Instant::now(),
        accepts,
    });
    bump();
}

pub fn snapshot(max_age: Duration) -> Vec<PeerInfo> {
    let Ok(list) = PEERS.lock() else {
        return Vec::new();
    };
    let mut alive: Vec<PeerInfo> = list
        .iter()
        .filter(|p| p.seen.elapsed() <= max_age)
        .cloned()
        .collect();
    alive.sort_by_key(|p| p.seen.elapsed());
    alive
}

/// 当前勾选的发送目标。
///
/// 每次读都顺手做两件事：把端口/名字刷成最新的（对方重开分享端口会变，用旧端口
/// 一定连不上），并把离线超过 [`LIST_TTL`] 的清掉——菜单里也不会再出现。
pub fn targets() -> Vec<PeerInfo> {
    ensure_loaded();
    let Ok(mut slot) = TARGETS.lock() else {
        return Vec::new();
    };
    if slot.is_empty() {
        return Vec::new();
    }
    let live = PEERS.lock().map(|list| list.clone()).unwrap_or_default();

    let mut dropped: Vec<String> = Vec::new();
    slot.retain_mut(|target| {
        let fresh = live.iter().find(|p| p.host == target.host);
        let seen = fresh.map(|p| p.seen).unwrap_or(target.seen);
        if seen.elapsed() > LIST_TTL {
            dropped.push(target.name.clone());
            return false;
        }
        if let Some(fresh) = fresh {
            target.port = fresh.port;
            target.accepts = fresh.accepts;
            target.seen = fresh.seen;
            if target.name != fresh.name {
                target.name.clear();
                target.name.push_str(&fresh.name);
            }
            if target.kind != fresh.kind {
                target.kind.clear();
                target.kind.push_str(&fresh.kind);
            }
        }
        true
    });
    let list = slot.clone();
    let empty = list.is_empty();
    drop(slot);

    if !dropped.is_empty() {
        // 目标自己消失了就别擅自挑一台顶上：宁可让用户重新选，
        // 也不能把文件发到一台他没点过的设备。
        if empty {
            USER_CLEARED.store(true, Ordering::SeqCst);
        }
        bump();
        save_targets();
        #[cfg(windows)]
        crate::tray::log_line(&format!(
            "[目标] 离线超过 5 分钟，已清除：{}",
            dropped.join("、")
        ));
    }
    list
}

pub fn is_target(host: &str) -> bool {
    ensure_loaded();
    TARGETS
        .lock()
        .map(|list| list.iter().any(|p| p.host == host))
        .unwrap_or(false)
}

/// 勾上 / 勾掉一台设备，返回操作后它是否还被勾着。
pub fn toggle_target(peer: &PeerInfo) -> bool {
    let Ok(mut list) = TARGETS.lock() else {
        return false;
    };
    let on = match list.iter().position(|p| p.host == peer.host) {
        Some(index) => {
            list.remove(index);
            false
        }
        None => {
            list.push(peer.clone());
            true
        }
    };
    // 勾上就是"我要发"；勾掉最后一台才是"我不要目标"。
    USER_CLEARED.store(!on && list.is_empty(), Ordering::SeqCst);
    // 用户亲手勾过，就不再是"代选"了。
    AUTO_PICKED.store(false, Ordering::SeqCst);
    bump();
    drop(list);
    save_targets();
    on
}

pub fn clear_targets() {
    if let Ok(mut list) = TARGETS.lock() {
        list.clear();
    }
    USER_CLEARED.store(true, Ordering::SeqCst);
    AUTO_PICKED.store(false, Ordering::SeqCst);
    bump();
    save_targets();
}

#[derive(Clone, Debug)]
pub struct TargetView {
    pub peers: Vec<PeerInfo>,
    pub selected: Vec<PeerInfo>,
    pub revision: u64,
}

fn ordered(mut peers: Vec<PeerInfo>) -> Vec<PeerInfo> {
    peers.sort_by(|a, b| {
        let a_online = a.seen.elapsed() <= ONLINE_WINDOW;
        let b_online = b.seen.elapsed() <= ONLINE_WINDOW;
        b_online
            .cmp(&a_online)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.host.cmp(&b.host))
    });
    peers
}

/// 用户从没表过态时替他把第一台**在线**的设备勾上。
/// 离线的不算：勾了也发不出去，只会让第一次拖放失败。
fn auto_target(peers: &[PeerInfo], suppressed: bool) -> Option<PeerInfo> {
    if suppressed {
        return None;
    }
    peers
        .iter()
        .find(|p| p.seen.elapsed() <= ONLINE_WINDOW)
        .cloned()
}

fn place_selected_first(mut peers: Vec<PeerInfo>, selected: &[PeerInfo]) -> Vec<PeerInfo> {
    if selected.is_empty() {
        return peers;
    }
    let mut front: Vec<PeerInfo> = Vec::with_capacity(selected.len());
    for pick in selected {
        match peers.iter().position(|p| p.host == pick.host) {
            Some(index) => front.push(peers.remove(index)),
            // 目标已经不在快照窗口里（刚超时），也照样排在最前面给用户看。
            None => front.push(pick.clone()),
        }
    }
    front.extend(peers);
    front
}

pub fn view(max_age: Duration) -> TargetView {
    let sorted = ordered(snapshot(max_age));
    let mut selected = targets();
    if selected.is_empty() {
        if let Some(pick) = auto_target(&sorted, USER_CLEARED.load(Ordering::SeqCst)) {
            if let Ok(mut slot) = TARGETS.lock() {
                *slot = vec![pick.clone()];
            }
            // 代选只活在本次运行里：不落盘，否则下次启动会拿着一台
            // 用户从没点过的设备当目标，文件就发到别人那儿去了。
            AUTO_PICKED.store(true, Ordering::SeqCst);
            crate::report::log(&format!(
                "[目标] 还没选过接收方，先替你勾上「{}」，可在托盘菜单里改",
                pick.name
            ));
            selected = vec![pick];
            bump();
        }
    }
    let peers = place_selected_first(sorted, &selected);
    TargetView {
        peers,
        selected,
        revision: revision(),
    }
}

pub fn revision() -> u64 {
    REVISION.load(Ordering::SeqCst)
}

/// 按地址反查已发现设备的名字。`host` 可能是 "ip" 或 "ip:port"。
/// 接收会话里只有对端地址，用它将浮窗上的「传输目标」显示成设备名。
pub fn name_for_host(host: &str) -> Option<String> {
    let ip = host.split(':').next().unwrap_or(host);
    let list = PEERS.lock().ok()?;
    list.iter()
        .find(|p| p.host == ip || p.host == host)
        .map(|p| p.name.clone())
}

pub fn is_online(peer: &PeerInfo) -> bool {
    let Ok(list) = PEERS.lock() else {
        return false;
    };
    list.iter()
        .any(|p| p.host == peer.host && p.seen.elapsed() <= ONLINE_WINDOW)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Open,
    Closed,
}

static VERDICTS: Mutex<Vec<(String, Verdict, Instant)>> = Mutex::new(Vec::new());

const VERDICT_TTL: Duration = Duration::from_secs(180);

pub fn mark_verdict(host: &str, verdict: Verdict) {
    let Ok(mut list) = VERDICTS.lock() else {
        return;
    };
    list.retain(|(h, _, at)| h != host && at.elapsed() < VERDICT_TTL);
    list.push((host.to_string(), verdict, Instant::now()));
}

pub fn verdict(host: &str) -> Option<Verdict> {
    let Ok(mut list) = VERDICTS.lock() else {
        return None;
    };
    list.retain(|(_, _, at)| at.elapsed() < VERDICT_TTL);
    list.iter()
        .find(|(h, _, _)| h == host)
        .map(|(_, v, _)| *v)
}

#[cfg(test)]
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

/// 把两张表清干净，给跨模块的用例用（托盘菜单测试会建菜单，会顺带自动代选）。
#[cfg(test)]
pub(crate) fn reset_for_test() {
    if let Ok(mut list) = PEERS.lock() {
        list.clear();
    }
    if let Ok(mut list) = TARGETS.lock() {
        list.clear();
    }
    // 默认「用户明确不要目标」：否则 view() 会自动勾一台，用例就不确定了。
    USER_CLEARED.store(true, Ordering::SeqCst);
    bump();
}

/// 造一台「N 秒前见过」的设备，用来测离线灰显 / 超时清除。
#[cfg(test)]
pub(crate) fn upsert_aged(name: &str, host: &str, port: u16, kind: &str, age: Duration) {
    upsert(name, host, port, kind, true);
    if let Ok(mut list) = PEERS.lock() {
        if let Some(peer) = list.iter_mut().find(|p| p.host == host) {
            peer.seen = Instant::now() - age;
        }
    }
    bump();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str, host: &str, age: Duration) -> PeerInfo {
        PeerInfo {
            name: name.to_string(),
            host: host.to_string(),
            port: 1234,
            kind: "phone".to_string(),
            seen: Instant::now() - age,
            accepts: true,
        }
    }

    fn reset() {
        reset_for_test();
    }

    #[test]
    fn new_peer_never_steals_target() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        upsert("手机A", "10.0.0.1", 1234, "phone", true);
        let picked = snapshot(Duration::from_secs(180))
            .into_iter()
            .find(|p| p.host == "10.0.0.1")
            .expect("A 应该在列表里");
        assert!(toggle_target(&picked));
        assert_eq!(
            targets().first().map(|p| p.host.clone()),
            Some("10.0.0.1".to_string())
        );

        upsert("手机B", "10.0.0.2", 5678, "phone", true);
        assert_eq!(
            targets().iter().map(|p| p.host.as_str()).collect::<Vec<_>>(),
            vec!["10.0.0.1"],
            "新设备不能被自动加进发送目标"
        );

        // 对方重开分享后端口会变，目标里的端口必须跟着刷，否则发到旧端口必失败。
        upsert("手机A", "10.0.0.1", 9999, "phone", true);
        assert_eq!(targets().first().map(|p| p.port), Some(9999));
        reset();
    }

    #[test]
    fn toggle_target_adds_and_removes() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let a = peer("A", "10.9.0.1", Duration::ZERO);
        let b = peer("B", "10.9.0.2", Duration::ZERO);
        upsert("A", "10.9.0.1", 1234, "phone", true);
        upsert("B", "10.9.0.2", 1234, "tablet", true);

        assert!(toggle_target(&a), "第一次点应该是勾上");
        assert!(toggle_target(&b));
        assert_eq!(targets().len(), 2, "多选：两台都要在");
        assert!(is_target("10.9.0.2"));

        assert!(!toggle_target(&a), "再点一次是取消");
        assert_eq!(targets().len(), 1);
        assert!(!is_target("10.9.0.1"));
        assert!(!USER_CLEARED.load(Ordering::SeqCst), "还有一台勾着，不算清空");

        assert!(!toggle_target(&b));
        assert!(targets().is_empty());
        assert!(USER_CLEARED.load(Ordering::SeqCst), "勾掉最后一台 = 明确不要目标");
        reset();
    }

    #[test]
    fn targets_drop_offline_peers_after_ttl() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let stale = peer("老设备", "10.9.1.9", LIST_TTL + Duration::from_secs(1));
        if let Ok(mut list) = TARGETS.lock() {
            list.push(stale);
        }
        USER_CLEARED.store(false, Ordering::SeqCst);
        assert!(targets().is_empty(), "超过 5 分钟没消息的目标要清掉");
        assert!(USER_CLEARED.load(Ordering::SeqCst), "清掉后不要再自动代选别人");
        reset();
    }

    #[test]
    fn recent_offline_peer_stays_selectable() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        // 4 分钟前见过：还在 5 分钟窗口里，菜单要继续列出（灰着、标「离线」）。
        let recent = peer("刚息屏", "10.9.2.9", Duration::from_secs(240));
        if let Ok(mut list) = TARGETS.lock() {
            list.push(recent);
        }
        assert_eq!(targets().len(), 1, "5 分钟内不能清");
        reset();
    }

    #[test]
    fn ordered_prefers_online_then_name() {
        let list = ordered(vec![
            peer("B", "10.0.0.2", Duration::from_secs(5)),
            peer("A", "10.0.0.1", Duration::from_secs(600)),
            peer("C", "10.0.0.3", Duration::from_secs(5)),
        ]);
        let names: Vec<&str> = list.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["B", "C", "A"], "在线优先，同组按名字");
    }

    #[test]
    fn auto_target_picks_first_online_unless_user_cleared() {
        let list = vec![
            peer("离线", "10.0.0.1", Duration::from_secs(60)),
            peer("在线", "10.0.0.2", Duration::ZERO),
        ];
        assert_eq!(
            auto_target(&list, false).map(|p| p.name),
            Some("在线".to_string()),
            "只代选在线的，离线的勾了也发不出去"
        );
        assert!(auto_target(&list, true).is_none(), "用户清空过就不代选");
        assert!(auto_target(&[], false).is_none(), "空列表不代选");
        let all_offline = vec![peer("A", "10.0.0.1", Duration::from_secs(60))];
        assert!(auto_target(&all_offline, false).is_none(), "全离线时不要代选");
    }

    #[test]
    fn selected_peers_are_moved_to_the_top() {
        let a = peer("A", "10.0.0.1", Duration::ZERO);
        let b = peer("B", "10.0.0.2", Duration::ZERO);
        let c = peer("C", "10.0.0.3", Duration::ZERO);
        let list = vec![a.clone(), b.clone(), c.clone()];

        let untouched = place_selected_first(list.clone(), &[]);
        assert_eq!(
            untouched.iter().map(|p| p.host.as_str()).collect::<Vec<_>>(),
            list.iter().map(|p| p.host.as_str()).collect::<Vec<_>>(),
            "没选目标时列表顺序不变"
        );
        let moved = place_selected_first(list.clone(), &[c.clone(), a.clone()]);
        assert_eq!(
            moved.iter().map(|p| p.host.as_str()).collect::<Vec<_>>(),
            vec![c.host.as_str(), a.host.as_str(), b.host.as_str()],
            "勾选的目标排最前，顺序跟勾选顺序一致"
        );
        assert_eq!(moved.len(), 3);

        let outsider = peer("Z", "10.9.9.9", Duration::ZERO);
        let added = place_selected_first(list, &[outsider.clone()]);
        assert_eq!(added.len(), 4);
        assert_eq!(added[0].host, outsider.host);
    }

    #[test]
    fn targets_json_round_trips() {
        let list = vec![
            peer("手机A", "10.7.0.1", Duration::ZERO),
            peer("平板B", "10.7.0.2", Duration::ZERO),
        ];
        let back = parse_targets(&targets_json(&list));
        assert_eq!(
            back.iter().map(|p| p.host.as_str()).collect::<Vec<_>>(),
            vec!["10.7.0.1", "10.7.0.2"],
            "顺序要保住：勾选顺序 = 目标顺序"
        );
        assert_eq!(back[0].name, "手机A");
        assert_eq!(back[0].port, 0, "端口不落盘，等发现包刷新");
    }

    #[test]
    fn parse_targets_survives_garbage() {
        assert!(parse_targets("").is_empty(), "空文件当没配过");
        assert!(parse_targets("not json").is_empty());
        assert!(
            parse_targets("{\"targets\":{}}").is_empty(),
            "类型不对也不许崩"
        );
        let mixed = r#"{"targets":[{"name":"","host":"10.7.1.1"},{"host":"  "},{"name":"只有名字"}]}"#;
        let list = parse_targets(mixed);
        assert_eq!(list.len(), 1, "没地址的条目直接丢");
        assert_eq!(list[0].name, "10.7.1.1", "名字空就用地址顶上");
        let bom = "\u{feff}{\"targets\":[{\"host\":\"10.7.2.2\"}]}";
        assert_eq!(parse_targets(bom).len(), 1, "带 BOM 的 json 也要认");
    }

    #[test]
    fn view_puts_selected_peer_first_and_bumps_revision() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        upsert("视图目标", "10.66.0.6", 4321, "phone", true);
        let picked = snapshot(Duration::from_secs(3600))
            .into_iter()
            .find(|p| p.host == "10.66.0.6")
            .expect("刚登记的设备应该在列表里");
        toggle_target(&picked);
        let before = revision();
        let v = view(Duration::from_secs(3600));
        assert_eq!(v.peers[0].host, "10.66.0.6");
        assert_eq!(
            v.selected.iter().map(|p| p.host.as_str()).collect::<Vec<_>>(),
            vec!["10.66.0.6"]
        );
        assert!(v.revision >= before);
        reset();
    }
}
