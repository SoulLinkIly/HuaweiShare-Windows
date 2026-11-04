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
}

static PEERS: Mutex<Vec<PeerInfo>> = Mutex::new(Vec::new());
static DEFAULT: Mutex<Option<PeerInfo>> = Mutex::new(None);
static REVISION: AtomicU64 = AtomicU64::new(0);
static USER_CLEARED: AtomicBool = AtomicBool::new(false);

fn bump() {
    REVISION.fetch_add(1, Ordering::SeqCst);
}

pub fn upsert(name: &str, host: &str, port: u16, kind: &str) {
    if std::env::var("HWSHARE_DEBUG").is_ok() {
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
        slot.name = name.to_string();
        slot.port = port;
        slot.kind = kind.to_string();
        slot.seen = Instant::now();
        bump();
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

#[derive(Clone, Debug)]
pub struct TargetView {
    pub peers: Vec<PeerInfo>,
    pub selected: Option<PeerInfo>,
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

fn auto_target(peers: &[PeerInfo], suppressed: bool) -> Option<PeerInfo> {
    if suppressed || peers.is_empty() {
        None
    } else {
        Some(peers[0].clone())
    }
}

fn place_selected_first(mut peers: Vec<PeerInfo>, sel: Option<&PeerInfo>) -> Vec<PeerInfo> {
    let Some(sel) = sel else { return peers };
    match peers.iter().position(|p| p.host == sel.host) {
        Some(index) => {
            let picked = peers.remove(index);
            peers.insert(0, picked);
        }
        None => peers.insert(0, sel.clone()),
    }
    peers
}

pub fn view(max_age: Duration) -> TargetView {
    let sorted = ordered(snapshot(max_age));
    let mut selected = selected();
    if selected.is_none() {
        if let Some(pick) = auto_target(&sorted, USER_CLEARED.load(Ordering::SeqCst)) {
            set_default(pick.clone());
            selected = Some(pick);
        }
    }
    let peers = place_selected_first(sorted, selected.as_ref());
    TargetView {
        peers,
        selected,
        revision: revision(),
    }
}

pub fn revision() -> u64 {
    REVISION.load(Ordering::SeqCst)
}

pub fn set_default(peer: PeerInfo) {
    if let Ok(mut slot) = DEFAULT.lock() {
        *slot = Some(peer);
    }
    USER_CLEARED.store(false, Ordering::SeqCst);
    bump();
}

pub fn clear_default() {
    if let Ok(mut slot) = DEFAULT.lock() {
        *slot = None;
    }
    USER_CLEARED.store(true, Ordering::SeqCst);
    bump();
}

pub fn selected() -> Option<PeerInfo> {
    let mut guard = DEFAULT.lock().ok()?;
    let peer = guard.as_ref()?.clone();
    let live = PEERS
        .lock()
        .ok()
        .and_then(|list| list.iter().find(|p| p.host == peer.host).cloned());
    match live {
        Some(fresh) => {
            *guard = Some(fresh.clone());
            Some(fresh)
        }
        None => Some(peer),
    }
}

pub const ONLINE_WINDOW: Duration = Duration::from_secs(180);

pub fn is_online(peer: &PeerInfo) -> bool {
    let Ok(list) = PEERS.lock() else {
        return false;
    };
    list.iter()
        .any(|p| p.host == peer.host && p.seen.elapsed() <= ONLINE_WINDOW)
}

#[cfg(test)]
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

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
        }
    }

    #[test]
    fn new_peer_never_steals_target() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        upsert("手机A", "10.0.0.1", 1234, "phone");
        let picked = snapshot(Duration::from_secs(180))
            .into_iter()
            .find(|p| p.host == "10.0.0.1")
            .expect("A 应该在列表里");
        set_default(picked);
        assert_eq!(selected().map(|p| p.host), Some("10.0.0.1".to_string()));

        upsert("手机B", "10.0.0.2", 5678, "phone");
        assert_eq!(
            selected().map(|p| p.host),
            Some("10.0.0.1".to_string()),
            "新设备不能顶替已选目标"
        );

        upsert("手机A", "10.0.0.1", 9999, "phone");
        assert_eq!(selected().map(|p| p.port), Some(9999));
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
    fn auto_target_picks_first_unless_user_cleared() {
        let list = vec![
            peer("A", "10.0.0.1", Duration::ZERO),
            peer("B", "10.0.0.2", Duration::ZERO),
        ];
        assert_eq!(
            auto_target(&list, false).map(|p| p.name),
            Some("A".to_string())
        );
        assert!(auto_target(&list, true).is_none(), "用户清除过就不代选");
        assert!(auto_target(&[], false).is_none(), "空列表不代选");
    }

    #[test]
    fn selected_peer_is_moved_to_the_top() {
        let a = peer("A", "10.0.0.1", Duration::ZERO);
        let b = peer("B", "10.0.0.2", Duration::ZERO);
        let c = peer("C", "10.0.0.3", Duration::ZERO);
        let list = vec![a.clone(), b.clone(), c.clone()];

        let untouched = place_selected_first(list.clone(), None);
        assert_eq!(
            untouched.iter().map(|p| p.host.as_str()).collect::<Vec<_>>(),
            list.iter().map(|p| p.host.as_str()).collect::<Vec<_>>(),
            "没选目标时列表顺序不变"
        );
        let moved = place_selected_first(list.clone(), Some(&c));
        assert_eq!(moved[0].host, c.host, "已勾选的目标必须排首位");
        assert_eq!(moved.len(), 3);

        let outsider = peer("Z", "10.9.9.9", Duration::ZERO);
        let added = place_selected_first(list, Some(&outsider));
        assert_eq!(added.len(), 4);
        assert_eq!(added[0].host, outsider.host);
    }

    #[test]
    fn view_puts_selected_peer_first_and_bumps_revision() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        upsert("视图目标", "10.66.0.6", 4321, "phone");
        let picked = snapshot(Duration::from_secs(3600))
            .into_iter()
            .find(|p| p.host == "10.66.0.6")
            .expect("刚登记的设备应该在列表里");
        set_default(picked);
        let before = revision();
        let v = view(Duration::from_secs(3600));
        assert_eq!(v.peers[0].host, "10.66.0.6");
        assert_eq!(v.selected.map(|p| p.host), Some("10.66.0.6".to_string()));
        assert!(v.revision >= before);
    }
}
