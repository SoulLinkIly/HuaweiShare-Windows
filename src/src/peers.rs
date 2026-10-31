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

impl PeerInfo {
    pub fn label(&self) -> String {
        format!("{} · {}", self.name, self.host)
    }
}

pub const ALIVE: Duration = Duration::from_secs(8);

static PEERS: Mutex<Vec<PeerInfo>> = Mutex::new(Vec::new());

static DEFAULT: Mutex<Option<PeerInfo>> = Mutex::new(None);

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

pub fn set_default(peer: PeerInfo) {
    if let Ok(mut slot) = DEFAULT.lock() {
        *slot = Some(peer);
    }
}

pub fn selected() -> Option<PeerInfo> {
    let stored = match DEFAULT.lock() {
        Ok(guard) => guard.as_ref().cloned(),
        Err(_) => None,
    };

    if let Some(peer) = stored {
        let live = PEERS
            .lock()
            .ok()
            .and_then(|list| list.iter().find(|p| p.host == peer.host).cloned());
        let current = live.unwrap_or_else(|| peer.clone());
        if let Ok(mut slot) = DEFAULT.lock() {
            *slot = Some(current.clone());
        }
        return Some(current);
    }

    let mut alive = snapshot(ALIVE);
    if alive.len() == 1 {
        return alive.pop();
    }
    None
}

pub fn is_online(peer: &PeerInfo) -> bool {
    let Ok(list) = PEERS.lock() else {
        return false;
    };
    list.iter().any(|p| p.host == peer.host && p.seen.elapsed() <= ALIVE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_selection_rules() {
        upsert("手机A", "10.0.0.1", 1234, "phone");
        assert_eq!(
            selected().map(|p| p.host),
            Some("10.0.0.1".to_string()),
            "只有一台设备时自动选上"
        );

        upsert("手机B", "10.0.0.2", 5678, "phone");
        assert!(selected().is_none(), "出现第二台就回到未选择，不猜用户要发给谁");

        let picked = snapshot(Duration::from_secs(180))
            .into_iter()
            .find(|p| p.host == "10.0.0.1")
            .expect("A 应该在列表里");
        set_default(picked);
        assert_eq!(selected().map(|p| p.host), Some("10.0.0.1".to_string()));

        upsert("手机A", "10.0.0.1", 9999, "phone");
        assert_eq!(selected().map(|p| p.port), Some(9999), "端口要跟着最新记录刷新");
    }
}
