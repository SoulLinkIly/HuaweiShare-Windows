use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

static SINK: OnceLock<Mutex<Option<std::fs::File>>> = OnceLock::new();
static START: OnceLock<Instant> = OnceLock::new();

fn startup() -> &'static Instant {
    START.get_or_init(Instant::now)
}

fn full() -> bool {
    std::env::var("HWSHARE_WIRE_FULL").is_ok()
}

fn sink() -> &'static Mutex<Option<std::fs::File>> {
    SINK.get_or_init(|| {
        let mut file = None;
        if std::env::var("HWSHARE_WIRE").is_ok() {
            if let Some(base) = std::env::var_os("LOCALAPPDATA") {
                let dir = std::path::PathBuf::from(base).join("HWShareWin");
                let _ = std::fs::create_dir_all(&dir);
                let path = dir.join(format!("wire-{}.jsonl", std::process::id()));
                file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .ok();
                if file.is_some() {
                    let wall = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis())
                        .unwrap_or(0);
                    if let Some(f) = file.as_mut() {
                        let _ = writeln!(
                            f,
                            "{{\"t\":0,\"dir\":\"mark\",\"ch\":\"-\",\"n\":0,\"hex\":\"\",\"note\":\"start wall_ms={wall} pid={}\"}}",
                            std::process::id()
                        );
                    }
                }
            }
        }
        Mutex::new(file)
    })
}

fn hex(data: &[u8]) -> String {
    let limit = if full() { data.len() } else { data.len().min(96) };
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(limit * 2 + 8);
    for &b in &data[..limit] {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0F) as usize] as char);
    }
    if limit < data.len() {
        out.push_str("..");
    }
    out
}

fn write_line(dir: &str, channel: &str, data: &[u8], note: &str) {
    let Ok(mut guard) = sink().lock() else { return };
    let Some(file) = guard.as_mut() else { return };
    let t = startup().elapsed().as_micros();
    let line = format!(
        "{{\"t\":{t},\"dir\":\"{dir}\",\"ch\":\"{channel}\",\"n\":{},\"hex\":\"{}\",\"note\":\"{}\"}}",
        data.len(),
        hex(data),
        note.replace('"', "'")
    );
    let _ = writeln!(file, "{line}");

    let _ = file.flush();
}

pub fn tx(channel: &str, data: &[u8], conn: u64) {
    crate::trace::bytes(channel, "tx", data, conn);
    if sink().lock().map(|g| g.is_some()).unwrap_or(false) {
        write_line("tx", channel, data, "");
    }
}

pub fn rx(channel: &str, data: &[u8], conn: u64) {
    crate::trace::bytes(channel, "rx", data, conn);
    if sink().lock().map(|g| g.is_some()).unwrap_or(false) {
        write_line("rx", channel, data, "");
    }
}

pub fn mark(channel: &str, note: &str) {
    if sink().lock().map(|g| g.is_some()).unwrap_or(false) {
        write_line("mark", channel, &[], note);
    }
}
