use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_LOG: u64 = 1024 * 1024;

fn log_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(PathBuf::from(base).join("HWShareWin").join("transfers.log"))
}

fn stamp(secs: u64) -> String {
    let offset = local_offset_secs();
    let total = secs as i64 + offset;
    let days = total.div_euclid(86_400);
    let rest = total.rem_euclid(86_400);
    let (h, m, s) = (rest / 3600, (rest % 3600) / 60, rest % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mth <= 2 { y + 1 } else { y };

    format!("{year:04}-{mth:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

fn local_offset_secs() -> i64 {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::SYSTEMTIME;
        use windows_sys::Win32::System::SystemInformation::{GetLocalTime, GetSystemTime};
        unsafe fn to_secs(t: SYSTEMTIME) -> i64 {
            let days = days_from_civil(t.wYear as i64, t.wMonth as i64, t.wDay as i64);
            days * 86_400
                + t.wHour as i64 * 3600
                + t.wMinute as i64 * 60
                + t.wSecond as i64
        }
        unsafe fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
            let y = if m <= 2 { y - 1 } else { y };
            let era = if y >= 0 { y } else { y - 399 } / 400;
            let yoe = y - era * 400;
            let mp = if m > 2 { m - 3 } else { m + 9 };
            let doy = (153 * mp + 2) / 5 + d - 1;
            let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            era * 146_097 + doe - 719_468
        }
        let mut local: SYSTEMTIME = unsafe { std::mem::zeroed() };
        let mut utc: SYSTEMTIME = unsafe { std::mem::zeroed() };
        unsafe {
            GetLocalTime(&mut local);
            GetSystemTime(&mut utc);
            to_secs(local) - to_secs(utc)
        }
    }
    #[cfg(not(windows))]
    {
        0
    }
}

fn summarize(files: &[(String, u64)]) -> String {
    if files.is_empty() {
        return "-".to_string();
    }
    let shown: Vec<String> = files.iter().take(5).map(|(n, _)| n.clone()).collect();
    let mut text = shown.join("; ");
    if files.len() > 5 {
        text.push_str(&format!("; 等 {} 个", files.len()));
    }
    text.replace('\t', " ")
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
    let Some(path) = log_path() else {
        return;
    };
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

    let secs = elapsed.as_secs_f64().max(0.001);
    let mb = bytes as f64 / 1_048_576.0;
    let speed = mb / secs;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let line = format!(
        "{}\t{}\t{}\t{}\t{} 个\t{:.1} MB\t{:.1} s\t{:.1} MB/s\t{}\t{}\n",
        stamp(now),
        direction,
        peer,
        if ok { "OK" } else { "FAIL" },
        files.len(),
        mb,
        secs,
        speed,
        summarize(files),
        note.replace('\t', " ")
    );

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = file.write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_is_readable() {
        let text = stamp(1_793_116_800);
        assert_eq!(text.len(), 19, "{text}");
        assert_eq!(&text[4..5], "-");
        assert_eq!(&text[10..11], " ");
        assert_eq!(&text[13..14], ":");
    }

    #[test]
    fn summarize_truncates() {
        let files: Vec<(String, u64)> = (0..8).map(|i| (format!("f{i}.jpg"), 1)).collect();
        let text = summarize(&files);
        assert!(text.contains("等 8 个"), "{text}");
    }
}
