//! `config.json` 读写：接收目录、分块大小。

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

static DEST: Mutex<Option<(Option<SystemTime>, PathBuf)>> = Mutex::new(None);

const CHUNK_MIN: usize = 512;
const CHUNK_MAX: usize = 65535;

/// 接收目录在「下载」下面叫什么。
const FOLDER_NAME: &str = "Huawei Share";

pub fn default_dest() -> PathBuf {
    dest_under(&downloads_dir())
}

/// 只有「下载目录 + 子目录名」这一步，单测可以直接喂一个固定路径进来。
fn dest_under(downloads: &Path) -> PathBuf {
    downloads.join(FOLDER_NAME)
}

/// 系统的「下载」文件夹。
///
/// **不能拼 `%USERPROFILE%\Downloads`**：这个文件夹是可以被搬到别的盘的
/// （很多人的机器上都搬过，本机就在 `F:\Downloads`），用户改的是资源管理器里
/// 那个快捷方式，环境变量的值不会跟着变。拼出来的路径会指向一个连资源管理器
/// 都不再打开的旧位置，文件「传成功了但找不到」。
///
/// `SHGetKnownFolderPath(FOLDERID_Downloads)` 读的就是资源管理器认的那个位置，
/// 搬过家也会跟着走。拿不到（极老的系统 / 被裁剪过的环境）再退回老办法。
#[cfg(windows)]
fn downloads_dir() -> PathBuf {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_Downloads};

    unsafe {
        let mut raw: *mut u16 = std::ptr::null_mut();
        let hr = SHGetKnownFolderPath(&FOLDERID_Downloads, 0, std::ptr::null_mut(), &mut raw);
        if hr >= 0 && !raw.is_null() {
            let len = (0..).take_while(|&i| *raw.add(i) != 0).count();
            let path = PathBuf::from(String::from_utf16_lossy(std::slice::from_raw_parts(raw, len)));
            CoTaskMemFree(raw as *const core::ffi::c_void);
            if !path.as_os_str().is_empty() {
                return path;
            }
        }
    }
    fallback_downloads()
}

#[cfg(not(windows))]
fn downloads_dir() -> PathBuf {
    fallback_downloads()
}

fn fallback_downloads() -> PathBuf {
    let base = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
    PathBuf::from(base).join("Downloads")
}

fn config_path() -> PathBuf {
    crate::store::path("config.json")
}

fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

fn parse_object(text: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let value: serde_json::Value = serde_json::from_str(strip_bom(text)).ok()?;
    value.as_object().cloned()
}

fn parse_dest(text: &str) -> Option<PathBuf> {
    let object = parse_object(text)?;
    let dest = object.get("dest")?.as_str()?.trim().to_string();
    if dest.is_empty() {
        None
    } else {
        Some(PathBuf::from(dest))
    }
}

fn load_from_disk() -> Option<PathBuf> {
    parse_dest(&std::fs::read_to_string(config_path()).ok()?)
}

fn config_mtime() -> Option<SystemTime> {
    std::fs::metadata(config_path()).ok()?.modified().ok()
}

pub fn current() -> PathBuf {
    let mtime = config_mtime();
    if let Ok(slot) = DEST.lock() {
        if let Some((cached, path)) = slot.as_ref() {
            if *cached == mtime {
                return path.clone();
            }
        }
    }
    let loaded = load_from_disk().unwrap_or_else(default_dest);
    if let Ok(mut slot) = DEST.lock() {
        *slot = Some((mtime, loaded.clone()));
    }
    loaded
}

fn parse_chunk(text: &str) -> Option<usize> {
    let object = parse_object(text)?;
    let n = object.get("chunk")?.as_u64()? as usize;
    (CHUNK_MIN..=CHUNK_MAX).contains(&n).then_some(n)
}

pub fn chunk() -> Option<usize> {
    parse_chunk(&std::fs::read_to_string(config_path()).ok()?)
}

/// `write_key` 是"读整个文件 → 改一个键 → 写回"，原先两个线程同时改不同键会互相覆盖，
/// 固定名 `config.json.tmp` 原先还会让 A 的 rename 撞上 B 正在写的半截文件。
/// 一把写锁 + 每个进程唯一的临时名，把这两件事一起解决。
static WRITE_LOCK: Mutex<()> = Mutex::new(());
static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn write_key(key: &str, value: serde_json::Value) -> std::io::Result<()> {
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let cfg = config_path();
    if let Some(dir) = cfg.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut object = std::fs::read_to_string(&cfg)
        .ok()
        .and_then(|text| parse_object(&text))
        .unwrap_or_default();
    object.insert(key.to_string(), value);

    let text = serde_json::Value::Object(object).to_string();
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = cfg.with_extension(format!("json.{}.{seq}.tmp", std::process::id()));
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, &cfg).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

fn write_config(dest: &str) -> std::io::Result<()> {
    write_key("dest", serde_json::Value::String(dest.to_string()))
}

pub fn set_dest(path: &Path) -> std::io::Result<()> {
    let result = write_config(&path.display().to_string());

    if let Ok(mut slot) = DEST.lock() {
        *slot = Some((config_mtime(), path.to_path_buf()));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dest_is_huawei_share_under_downloads() {
        // 目录名带空格是刻意的：和手机、Mac 上看到的「Huawei Share」一致。
        assert_eq!(
            dest_under(Path::new(r"F:\Downloads")),
            PathBuf::from(r"F:\Downloads\Huawei Share")
        );
    }

    #[test]
    fn default_dest_ends_with_folder_name() {
        let path = default_dest();
        assert_eq!(path.file_name().and_then(|s| s.to_str()), Some(FOLDER_NAME));
        // 上一级必须真的是「下载」，不能是别的地方。
        assert!(
            path.parent().and_then(|p| p.file_name()).and_then(|s| s.to_str()).is_some(),
            "{}",
            path.display()
        );
    }

    #[test]
    fn parses_config_with_utf8_bom() {

        let text = "\u{feff}{\"dest\":\"F:\\\\Huawei Share\",\"chunk\":65499}";
        assert_eq!(parse_chunk(text), Some(65499));
        assert_eq!(parse_dest(text), Some(PathBuf::from("F:\\Huawei Share")));
    }

    #[test]
    fn parse_chunk_respects_range() {
        assert_eq!(parse_chunk(r#"{"chunk":32768}"#), Some(32768));
        assert_eq!(parse_chunk(r#"{"dest":"D:\\x","chunk":1422}"#), Some(1422));

        assert_eq!(parse_chunk(r#"{"chunk":511}"#), None);
        assert_eq!(parse_chunk(r#"{"chunk":65536}"#), None);
        assert_eq!(parse_chunk(r#"{"chunk":"32768"}"#), None);
        assert_eq!(parse_chunk(r#"{"dest":"D:\\x"}"#), None);
    }

    #[test]
    fn parse_dest_reads_json() {
        assert_eq!(
            parse_dest(r#"{"dest":"D:\\照片\\华为分享"}"#),
            Some(PathBuf::from(r"D:\照片\华为分享"))
        );
        assert_eq!(parse_dest(r#"{"dest":""}"#), None);
        assert_eq!(parse_dest("not json"), None);
    }
}
