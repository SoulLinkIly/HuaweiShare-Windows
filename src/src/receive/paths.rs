use std::io::BufWriter;
use std::path::{Path, PathBuf};

pub(super) const WRITE_BUF: usize = 64 * 1024;

#[cfg(windows)]
pub(super) fn preallocate(file: &std::fs::File, size: u64, debug: bool) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileAllocationInfo, SetFileInformationByHandle, FILE_ALLOCATION_INFO,
    };
    if size == 0 {
        return;
    }
    let allocation = size.min(i64::MAX as u64) as i64;
    let info = FILE_ALLOCATION_INFO { AllocationSize: allocation };
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as *mut core::ffi::c_void,
            FileAllocationInfo,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<FILE_ALLOCATION_INFO>() as u32,
        )
    };
    if ok == 0 && debug {
        eprintln!("[dfile] 预分配 {size} 字节失败（忽略，退化为边写边扩展）");
    }
}

#[cfg(not(windows))]
pub(super) fn preallocate(_file: &std::fs::File, _size: u64, _debug: bool) {}

pub(super) struct ActiveFile {
    pub(super) file: BufWriter<std::fs::File>,
    pub(super) path: PathBuf,
    pub(super) part: PathBuf,
    pub(super) written: u64,
}

pub(super) fn part_path(target: &Path) -> PathBuf {
    let mut name = target.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    name.push(".part");
    target.with_file_name(name)
}

pub(super) fn sanitize(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
    let cleaned: String = base
        .chars()
        .map(|c| if c.is_control() || "<>:\"|?*".contains(c) { '_' } else { c })
        .collect();
    let cleaned = cleaned.trim_end_matches(['.', ' ']).to_string();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return "received.bin".to_string();
    }
    if is_reserved_device_name(&cleaned) {
        return truncate_chars(&format!("_{cleaned}"), 120);
    }
    truncate_chars(&cleaned, 120)
}

pub(super) fn is_reserved_device_name(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim()
        .to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    let bytes = stem.as_bytes();
    bytes.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && bytes[3].is_ascii_digit()
}

pub(super) fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        text.chars().take(max).collect()
    }
}

pub(super) fn split_name(name: &str) -> (&str, String) {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, format!(".{ext}")),
        _ => (name, String::new()),
    }
}

pub(super) fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !occupied(&first) {
        return first;
    }
    let (stem, ext) = split_name(name);
    for n in 1..=9999u32 {
        let candidate = dir.join(format!("{stem} ({n}){ext}"));
        if !occupied(&candidate) {
            return candidate;
        }
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    dir.join(format!("{stem}-{stamp}{ext}"))
}

pub(super) fn create_part_atomic(
    dir: &Path,
    name: &str,
) -> std::io::Result<(PathBuf, PathBuf, std::fs::File)> {
    let (stem, ext) = split_name(name);
    for n in 0..=9999u32 {
        let candidate = if n == 0 {
            dir.join(name)
        } else {
            dir.join(format!("{stem} ({n}){ext}"))
        };
        if candidate.exists() {
            continue;
        }
        let part = part_path(&candidate);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)
        {
            Ok(file) => return Ok((candidate, part, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let candidate = dir.join(format!("{stem}-{stamp}{ext}"));
    let part = part_path(&candidate);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&part)?;
    Ok((candidate, part, file))
}

pub(super) fn occupied(target: &Path) -> bool {
    target.exists() || part_path(target).exists()
}
