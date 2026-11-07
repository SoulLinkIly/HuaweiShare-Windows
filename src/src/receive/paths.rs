//! 落盘路径清洗：非法字符、Windows 保留名、重名去重。

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use super::clip;

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

/// 一个正在接收的文件的写入目标。
///
/// 绝大多数落盘；名字是 `Huawei Share.txt` 的文本按需求不落盘，直接留在内存里，
/// 收齐后写剪贴板。两种目标共用「打开 → 写入 → 收尾」这套骨架，接收状态机那边
/// 不必关心字节到底去了磁盘还是内存。
pub(super) enum Sink {
    Disk(BufWriter<std::fs::File>),
    Text { buf: Vec<u8>, overflow: bool },
}

pub(super) struct ActiveFile {
    pub(super) sink: Sink,

    /// 落盘：最终目标路径；文本：清单里的名字（不产生文件，只用于日志）。
    pub(super) path: PathBuf,

    /// 落盘：`.part` 路径；文本：空——从头到尾没有临时文件。
    pub(super) part: PathBuf,
    pub(super) written: u64,
}

/// 一个文件收尾后的结果。
pub(super) enum Finished {
    /// 已落盘（`.part` 已改名成目标名）。
    Saved(PathBuf),
    /// 只在内存里，交给剪贴板。
    Text { buf: Vec<u8>, overflow: bool },
}

impl ActiveFile {
    pub(super) fn open(
        dest: &Path,
        name: &str,
        declared: u64,
        debug: bool,
    ) -> std::io::Result<Self> {
        if clip::is_target(name) {
            if debug {
                eprintln!("[dfile] {name} 走剪贴板：内存缓冲，不落盘（声明 {declared} 字节）");
            }
            let capacity = declared.min(clip::MAX_BYTES as u64) as usize;
            return Ok(ActiveFile {
                sink: Sink::Text { buf: Vec::with_capacity(capacity), overflow: false },
                path: PathBuf::from(name),
                part: PathBuf::new(),
                written: 0,
            });
        }

        let (target, part, raw) = create_part_atomic(dest, name)?;
        preallocate(&raw, declared, debug);
        if debug {
            eprintln!("[dfile] 开始落盘 {}", target.display());
        }
        Ok(ActiveFile {
            sink: Sink::Disk(BufWriter::with_capacity(WRITE_BUF, raw)),
            path: target,
            part,
            written: 0,
        })
    }

    pub(super) fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        match &mut self.sink {
            Sink::Disk(file) => file.write_all(data)?,
            Sink::Text { buf, overflow } => {
                // 超过上限就停止缓冲：不撑爆内存，但字节数照记——否则「收了多少」
                // 和浮窗进度会开始说谎。
                if !*overflow {
                    if buf.len() + data.len() > clip::MAX_BYTES {
                        *overflow = true;
                        buf.clear();
                        crate::trace::note("file#1", "剪贴板文本超过上限，已停止缓冲");
                    } else {
                        buf.extend_from_slice(data);
                    }
                }
            }
        }
        self.written += data.len() as u64;
        Ok(())
    }

    /// 收尾：落盘的 flush + 改名；文本的把缓冲交出去。
    ///
    /// 错误信息在这里拼好（带上路径），调用方只管转成 `Error::Io`——这样
    /// 「刷新失败 / 改名失败」的文案和以前一致，不会因为搬家而变。
    pub(super) fn finish(self, dest: &Path) -> std::io::Result<Finished> {
        let ActiveFile { sink, path, part, written: _ } = self;
        match sink {
            Sink::Text { buf, overflow } => Ok(Finished::Text { buf, overflow }),
            Sink::Disk(mut file) => {
                file.flush()
                    .map_err(|e| std::io::Error::new(e.kind(), format!("刷新落盘失败: {e}")))?;
                drop(file);

                let path = if path.exists() {
                    let parent = path
                        .parent()
                        .map(|p| p.to_path_buf())
                        .unwrap_or_else(|| dest.to_path_buf());
                    let leaf = path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("received.bin")
                        .to_string();
                    unique_path(&parent, &leaf)
                } else {
                    path
                };
                std::fs::rename(&part, &path).map_err(|e| {
                    std::io::Error::new(e.kind(), format!("改名 {} 失败: {e}", path.display()))
                })?;
                Ok(Finished::Saved(path))
            }
        }
    }
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
        return crate::clip_chars(&format!("_{cleaned}"), 120).to_string();
    }
    crate::clip_chars(&cleaned, 120).to_string()
}

pub(super) fn safe_rel_segments(rel: &str) -> Vec<String> {
    rel.split(['/', '\\'])
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")

        .filter(|s| !(s.len() == 2 && s.ends_with(':')))
        .map(sanitize)

        .filter(|s| !s.is_empty())
        .collect()
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
    dest: &Path,
    rel: &str,
) -> std::io::Result<(PathBuf, PathBuf, std::fs::File)> {

    let segs = safe_rel_segments(rel);
    let (parent, name) = match segs.split_last() {
        Some((last, rest)) => {
            let mut p = dest.to_path_buf();
            for s in rest {
                p.push(s);
            }
            (p, last.clone())
        }
        None => (dest.to_path_buf(), "received.bin".to_string()),
    };

    if parent != dest {
        std::fs::create_dir_all(&parent)?;
    }
    let dir = parent.as_path();
    let name = name.as_str();
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hwshare-sink-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entries(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect()
    }

    #[test]
    fn clipboard_text_never_touches_disk() {
        let dir = scratch("clip");
        let text = "你好，剪贴板";

        let mut slot = ActiveFile::open(&dir, "Huawei Share.txt", text.len() as u64, false)
            .expect("打开写入目标");
        assert!(slot.part.as_os_str().is_empty(), "文本不该有 .part");
        slot.write(text.as_bytes()).unwrap();
        assert_eq!(slot.written, text.len() as u64);

        match slot.finish(&dir).unwrap() {
            Finished::Text { buf, overflow } => {
                assert!(!overflow);
                assert_eq!(String::from_utf8(buf).unwrap(), text);
            }
            Finished::Saved(p) => panic!("文本被落盘了：{}", p.display()),
        }
        assert!(entries(&dir).is_empty(), "目录必须干干净净：{:?}", entries(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overflow_drops_buffer_but_keeps_counting() {
        let dir = scratch("overflow");
        let mut slot = ActiveFile::open(&dir, "Huawei Share.txt", 0, false).unwrap();

        let chunk = vec![b'x'; 3 * 1024 * 1024];
        slot.write(&chunk).unwrap();
        slot.write(&chunk).unwrap();
        assert_eq!(slot.written, 6 * 1024 * 1024, "字节数必须照实记");

        match slot.finish(&dir).unwrap() {
            Finished::Text { buf, overflow } => {
                assert!(overflow, "超过上限必须置位");
                assert!(buf.is_empty(), "超限后缓冲应被丢弃");
            }
            Finished::Saved(_) => panic!("文本被落盘了"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ordinary_file_still_writes_part_then_renames() {
        let dir = scratch("disk");
        let mut slot = ActiveFile::open(&dir, "a.txt", 3, false).unwrap();
        assert!(!slot.part.as_os_str().is_empty(), "普通文件要有 .part");
        slot.write(b"abc").unwrap();

        match slot.finish(&dir).unwrap() {
            Finished::Saved(p) => {
                assert_eq!(p, dir.join("a.txt"));
                assert_eq!(std::fs::read(&p).unwrap(), b"abc");
            }
            Finished::Text { .. } => panic!("普通文件不该走剪贴板"),
        }
        assert_eq!(entries(&dir), vec!["a.txt".to_string()], "只该剩最终文件");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
