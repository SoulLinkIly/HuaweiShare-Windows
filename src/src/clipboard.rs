//! 剪贴板读写：把剪贴板文本落成临时文件交给发送流程复用，
//! 以及把接收到的文本直接写回剪贴板。

#![cfg(windows)]

use std::path::PathBuf;

use windows_sys::Win32::Foundation::{GlobalFree, HWND};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    SetClipboardData,
};
use windows_sys::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
};

const CF_UNICODETEXT: u32 = 13;

const MAX_UNITS: usize = 4 * 1024 * 1024;

pub fn read_text() -> Option<String> {
    unsafe {
        if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 {
            return None;
        }
        if OpenClipboard(std::ptr::null_mut::<std::ffi::c_void>() as HWND) == 0 {
            return None;
        }
        let handle = GetClipboardData(CF_UNICODETEXT);
        if handle.is_null() {
            CloseClipboard();
            return None;
        }
        let pointer = GlobalLock(handle) as *const u16;
        if pointer.is_null() {
            CloseClipboard();
            return None;
        }

        let limit = (GlobalSize(handle) / 2).min(MAX_UNITS);
        let mut len = 0usize;
        while len < limit && *pointer.add(len) != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(pointer, len));
        GlobalUnlock(handle);
        CloseClipboard();
        if text.trim().is_empty() {
            None
        } else {
            Some(text)
        }
    }
}

/// 把一段文本写进系统剪贴板（覆盖原有内容）。
///
/// 失败只返回原因、不 panic：调用方是接收线程，剪贴板写不进去不该让一次
/// 已经收完的传输变成失败。剪贴板常被别的程序（剪贴板管理器、远程桌面、
/// 输入法）短暂占着，`OpenClipboard` 会直接失败，所以这里重试几次再放弃。
pub fn write_text(text: &str) -> Result<(), String> {
    if text.is_empty() {
        return Err("文本为空".to_string());
    }

    let mut opened = false;
    for _ in 0..5 {
        if unsafe { OpenClipboard(std::ptr::null_mut::<std::ffi::c_void>() as HWND) } != 0 {
            opened = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    if !opened {
        return Err("剪贴板被其它程序占用".to_string());
    }

    // Windows 剪贴板要的是可移动内存块，且必须是「写完就不归我们管」的
    // UTF-16 以 NUL 结尾。长度按 u16 算，别用字节数。
    let units: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe { GlobalAlloc(GMEM_MOVEABLE, units.len() * 2) };
    if handle.is_null() {
        unsafe { CloseClipboard() };
        return Err("分配剪贴板内存失败".to_string());
    }

    let pointer = unsafe { GlobalLock(handle) } as *mut u16;
    if pointer.is_null() {
        unsafe {
            GlobalFree(handle);
            CloseClipboard();
        }
        return Err("锁定剪贴板内存失败".to_string());
    }

    unsafe {
        std::ptr::copy_nonoverlapping(units.as_ptr(), pointer, units.len());
        GlobalUnlock(handle);
        EmptyClipboard();
        // 成功后这块内存归系统所有，不能再 GlobalFree。
        if SetClipboardData(CF_UNICODETEXT, handle).is_null() {
            GlobalFree(handle);
            CloseClipboard();
            return Err("写入剪贴板失败".to_string());
        }
        CloseClipboard();
    }
    Ok(())
}

pub fn write_temp(text: &str) -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join("hwshare-clip");
    std::fs::create_dir_all(&dir)?;
    sweep(&dir);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let path = dir.join(format!("clipboard-{stamp}-{}.txt", std::process::id()));
    std::fs::write(&path, text.as_bytes())?;
    Ok(path)
}

fn sweep(dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let cutoff = std::time::Duration::from_secs(3600);
    for entry in entries.flatten() {
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .map(|t| t.elapsed().map(|e| e > cutoff).unwrap_or(false))
            .unwrap_or(false);
        if old {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

pub fn preview(text: &str, limit: usize) -> String {
    let first = text.lines().next().unwrap_or("").trim();
    let mut out = String::new();
    let mut taken = 0usize;
    let mut truncated = false;
    for ch in first.chars() {
        if taken >= limit {
            truncated = true;
            break;
        }
        out.push(ch);
        taken += 1;
    }

    if !truncated && text.lines().nth(1).is_some() {
        truncated = true;
    }
    if truncated {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_short_single_line_is_untouched() {
        assert_eq!(preview("你好世界", 24), "你好世界");

        assert_eq!(preview("四个字符", 4), "四个字符");
    }

    #[test]
    fn preview_marks_truncation() {
        assert_eq!(preview("0123456789", 4), "0123…");

        assert_eq!(preview("第一行\n第二行", 24), "第一行…");

        assert_eq!(preview("   内容   ", 24), "内容");
    }

    #[test]
    fn preview_counts_chars_not_bytes() {

        assert_eq!(preview("华为分享测试", 3), "华为分…");
    }
}
