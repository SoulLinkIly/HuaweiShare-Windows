#![cfg(windows)]
use std::path::PathBuf;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
};
use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};

const CF_UNICODETEXT: u32 = 13;

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

        let mut len = 0usize;
        while *pointer.add(len) != 0 {
            len += 1;
            if len > 4 * 1024 * 1024 {
                break;
            }
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

pub fn write_temp(text: &str) -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join("hwshare-clip");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("clipboard.txt");
    std::fs::write(&path, text.as_bytes())?;
    Ok(path)
}

pub fn preview(text: &str, limit: usize) -> String {
    let first = text.lines().next().unwrap_or("").trim();
    let mut out: String = first.chars().take(limit).collect();
    if first.chars().count() > limit || text.lines().count() > 1 {
        out.push('…');
    }
    out
}
