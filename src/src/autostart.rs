//! 开机自启：读写 HKCU 的 Run 项，并核对当前 exe 路径。

#![cfg(windows)]

use crate::ui::text::wide;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_SZ,
};

const RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "HWShareWin";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {

    Enabled,

    Disabled,

    Stale,

    Unavailable,
}

impl Status {
    pub fn on(self) -> bool {
        self == Status::Enabled
    }
}

pub fn menu_label(status: Status) -> String {
    match status {
        Status::Stale => "开机自启动（路径已变更，点此修复）".to_string(),
        Status::Unavailable => "开机自启动（无法读取设置）".to_string(),
        _ => "开机自启动".to_string(),
    }
}

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
}

fn open_key(write: bool) -> Result<Key, String> {
    let mut handle: HKEY = std::ptr::null_mut();
    let access = if write { KEY_READ | KEY_WRITE } else { KEY_READ };
    let code = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            wide(RUN_SUBKEY).as_ptr(),
            0,
            access,
            &mut handle,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(format!("打开启动项注册表键失败（错误码 {code}）"));
    }
    Ok(Key(handle))
}

fn read_value(key: HKEY) -> Result<Option<String>, String> {
    let name = wide(VALUE_NAME);
    let mut size: u32 = 0;
    let mut kind: u32 = 0;

    let code = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if code != ERROR_SUCCESS {
        return Err(format!("读取启动项失败（错误码 {code}）"));
    }
    if size == 0 {
        return Ok(None);
    }

    let mut bytes = vec![0u8; size as usize];
    let code = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            bytes.as_mut_ptr(),
            &mut size,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(format!("读取启动项失败（错误码 {code}）"));
    }
    let usable = (size as usize).min(bytes.len());
    let units: Vec<u16> = bytes[..usable]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|u| *u == 0).unwrap_or(units.len());
    Ok(Some(String::from_utf16_lossy(&units[..end])))
}

pub fn command_for(path: &Path) -> String {
    format!("\"{}\"", path.display())
}

fn exe_path_from_command(command: &str) -> &str {
    let s = command.trim();
    if let Some(rest) = s.strip_prefix('"') {
        return match rest.find('"') {
            Some(i) => &rest[..i],
            None => rest,
        };
    }
    match s.find(' ') {
        Some(i) => &s[..i],
        None => s,
    }
}

fn normalize(path: &str) -> String {
    let s = path.trim().trim_matches('"');
    let s = s.strip_prefix(r"\\?\").unwrap_or(s);
    s.replace('/', "\\").to_lowercase()
}

fn same_exe(stored: &str, current: &Path) -> bool {
    normalize(exe_path_from_command(stored)) == normalize(&current.to_string_lossy())
}

fn current_exe() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("取不到当前程序路径：{e}"))
}

pub fn status() -> Status {
    let Ok(current) = current_exe() else {
        return Status::Unavailable;
    };
    let Ok(key) = open_key(false) else {
        return Status::Unavailable;
    };
    match read_value(key.0) {
        Ok(None) => Status::Disabled,
        Ok(Some(value)) if same_exe(&value, &current) => Status::Enabled,
        Ok(Some(_)) => Status::Stale,
        Err(_) => Status::Unavailable,
    }
}

pub fn is_enabled() -> bool {
    status().on()
}

pub fn set_enabled(on: bool) -> Result<(), String> {
    let key = open_key(true)?;
    let name = wide(VALUE_NAME);
    let code = if on {
        let command = wide(&command_for(&current_exe()?));
        unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_SZ,
                command.as_ptr() as *const u8,
                (command.len() * 2) as u32,
            )
        }
    } else {
        unsafe { RegDeleteValueW(key.0, name.as_ptr()) }
    };
    if code == ERROR_SUCCESS || (!on && code == ERROR_FILE_NOT_FOUND) {
        Ok(())
    } else {
        Err(format!(
            "{}启动项失败（错误码 {code}）",
            if on { "写入" } else { "删除" }
        ))
    }
}

pub fn toggle() -> Result<bool, String> {
    let next = !is_enabled();
    set_enabled(next)?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_is_quoted_and_keeps_unicode_path() {
        let p = Path::new(r"F:\华为分享\bin\hwshare.exe");
        assert_eq!(command_for(p), "\"F:\\华为分享\\bin\\hwshare.exe\"");
        assert_eq!(command_for(Path::new(r"C:\Program Files\HWShare\hwshare.exe")),
                   "\"C:\\Program Files\\HWShare\\hwshare.exe\"");
    }

    #[test]
    fn extracts_exe_from_run_value() {
        assert_eq!(exe_path_from_command(r#""F:\华为分享\bin\hwshare.exe""#),
                   r"F:\华为分享\bin\hwshare.exe");
        assert_eq!(exe_path_from_command(r#""C:\Program Files\a.exe" --dest D:\x"#),
                   r"C:\Program Files\a.exe");
        assert_eq!(exe_path_from_command(r"C:\HWShare\hwshare.exe"),
                   r"C:\HWShare\hwshare.exe");
        assert_eq!(exe_path_from_command(""), "");
    }

    #[test]
    fn comparison_ignores_case_slashes_and_prefix() {
        let current = Path::new(r"C:\HWShare\Bin\hwshare.exe");
        assert!(same_exe(r#""c:/hwshare/bin/HWSHARE.EXE""#, current));
        assert!(same_exe(r#""\\?\C:\HWShare\Bin\hwshare.exe""#, current));
        assert!(!same_exe(r#""D:\old\hwshare.exe""#, current));
        assert!(!same_exe(r#""C:\HWShare\Bin\hwshare-cli.exe""#, current));
    }

    #[test]
    fn status_enum_and_label() {
        assert!(Status::Enabled.on());
        assert!(!Status::Disabled.on());
        assert!(!Status::Stale.on());
        assert!(!Status::Unavailable.on());
        assert_eq!(menu_label(Status::Enabled), "开机自启动");
        assert!(menu_label(Status::Stale).contains("路径已变更"));
    }

    #[test]
    fn reading_status_never_panics() {
        let _ = status();
        let _ = is_enabled();
    }
}
