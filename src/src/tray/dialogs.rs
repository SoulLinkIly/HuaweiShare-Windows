//! 托盘里的对话框与剪贴板发送：选目录、选文件、发剪贴板。

use crate::ui::text::wide;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use super::{alert, device_name, log_line, message_box, notify, set_dest};

pub fn open_or_pick_dest(owner: HWND) {
    let dest = crate::config::current();
    if dest.is_dir() {
        let text = dest.display().to_string();
        unsafe { open_folder(&text) };
        return;
    }
    log_line(&format!(
        "接收目录不存在：{}，弹选择框",
        dest.display()
    ));
    unsafe {

        let _ = windows_sys::Win32::System::Com::CoInitializeEx(
            std::ptr::null(),
            windows_sys::Win32::System::Com::COINIT_APARTMENTTHREADED as u32,
        );
        let Some(path) = pick_folder(owner) else {
            log_line("用户取消了重新选择接收目录");
            return;
        };
        let text = path.display().to_string();
        if let Err(e) = crate::config::set_dest(&path) {
            log_line(&format!("保存接收目录失败: {e}"));
        }
        if let Err(e) = std::fs::create_dir_all(&path) {
            log_line(&format!("创建接收目录失败: {e}"));
        }
        set_dest(&text);
        notify("接收目录已更新", &text);
        log_line(&format!("接收目录 -> {text}（原目录不存在）"));
        open_folder(&text);
    }
}

pub fn send_clipboard_now(owner: HWND) {
    let targets = crate::peers::targets();
    if targets.is_empty() {
        alert(
            "还没选发送目标",
            "右键托盘图标 →「发送目标」里勾一台或多台，再发剪贴板。",
        );
        return;
    }
    unsafe {
        let Some((path, summary)) = clipboard_file(owner) else {
            return;
        };
        match crate::dispatch::send_many(targets, vec![path], device_name()) {
            Ok(_) => notify("正在发送剪贴板", &summary),
            Err(e) => {
                message_box(owner, &e, MB_OK | MB_ICONWARNING);
            }
        }
    }
}

pub(super) unsafe fn open_folder(dest: &str) {
    if dest.is_empty() {
        return;
    }
    let op = wide("open");
    let path = wide(dest);
    ShellExecuteW(
        std::ptr::null_mut(),
        op.as_ptr(),
        path.as_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        1,
    );
}

/// 用默认程序打开一个文件。`.log` 没关联程序时 ShellExecuteW 会返回错误码，
/// 这时退一步用记事本打开——总比点了菜单毫无反应强。
pub(super) unsafe fn open_file(path: &str) {
    if path.is_empty() {
        return;
    }
    let op = wide("open");
    let wide_path = wide(path);
    let r = ShellExecuteW(
        std::ptr::null_mut(),
        op.as_ptr(),
        wide_path.as_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        1,
    ) as isize;
    if r > 32 {
        return;
    }
    let notepad = wide("notepad.exe");
    ShellExecuteW(
        std::ptr::null_mut(),
        notepad.as_ptr(),
        wide_path.as_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        1,
    );
}


unsafe fn pick_folder(owner: HWND) -> Option<std::path::PathBuf> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        SHBrowseForFolderW, SHGetPathFromIDListW, BIF_NEWDIALOGSTYLE, BIF_RETURNONLYFSDIRS,
        BROWSEINFOW,
    };

    let mut display = [0u16; 260];
    let title = wide("选择接收文件夹");
    let mut info = BROWSEINFOW {
        hwndOwner: owner,
        pidlRoot: std::ptr::null_mut(),
        pszDisplayName: display.as_mut_ptr(),
        lpszTitle: title.as_ptr(),
        ulFlags: BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE,
        lpfn: None,
        lParam: 0,
        iImage: 0,
    };

    let pidl = SHBrowseForFolderW(&mut info);
    if pidl.is_null() {
        return None;
    }
    let mut buffer = [0u16; 1024];
    let ok = SHGetPathFromIDListW(pidl, buffer.as_mut_ptr());
    CoTaskMemFree(pidl as *const core::ffi::c_void);
    if ok == 0 {
        return None;
    }
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    Some(std::path::PathBuf::from(String::from_utf16_lossy(
        &buffer[..len],
    )))
}

pub(super) unsafe fn choose_dir(owner: HWND) {
    let Some(path) = pick_folder(owner) else {
        return;
    };
    let text = path.display().to_string();
    if let Err(e) = crate::config::set_dest(&path) {
        log_line(&format!("保存接收目录失败: {e}"));
    }
    let _ = std::fs::create_dir_all(&path);
    set_dest(&text);
    notify("接收目录已更新", &text);
    log_line(&format!("接收目录 -> {text}"));
}


/// 剪贴板文本 → 临时 `.txt`。返回 (文件, 摘要)，失败时已经弹过框。
pub(super) unsafe fn clipboard_file(owner: HWND) -> Option<(PathBuf, String)> {
    let Some(text) = crate::clipboard::read_text() else {
        message_box(
            owner,
            "剪贴板里没有文本。\n\n目前只支持纯文本，图片和文件请用「发送文件到手机」。",
            MB_OK | MB_ICONINFORMATION,
        );
        return None;
    };
    let path = match crate::clipboard::write_temp(&text) {
        Ok(path) => path,
        Err(e) => {
            message_box(owner, &format!("写入临时文件失败：{e}"), MB_OK | MB_ICONERROR);
            return None;
        }
    };
    Some((path, crate::clipboard::preview(&text, 24)))
}

pub(super) unsafe fn send_clipboard(owner: HWND, peer: crate::peers::PeerInfo) {
    let Some((path, summary)) = clipboard_file(owner) else {
        return;
    };
    match crate::dispatch::send_to(peer, vec![path], device_name()) {
        Ok(_) => notify("正在发送剪贴板", &summary),
        Err(e) => {
            message_box(owner, &e, MB_OK | MB_ICONWARNING);
        }
    }
}

pub(super) unsafe fn pick_files(owner: HWND) -> Vec<PathBuf> {
    use windows_sys::Win32::UI::Controls::Dialogs::{
        GetOpenFileNameW, OFN_ALLOWMULTISELECT, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR,
        OFN_PATHMUSTEXIST, OPENFILENAMEW,
    };

    let mut buffer = vec![0u16; 64 * 1024];
    let filter: Vec<u16> =
        "所有文件\0*.*\0图片\0*.jpg;*.jpeg;*.png;*.gif;*.webp;*.bmp\0视频\0*.mp4;*.mov;*.mkv\0\0"
            .encode_utf16()
            .collect();
    let title = wide("选择要发送的文件");
    let mut ofn: OPENFILENAMEW = std::mem::zeroed();
    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = filter.as_ptr();
    ofn.lpstrFile = buffer.as_mut_ptr();
    ofn.nMaxFile = buffer.len() as u32;
    ofn.lpstrTitle = title.as_ptr();
    ofn.Flags = OFN_ALLOWMULTISELECT
        | OFN_EXPLORER
        | OFN_FILEMUSTEXIST
        | OFN_PATHMUSTEXIST
        | OFN_NOCHANGEDIR;
    if GetOpenFileNameW(&mut ofn) == 0 {
        return Vec::new();
    }
    parse_multi(&buffer)
}

fn parse_multi(buffer: &[u16]) -> Vec<PathBuf> {
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(0);
    let first = String::from_utf16_lossy(&buffer[..end]);
    let rest = &buffer[(end + 1).min(buffer.len())..];
    if rest.first().copied().unwrap_or(0) == 0 {
        return if first.is_empty() {
            Vec::new()
        } else {
            vec![PathBuf::from(first)]
        };
    }
    let dir = Path::new(&first);
    let mut names = Vec::new();
    let mut index = 0usize;
    while index < rest.len() && rest[index] != 0 {
        let len = rest[index..].iter().position(|&c| c == 0).unwrap_or(0);
        if len == 0 {
            break;
        }
        names.push(String::from_utf16_lossy(&rest[index..index + len]));
        index += len + 1;
    }
    names.into_iter().map(|name| dir.join(name)).collect()
}

