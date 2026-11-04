#![cfg(windows)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicIsize, AtomicU64, Ordering};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::System::Console::GetConsoleWindow;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, ShellExecuteW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIM_ADD,
    NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const WM_APP: u32 = 0x8000;
const WM_TRAY: u32 = WM_APP + 1;
const WM_NOTICE: u32 = WM_APP + 2;

const ID_OPEN: usize = 1001;
const ID_ABOUT: usize = 1004;
const ID_PICK_DIR: usize = 1008;
const ID_AUTOSTART: usize = 1010;
const ID_SEND_BASE: usize = 1200;
const ID_TARGET_BASE: usize = 1400;
const ID_TARGET_RESCAN: usize = 1464;
const ID_TARGET_CLEAR: usize = 1465;
const ID_TARGET_HINT: usize = 1466;
const ID_SEND_NONE: usize = 1299;
const ID_CLIP_BASE: usize = 1300;
const ID_CLIP_NONE: usize = 1399;
const ID_QUIT: usize = 1099;

const TRAY_UID: u32 = 1;

static HWND_SLOT: AtomicIsize = AtomicIsize::new(0);
static RECEIVED_FILES: AtomicU64 = AtomicU64::new(0);
static RECEIVED_BYTES: AtomicU64 = AtomicU64::new(0);
static ICON_SLOT: AtomicIsize = AtomicIsize::new(0);

static CONTEXT: Mutex<Option<Context>> = Mutex::new(None);
static NOTICES: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
static MENU_PEERS: Mutex<Vec<crate::peers::PeerInfo>> = Mutex::new(Vec::new());

#[derive(Clone)]
struct Context {
    name: String,
    dest: String,
    local: String,
}

pub fn log_line(text: &str) {
    use std::io::Write;
    let Some(base) = std::env::var_os("LOCALAPPDATA") else {
        return;
    };
    static LOG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOG_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let dir = std::path::PathBuf::from(base).join("HWShareWin");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("hwshare.log");
    const MAX_LOG: u64 = 512 * 1024;
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > MAX_LOG {
            let old = dir.join("hwshare.log.1");
            let _ = std::fs::remove_file(&old);
            let _ = std::fs::rename(&path, &old);
        }
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "[{stamp}] pid={} {text}", std::process::id());
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn context_text() -> Context {
    CONTEXT
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(|| Context {
            name: "Windows PC".into(),
            dest: String::new(),
            local: String::new(),
        })
}

pub fn device_name() -> String {
    context_text().name
}

pub fn set_context(name: &str, dest: &str, local: &str) {
    if let Ok(mut slot) = CONTEXT.lock() {
        *slot = Some(Context {
            name: name.to_string(),
            dest: dest.to_string(),
            local: local.to_string(),
        });
    }
}

pub fn set_dest(dest: &str) {
    if let Ok(mut slot) = CONTEXT.lock() {
        if let Some(ctx) = slot.as_mut() {
            ctx.dest = dest.to_string();
        }
    }
}

pub fn notify(title: &str, body: &str) {
    if let Ok(mut q) = NOTICES.lock() {
        q.push((title.to_string(), body.to_string()));
        if q.len() > 16 {
            q.remove(0);
        }
    }
    let hwnd = HWND_SLOT.load(Ordering::Relaxed);
    if hwnd != 0 {
        unsafe {
            PostMessageW(hwnd as HWND, WM_NOTICE, 0, 0);
        }
    }
}

pub fn add_received(files: u64, bytes: u64) {
    RECEIVED_FILES.fetch_add(files, Ordering::Relaxed);
    RECEIVED_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

unsafe fn load_icon(blob: &[u8], want: i32) -> *mut c_void {
    if blob.len() < 4 {
        return std::ptr::null_mut();
    }
    let count = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let mut offset = 4usize;
    let mut candidates: Vec<(i64, usize, usize)> = Vec::new();
    for _ in 0..count {
        if offset + 8 > blob.len() {
            break;
        }
        let width = u32::from_le_bytes([
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ]) as i64;
        let size = u32::from_le_bytes([
            blob[offset + 4],
            blob[offset + 5],
            blob[offset + 6],
            blob[offset + 7],
        ]) as usize;
        offset += 8;
        if offset + size > blob.len() || size == 0 {
            break;
        }
        candidates.push(((width - want as i64).abs(), offset, size));
        offset += size;
    }
    candidates.sort();
    for (_, start, size) in candidates {
        let icon = CreateIconFromResourceEx(
            blob[start..].as_ptr(),
            size as u32,
            1,
            0x0003_0000,
            want,
            want,
            0,
        );
        if !icon.is_null() {
            return icon;
        }
    }
    std::ptr::null_mut()
}

pub fn open_dest_folder() {
    let dest = context_text().dest;
    unsafe { open_folder(&dest) };
}

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
    let Some(peer) = crate::peers::selected() else {
        alert(
            "还没选发送目标",
            "右键托盘图标 →「发送目标」里挑一台手机，再发剪贴板。",
        );
        return;
    };
    unsafe { send_clipboard(owner, peer) };
}

unsafe fn open_folder(dest: &str) {
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

unsafe fn balloon(hwnd: HWND, title: &str, body: &str) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_UID;
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = NIIF_INFO;
    for (i, ch) in wide(title).iter().take(63).enumerate() {
        nid.szInfoTitle[i] = *ch;
    }
    for (i, ch) in wide(body).iter().take(255).enumerate() {
        nid.szInfo[i] = *ch;
    }
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

fn kind_text(kind: &str) -> &'static str {
    match kind {
        "phone" => "手机",
        "tablet" => "平板",
        "computer" => "电脑",
        _ => "",
    }
}

fn ago_text(age: std::time::Duration) -> String {
    let secs = age.as_secs();
    if secs < 90 {
        "1 分钟".to_string()
    } else if secs < 3600 {
        format!("{} 分钟", secs / 60)
    } else {
        format!("{} 小时", secs / 3600)
    }
}

fn peer_name(p: &crate::peers::PeerInfo) -> String {
    let kind = kind_text(&p.kind);
    if kind.is_empty() {
        p.name.clone()
    } else {
        format!("{}（{}）", p.name, kind)
    }
}

fn peer_line(p: &crate::peers::PeerInfo) -> String {
    let online = p.seen.elapsed() <= crate::peers::ONLINE_WINDOW;
    let kind = kind_text(&p.kind);
    let mut detail: Vec<String> = Vec::new();
    if !kind.is_empty() {
        detail.push(kind.to_string());
    }
    if !online {
        detail.push(format!("{}前", ago_text(p.seen.elapsed())));
    }
    let line = if detail.is_empty() {
        p.name.clone()
    } else {
        format!("{}（{}）", p.name, detail.join(" · "))
    };
    menu_text(&line)
}

fn menu_text(s: &str) -> String {
    s.replace('&', "&&")
        .replace('\t', " ")
        .replace('\n', " ")
        .replace('\r', " ")
}

pub fn refresh_tooltip() {
    let raw = HWND_SLOT.load(Ordering::Relaxed);
    if raw == 0 {
        return;
    }
    let ctx = context_text();
    let target = match crate::peers::selected() {
        Some(p) if crate::peers::is_online(&p) => format!("发送给 {}", p.name),
        Some(p) => format!("发送给 {}（离线）", p.name),
        None => "未选发送目标".to_string(),
    };
    let text = format!("华为分享 · {} · {}", ctx.name, target);
    unsafe {
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = raw as HWND;
        nid.uID = TRAY_UID;
        nid.uFlags = NIF_TIP;
        for (i, ch) in wide(&text).iter().take(127).enumerate() {
            nid.szTip[i] = *ch;
        }
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
}

unsafe fn build_menu() -> HMENU {
    let menu = CreatePopupMenu();
    if menu.is_null() {
        return menu;
    }
    let view = crate::peers::view(std::time::Duration::from_secs(3600));
    let peers = view.peers;
    let effective = view.selected;
    if let Ok(mut slot) = MENU_PEERS.lock() {
        *slot = peers.clone();
    }

    let target_menu = CreatePopupMenu();
    if peers.is_empty() {
        AppendMenuW(
            target_menu,
            MF_STRING | MF_GRAYED,
            ID_TARGET_HINT,
            wide("未发现设备").as_ptr(),
        );
        AppendMenuW(
            target_menu,
            MF_STRING | MF_GRAYED,
            ID_TARGET_HINT,
            wide("① 手机/平板打开「华为分享」").as_ptr(),
        );
        AppendMenuW(
            target_menu,
            MF_STRING | MF_GRAYED,
            ID_TARGET_HINT,
            wide("② 保持亮屏，与本机同一 Wi-Fi").as_ptr(),
        );
    } else {
        for (index, peer) in peers.iter().enumerate() {
            let checked = effective
                .as_ref()
                .map(|e| e.host == peer.host)
                .unwrap_or(false);
            let flags = MF_STRING | if checked { MF_CHECKED } else { 0 };
            AppendMenuW(
                target_menu,
                flags,
                ID_TARGET_BASE + index,
                wide(&peer_line(peer)).as_ptr(),
            );
        }
    }
    AppendMenuW(target_menu, MF_SEPARATOR, 0, std::ptr::null());
    AppendMenuW(
        target_menu,
        MF_STRING,
        ID_TARGET_RESCAN,
        wide("重新扫描局域网").as_ptr(),
    );
    if effective.is_some() {
        AppendMenuW(
            target_menu,
            MF_STRING,
            ID_TARGET_CLEAR,
            wide("清除选择（不指定目标）").as_ptr(),
        );
    }

    let target_label = match &effective {
        Some(p) if crate::peers::is_online(p) => format!("发送目标：{}", p.name),
        Some(p) => format!("发送目标：{}（离线）", p.name),
        None => "发送目标：未选择".to_string(),
    };
    AppendMenuW(
        menu,
        MF_POPUP | MF_STRING,
        target_menu as usize,
        wide(&target_label).as_ptr(),
    );
    AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
    AppendMenuW(menu, MF_STRING, ID_OPEN, wide("打开接收文件夹").as_ptr());
    AppendMenuW(menu, MF_STRING, ID_PICK_DIR, wide("选择接收文件夹…").as_ptr());

    let submenu = CreatePopupMenu();
    if peers.is_empty() {
        AppendMenuW(
            submenu,
            MF_STRING | MF_GRAYED,
            ID_SEND_NONE,
            wide("未发现设备 · 先打开手机分享").as_ptr(),
        );
    } else {
        for (index, peer) in peers.iter().enumerate() {
            let flags = MF_STRING
                | if crate::peers::is_online(peer) {
                    0
                } else {
                    MF_GRAYED
                };
            AppendMenuW(
                submenu,
                flags,
                ID_SEND_BASE + index,
                wide(&peer_line(peer)).as_ptr(),
            );
        }
    }
    AppendMenuW(
        menu,
        MF_POPUP | MF_STRING,
        submenu as usize,
        wide("发送文件到手机").as_ptr(),
    );

    let clip_menu = CreatePopupMenu();
    if peers.is_empty() {
        AppendMenuW(
            clip_menu,
            MF_STRING | MF_GRAYED,
            ID_CLIP_NONE,
            wide("未发现设备 · 先打开手机分享").as_ptr(),
        );
    } else {
        for (index, peer) in peers.iter().enumerate() {
            let flags = MF_STRING
                | if crate::peers::is_online(peer) {
                    0
                } else {
                    MF_GRAYED
                };
            AppendMenuW(
                clip_menu,
                flags,
                ID_CLIP_BASE + index,
                wide(&peer_line(peer)).as_ptr(),
            );
        }
    }
    let clip_flags = MF_POPUP | MF_STRING | if peers.is_empty() { MF_GRAYED } else { 0 };
    AppendMenuW(
        menu,
        clip_flags,
        clip_menu as usize,
        wide("发送剪贴板文本").as_ptr(),
    );

    AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
    let startup = crate::autostart::status();
    let startup_flags = MF_STRING | if startup.on() { MF_CHECKED } else { 0 };
    AppendMenuW(
        menu,
        startup_flags,
        ID_AUTOSTART,
        wide(&crate::autostart::menu_label(startup)).as_ptr(),
    );
    AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
    AppendMenuW(menu, MF_STRING, ID_ABOUT, wide("关于").as_ptr());
    AppendMenuW(menu, MF_STRING, ID_QUIT, wide("退出").as_ptr());

    menu
}

unsafe fn show_menu(hwnd: HWND) {
    refresh_tooltip();
    let menu = build_menu();
    if menu.is_null() {
        return;
    }
    let mut pt = POINT { x: 0, y: 0 };
    GetCursorPos(&mut pt);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, std::ptr::null());
    DestroyMenu(menu);
}

unsafe fn toggle_autostart(hwnd: HWND) {
    match crate::autostart::toggle() {
        Ok(true) => notify(
            "开机自启动",
            "已开启：下次登录 Windows 时自动启动，浮窗停在上次退出时的位置",
        ),
        Ok(false) => notify("开机自启动", "已关闭：登录时不再自动启动"),
        Err(e) => {
            log_line(&format!("[自启动] 切换失败：{e}"));
            MessageBoxW(
                hwnd,
                wide(&format!("设置开机自启动失败：\n{e}")).as_ptr(),
                wide("华为分享").as_ptr(),
                MB_OK | MB_ICONWARNING,
            );
        }
    }
}

unsafe fn show_about(hwnd: HWND) {
    let ctx = context_text();
    let text = format!(
        "华为分享  v{}\n\n设备名：{}\n保存到：{}\n本机地址：{}\n\n第三方互操作性实现，与华为公司无隶属关系。\n按 GPL-3.0 分发，详见随附的 LICENSE。\n\n手机端「华为分享」可见性只有 10 分钟，\n超时后需要重新打开开关。",
        env!("CARGO_PKG_VERSION"),
        ctx.name,
        ctx.dest,
        ctx.local
    );
    MessageBoxW(
        hwnd,
        wide(&text).as_ptr(),
        wide("关于 华为分享").as_ptr(),
        MB_OK | MB_ICONINFORMATION,
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

unsafe fn choose_dir(owner: HWND) {
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

unsafe fn send_clipboard(owner: HWND, peer: crate::peers::PeerInfo) {
    let Some(text) = crate::clipboard::read_text() else {
        MessageBoxW(
            owner,
            wide("剪贴板里没有文本。\n\n目前只支持纯文本，图片和文件请用「发送文件到手机」。").as_ptr(),
            wide("华为分享").as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
        return;
    };
    let path = match crate::clipboard::write_temp(&text) {
        Ok(path) => path,
        Err(e) => {
            MessageBoxW(
                owner,
                wide(&format!("写入临时文件失败：{e}")).as_ptr(),
                wide("华为分享").as_ptr(),
                MB_OK | MB_ICONERROR,
            );
            return;
        }
    };
    let summary = crate::clipboard::preview(&text, 24);
    match crate::dispatch::send_to(peer, vec![path], device_name()) {
        Ok(_) => notify("正在发送剪贴板", &summary),
        Err(e) => {
            MessageBoxW(
                owner,
                wide(&e).as_ptr(),
                wide("华为分享").as_ptr(),
                MB_OK | MB_ICONWARNING,
            );
        }
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_TRAY => {
            let event = (lparam & 0xFFFF) as u32;
            if event == WM_LBUTTONDBLCLK as u32 {
                crate::dropzone::toggle();
            } else if event == WM_RBUTTONUP as u32 || event == WM_CONTEXTMENU as u32 {
                show_menu(hwnd);
            }
            0
        }
        WM_NOTICE => {
            let pending: Vec<(String, String)> = NOTICES
                .lock()
                .map(|mut q| q.drain(..).collect())
                .unwrap_or_default();
            for (title, body) in pending {
                balloon(hwnd, &title, &body);
            }
            0
        }
        WM_COMMAND => {
            match (wparam & 0xFFFF) as usize {
                ID_OPEN => open_folder(&context_text().dest),
                ID_PICK_DIR => choose_dir(hwnd),
                ID_AUTOSTART => toggle_autostart(hwnd),
                ID_ABOUT => show_about(hwnd),
                ID_QUIT => PostQuitMessage(0),
                id if (ID_TARGET_BASE..ID_TARGET_BASE + 64).contains(&id) => {
                    let index = id - ID_TARGET_BASE;
                    let peer = MENU_PEERS
                        .lock()
                        .ok()
                        .and_then(|slot| slot.get(index).cloned());
                    if let Some(peer) = peer {
                        crate::peers::set_default(peer.clone());
                        let body = if crate::peers::is_online(&peer) {
                            format!("已选择 {}", peer_name(&peer))
                        } else {
                            format!("已选择 {}（当前离线，等它亮屏后再发）", peer_name(&peer))
                        };
                        notify("默认发送目标", &body);
                        refresh_tooltip();
                    }
                }
                ID_TARGET_RESCAN => {
                    crate::discovery::request_scan();
                    notify(
                        "正在扫描",
                        "设备会在一两秒内出现在「发送目标」里（手机需亮屏、开着分享）",
                    );
                }
                ID_TARGET_CLEAR => {
                    crate::peers::clear_default();
                    notify(
                        "已清除发送目标",
                        "把文件拖进投递窗时会再问一次要发给谁",
                    );
                    refresh_tooltip();
                }
                id if (ID_SEND_BASE..ID_SEND_BASE + 64).contains(&id) => {
                    let index = id - ID_SEND_BASE;
                    let peer = MENU_PEERS
                        .lock()
                        .ok()
                        .and_then(|slot| slot.get(index).cloned());
                    if let Some(peer) = peer {
                        let files = pick_files(hwnd);
                        if !files.is_empty() {
                            if let Err(e) =
                                crate::dispatch::send_to(peer, files, device_name())
                            {
                                MessageBoxW(
                                    hwnd,
                                    wide(&e).as_ptr(),
                                    wide("华为分享").as_ptr(),
                                    MB_OK | MB_ICONWARNING,
                                );
                            }
                        }
                    }
                }
                id if (ID_CLIP_BASE..ID_CLIP_BASE + 64).contains(&id) => {
                    let index = id - ID_CLIP_BASE;
                    let peer = MENU_PEERS
                        .lock()
                        .ok()
                        .and_then(|slot| slot.get(index).cloned());
                    if let Some(peer) = peer {
                        send_clipboard(hwnd, peer);
                    }
                }
                _ => {}
            }
            0
        }
        WM_CLOSE => {
            PostQuitMessage(0);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub fn enable_dpi_awareness() {
    unsafe {
        let lib = windows_sys::Win32::System::LibraryLoader::LoadLibraryW(wide("user32.dll").as_ptr());
        if lib.is_null() {
            return;
        }
        let get = |name: &[u8]| -> Option<usize> {
            let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(lib, name.as_ptr());
            addr.map(|f| f as usize)
        };
        if let Some(addr) = get(b"SetProcessDpiAwarenessContext\0") {
            let f: unsafe extern "system" fn(isize) -> i32 = std::mem::transmute(addr);
            if f(-4) != 0 {
                return;
            }
        }
        if let Some(addr) = get(b"SetProcessDPIAware\0") {
            let f: unsafe extern "system" fn() -> i32 = std::mem::transmute(addr);
            f();
        }
    }
}

unsafe fn pick_files(owner: HWND) -> Vec<PathBuf> {
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

pub fn run_loop() -> i32 {
    unsafe {
        let _ = windows_sys::Win32::System::Com::CoInitializeEx(
            std::ptr::null(),
            windows_sys::Win32::System::Com::COINIT_APARTMENTTHREADED as u32,
        );
    }
    log_line("run 开始：建窗口");
    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let class_name = wide("HWShareTrayWindow");

        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
        };
        RegisterClassW(&wc);

        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            wide("华为分享").as_ptr(),
            0,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            log_line("失败：CreateWindowExW 返回空");
            return 1;
        }
        HWND_SLOT.store(hwnd as isize, Ordering::Relaxed);

        let want = {
            let metric = GetSystemMetrics(SM_CXSMICON);
            if metric > 0 {
                metric
            } else {
                16
            }
        };
        let blob = include_bytes!("../assets/tray_icon.bin");
        let mut icon = load_icon(blob, want);
        let custom = !icon.is_null();
        if icon.is_null() {
            icon = LoadIconW(std::ptr::null_mut(), IDI_APPLICATION);
        }
        if std::env::var("HWSHARE_DEBUG").is_ok() {
            let note = if custom {
                format!("自定义图标已加载（{want}px）")
            } else {
                format!("警告：自定义图标创建失败，已退回系统默认（{want}px）")
            };
            let _ = std::fs::write(std::env::temp_dir().join("hwshare-tray.log"), note);
        }
        ICON_SLOT.store(icon as isize, Ordering::Relaxed);

        let ctx = context_text();
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = TRAY_UID;
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        nid.uCallbackMessage = WM_TRAY;
        nid.hIcon = icon;
        for (i, ch) in wide(&format!("华为分享 · {}", ctx.name)).iter().take(127).enumerate() {
            nid.szTip[i] = *ch;
        }
        if Shell_NotifyIconW(NIM_ADD, &nid) == 0 {
            log_line("失败：Shell_NotifyIcon(NIM_ADD) 返回 0（任务栏不接收图标）");
            return 1;
        }
        log_line(if custom {
            "托盘图标已挂载（自绘 Hi）"
        } else {
            "托盘图标已挂载（退化为系统默认图标）"
        });

        let _ = crate::peers::view(std::time::Duration::from_secs(3600));
        refresh_tooltip();
        crate::dropzone::show();

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        Shell_NotifyIconW(NIM_DELETE, &nid);
        if !icon.is_null() {
            DestroyIcon(icon);
        }
        log_line("消息循环结束，已注销图标");
        0
    }
}

pub fn hide_console() {
    unsafe {
        let console = GetConsoleWindow();
        if !console.is_null() {
            ShowWindow(console, SW_HIDE);
        }
    }
}

pub fn alert(title: &str, body: &str) -> i32 {
    if crate::notice::show(title, body) {
        1
    } else {
        0
    }
}

pub fn active() -> bool {
    HWND_SLOT.load(Ordering::Relaxed) != 0
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn assert<T: Send + Sync>() {}
    assert::<AtomicI64>();
}

#[cfg(test)]
mod menu_text_tests {
    use super::*;
    use crate::peers::PeerInfo;
    use std::time::{Duration, Instant};

    fn peer(name: &str, kind: &str, age: Duration) -> PeerInfo {
        PeerInfo {
            name: name.to_string(),
            host: "192.168.1.9".to_string(),
            port: 1234,
            kind: kind.to_string(),
            seen: Instant::now() - age,
        }
    }

    #[test]
    fn peer_line_shows_kind_without_dot() {
        let line = peer_line(&peer("HUAWEI Mate 60", "phone", Duration::from_secs(5)));
        assert_eq!(line, "HUAWEI Mate 60（手机）");
        assert!(!line.contains('●'), "{line}");
        assert!(!line.contains('○'), "{line}");
    }

    #[test]
    fn offline_peer_shows_age_without_dot() {
        let line = peer_line(&peer("HUAWEI MatePad", "tablet", Duration::from_secs(300)));
        assert!(line.starts_with("HUAWEI MatePad"), "{line}");
        assert!(line.contains("平板"), "{line}");
        assert!(line.contains("5 分钟前"), "{line}");
        assert!(!line.contains('○'), "{line}");
        assert!(!line.contains('●'), "{line}");
    }

    #[test]
    fn unknown_kind_does_not_add_empty_brackets() {
        let line = peer_line(&peer("某设备", "", Duration::from_secs(5)));
        assert_eq!(line, "某设备");
        assert!(!line.contains("（）"), "{line}");
    }

    #[test]
    fn age_text_is_readable() {
        assert_eq!(ago_text(Duration::from_secs(10)), "1 分钟");
        assert_eq!(ago_text(Duration::from_secs(600)), "10 分钟");
        assert_eq!(ago_text(Duration::from_secs(7200)), "2 小时");
    }

    #[test]
    fn ampersand_in_name_is_escaped_for_menus() {
        let line = peer_line(&peer("R&D-PC", "computer", Duration::from_secs(3)));
        assert!(line.contains("R&&D-PC"), "{line}");
        assert!(!line.contains('\t'));
    }

    unsafe fn menu_labels(menu: HMENU) -> Vec<String> {
        let mut out = Vec::new();
        let count = GetMenuItemCount(menu);
        for index in 0..count.max(0) {
            let mut buf = [0u16; 256];
            let n = GetMenuStringW(
                menu,
                index as u32,
                buf.as_mut_ptr(),
                buf.len() as i32,
                MF_BYPOSITION,
            );
            if n > 0 {
                out.push(String::from_utf16_lossy(&buf[..n as usize]));
            }
            let sub = GetSubMenu(menu, index);
            if !sub.is_null() {
                out.extend(menu_labels(sub));
            }
        }
        out
    }

    #[test]
    fn menu_lists_peers_with_state_and_actions() {
        let _g = crate::peers::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::peers::upsert("测试机甲", "10.77.0.1", 4321, "phone");
        crate::peers::upsert("测试平板乙", "10.77.0.2", 4322, "tablet");

        unsafe {
            let menu = build_menu();
            assert!(!menu.is_null(), "菜单没建出来");
            let labels = menu_labels(menu);
            DestroyMenu(menu);

            for label in &labels {
                println!("  [菜单] {label}");
            }

            let text = labels.join(" | ");
            assert!(
                labels.iter().any(|l| l.contains("测试机甲（手机）")),
                "{text}"
            );
            assert!(
                labels
                    .iter()
                    .any(|l| l.contains("测试平板乙（平板）")),
                "{text}"
            );
            assert!(
                !labels.iter().any(|l| l.contains('●') || l.contains('○')),
                "菜单里不该再有圆点标记：{text}"
            );
            assert!(
                labels.iter().any(|l| l.contains("重新扫描局域网")),
                "{text}"
            );
            assert!(
                labels.iter().any(|l| l.contains("打开接收文件夹")),
                "{text}"
            );
            assert!(
                labels.iter().any(|l| l.contains("开机自启动")),
                "{text}"
            );
            let pos_tab = labels.iter().position(|l| l.contains("测试平板乙")).unwrap();
            let pos_ph = labels.iter().position(|l| l.contains("测试机甲")).unwrap();
            assert!(pos_tab < pos_ph, "菜单顺序不稳定: {text}");

            assert!(text.contains("发送目标："), "{text}");
            assert!(text.contains("发送文件到手机"), "{text}");
            assert!(text.contains("发送剪贴板文本"), "{text}");
        }
    }

    #[test]
    fn autostart_item_follows_registry_state() {
        let _g = crate::peers::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            let menu = build_menu();
            assert!(!menu.is_null(), "菜单没建出来");
            let state = GetMenuState(menu, ID_AUTOSTART as u32, MF_BYCOMMAND);
            DestroyMenu(menu);
            assert_ne!(state, u32::MAX, "菜单里找不到开机自启动项");
            assert_eq!(
                state & MF_CHECKED != 0,
                crate::autostart::is_enabled(),
                "勾选状态没跟注册表同步"
            );
        }
    }

    #[test]
    fn peer_name_omits_unknown_kind() {
        assert_eq!(peer_name(&peer("手机", "phone", Duration::ZERO)), "手机（手机）");
        assert_eq!(peer_name(&peer("怪东西", "", Duration::ZERO)), "怪东西");
    }
}
