//! 托盘图标与消息循环：菜单命令分发、气泡、通知队列。

#![cfg(windows)]

use crate::ui::text::wide;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicIsize, Ordering};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIM_ADD,
    NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

mod dialogs;
mod menu;

use dialogs::*;
use menu::*;

pub use dialogs::{open_or_pick_dest, send_clipboard_now};

const WM_APP: u32 = 0x8000;
const WM_TRAY: u32 = WM_APP + 1;
const WM_NOTICE: u32 = WM_APP + 2;
/// 「又有人启动了一个」：由后启动的那个进程投递给这里，让**活着的**这个去弹提示。
///
/// 后启动的进程拿不到互斥量就得立刻退出，自己弹的窗口会被进程退出一起带走——
/// 屏幕上什么也留不下，用户只知道「双击了但没反应」。所以提示交给已经在跑的这个来弹。
const WM_DUP_START: u32 = WM_APP + 3;


const TRAY_UID: u32 = 1;

static HWND_SLOT: AtomicIsize = AtomicIsize::new(0);
static ICON_SLOT: AtomicIsize = AtomicIsize::new(0);

static CONTEXT: Mutex<Option<Context>> = Mutex::new(None);
static NOTICES: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// 同一时刻只放一条通知窗，后来的直接丢。
static ALERT_BUSY: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
struct Context {
    name: String,
    dest: String,
    local: String,
}

pub fn log_line(text: &str) {
    use std::io::Write;

    static LOG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOG_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let dir = crate::store::home();
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
    // 优先走自绘的右下角提示：系统气泡会被专注助手整条吞掉，样式也不受控。
    // 起不来（建窗失败 / 非 Windows / `HWSHARE_TOAST=0`）时才回落到气泡。
    if crate::toast::push(title, body) {
        return;
    }
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

fn copy_wide<const N: usize>(dst: &mut [u16; N], text: &str) {
    for (i, ch) in wide(text).iter().take(N - 1).enumerate() {
        dst[i] = *ch;
    }
}

pub(super) fn message_box(owner: HWND, text: &str, flags: u32) {
    unsafe {
        MessageBoxW(
            owner,
            wide(text).as_ptr(),
            wide("华为分享").as_ptr(),
            flags,
        );
    }
}

unsafe fn balloon(hwnd: HWND, title: &str, body: &str) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_UID;
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = NIIF_INFO;
    copy_wide(&mut nid.szInfoTitle, title);
    copy_wide(&mut nid.szInfo, body);
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

pub fn refresh_tooltip() {
    let raw = HWND_SLOT.load(Ordering::Relaxed);
    if raw == 0 {
        return;
    }
    let ctx = context_text();
    let targets = crate::peers::targets();
    let target = if targets.is_empty() {
        "未选发送目标".to_string()
    } else {
        target_summary(&targets, "发送给 ")
    };
    let text = format!("华为分享 · {} · {}", ctx.name, target);
    unsafe {
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = raw as HWND;
        nid.uID = TRAY_UID;
        nid.uFlags = NIF_TIP;
        copy_wide(&mut nid.szTip, &text);
        Shell_NotifyIconW(NIM_MODIFY, &nid);
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

pub fn run_loop() -> i32 {
    // GUI 进程的事件出口：库里的日志写进托盘日志，文本进度条不画（进度由浮窗显示）。
    crate::report::install(log_line, |_| {}, || {});

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

        if crate::env::present("HWSHARE_DEBUG") {
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
        copy_wide(&mut nid.szTip, &format!("华为分享 · {}", ctx.name));
        if Shell_NotifyIconW(NIM_ADD, &nid) == 0 {
            log_line("失败：Shell_NotifyIcon(NIM_ADD) 返回 0（任务栏不接收图标）");
            return 1;
        }
        log_line(if custom {
            "托盘图标已挂载（自绘 Hi）"
        } else {
            "托盘图标已挂载（退化为系统默认图标）"
        });

        let _ = crate::peers::view(crate::peers::LIST_TTL);
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
        WM_DUP_START => {
            // 有人又双击了一次 exe。他要的信息只有两条：程序在跑、窗口在哪。
            // 顺手把投递窗叫回来——「我双击了怎么没反应」通常就是面板被收进托盘了。
            crate::dropzone::show();
            refresh_tooltip();
            log_line("[启动] 又开了一次，已提示「已在运行」并叫回投递窗");
            notify(
                "华为分享已经在运行了",
                "图标在屏幕右下角，投递窗口已经帮你叫回来",
            );
            0
        }
        WM_COMMAND => {
            run_command(hwnd, (wparam & 0xFFFF) as usize);
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

/// 主菜单命令的统一下发点。
///
/// 菜单用 `TPM_RETURNCMD` 自己取返回值（这样「发送目标」才能做成原地重开的多选弹窗），
/// 所以命令不一定经过 `WM_COMMAND`；两条路径都收敛到这里，逻辑只写一遍。
fn run_command(hwnd: HWND, id: usize) {
    unsafe {
        match id {
            ID_OPEN => open_folder(&context_text().dest),
            ID_PICK_DIR => choose_dir(hwnd),
            ID_AUTOSTART => toggle_autostart(hwnd),
            ID_HISTORY_FILE => {
                let path = crate::history::log_file();
                if path.exists() {
                    open_file(&path.to_string_lossy());
                } else {
                    notify(
                        "还没有传输记录",
                        "收发过一次文件后，这里会有完整日志（几点、发给谁、几个文件、多大）",
                    );
                }
            }
            ID_ABOUT => show_about(hwnd),
            ID_QUIT => PostQuitMessage(0),
            id if (ID_TARGET_BASE..ID_TARGET_BASE + MENU_PEER_CAP).contains(&id) => {
                if let Some(peer) = peer_at(id - ID_TARGET_BASE) {
                    let on = crate::peers::toggle_target(&peer);
                    log_line(&format!(
                        "[目标] {} {}",
                        if on { "勾选" } else { "取消" },
                        peer_name(&peer)
                    ));
                    refresh_tooltip();
                }
            }
            ID_TARGET_RESCAN => {
                crate::discovery::request_scan();
                log_line("[目标] 手动重新扫描");
                notify(
                    "正在扫描",
                    "设备会在一两秒内出现在「发送目标」里（手机需亮屏、开着分享）",
                );
            }
            ID_TARGET_CLEAR => {
                crate::peers::clear_targets();
                log_line("[目标] 已清空");
                notify("已清除发送目标", "拖文件进投递窗时会提示先挑一台");
                refresh_tooltip();
            }
            id if (ID_SEND_BASE..ID_SEND_BASE + MENU_PEER_CAP).contains(&id) => {
                let peer = peer_at(id - ID_SEND_BASE);
                if let Some(peer) = peer {
                    let files = pick_files(hwnd);
                    if !files.is_empty() {
                        if let Err(e) = crate::dispatch::send_to(peer, files, device_name()) {
                            message_box(hwnd, &e, MB_OK | MB_ICONWARNING);
                        }
                    }
                }
            }
            id if (ID_CLIP_BASE..ID_CLIP_BASE + MENU_PEER_CAP).contains(&id) => {
                if let Some(peer) = peer_at(id - ID_CLIP_BASE) {
                    send_clipboard(hwnd, peer);
                }
            }
            _ => {}
        }
    }
}

fn peer_at(index: usize) -> Option<crate::peers::PeerInfo> {
    MENU_PEERS
        .lock()
        .ok()
        .and_then(|slot| slot.get(index).cloned())
}

/// 弹一条通知。
///
/// **不阻塞调用方**：过去这里直接跑 `notice::show`，而它内部是 `GetMessageW` 模态循环，
/// 于是从浮窗线程调用时会把进度绘制和定时器一起冻住（更糟的情况是从接收线程调用，
/// 连接收都会停）。现在丢到独立线程去弹，调用方立刻返回。
pub fn alert(title: &str, body: &str) {
    if ALERT_BUSY.swap(true, Ordering::SeqCst) {
        // 已经有一条在显示：丢掉后来的，别让错误处理把屏幕铺满。
        return;
    }
    let title = title.to_string();
    let body = body.to_string();
    std::thread::spawn(move || {
        // notice::show 里有 GDI 调用，异常路径下 panic 并非不可能；
        // 一旦 panic 而没复位 ALERT_BUSY，之后所有通知都会被当成"已有一条"丢掉。
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::notice::show(&title, &body);
        }));
        ALERT_BUSY.store(false, Ordering::SeqCst);
    });
}

/// `alert` 的同步版：调用线程一直卡到用户点「好」为止。
///
/// 只给「马上就要 `exit`」的启动路径用。`alert` 是丢线程去弹的，而进程一退出所有线程
/// 都被硬杀，那张卡还没来得及画出来就没了——正是「重复启动毫无提示」的成因。
pub fn alert_blocking(title: &str, body: &str) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::notice::show(title, body);
    }));
}

/// 叫醒已经在运行的那个实例，让它弹提示并把投递窗叫回来。
///
/// 按类名找窗：`FindWindowW` 只在同一会话/同一桌面的顶层窗口里找，正好是本进程要的
/// 那个。找不到就返回 `false`（对方可能刚拿到互斥量、窗口还没建出来），调用方自己兜底。
pub fn poke_running_instance() -> bool {
    unsafe {
        let class = wide("HWShareTrayWindow");
        let hwnd = FindWindowW(class.as_ptr(), std::ptr::null());
        if hwnd.is_null() {
            return false;
        }
        PostMessageW(hwnd, WM_DUP_START, 0, 0) != 0
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
            accepts: true,
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
    fn closed_peer_shows_hint_without_dot() {
        let mut p = peer("nova 14 Ultra", "phone", Duration::from_secs(5));
        p.accepts = false;
        let line = peer_line(&p);
        assert!(line.contains("对方关了华为分享"), "{line}");
        assert!(line.contains("手机"), "{line}");
        assert!(!line.contains('●') && !line.contains('○'), "{line}");
    }

    #[test]
    fn offline_peer_says_offline_without_dot() {
        let line = peer_line(&peer("HUAWEI MatePad", "tablet", Duration::from_secs(300)));
        assert!(line.starts_with("HUAWEI MatePad"), "{line}");
        assert!(line.contains("平板"), "{line}");
        assert!(line.contains("离线"), "{line}");
        assert!(!line.contains("分钟前"), "离线只写「离线」，不写多久以前：{line}");
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
    fn target_summary_counts_multiple_picks() {
        let a = peer("nova 14 Ultra", "phone", Duration::from_secs(1));
        let b = peer("MatePad", "tablet", Duration::from_secs(1));
        assert_eq!(target_summary(&[], "发送目标："), "发送目标：未选择");
        assert_eq!(target_summary(&[a.clone()], "发送目标："), "发送目标：nova 14 Ultra");
        assert_eq!(
            target_summary(&[a.clone(), b], "发送目标："),
            "发送目标：nova 14 Ultra 等 2 台"
        );
        let offline = peer("息屏手机", "phone", Duration::from_secs(60));
        assert_eq!(
            target_summary(&[offline], "发送目标："),
            "发送目标：息屏手机（离线）"
        );
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

    /// 按文字找菜单项（含子菜单），返回它的状态位（`MF_CHECKED` / `MF_GRAYED` …）。
    unsafe fn item_state(menu: HMENU, needle: &str) -> Option<u32> {
        for index in 0..GetMenuItemCount(menu).max(0) {
            let mut buf = [0u16; 256];
            let n = GetMenuStringW(
                menu,
                index as u32,
                buf.as_mut_ptr(),
                buf.len() as i32,
                MF_BYPOSITION,
            );
            if n > 0 && String::from_utf16_lossy(&buf[..n as usize]).contains(needle) {
                return Some(GetMenuState(menu, index as u32, MF_BYPOSITION));
            }
            let sub = GetSubMenu(menu, index);
            if !sub.is_null() {
                if let Some(state) = item_state(sub, needle) {
                    return Some(state);
                }
            }
        }
        None
    }

    #[test]
    fn menu_lists_peers_with_state_and_actions() {

        let _g = crate::peers::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::peers::reset_for_test();

        crate::peers::upsert("测试机甲", "10.77.0.1", 4321, "phone", true);
        crate::peers::upsert("测试平板乙", "10.77.0.2", 4322, "tablet", true);

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
                !text.contains("同时发给"),
                "群发开关已经换成「发送目标」多选：{text}"
            );
            assert!(
                text.contains("发送目标：未选择"),
                "没勾设备时标题该是「未选择」：{text}"
            );
            assert!(
                text.contains("重新扫描局域网"),
                "「重新扫描」应该在发送目标二级菜单里：{text}"
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

            assert!(text.contains("发送文件到手机"), "{text}");
            assert!(text.contains("发送剪贴板文本"), "{text}");
        }
    }

    #[test]
    fn target_menu_is_multi_select_and_greys_offline() {
        let _g = crate::peers::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::peers::reset_for_test();

        crate::peers::upsert("在线甲", "10.78.0.1", 4001, "phone", true);
        crate::peers::upsert("在线乙", "10.78.0.2", 4002, "tablet", true);
        crate::peers::upsert_aged("熄屏丙", "10.78.0.3", 4003, "phone", Duration::from_secs(30));
        // 超过 5 分钟没消息：连列表都不该进。
        crate::peers::upsert_aged(
            "很久以前",
            "10.78.0.4",
            4004,
            "phone",
            crate::peers::LIST_TTL + Duration::from_secs(1),
        );

        let picked = crate::peers::snapshot(crate::peers::LIST_TTL)
            .into_iter()
            .find(|p| p.host == "10.78.0.1")
            .expect("在线甲 应该在表里");
        crate::peers::toggle_target(&picked);

        unsafe {
            let menu = build_menu();
            assert!(!menu.is_null());
            let labels = menu_labels(menu);
            let checked = item_state(menu, "在线甲（手机）");
            let offline = item_state(menu, "熄屏丙（手机");
            let gone = item_state(menu, "很久以前");
            let single = item_state(menu, "在线乙（平板）");
            DestroyMenu(menu);

            let text = labels.join(" | ");
            assert!(checked.expect("在线甲 不见了") & MF_CHECKED != 0, "{text}");
            assert!(single.expect("在线乙 不见了") & MF_CHECKED == 0, "{text}");
            assert!(
                single.expect("在线乙 不见了") & MF_GRAYED == 0,
                "在线的要能点：{text}"
            );
            assert!(
                offline.expect("熄屏丙 不见了") & MF_GRAYED != 0,
                "离线的必须灰掉：{text}"
            );
            assert!(text.contains("熄屏丙") && text.contains("离线"), "{text}");
            assert!(gone.is_none(), "超过 5 分钟的设备要从菜单里消失：{text}");
            assert!(text.contains("重新扫描局域网"), "{text}");
            assert!(text.contains("清除选择"), "已经勾了设备，要给清除入口：{text}");
        }

        // 勾第二台：两台都打勾，标题变成「等 2 台」。
        let second = crate::peers::snapshot(crate::peers::LIST_TTL)
            .into_iter()
            .find(|p| p.host == "10.78.0.2")
            .expect("在线乙 应该在表里");
        crate::peers::toggle_target(&second);

        unsafe {
            let menu = build_menu();
            let labels = menu_labels(menu);
            DestroyMenu(menu);
            let text = labels.join(" | ");
            assert!(text.contains("等 2 台"), "多选后标题要报总数：{text}");
        }
        crate::peers::reset_for_test();
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
