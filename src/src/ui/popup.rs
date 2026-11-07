#![cfg(windows)]

//! 卡片窗口的公共骨架。
//!
//! 三张卡片（常驻浮窗 / 接收确认 / 一次性通知）原先各自抄一遍：注册窗口类、
//! 取系统 DPI、按 DPI 换算尺寸、建 `WS_EX_LAYERED` 窗口、跑消息循环。
//! 这段样板和「画什么」完全无关，出错时的表现却一样（忘了 `SetProcessDPIAware`
//! 字就糊、忘了 `WS_EX_NOACTIVATE` 就抢焦点），所以统一到这里。
//!
//! 卡片模块只负责三件事：`wndproc`、绘制函数、自己的状态。

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::GetDpiForSystem;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DispatchMessageW, GetMessageW, GetSystemMetrics, LoadCursorW, RegisterClassW,
    TranslateMessage, MSG, WNDCLASSW, WNDPROC, WS_POPUP,
};

const IDC_ARROW: usize = 32512;
const SM_CXSCREEN: i32 = 0;
const SM_CYSCREEN: i32 = 1;

/// `CS_VREDRAW | CS_HREDRAW`：尺寸变化时整块重画。
const CS_REDRAW: u32 = 0x0001 | 0x0002;
/// 需要双击消息（浮窗用）时叠加这个。
pub const CS_DBLCLKS: u32 = 0x0008;

/// 系统 DPI。取不到（远程会话/老系统）时按 96，避免除零。
pub fn system_dpi() -> i32 {
    let d = unsafe { GetDpiForSystem() };
    if d == 0 {
        96
    } else {
        d as i32
    }
}

/// 注册窗口类。同名类重复注册在 Win32 里是无害的（后续调用返回 0），
/// 三个卡片都是「显示时才建窗口」，所以这里不做一次性保护。
pub fn register_class(class: &str, proc: WNDPROC, extra_style: u32) {
    let mut name: Vec<u16> = class.encode_utf16().collect();
    name.push(0);
    unsafe {
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.style = CS_REDRAW | extra_style;
        wc.lpfnWndProc = proc;
        wc.hInstance = GetModuleHandleW(std::ptr::null());
        wc.hCursor = LoadCursorW(std::ptr::null_mut(), IDC_ARROW as *const u16) as _;
        wc.lpszClassName = name.as_ptr();
        RegisterClassW(&wc);
    }
}

/// 新建窗口放在哪。
#[derive(Clone, Copy)]
pub enum Placement {
    /// 屏幕正中（确认框 / 通知卡）。
    Centered,
    /// 指定左上角（浮窗恢复上次位置）。
    At(i32, i32),
}

/// 建好的分层窗口与它实际占用的像素尺寸。
pub struct Window {
    pub hwnd: HWND,
    pub dpi: i32,
    pub w: i32,
    pub h: i32,
    pub x: i32,
    pub y: i32,
}

/// 按逻辑尺寸建一个 `WS_POPUP` 分层窗口。尺寸与坐标都按 DPI 换算。
pub fn create_layered(
    class: &str,
    caption: &str,
    logical: (i32, i32),
    ex_style: u32,
    placement: Placement,
) -> Option<Window> {
    let dpi = system_dpi();
    let mut class_w: Vec<u16> = class.encode_utf16().collect();
    class_w.push(0);
    let mut cap: Vec<u16> = caption.encode_utf16().collect();
    cap.push(0);

    let w = crate::ui::theme::px(logical.0, dpi);
    let h = crate::ui::theme::px(logical.1, dpi);
    let (x, y) = match placement {
        Placement::Centered => {
            let (sw, sh) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
            ((sw - w) / 2, (sh - h) / 2)
        }
        Placement::At(x, y) => (x, y),
    };

    let hwnd = unsafe {
        CreateWindowExW(
            ex_style,
            class_w.as_ptr(),
            cap.as_ptr(),
            WS_POPUP,
            x,
            y,
            w,
            h,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        return None;
    }
    Some(Window { hwnd, dpi, w, h, x, y })
}

/// 跑本线程的消息循环，直到窗口发 `PostQuitMessage`。
pub fn run_message_loop() {
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
