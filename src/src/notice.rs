//! 一次性通知卡：居中显示，点「好」或按回车关闭。

#![cfg(windows)]

use crate::ui::font::{WEIGHT_BOLD, WEIGHT_NORMAL};
use crate::ui::draw as ui_draw;
use crate::ui::popup;
use crate::ui::theme::{
    ACCENT as COL_ACCENT, BG as COL_BG, HOVER as COL_HOVER, LINE as COL_LINE, MAIN as COL_MAIN,
    RADIUS, SUB as COL_SUB,
};
use std::sync::atomic::{AtomicI32, AtomicIsize, Ordering};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    DeleteObject, DrawTextW, SelectObject, SetBkMode,
    SetTextColor, DT_CENTER, DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, TRANSPARENT
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, DestroyWindow, FlashWindow, GetClientRect, PostQuitMessage, SetForegroundWindow,
    ShowWindow, WS_EX_LAYERED, WS_EX_TOPMOST,
};

const CLASS: &str = "HWShareNotice";

const CARD_W: i32 = 380;
const CARD_H: i32 = 208;
const BTN_H: i32 = 50;

const WM_PAINT: u32 = 0x000F;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_ERASEBKGND: u32 = 0x0014;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_CLOSE: u32 = 0x0010;
const WM_DESTROY: u32 = 0x0002;
const WM_KEYDOWN: u32 = 0x0100;
const WM_GETDLGCODE: u32 = 0x0087;
const SW_SHOW: i32 = 5;
const VK_RETURN: usize = 0x0D;
const VK_ESCAPE: usize = 0x1B;
const DLGC_WANTALLKEYS: isize = 0x0004;

static CLICKED: AtomicI32 = AtomicI32::new(0);
static HOVER: AtomicI32 = AtomicI32::new(0);
static CARD_DPI: AtomicI32 = AtomicI32::new(96);
static TITLE: Mutex<String> = Mutex::new(String::new());
static BODY: Mutex<String> = Mutex::new(String::new());
static CANVAS: std::sync::OnceLock<Mutex<Option<crate::layered::Canvas>>> =
    std::sync::OnceLock::new();
static WIN_POS: [AtomicI32; 2] = [AtomicI32::new(0), AtomicI32::new(0)];
static FONT_TITLE: AtomicIsize = AtomicIsize::new(0);
static FONT_BODY: AtomicIsize = AtomicIsize::new(0);
static FONT_BTN: AtomicIsize = AtomicIsize::new(0);

static SHOW_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn show(title: &str, body: &str) -> bool {
    let _guard = match SHOW_LOCK.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => return false,

        Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
    };

    crate::tray::enable_dpi_awareness();
    popup::register_class(CLASS, Some(wndproc), 0);
    let Some(win) = popup::create_layered(
        CLASS,
        "华为分享",
        (CARD_W, CARD_H),
        WS_EX_TOPMOST | WS_EX_LAYERED,
        popup::Placement::Centered,
    ) else {
        return false;
    };

    CARD_DPI.store(win.dpi, Ordering::SeqCst);
    if let Ok(mut s) = TITLE.lock() {
        *s = title.to_string();
    }
    if let Ok(mut s) = BODY.lock() {
        *s = body.to_string();
    }
    CLICKED.store(0, Ordering::SeqCst);
    HOVER.store(0, Ordering::SeqCst);

    WIN_POS[0].store(win.x, Ordering::SeqCst);
    WIN_POS[1].store(win.y, Ordering::SeqCst);
    crate::layered::install_canvas(&CANVAS, unsafe {
        crate::layered::Canvas::new(win.w, win.h)
    });

    let (f_title, f_body, f_btn) = unsafe {
        let mk = |h: i32, weight: i32| {
            crate::ui::font::ui(crate::ui::theme::px(h, win.dpi), weight)
        };
        (mk(17, WEIGHT_BOLD), mk(14, WEIGHT_NORMAL), mk(16, WEIGHT_BOLD))
    };
    FONT_TITLE.store(f_title as isize, Ordering::SeqCst);
    FONT_BODY.store(f_body as isize, Ordering::SeqCst);
    FONT_BTN.store(f_btn as isize, Ordering::SeqCst);

    unsafe {
        paint(win.hwnd);
        ShowWindow(win.hwnd, SW_SHOW);
        SetForegroundWindow(win.hwnd);
        BringWindowToTop(win.hwnd);
        FlashWindow(win.hwnd, 1);
    }

    popup::run_message_loop();

    for f in [f_title, f_body, f_btn] {
        if !f.is_null() {
            unsafe { DeleteObject(f as _) };
        }
    }
    CLICKED.load(Ordering::SeqCst) == 1
}

unsafe fn paint(hwnd: HWND) {
    let Some((hdc, w, h)) = crate::layered::canvas_info(CANVAS.get()) else { return };
    let rc = RECT { left: 0, top: 0, right: w, bottom: h };
    let dpi = CARD_DPI.load(Ordering::SeqCst).max(96);
    let px = |v: i32| v * dpi / 96;

    ui_draw::fill(hdc, rc.left, rc.top, rc.right, rc.bottom, COL_BG);
    SetBkMode(hdc, TRANSPARENT as i32);

    let btn_top = h - px(BTN_H);

    let title = TITLE.lock().map(|s| s.clone()).unwrap_or_default();
    SelectObject(hdc, FONT_TITLE.load(Ordering::SeqCst) as _);
    SetTextColor(hdc, COL_MAIN);
    let mut r0 = RECT { left: px(24), top: px(22), right: w - px(24), bottom: px(50) };
    let u0: Vec<u16> = title.encode_utf16().collect();
    DrawTextW(hdc, u0.as_ptr(), u0.len() as i32, &mut r0, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

    let body = BODY.lock().map(|s| s.clone()).unwrap_or_default();
    SelectObject(hdc, FONT_BODY.load(Ordering::SeqCst) as _);
    SetTextColor(hdc, COL_SUB);
    let mut r1 = RECT { left: px(28), top: px(56), right: w - px(28), bottom: btn_top - px(10) };
    let u1: Vec<u16> = body.encode_utf16().collect();
    DrawTextW(hdc, u1.as_ptr(), u1.len() as i32, &mut r1, DT_CENTER | DT_WORDBREAK);

    ui_draw::hline(hdc, 0, w, btn_top, COL_LINE);

    if HOVER.load(Ordering::SeqCst) == 1 {
        ui_draw::fill(hdc, 0, btn_top + 1, w, h, COL_HOVER);
    }
    SelectObject(hdc, FONT_BTN.load(Ordering::SeqCst) as _);
    SetTextColor(hdc, COL_ACCENT);
    let mut r2 = RECT { left: 0, top: btn_top + 1, right: w, bottom: h };
    let u2: Vec<u16> = "好".encode_utf16().collect();
    DrawTextW(hdc, u2.as_ptr(), u2.len() as i32, &mut r2, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

    let radius = RADIUS * CARD_DPI.load(Ordering::SeqCst).max(96) / 96;
    crate::layered::commit_canvas(
        &CANVAS,
        hwnd,
        WIN_POS[0].load(Ordering::SeqCst),
        WIN_POS[1].load(Ordering::SeqCst),
        radius,
        255,
    );
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            paint(hwnd);
            0
        }
        WM_MOUSEMOVE => {
            let y = ((lparam >> 16) & 0xFFFF) as i32;
            let mut rc: RECT = std::mem::zeroed();
            GetClientRect(hwnd, &mut rc);
            let dpi = CARD_DPI.load(Ordering::SeqCst).max(96);
            let over = if y >= rc.bottom - BTN_H * dpi / 96 { 1 } else { 0 };
            if HOVER.swap(over, Ordering::SeqCst) != over {
                paint(hwnd);
            }
            0
        }
        WM_LBUTTONDOWN => {
            let y = ((lparam >> 16) & 0xFFFF) as i32;
            let mut rc: RECT = std::mem::zeroed();
            GetClientRect(hwnd, &mut rc);
            let dpi = CARD_DPI.load(Ordering::SeqCst).max(96);
            if y >= rc.bottom - BTN_H * dpi / 96 {
                CLICKED.store(1, Ordering::SeqCst);
                DestroyWindow(hwnd);
            }
            0
        }
        WM_ERASEBKGND => 1,
        WM_CLOSE => {
            CLICKED.store(1, Ordering::SeqCst);
            DestroyWindow(hwnd);
            0
        }
        WM_KEYDOWN => {
            if wparam == VK_RETURN || wparam == VK_ESCAPE || wparam == 32 {
                CLICKED.store(1, Ordering::SeqCst);
                DestroyWindow(hwnd);
            }
            0
        }
        WM_GETDLGCODE => DLGC_WANTALLKEYS,
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => windows_sys::Win32::UI::WindowsAndMessaging::DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}
