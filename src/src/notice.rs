#![cfg(windows)]

use std::sync::atomic::{AtomicI32, AtomicIsize, Ordering};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, CreateSolidBrush, DeleteObject, DrawTextW, FillRect, SelectObject, SetBkMode,
    SetTextColor,
    ANTIALIASED_QUALITY, CLIP_DEFAULT_PRECIS, DEFAULT_PITCH, DT_CENTER, DT_SINGLELINE, DT_VCENTER,
    DT_WORDBREAK, FF_DONTCARE, FW_BOLD, FW_NORMAL, GB2312_CHARSET, OUT_DEFAULT_PRECIS, TRANSPARENT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::GetDpiForSystem;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    FlashWindow, GetClientRect, GetMessageW, GetSystemMetrics, LoadCursorW, PostQuitMessage,
    RegisterClassW, SetForegroundWindow, ShowWindow, TranslateMessage, MSG,
    WNDCLASSW, WS_EX_LAYERED, WS_EX_TOPMOST, WS_POPUP,
};

const CARD_W: i32 = 380;
const CARD_H: i32 = 208;
const RADIUS: i32 = 22;
const BTN_H: i32 = 50;

const COL_BG: u32 = 0x00FF_FFFF;
const COL_MAIN: u32 = 0x001A_1A1A;
const COL_SUB: u32 = 0x0080_8080;
const COL_LINE: u32 = 0x00EA_E5E5;
const COL_HOVER: u32 = 0x00F7_F2F2;
const COL_ACCENT: u32 = 0x00FF_7A00;

const WM_PAINT: u32 = 0x000F;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_ERASEBKGND: u32 = 0x0014;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_CLOSE: u32 = 0x0010;
const WM_DESTROY: u32 = 0x0002;
const WM_KEYDOWN: u32 = 0x0100;
const WM_GETDLGCODE: u32 = 0x0087;
const SM_CXSCREEN: i32 = 0;
const SM_CYSCREEN: i32 = 1;
const IDC_ARROW: usize = 32512;
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
    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let class: Vec<u16> = "HWShareNotice\0".encode_utf16().collect();
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.style = 0x0001 | 0x0002;
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = instance;
        wc.hCursor = LoadCursorW(std::ptr::null_mut(), IDC_ARROW as *const u16) as _;
        wc.lpszClassName = class.as_ptr();
        RegisterClassW(&wc);

        let dpi = {
            let d = GetDpiForSystem();
            if d == 0 { 96 } else { d as i32 }
        };
        CARD_DPI.store(dpi, Ordering::SeqCst);
        if let Ok(mut s) = TITLE.lock() {
            *s = title.to_string();
        }
        if let Ok(mut s) = BODY.lock() {
            *s = body.to_string();
        }
        CLICKED.store(0, Ordering::SeqCst);
        HOVER.store(0, Ordering::SeqCst);

        let cw = CARD_W * dpi / 96;
        let ch = CARD_H * dpi / 96;
        let x = (GetSystemMetrics(SM_CXSCREEN) - cw) / 2;
        let y = (GetSystemMetrics(SM_CYSCREEN) - ch) / 2;

        let caption = wide("华为分享");
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_LAYERED,
            class.as_ptr(),
            caption.as_ptr(),
            WS_POPUP,
            x,
            y,
            cw,
            ch,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return false;
        }

        WIN_POS[0].store(x, Ordering::SeqCst);
        WIN_POS[1].store(y, Ordering::SeqCst);
        if let Some(canvas) = crate::layered::Canvas::new(cw, ch) {
            *CANVAS.get_or_init(|| Mutex::new(None)).lock().unwrap_or_else(|e| e.into_inner()) =
                Some(canvas);
        }

        let face = wide("Microsoft YaHei UI");
        let mk = |h: i32, weight: i32| {
            CreateFontW(
                -h * dpi / 96, 0, 0, 0, weight, 0, 0, 0,
                GB2312_CHARSET as u32, OUT_DEFAULT_PRECIS as u32, CLIP_DEFAULT_PRECIS as u32,
                ANTIALIASED_QUALITY as u32, (DEFAULT_PITCH | FF_DONTCARE) as u32, face.as_ptr(),
            )
        };
        let f_title = mk(17, FW_BOLD as i32);
        let f_body = mk(14, FW_NORMAL as i32);
        let f_btn = mk(16, FW_BOLD as i32);
        FONT_TITLE.store(f_title as isize, Ordering::SeqCst);
        FONT_BODY.store(f_body as isize, Ordering::SeqCst);
        FONT_BTN.store(f_btn as isize, Ordering::SeqCst);

        paint(hwnd);
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        BringWindowToTop(hwnd);
        FlashWindow(hwnd, 1);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        for f in [f_title, f_body, f_btn] {
            if !f.is_null() {
                DeleteObject(f as _);
            }
        }
        CLICKED.load(Ordering::SeqCst) == 1
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn paint(hwnd: HWND) {
    let Some(slot) = CANVAS.get() else { return };
    let Ok(guard) = slot.lock() else { return };
    let Some(canvas) = guard.as_ref() else { return };
    let hdc = canvas.mem;
    let (w, h) = (canvas.w, canvas.h);
    let rc = RECT { left: 0, top: 0, right: w, bottom: h };
    let dpi = CARD_DPI.load(Ordering::SeqCst).max(96);
    let px = |v: i32| v * dpi / 96;

    let bg = CreateSolidBrush(COL_BG);
    FillRect(hdc, &rc, bg);
    DeleteObject(bg as _);
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

    let line = CreateSolidBrush(COL_LINE);
    let hl = RECT { left: 0, top: btn_top, right: w, bottom: btn_top + 1 };
    FillRect(hdc, &hl, line);
    DeleteObject(line as _);

    if HOVER.load(Ordering::SeqCst) == 1 {
        let hb = CreateSolidBrush(COL_HOVER);
        let hr = RECT { left: 0, top: btn_top + 1, right: w, bottom: h };
        FillRect(hdc, &hr, hb);
        DeleteObject(hb as _);
    }
    SelectObject(hdc, FONT_BTN.load(Ordering::SeqCst) as _);
    SetTextColor(hdc, COL_ACCENT);
    let mut r2 = RECT { left: 0, top: btn_top + 1, right: w, bottom: h };
    let u2: Vec<u16> = "好".encode_utf16().collect();
    DrawTextW(hdc, u2.as_ptr(), u2.len() as i32, &mut r2, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

    let radius = RADIUS * CARD_DPI.load(Ordering::SeqCst).max(96) / 96;
    canvas.commit(
        hwnd,
        WIN_POS[0].load(Ordering::SeqCst),
        WIN_POS[1].load(Ordering::SeqCst),
        radius,
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
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}
