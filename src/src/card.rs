#![cfg(windows)]

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicIsize, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, SIZE, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CreateCompatibleDC, CreateDIBSection, CreateFontW, CreatePen, CreateSolidBrush,
    DeleteDC, DeleteObject, DrawTextW, Ellipse, EndPaint, ExtCreatePen, FillRect, GetStockObject,
    Polygon, Polyline, RoundRect, SelectObject, SetBkMode, SetTextColor,
    ANTIALIASED_QUALITY, BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BLENDFUNCTION, CLIP_DEFAULT_PRECIS,
    DEFAULT_PITCH, DIB_RGB_COLORS, DT_CENTER, DT_LEFT, DT_SINGLELINE, DT_VCENTER, FF_DONTCARE,
    FW_BOLD,
    FW_NORMAL, GB2312_CHARSET, HDC, LOGBRUSH, NULL_BRUSH, OUT_DEFAULT_PRECIS, PAINTSTRUCT,
    PS_GEOMETRIC,
    TRANSPARENT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::GetDpiForSystem;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{ReleaseCapture, SetCapture};
use windows_sys::Win32::UI::Shell::{DragAcceptFiles, DragFinish, DragQueryFileW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW,
    SetWindowPos, UpdateLayeredWindow, SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER,
    KillTimer, LoadCursorW, PostQuitMessage, RegisterClassW, SetTimer, ShowWindow, TranslateMessage,
    MSG, ULW_ALPHA,
    UPDATE_LAYERED_WINDOW_FLAGS, WNDCLASSW, WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW,
    WS_EX_TOPMOST, WS_POPUP,
};

const CARD_W: i32 = 344;
const CARD_H: i32 = 108;
const RADIUS: i32 = 20;
const RING_CX: i32 = 54;
const RING_CY: i32 = 54;
const RING_R: i32 = 32;
const RING_W: i32 = 7;

const BTN_W: i32 = 58;
const BTN_H: i32 = 24;
const BTN_RIGHT: i32 = 14;
const BTN_BOTTOM: i32 = 13;

const COL_BG: u32 = 0x00FF_FFFF;
const COL_MAIN: u32 = 0x001A_1A1A;
const COL_SUB: u32 = 0x0093_8E8E;
const COL_TRACK: u32 = 0x00EA_E5E5;
const COL_BTN_BG: u32 = 0x00E1_DDF9;
const COL_BTN_TEXT: u32 = 0x007A_70C2;
const COL_BTN_HOVER_BG: u32 = 0x00EA_E7FC;
const COL_ACCENT: u32 = 0x00FF_7A00;
const COL_ERROR: u32 = 0x0030_3BFF;
const COL_MEDIA: u32 = 0x0035_C734;
const COL_FILE_BODY: u32 = 0x00F6_F5F7;
const COL_FILE_LINE: u32 = 0x00D6_D4DA;
const COL_ASK: u32 = 0x0078_747D;
const COL_ICON_BG: u32 = 0x00FF_F2EA;
const COL_BORDER: u32 = 0x00E6_E2E9;
const COL_HINT: u32 = 0x00B4_B0B8;

const WM_PAINT: u32 = 0x000F;
const WM_ERASEBKGND: u32 = 0x0014;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_CAPTURECHANGED: u32 = 0x0215;
const WM_RBUTTONUP: u32 = 0x0205;
const WM_LBUTTONDBLCLK: u32 = 0x0203;
const WM_DROPFILES: u32 = 0x0233;
const WM_TIMER: u32 = 0x0113;
const WM_DESTROY: u32 = 0x0002;
const IDC_ARROW: usize = 32512;
const SW_SHOWNOACTIVATE: i32 = 4;
const SW_HIDE: i32 = 0;
const TIMER_ID: usize = 1;
const ANIM_TIMER: usize = 2;
const ANIM_MS: u32 = 300;
const ANIM_IN_PART: f32 = 0.35;
const RESTORE_HOLD_MS: u32 = 3000;

static STATE: AtomicU8 = AtomicU8::new(0);
static MODE: AtomicU8 = AtomicU8::new(0);
static PINNED: AtomicBool = AtomicBool::new(false);
static PCT: AtomicU32 = AtomicU32::new(0);
static RECEIVED: AtomicU64 = AtomicU64::new(0);
static TOTAL: AtomicU64 = AtomicU64::new(0);
static SPEED_KB: AtomicU32 = AtomicU32::new(0);
static NAME: Mutex<String> = Mutex::new(String::new());
static DONE_AT: AtomicU32 = AtomicU32::new(0);
static MEDIA: AtomicBool = AtomicBool::new(false);
static MULTI: AtomicBool = AtomicBool::new(false);
static STARTED: AtomicU8 = AtomicU8::new(0);
static DPI: AtomicU32 = AtomicU32::new(96);
static LAST_MS: AtomicU32 = AtomicU32::new(0);
static LAST_STATE: AtomicU8 = AtomicU8::new(u8::MAX);
static LAST_PCT: AtomicU32 = AtomicU32::new(u32::MAX);
static LAST_SPEED: AtomicU32 = AtomicU32::new(u32::MAX);
static LAST_MODE: AtomicU8 = AtomicU8::new(u8::MAX);
static OUTGOING: AtomicBool = AtomicBool::new(false);
static CANCELED: AtomicBool = AtomicBool::new(false);
static HOVER_CANCEL: AtomicBool = AtomicBool::new(false);
static TUCKED: AtomicU8 = AtomicU8::new(0);
static STARTUP_RESTORE: AtomicBool = AtomicBool::new(false);
static RESTORE_TUCK_AT: AtomicU32 = AtomicU32::new(0);
static FADE: AtomicU32 = AtomicU32::new(255);
static FADE_TO: AtomicU32 = AtomicU32::new(255);
static VISIBLE: AtomicBool = AtomicBool::new(false);
static PENDING_SWITCH: AtomicU8 = AtomicU8::new(0);
static LAST_ALPHA: AtomicU32 = AtomicU32::new(u32::MAX);
const FADE_STEP: u32 = 42;

static ANIM_ON: AtomicBool = AtomicBool::new(false);
static ANIM_T0: AtomicU32 = AtomicU32::new(0);
static ANIM_EDGE: AtomicU8 = AtomicU8::new(0);
static ANIM_FROM: [AtomicI32; 2] = [AtomicI32::new(0), AtomicI32::new(0)];
static ANIM_FULL: [AtomicI32; 2] = [AtomicI32::new(0), AtomicI32::new(0)];
static ANIM_REST: [AtomicI32; 2] = [AtomicI32::new(0), AtomicI32::new(0)];
static CANVAS_DC: AtomicIsize = AtomicIsize::new(0);
static CANVAS_BITS: AtomicIsize = AtomicIsize::new(0);
static WIN_POS: [AtomicI32; 2] = [AtomicI32::new(0), AtomicI32::new(0)];
static WIN_SIZE: [AtomicI32; 2] = [AtomicI32::new(0), AtomicI32::new(0)];
static LAST_RX: AtomicU64 = AtomicU64::new(0);
static TARGET_VIEW: Mutex<Option<crate::peers::TargetView>> = Mutex::new(None);
static LAST_TARGET_REV: AtomicU64 = AtomicU64::new(u64::MAX);

fn now_ms() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u32)
        .unwrap_or(0)
}

fn is_media_name(name: &str) -> bool {
    let ext = std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "bmp" | "heic" | "heif" | "dng"
            | "mp4" | "mov" | "mkv" | "avi" | "3gp" | "webm" | "m4v"
    )
}

pub fn set_outgoing(ours: bool) {
    OUTGOING.store(ours, Ordering::SeqCst);
}

pub fn set_multi(count: usize) {
    MULTI.store(count > 1, Ordering::SeqCst);
    if count > 1 {
        MEDIA.store(false, Ordering::SeqCst);
    }
}

pub fn start(name: &str) {
    if let Ok(mut slot) = NAME.lock() {
        *slot = name.to_string();
    }
    MEDIA.store(!MULTI.load(Ordering::SeqCst) && is_media_name(name), Ordering::SeqCst);
    PCT.store(0, Ordering::SeqCst);
    RECEIVED.store(0, Ordering::SeqCst);
    TOTAL.store(0, Ordering::SeqCst);
    SPEED_KB.store(0, Ordering::SeqCst);
    DONE_AT.store(0, Ordering::SeqCst);
    LAST_MS.store(now_ms(), Ordering::SeqCst);
    LAST_RX.store(0, Ordering::SeqCst);
    CANCELED.store(false, Ordering::SeqCst);
    HOVER_CANCEL.store(false, Ordering::SeqCst);
    MODE.store(0, Ordering::SeqCst);
    STATE.store(1, Ordering::SeqCst);
    ensure_thread();
}

pub fn waiting(name: &str) {
    if let Ok(mut slot) = NAME.lock() {
        *slot = name.to_string();
    }
    MEDIA.store(!MULTI.load(Ordering::SeqCst) && is_media_name(name), Ordering::SeqCst);
    PCT.store(0, Ordering::SeqCst);
    RECEIVED.store(0, Ordering::SeqCst);
    TOTAL.store(0, Ordering::SeqCst);
    SPEED_KB.store(0, Ordering::SeqCst);
    DONE_AT.store(0, Ordering::SeqCst);
    CANCELED.store(false, Ordering::SeqCst);
    HOVER_CANCEL.store(false, Ordering::SeqCst);
    MODE.store(0, Ordering::SeqCst);
    STATE.store(3, Ordering::SeqCst);
    ensure_thread();
}

pub fn update(received: u64, total: u64) {
    if STATE.load(Ordering::SeqCst) != 1 {
        return;
    }
    let rx = received;
    RECEIVED.store(rx, Ordering::SeqCst);
    TOTAL.store(total, Ordering::SeqCst);
    if total > 0 {
        PCT.store(
            (received as f64 * 10000.0 / total as f64).min(10000.0) as u32,
            Ordering::SeqCst,
        );
    }

    let now = now_ms();
    let dt = now.wrapping_sub(LAST_MS.load(Ordering::SeqCst));
    if dt >= 500 {
        let last_rx = LAST_RX.load(Ordering::SeqCst);
        let db = rx.saturating_sub(last_rx);
        let kb = (db / dt.max(1) as u64).min(u32::MAX as u64) as u32;
        SPEED_KB.store(kb, Ordering::SeqCst);
        LAST_MS.store(now, Ordering::SeqCst);
        LAST_RX.store(rx, Ordering::SeqCst);
    }
}

pub fn finish() {
    if STATE.load(Ordering::SeqCst) == 0 || CANCELED.load(Ordering::SeqCst) {
        return;
    }
    STATE.store(2, Ordering::SeqCst);
    DONE_AT.store(now_ms(), Ordering::SeqCst);
}

pub fn fail() {
    let state = STATE.load(Ordering::SeqCst);
    if state == 0 || state == 2 || CANCELED.load(Ordering::SeqCst) {
        return;
    }
    STATE.store(4, Ordering::SeqCst);
    DONE_AT.store(now_ms(), Ordering::SeqCst);
}

pub fn hide() {
    let state = STATE.load(Ordering::SeqCst);
    if state == 2 || state == 4 {
        return;
    }
    if PINNED.load(Ordering::SeqCst) {
        DONE_AT.store(0, Ordering::SeqCst);
        MODE.store(1, Ordering::SeqCst);
        STATE.store(1, Ordering::SeqCst);
        return;
    }
    STATE.store(0, Ordering::SeqCst);
}

fn ensure_thread() {
    if STARTED.swap(1, Ordering::SeqCst) == 1 {
        return;
    }
    std::thread::spawn(|| unsafe {
        run_card();
    });
}

unsafe fn run_card() {
    crate::tray::enable_dpi_awareness();
    let instance = GetModuleHandleW(std::ptr::null());
    let class: Vec<u16> = "HWShareCard\0".encode_utf16().collect();

    let mut wc: WNDCLASSW = std::mem::zeroed();
    wc.style = 0x0001 | 0x0002 | 0x0008;
    wc.lpfnWndProc = Some(wndproc);
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(std::ptr::null_mut(), IDC_ARROW as *const u16) as _;
    wc.lpszClassName = class.as_ptr();
    RegisterClassW(&wc);

    let dpi = {
        let d = GetDpiForSystem();
        if d == 0 { 96 } else { d as i32 }
    };
    DPI.store(dpi as u32, Ordering::SeqCst);
    let cw = CARD_W * dpi / 96;
    let ch = CARD_H * dpi / 96;
    let (x, y, restore_edge) = match crate::float::load_layout() {
        Some(layout) if layout.edge != crate::float::Edge::None => {
            let (x, y) = crate::float::expanded_pos(layout.edge, layout.x, layout.y, cw, ch);
            (x, y, layout.edge)
        }
        Some(layout) => {
            let (x, y) = crate::float::clamp_to_work_area(layout.x, layout.y, cw, ch);
            (x, y, crate::float::Edge::None)
        }
        None => {
            let (x, y) = crate::float::initial_pos(cw, ch, dpi);
            (x, y, crate::float::Edge::None)
        }
    };
    TUCKED.store(restore_edge.code(), Ordering::SeqCst);
    STARTUP_RESTORE.store(restore_edge != crate::float::Edge::None, Ordering::SeqCst);

    let hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED,
        class.as_ptr(),
        std::ptr::null(),
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
        STARTED.store(2, Ordering::SeqCst);
        return;
    }
    DragAcceptFiles(hwnd, 1);

    let screen = windows_sys::Win32::Graphics::Gdi::GetDC(std::ptr::null_mut());
    let mut bmi: BITMAPINFO = std::mem::zeroed();
    bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
    bmi.bmiHeader.biWidth = cw;
    bmi.bmiHeader.biHeight = -ch;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    let mut bits: *mut std::ffi::c_void = std::ptr::null_mut();
    let dib = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &mut bits, std::ptr::null_mut(), 0);
    let mem = CreateCompatibleDC(screen);
    if !dib.is_null() {
        SelectObject(mem, dib);
    }
    windows_sys::Win32::Graphics::Gdi::ReleaseDC(std::ptr::null_mut(), screen);

    CANVAS_DC.store(mem as isize, Ordering::SeqCst);
    CANVAS_BITS.store(bits as isize, Ordering::SeqCst);
    WIN_POS[0].store(x, Ordering::SeqCst);
    WIN_POS[1].store(y, Ordering::SeqCst);
    crate::float::remember(x, y);
    WIN_SIZE[0].store(cw, Ordering::SeqCst);
    WIN_SIZE[1].store(ch, Ordering::SeqCst);

    commit(hwnd);
    SetTimer(hwnd, TIMER_ID, 100, None);
    let mut msg: MSG = std::mem::zeroed();
    while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    KillTimer(hwnd, TIMER_ID);
    DestroyWindow(hwnd);

    let canvas = CANVAS_DC.swap(0, Ordering::SeqCst);
    if canvas != 0 {
        DeleteDC(canvas as _);
    }
    if !dib.is_null() {
        DeleteObject(dib as _);
    }
    CANVAS_BITS.store(0, Ordering::SeqCst);
}

fn corner_alpha(x: i32, y: i32, w: i32, h: i32, r: i32) -> u8 {
    let (cx, cy) = if x < r && y < r {
        (r as f32, r as f32)
    } else if x >= w - r && y < r {
        ((w - r) as f32, r as f32)
    } else if x < r && y >= h - r {
        (r as f32, (h - r) as f32)
    } else if x >= w - r && y >= h - r {
        ((w - r) as f32, (h - r) as f32)
    } else {
        return 255;
    };
    let dx = x as f32 + 0.5 - cx;
    let dy = y as f32 + 0.5 - cy;
    let d = (dx * dx + dy * dy).sqrt();
    let inner = r as f32 - 0.5;
    let outer = r as f32 + 0.5;
    if d <= inner {
        255
    } else if d >= outer {
        0
    } else {
        (((outer - d) / (outer - inner)) * 255.0) as u8
    }
}

unsafe fn commit(hwnd: HWND) {
    let mem = CANVAS_DC.load(Ordering::SeqCst) as HDC;
    let bits = CANVAS_BITS.load(Ordering::SeqCst) as *mut u8;
    let w = WIN_SIZE[0].load(Ordering::SeqCst);
    let h = WIN_SIZE[1].load(Ordering::SeqCst);
    if mem.is_null() || bits.is_null() || w <= 0 || h <= 0 {
        return;
    }

    if MODE.load(Ordering::SeqCst) == 1 {
        draw_drop();
    } else {
        draw_progress(hwnd, STATE.load(Ordering::SeqCst));
    }

    let fade = FADE.load(Ordering::SeqCst).min(255);
    if fade < 255 {
        for y in 0..h {
            for x in 0..w {
                let base = ((y * w + x) * 4) as usize;
                for c in 0..3 {
                    let v = *bits.add(base + c) as u32;
                    *bits.add(base + c) = (255 - (255 - v) * fade / 255) as u8;
                }
            }
        }
    }

    let r = RADIUS * DPI.load(Ordering::SeqCst).max(96) as i32 / 96;
    for y in 0..h {
        for x in 0..w {
            let base = ((y * w + x) * 4) as usize;
            let a = corner_alpha(x, y, w, h, r) as u32;
            if a == 255 {
                *bits.add(base + 3) = 255;
                continue;
            }
            for c in 0..3 {
                let v = *bits.add(base + c) as u32;
                *bits.add(base + c) = ((v * a + 127) / 255) as u8;
            }
            *bits.add(base + 3) = a as u8;
        }
    }

    let mut pt_dst = POINT { x: WIN_POS[0].load(Ordering::SeqCst), y: WIN_POS[1].load(Ordering::SeqCst) };
    let size = SIZE { cx: w, cy: h };
    let pt_src = POINT { x: 0, y: 0 };
    let blend = BLENDFUNCTION {
        BlendOp: 0,
        BlendFlags: 0,
        SourceConstantAlpha: 255,
        AlphaFormat: 1,
    };
    UpdateLayeredWindow(
        hwnd,
        std::ptr::null_mut(),
        &mut pt_dst,
        &size,
        mem,
        &pt_src,
        0,
        &blend,
        ULW_ALPHA as UPDATE_LAYERED_WINDOW_FLAGS,
    );
}

fn cancel_rect() -> (i32, i32, i32, i32) {
    let dpi = DPI.load(Ordering::SeqCst).max(96) as i32;
    let w = WIN_SIZE[0].load(Ordering::SeqCst);
    let h = WIN_SIZE[1].load(Ordering::SeqCst);
    let x2 = w - BTN_RIGHT * dpi / 96;
    let x1 = x2 - BTN_W * dpi / 96;
    let y2 = h - BTN_BOTTOM * dpi / 96;
    let y1 = y2 - BTN_H * dpi / 96;
    (x1, y1, x2, y2)
}

fn hit_cancel(x: i32, y: i32) -> bool {
    let state = STATE.load(Ordering::SeqCst);
    if state != 1 && state != 3 {
        return false;
    }
    let (x1, y1, x2, y2) = cancel_rect();
    x >= x1 && x < x2 && y >= y1 && y < y2
}

unsafe fn cursor_hover_hit() -> bool {
    let mut pt = POINT { x: 0, y: 0 };
    if GetCursorPos(&mut pt) == 0 {
        return false;
    }
    let (x, y) = (
        pt.x - WIN_POS[0].load(Ordering::SeqCst),
        pt.y - WIN_POS[1].load(Ordering::SeqCst),
    );
    if MODE.load(Ordering::SeqCst) == 1 {
        hit_close(x, y)
    } else {
        hit_cancel(x, y)
    }
}

unsafe fn move_to(hwnd: HWND, x: i32, y: i32) {
    SetWindowPos(
        hwnd,
        std::ptr::null_mut(),
        x,
        y,
        0,
        0,
        SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
    );
    WIN_POS[0].store(x, Ordering::SeqCst);
    WIN_POS[1].store(y, Ordering::SeqCst);
}

unsafe fn tuck_tick(hwnd: HWND) {
    let edge = crate::float::Edge::from_code(TUCKED.load(Ordering::SeqCst));
    if edge == crate::float::Edge::None
        || crate::float::is_dragging()
        || ANIM_ON.load(Ordering::SeqCst)
        || STATE.load(Ordering::SeqCst) == 0
        || RESTORE_TUCK_AT.load(Ordering::SeqCst) != 0
    {
        return;
    }
    let w = WIN_SIZE[0].load(Ordering::SeqCst);
    let h = WIN_SIZE[1].load(Ordering::SeqCst);
    let (x, y) = (
        WIN_POS[0].load(Ordering::SeqCst),
        WIN_POS[1].load(Ordering::SeqCst),
    );
    let (mx, my) = crate::float::cursor();
    let inside = mx >= x && mx < x + w && my >= y && my < y + h;
    let peek = crate::float::PEEK;
    let want = if inside {
        crate::float::expanded_pos(edge, x, y, w, h)
    } else {
        crate::float::tucked_pos(edge, x, y, w, h, peek)
    };
    if want != (x, y) {
        move_to(hwnd, want.0, want.1);
        if inside {
            crate::float::save_layout(want.0, want.1, edge);
        }
    }
}

unsafe fn finish_drag(hwnd: HWND) {
    let edge = crate::float::drag_end();
    TUCKED.store(edge.code(), Ordering::SeqCst);
    let w = WIN_SIZE[0].load(Ordering::SeqCst);
    let h = WIN_SIZE[1].load(Ordering::SeqCst);
    let (x, y) = (
        WIN_POS[0].load(Ordering::SeqCst),
        WIN_POS[1].load(Ordering::SeqCst),
    );
    if edge == crate::float::Edge::None {
        crate::float::save_layout(x, y, crate::float::Edge::None);
        return;
    }
    start_tuck_anim(hwnd, edge, x, y);
    let expanded = crate::float::expanded_pos(edge, x, y, w, h);
    crate::float::save_layout(expanded.0, expanded.1, edge);
}

unsafe fn start_tuck_anim(hwnd: HWND, edge: crate::float::Edge, x: i32, y: i32) {
    let w = WIN_SIZE[0].load(Ordering::SeqCst);
    let h = WIN_SIZE[1].load(Ordering::SeqCst);
    let peek = crate::float::PEEK;
    let full = crate::float::tucked_pos(edge, x, y, w, h, 0);
    let rest = crate::float::tucked_pos(edge, x, y, w, h, peek);
    ANIM_FROM[0].store(x, Ordering::SeqCst);
    ANIM_FROM[1].store(y, Ordering::SeqCst);
    ANIM_FULL[0].store(full.0, Ordering::SeqCst);
    ANIM_FULL[1].store(full.1, Ordering::SeqCst);
    ANIM_REST[0].store(rest.0, Ordering::SeqCst);
    ANIM_REST[1].store(rest.1, Ordering::SeqCst);
    ANIM_EDGE.store(edge.code(), Ordering::SeqCst);
    ANIM_T0.store(now_ms(), Ordering::SeqCst);
    ANIM_ON.store(true, Ordering::SeqCst);
    SetTimer(hwnd, ANIM_TIMER, 16, None);
}

fn arm_restore_tuck() {
    let due = now_ms().wrapping_add(RESTORE_HOLD_MS);
    RESTORE_TUCK_AT.store(if due == 0 { 1 } else { due }, Ordering::SeqCst);
}

fn restore_tuck_due() -> bool {
    let at = RESTORE_TUCK_AT.load(Ordering::SeqCst);
    at != 0 && now_ms().wrapping_sub(at) < 0x8000_0000
}

fn cancel_restore_tuck() {
    RESTORE_TUCK_AT.store(0, Ordering::SeqCst);
}

unsafe fn start_restore_tuck(hwnd: HWND) {
    cancel_restore_tuck();
    let edge = crate::float::Edge::from_code(TUCKED.load(Ordering::SeqCst));
    if edge == crate::float::Edge::None {
        return;
    }
    let (x, y) = (
        WIN_POS[0].load(Ordering::SeqCst),
        WIN_POS[1].load(Ordering::SeqCst),
    );
    start_tuck_anim(hwnd, edge, x, y);
    crate::float::remember(x, y);
}

fn lerp(a: i32, b: i32, k: f32) -> i32 {
    a + ((b - a) as f32 * k) as i32
}

fn ease_out_back(u: f32) -> f32 {
    const C1: f32 = 1.70158;
    const C3: f32 = C1 + 1.0;
    let p = u - 1.0;
    1.0 + C3 * p * p * p + C1 * p * p
}

unsafe fn anim_tick(hwnd: HWND) {
    if !ANIM_ON.load(Ordering::SeqCst) {
        KillTimer(hwnd, ANIM_TIMER);
        return;
    }
    let t = now_ms().wrapping_sub(ANIM_T0.load(Ordering::SeqCst)) as f32 / ANIM_MS as f32;
    let (fx, fy) = (ANIM_FROM[0].load(Ordering::SeqCst), ANIM_FROM[1].load(Ordering::SeqCst));
    let (ux, uy) = (ANIM_FULL[0].load(Ordering::SeqCst), ANIM_FULL[1].load(Ordering::SeqCst));
    let (rx, ry) = (ANIM_REST[0].load(Ordering::SeqCst), ANIM_REST[1].load(Ordering::SeqCst));

    let (x, y) = if t < ANIM_IN_PART {
        let k = (t / ANIM_IN_PART).clamp(0.0, 1.0);
        (lerp(fx, ux, k), lerp(fy, uy, k))
    } else if t < 1.0 {
        let u = ((t - ANIM_IN_PART) / (1.0 - ANIM_IN_PART)).clamp(0.0, 1.0);
        let e = ease_out_back(u);
        (lerp(ux, rx, e), lerp(uy, ry, e))
    } else {
        (rx, ry)
    };
    move_to(hwnd, x, y);
    if t >= 1.0 {
        ANIM_ON.store(false, Ordering::SeqCst);
        ANIM_EDGE.store(0, Ordering::SeqCst);
        KillTimer(hwnd, ANIM_TIMER);
    }
}

unsafe fn show_expanded(hwnd: HWND) {
    if ANIM_ON.swap(false, Ordering::SeqCst) {
        KillTimer(hwnd, ANIM_TIMER);
    }
    cancel_restore_tuck();
    let edge = crate::float::Edge::from_code(TUCKED.swap(0, Ordering::SeqCst));
    if edge == crate::float::Edge::None {
        return;
    }
    let w = WIN_SIZE[0].load(Ordering::SeqCst);
    let h = WIN_SIZE[1].load(Ordering::SeqCst);
    let (x, y) = (
        WIN_POS[0].load(Ordering::SeqCst),
        WIN_POS[1].load(Ordering::SeqCst),
    );
    let p = crate::float::expanded_pos(edge, x, y, w, h);
    move_to(hwnd, p.0, p.1);
    crate::float::save_layout(p.0, p.1, crate::float::Edge::None);
}

fn request_cancel() {
    if CANCELED.swap(true, Ordering::SeqCst) {
        return;
    }
    if OUTGOING.load(Ordering::SeqCst) {
        crate::outbound::request_cancel_send();
        crate::tray::log_line("[取消] 浮窗按钮：已请求取消发送");
    } else {
        crate::receive::request_cancel_recv();
        crate::tray::log_line("[取消] 浮窗按钮：已请求取消接收");
    }
    HOVER_CANCEL.store(false, Ordering::SeqCst);
    STATE.store(4, Ordering::SeqCst);
    DONE_AT.store(now_ms(), Ordering::SeqCst);
}

static FONTS: [AtomicIsize; 7] = [
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
    AtomicIsize::new(0),
];

unsafe fn font(idx: usize, height: i32, weight: i32) -> *mut std::ffi::c_void {
    let cached = FONTS[idx].load(Ordering::SeqCst);
    if cached != 0 {
        return cached as *mut std::ffi::c_void;
    }
    let face: Vec<u16> = "Microsoft YaHei UI\0".encode_utf16().collect();
    let f = CreateFontW(
        -height,
        0,
        0,
        0,
        weight,
        0,
        0,
        0,
        GB2312_CHARSET as u32,
        OUT_DEFAULT_PRECIS as u32,
        CLIP_DEFAULT_PRECIS as u32,
        ANTIALIASED_QUALITY as u32,
        (DEFAULT_PITCH | FF_DONTCARE) as u32,
        face.as_ptr(),
    );
    FONTS[idx].store(f as isize, Ordering::SeqCst);
    f
}

fn cos100(deg10: i32) -> i32 {
    let rad = (deg10 as f64) * std::f64::consts::PI / 1800.0;
    (rad.cos() * 100.0) as i32
}
fn sin100(deg10: i32) -> i32 {
    let rad = (deg10 as f64) * std::f64::consts::PI / 1800.0;
    (rad.sin() * 100.0) as i32
}

fn human(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / 1073741824.0)
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / 1048576.0)
    } else if bytes >= 1024 {
        format!("{:.0} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

unsafe fn draw_media_icon(hdc: HDC, cx: i32, cy: i32, px: &dyn Fn(i32) -> i32) {
    let s = px(30);
    let (x0, y0) = (cx - s / 2, cy - s / 2);

    let green = CreateSolidBrush(COL_MEDIA);
    let gpen = CreatePen(0, 1, COL_MEDIA);
    let ob = SelectObject(hdc, green as _);
    let op = SelectObject(hdc, gpen as _);
    RoundRect(hdc, x0, y0, x0 + s, y0 + s, px(7), px(7));
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(green as _);
    DeleteObject(gpen as _);

    let white = CreateSolidBrush(COL_BG);
    let wpen = CreatePen(0, 1, COL_BG);
    let ob = SelectObject(hdc, white as _);
    let op = SelectObject(hdc, wpen as _);
    let sr = px(3);
    let (scx, scy) = (x0 + px(9), y0 + px(9));
    Ellipse(hdc, scx - sr, scy - sr, scx + sr, scy + sr);

    let back = [
        POINT { x: x0 + px(13), y: y0 + px(17) },
        POINT { x: x0 + px(20), y: y0 + px(9) },
        POINT { x: x0 + px(27), y: y0 + px(17) },
    ];
    Polygon(hdc, back.as_ptr(), 3);
    let front = [
        POINT { x: x0 + px(2), y: y0 + px(25) },
        POINT { x: x0 + px(11), y: y0 + px(13) },
        POINT { x: x0 + px(20), y: y0 + px(25) },
    ];
    Polygon(hdc, front.as_ptr(), 3);

    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(white as _);
    DeleteObject(wpen as _);
}

unsafe fn draw_file_icon(hdc: HDC, cx: i32, cy: i32, px: &dyn Fn(i32) -> i32) {
    let fw = px(28);
    let fh = px(35);
    let (fx, fy) = (cx - fw / 2, cy - fh / 2);

    let body = CreateSolidBrush(COL_FILE_BODY);
    let pen = CreatePen(0, 1, COL_FILE_LINE);
    let ob = SelectObject(hdc, body as _);
    let op = SelectObject(hdc, pen as _);
    RoundRect(hdc, fx, fy, fx + fw, fy + fh, px(6), px(6));
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(body as _);
    DeleteObject(pen as _);

    let fold = [
        POINT { x: fx + fw - px(9), y: fy },
        POINT { x: fx + fw, y: fy },
        POINT { x: fx + fw, y: fy + px(9) },
    ];
    let fpen = CreatePen(0, 1, COL_FILE_LINE);
    let old = SelectObject(hdc, fpen as _);
    let fbrush = CreateSolidBrush(COL_TRACK);
    let obr = SelectObject(hdc, fbrush as _);
    Polygon(hdc, fold.as_ptr(), 3);
    SelectObject(hdc, obr);
    SelectObject(hdc, old);
    DeleteObject(fpen as _);
    DeleteObject(fbrush as _);

    let r = px(8);
    let wc = CreateSolidBrush(COL_BG);
    let cpen = CreatePen(0, 1, COL_FILE_LINE);
    let ob = SelectObject(hdc, wc as _);
    let op = SelectObject(hdc, cpen as _);
    Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(wc as _);
    DeleteObject(cpen as _);

    let f = font(3, px(12), FW_BOLD as i32);
    let old = SelectObject(hdc, f as _);
    SetTextColor(hdc, COL_ASK);
    SetBkMode(hdc, TRANSPARENT as i32);
    let mut rc = RECT { left: cx - r, top: cy - r, right: cx + r, bottom: cy + r };
    let q: Vec<u16> = "?".encode_utf16().collect();
    DrawTextW(hdc, q.as_ptr(), q.len() as i32, &mut rc, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    SelectObject(hdc, old);
}

unsafe fn draw_fail_badge(hdc: HDC, cx: i32, cy: i32, r: i32, px: &dyn Fn(i32) -> i32) {
    let brush = CreateSolidBrush(COL_ERROR);
    let pen = CreatePen(0, 1, COL_ERROR);
    let ob = SelectObject(hdc, brush as _);
    let op = SelectObject(hdc, pen as _);
    Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(brush as _);
    DeleteObject(pen as _);

    let white_pen = CreatePen(0, px(5), COL_BG);
    let old = SelectObject(hdc, white_pen as _);
    let bar = [
        POINT { x: cx, y: cy - px(12) },
        POINT { x: cx, y: cy + px(3) },
    ];
    Polyline(hdc, bar.as_ptr(), 2);
    SelectObject(hdc, old);
    DeleteObject(white_pen as _);

    let dot = CreateSolidBrush(COL_BG);
    let dpen = CreatePen(0, 1, COL_BG);
    let ob = SelectObject(hdc, dot as _);
    let op = SelectObject(hdc, dpen as _);
    let dr = px(2).max(2);
    let dy = cy + px(8);
    Ellipse(hdc, cx - dr, dy - dr, cx + dr, dy + dr);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(dot as _);
    DeleteObject(dpen as _);
}

unsafe fn draw_progress(_hwnd: HWND, state: u8) {
    let done = state == 2;
    let failed = state == 4;
    let hdc = CANVAS_DC.load(Ordering::SeqCst) as HDC;
    let (vw, vh) = (
        WIN_SIZE[0].load(Ordering::SeqCst),
        WIN_SIZE[1].load(Ordering::SeqCst),
    );
    if hdc.is_null() || vw <= 0 {
        return;
    }
    let rc = RECT { left: 0, top: 0, right: vw, bottom: vh };
    let dpi = DPI.load(Ordering::SeqCst).max(96) as i32;
    let px = |v: i32| v * dpi / 96;

    let bg = CreateSolidBrush(COL_BG);
    FillRect(hdc, &rc, bg);
    DeleteObject(bg as _);
    SetBkMode(hdc, TRANSPARENT as i32);

    let (cx, cy, r, ring) = (px(RING_CX), px(RING_CY), px(RING_R), px(RING_W));

    if done {
        let brush = CreateSolidBrush(COL_ACCENT);
        let pen = CreatePen(0, 1, COL_ACCENT);
        let ob = SelectObject(hdc, brush as _);
        let op = SelectObject(hdc, pen as _);
        Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
        SelectObject(hdc, ob);
        SelectObject(hdc, op);
        DeleteObject(brush as _);
        DeleteObject(pen as _);

        let white_pen = CreatePen(0, px(5), COL_BG);
        let old = SelectObject(hdc, white_pen as _);
        let pts = [
            POINT { x: cx - px(13), y: cy + px(1) },
            POINT { x: cx - px(3), y: cy + px(11) },
            POINT { x: cx + px(14), y: cy - px(10) },
        ];
        Polyline(hdc, pts.as_ptr(), 3);
        SelectObject(hdc, old);
        DeleteObject(white_pen as _);
    } else if failed {
        draw_fail_badge(hdc, cx, cy, r, &px);
    } else {
        let pct = PCT.load(Ordering::SeqCst).min(10000);
        if pct > 0 {
            let lb = LOGBRUSH { lbStyle: 0, lbColor: COL_ACCENT, lbHatch: 0 };
            let pen = ExtCreatePen(PS_GEOMETRIC as u32, ring as u32, &lb, 0, std::ptr::null());
            let old = SelectObject(hdc, pen as _);
            let null_brush = GetStockObject(NULL_BRUSH);
            let ob = SelectObject(hdc, null_brush);

            let sweep_deg = pct as f32 * 0.036;
            let aa = crate::gp::draw_arc_aa(
                hdc,
                cx - r,
                cy - r,
                r * 2,
                r * 2,
                -90.0,
                sweep_deg,
                ring,
                crate::gp::colorref_to_argb(COL_ACCENT),
            );
            if !aa {
                let start = 900i32;
                let sweep = (pct as i32 * 3600) / 10000;
                let draw_sweep = if sweep < 24 { 24 } else { sweep };
                const STEPS: i32 = 96;
                let mut pts: Vec<POINT> = Vec::with_capacity(STEPS as usize + 1);
                for i in 0..=STEPS {
                    let ang = start - draw_sweep * i / STEPS;
                    pts.push(POINT {
                        x: cx + (r * cos100(ang)) / 100,
                        y: cy - (r * sin100(ang)) / 100,
                    });
                }
                Polyline(hdc, pts.as_ptr(), pts.len() as i32);
            }

            SelectObject(hdc, ob);
            SelectObject(hdc, old);
            DeleteObject(pen as _);
        }

        if MEDIA.load(Ordering::SeqCst) {
            draw_media_icon(hdc, cx, cy, &px);
        } else {
            draw_file_icon(hdc, cx, cy, &px);
        }
    }

    let name = NAME.lock().map(|s| s.clone()).unwrap_or_default();
    let shown: String = if name.chars().count() > 16 {
        let mut t: String = name.chars().take(15).collect();
        t.push('…');
        t
    } else {
        name
    };

    let left = px(102);
    let right = px(CARD_W) - px(14);

    let f0 = font(0, px(15), FW_BOLD as i32);
    SelectObject(hdc, f0 as _);
    SetTextColor(hdc, COL_MAIN);
    let mut r0 = RECT { left, top: px(16), right, bottom: px(38) };
    let u0: Vec<u16> = shown.encode_utf16().collect();
    DrawTextW(hdc, u0.as_ptr(), u0.len() as i32, &mut r0, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    let f1 = font(1, px(12), FW_NORMAL as i32);
    SelectObject(hdc, f1 as _);
    SetTextColor(hdc, if failed { COL_ERROR } else { COL_SUB });
    let sub = if done {
        format!("已完成 · {}", human(TOTAL.load(Ordering::SeqCst)))
    } else if failed {
        "传输失败".to_string()
    } else {
        let waiting = STATE.load(Ordering::SeqCst) == 3;
        let sp = SPEED_KB.load(Ordering::SeqCst);
        if waiting {
            "等待对方接收…".to_string()
        } else if sp > 0 {
            format!(
                "{} / {} · {:.1} MB/s",
                human(RECEIVED.load(Ordering::SeqCst)),
                human(TOTAL.load(Ordering::SeqCst)),
                sp as f64 / 1024.0
            )
        } else {
            format!(
                "{} / {}",
                human(RECEIVED.load(Ordering::SeqCst)),
                human(TOTAL.load(Ordering::SeqCst))
            )
        }
    };
    let mut r1 = RECT { left, top: px(40), right, bottom: px(60) };
    let u1: Vec<u16> = sub.encode_utf16().collect();
    DrawTextW(hdc, u1.as_ptr(), u1.len() as i32, &mut r1, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    let f2 = font(2, px(22), FW_BOLD as i32);
    SelectObject(hdc, f2 as _);
    SetTextColor(hdc, COL_ACCENT);
    let waiting = !done && !failed && state == 3;
    let pct_text = if done {
        "100%".to_string()
    } else if waiting || failed {
        String::new()
    } else {
        format!("{:.0}%", PCT.load(Ordering::SeqCst) as f64 / 100.0)
    };
    if !pct_text.is_empty() {
        let mut r2 = RECT { left, top: px(62), right, bottom: px(96) };
        let u2: Vec<u16> = pct_text.encode_utf16().collect();
        DrawTextW(hdc, u2.as_ptr(), u2.len() as i32, &mut r2, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    }

    if !done && !failed && state != 0 {
        let (bx1, by1, bx2, by2) = cancel_rect();
        let hover = HOVER_CANCEL.load(Ordering::SeqCst);
        let bg_col = if hover { COL_BTN_HOVER_BG } else { COL_BTN_BG };
        let brush = CreateSolidBrush(bg_col);
        let pen = CreatePen(0, 1, bg_col);
        let ob = SelectObject(hdc, brush as _);
        let op = SelectObject(hdc, pen as _);
        RoundRect(hdc, bx1, by1, bx2, by2, px(12), px(12));
        SelectObject(hdc, ob);
        SelectObject(hdc, op);
        DeleteObject(brush as _);
        DeleteObject(pen as _);

        if hover {
            let ring = CreatePen(0, px(1).max(1), COL_BG);
            let null = GetStockObject(NULL_BRUSH);
            let op = SelectObject(hdc, ring as _);
            let ob = SelectObject(hdc, null);
            RoundRect(
                hdc,
                bx1 + px(2),
                by1 + px(2),
                bx2 - px(2),
                by2 - px(2),
                px(10),
                px(10),
            );
            SelectObject(hdc, ob);
            SelectObject(hdc, op);
            DeleteObject(ring as _);
        }

        let fb = font(1, px(12), FW_BOLD as i32);
        let old = SelectObject(hdc, fb as _);
        SetTextColor(hdc, COL_BTN_TEXT);
        let mut rb = RECT { left: bx1, top: by1, right: bx2, bottom: by2 };
        let label: Vec<u16> = "取消".encode_utf16().collect();
        DrawTextW(
            hdc,
            label.as_ptr(),
            label.len() as i32,
            &mut rb,
            DT_CENTER | DT_SINGLELINE | DT_VCENTER,
        );
        SelectObject(hdc, old);
    }
}

fn lo_word(v: LPARAM) -> i32 {
    (v & 0xFFFF) as u16 as i16 as i32
}

fn short_name(name: &str) -> String {
    if name.chars().count() > 12 {
        let mut t: String = name.chars().take(11).collect();
        while t.ends_with(' ') {
            t.pop();
        }
        t.push('…');
        t
    } else {
        name.to_string()
    }
}

fn current_target() -> Option<crate::peers::PeerInfo> {
    let cached = TARGET_VIEW
        .lock()
        .ok()
        .and_then(|g| g.as_ref().and_then(|v| v.selected.clone()));
    cached.or_else(|| crate::peers::selected())
}

fn refresh_target_view() -> bool {
    let view = crate::peers::view(std::time::Duration::from_secs(3600));
    let changed = LAST_TARGET_REV.swap(view.revision, Ordering::SeqCst) != view.revision;
    if let Ok(mut slot) = TARGET_VIEW.lock() {
        *slot = Some(view);
    }
    changed
}

fn close_rect(w: i32) -> (i32, i32, i32, i32) {
    let dpi = DPI.load(Ordering::SeqCst).max(96) as i32;
    let size = 22 * dpi / 96;
    let pad = 7 * dpi / 96;
    (w - size - pad, pad, w - pad, pad + size)
}

fn hit_close(x: i32, y: i32) -> bool {
    let w = WIN_SIZE[0].load(Ordering::SeqCst);
    if w <= 0 {
        return false;
    }
    let (x1, y1, x2, y2) = close_rect(w);
    x >= x1 && x < x2 && y >= y1 && y < y2
}

unsafe fn start_drag(hwnd: HWND) {
    if ANIM_ON.swap(false, Ordering::SeqCst) {
        KillTimer(hwnd, ANIM_TIMER);
    }
    cancel_restore_tuck();
    let size = (
        WIN_SIZE[0].load(Ordering::SeqCst),
        WIN_SIZE[1].load(Ordering::SeqCst),
    );
    let pos = (
        WIN_POS[0].load(Ordering::SeqCst),
        WIN_POS[1].load(Ordering::SeqCst),
    );
    crate::float::drag_start(crate::float::cursor(), pos, size);
    SetCapture(hwnd);
}

unsafe fn draw_drop() {
    let hdc = CANVAS_DC.load(Ordering::SeqCst) as HDC;
    let (vw, vh) = (
        WIN_SIZE[0].load(Ordering::SeqCst),
        WIN_SIZE[1].load(Ordering::SeqCst),
    );
    if hdc.is_null() || vw <= 0 {
        return;
    }
    let dpi = DPI.load(Ordering::SeqCst).max(96) as i32;
    let px = |v: i32| v * dpi / 96;

    let rc = RECT { left: 0, top: 0, right: vw, bottom: vh };
    let bg = CreateSolidBrush(COL_BG);
    FillRect(hdc, &rc, bg);
    DeleteObject(bg as _);
    SetBkMode(hdc, TRANSPARENT as i32);

    let pen = CreatePen(0, px(1).max(1), COL_BORDER);
    let null = GetStockObject(NULL_BRUSH);
    let op = SelectObject(hdc, pen as _);
    let ob = SelectObject(hdc, null);
    RoundRect(hdc, px(1), px(1), vw - px(1), vh - px(1), px(20), px(20));
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(pen as _);

    let cxx = px(54);
    let cyy = px(54);
    let r = px(32);
    let circle = CreateSolidBrush(COL_ICON_BG);
    let cpen = CreatePen(0, 1, COL_ICON_BG);
    let ob = SelectObject(hdc, circle as _);
    let op = SelectObject(hdc, cpen as _);
    Ellipse(hdc, cxx - r, cyy - r, cxx + r, cyy + r);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(circle as _);
    DeleteObject(cpen as _);

    let apen = CreatePen(0, px(3).max(1), COL_ACCENT);
    let old = SelectObject(hdc, apen as _);
    let shaft = [
        POINT { x: cxx, y: cyy - px(13) },
        POINT { x: cxx, y: cyy + px(4) },
    ];
    Polyline(hdc, shaft.as_ptr(), 2);
    let head = [
        POINT { x: cxx - px(7), y: cyy - px(3) },
        POINT { x: cxx, y: cyy + px(4) },
        POINT { x: cxx + px(7), y: cyy - px(3) },
    ];
    Polyline(hdc, head.as_ptr(), 3);
    let tray = [
        POINT { x: cxx - px(11), y: cyy + px(11) },
        POINT { x: cxx + px(11), y: cyy + px(11) },
    ];
    Polyline(hdc, tray.as_ptr(), 2);
    SelectObject(hdc, old);
    DeleteObject(apen as _);

    let left = px(102);
    let right = vw - px(16);

    let f_title = font(4, px(16), FW_BOLD as i32);
    let old = SelectObject(hdc, f_title as _);
    SetTextColor(hdc, COL_MAIN);
    let mut r1 = RECT { left, top: px(30), right: vw - px(38), bottom: px(58) };
    let t1: Vec<u16> = "把文件拖进这里".encode_utf16().collect();
    DrawTextW(hdc, t1.as_ptr(), t1.len() as i32, &mut r1, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    SelectObject(hdc, old);

    let sub = match current_target() {
        Some(p) if crate::peers::is_online(&p) => format!("发送给 {}", short_name(&p.name)),
        Some(p) => format!("发送给 {}（离线）", short_name(&p.name)),
        None => "未选发送目标 · 托盘里挑一台".to_string(),
    };
    let f_sub = font(5, px(12), FW_NORMAL as i32);
    let old = SelectObject(hdc, f_sub as _);
    SetTextColor(hdc, COL_SUB);
    let mut r2 = RECT { left, top: px(58), right, bottom: px(82) };
    let t2: Vec<u16> = sub.encode_utf16().collect();
    DrawTextW(hdc, t2.as_ptr(), t2.len() as i32, &mut r2, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    SelectObject(hdc, old);

    let f_close = font(6, px(12), FW_NORMAL as i32);
    let old = SelectObject(hdc, f_close as _);
    SetTextColor(
        hdc,
        if HOVER_CANCEL.load(Ordering::SeqCst) { COL_MAIN } else { COL_HINT },
    );
    let (x1, y1, x2, y2) = close_rect(vw);
    let mut r4 = RECT { left: x1, top: y1, right: x2, bottom: y2 };
    let t4: Vec<u16> = "✕".encode_utf16().collect();
    DrawTextW(hdc, t4.as_ptr(), t4.len() as i32, &mut r4, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    SelectObject(hdc, old);
}

unsafe fn handle_drop(hdrop: *mut std::ffi::c_void) {
    let count = DragQueryFileW(hdrop, u32::MAX, std::ptr::null_mut(), 0);
    let mut paths: Vec<std::path::PathBuf> = Vec::with_capacity(count as usize);
    let mut buf = vec![0u16; 32768];
    for i in 0..count {
        let written = DragQueryFileW(hdrop, i, buf.as_mut_ptr(), buf.len() as u32);
        if written > 0 {
            paths.push(std::path::PathBuf::from(String::from_utf16_lossy(
                &buf[..written as usize],
            )));
        }
    }
    DragFinish(hdrop);
    if paths.is_empty() {
        return;
    }

    let Some(peer) = current_target() else {
        crate::tray::alert(
            "还没选发送目标",
            "右键托盘图标 →「发送目标」里挑一台手机。\n\n\
             列表里没有设备的话：先在手机上打开「华为分享」并保持亮屏，\
             等托盘菜单里出现设备名再选。",
        );
        return;
    };

    if let Err(e) = crate::dispatch::send_to(peer, paths, crate::tray::device_name()) {
        crate::tray::alert("发送失败", &e);
    }
}

pub fn toggle_drop() {
    if STATE.load(Ordering::SeqCst) != 0 {
        PINNED.store(false, Ordering::SeqCst);
        STATE.store(0, Ordering::SeqCst);
        return;
    }
    PINNED.store(true, Ordering::SeqCst);
    MODE.store(1, Ordering::SeqCst);
    HOVER_CANCEL.store(false, Ordering::SeqCst);
    STATE.store(1, Ordering::SeqCst);
    ensure_thread();
}

pub fn hide_drop() {
    STATE.store(0, Ordering::SeqCst);
}

pub fn show_drop() {
    if STATE.load(Ordering::SeqCst) == 0 {
        toggle_drop();
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let _ = wparam;
    match msg {
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            BeginPaint(hwnd, &mut ps);
            EndPaint(hwnd, &ps);
            0
        }
        WM_TIMER => {
            if wparam == ANIM_TIMER {
                anim_tick(hwnd);
                return 0;
            }
            let target_changed = refresh_target_view();
            let mut state = STATE.load(Ordering::SeqCst);

            if state == 2 || state == 4 {
                let t = DONE_AT.load(Ordering::SeqCst);
                if t != 0 && now_ms().saturating_sub(t) > 3000 {
                    DONE_AT.store(0, Ordering::SeqCst);
                    PENDING_SWITCH.store(1, Ordering::SeqCst);
                    FADE_TO.store(0, Ordering::SeqCst);
                }
            }

            if state != 0 && !VISIBLE.load(Ordering::SeqCst) {
                if STARTUP_RESTORE.swap(false, Ordering::SeqCst) {
                    arm_restore_tuck();
                } else {
                    show_expanded(hwnd);
                }
                ShowWindow(hwnd, SW_SHOWNOACTIVATE);
                VISIBLE.store(true, Ordering::SeqCst);
                FADE.store(0, Ordering::SeqCst);
                FADE_TO.store(255, Ordering::SeqCst);
            }

            if restore_tuck_due() {
                cancel_restore_tuck();
                if !crate::float::is_dragging()
                    && MODE.load(Ordering::SeqCst) == 1
                    && VISIBLE.load(Ordering::SeqCst)
                    && STATE.load(Ordering::SeqCst) != 0
                {
                    start_restore_tuck(hwnd);
                }
            }

            let cur = FADE.load(Ordering::SeqCst);
            let to = FADE_TO.load(Ordering::SeqCst);
            let next = if cur < to {
                (cur + FADE_STEP).min(to)
            } else if cur > to {
                cur.saturating_sub(FADE_STEP).max(to)
            } else {
                cur
            };
            if next != cur {
                FADE.store(next, Ordering::SeqCst);
            }

            if next == 0 {
                if PENDING_SWITCH.swap(0, Ordering::SeqCst) == 1 {
                    MODE.store(1, Ordering::SeqCst);
                    PINNED.store(true, Ordering::SeqCst);
                    state = 1;
                    STATE.store(1, Ordering::SeqCst);
                    FADE_TO.store(255, Ordering::SeqCst);
                } else if state == 0 && VISIBLE.swap(false, Ordering::SeqCst) {
                    ShowWindow(hwnd, SW_HIDE);
                }
            }

            let pct = PCT.load(Ordering::SeqCst);
            let sp = SPEED_KB.load(Ordering::SeqCst);
            let mode = MODE.load(Ordering::SeqCst);
            let prev_state = LAST_STATE.swap(state, Ordering::SeqCst);
            let prev_pct = LAST_PCT.swap(pct, Ordering::SeqCst);
            let prev_sp = LAST_SPEED.swap(sp, Ordering::SeqCst);
            let prev_mode = LAST_MODE.swap(mode, Ordering::SeqCst);
            let hover = cursor_hover_hit();
            let prev_hover = HOVER_CANCEL.swap(hover, Ordering::SeqCst);
            let prev_alpha = LAST_ALPHA.swap(next, Ordering::SeqCst);

            if state == 0 {
                if VISIBLE.load(Ordering::SeqCst) && FADE_TO.load(Ordering::SeqCst) != 0 {
                    FADE_TO.store(0, Ordering::SeqCst);
                }
            } else if prev_state != state
                || prev_pct != pct
                || prev_sp != sp
                || prev_hover != hover
                || prev_mode != mode
                || prev_alpha != next
                || target_changed
            {
                commit(hwnd);
            }
            tuck_tick(hwnd);
            0
        }
        WM_MOUSEMOVE => {
            if crate::float::is_dragging() {
                if let Some((nx, ny, _)) = crate::float::drag_update(crate::float::cursor()) {
                    move_to(hwnd, nx, ny);
                }
                return 0;
            }
            let (x, y) = (lo_word(lparam), lo_word(lparam >> 16));
            let inside = if MODE.load(Ordering::SeqCst) == 1 {
                hit_close(x, y)
            } else {
                hit_cancel(x, y)
            };
            if HOVER_CANCEL.swap(inside, Ordering::SeqCst) != inside {
                commit(hwnd);
            }
            0
        }
        WM_LBUTTONDOWN => {
            let (x, y) = (lo_word(lparam), lo_word(lparam >> 16));
            if MODE.load(Ordering::SeqCst) == 1 {
                if hit_close(x, y) {
                    PINNED.store(false, Ordering::SeqCst);
                    STATE.store(0, Ordering::SeqCst);
                } else {
                    start_drag(hwnd);
                }
            } else if hit_cancel(x, y) {
                request_cancel();
            } else if STATE.load(Ordering::SeqCst) != 0 {
                start_drag(hwnd);
            }
            0
        }
        WM_RBUTTONUP => {
            if MODE.load(Ordering::SeqCst) == 1 && STATE.load(Ordering::SeqCst) != 0 {
                crate::tray::send_clipboard_now(hwnd);
            }
            0
        }
        WM_LBUTTONDBLCLK => {
            if MODE.load(Ordering::SeqCst) == 1 && STATE.load(Ordering::SeqCst) != 0 {
                crate::tray::open_or_pick_dest(hwnd);
            }
            0
        }
        WM_DROPFILES => {
            if MODE.load(Ordering::SeqCst) == 1 {
                handle_drop(wparam as *mut std::ffi::c_void);
            }
            0
        }
        WM_LBUTTONUP => {
            if crate::float::is_dragging() {
                finish_drag(hwnd);
                ReleaseCapture();
            }
            0
        }
        WM_CAPTURECHANGED => {
            if crate::float::is_dragging() {
                finish_drag(hwnd);
            }
            0
        }
        WM_ERASEBKGND => 1,
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}
