use std::ffi::OsStr;
use std::io::Read;
use std::net::TcpStream;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, CreateSolidBrush, DeleteObject, DrawTextW, FillRect, SelectObject, SetBkMode,
    SetTextColor, UpdateWindow,
    CLIP_DEFAULT_PRECIS, DEFAULT_PITCH, DT_CENTER, DT_SINGLELINE, DT_VCENTER,
    ANTIALIASED_QUALITY, FF_DONTCARE, FW_BOLD, FW_NORMAL, GB2312_CHARSET, OUT_DEFAULT_PRECIS,
    TRANSPARENT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::GetDpiForSystem;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    FlashWindow, GetClientRect, GetMessageW, GetSystemMetrics, LoadCursorW, PostMessageW,
    PostQuitMessage, RegisterClassW, SetForegroundWindow, SetWindowPos, ShowWindow,
    TranslateMessage, HWND_TOPMOST, MSG, SWP_NOMOVE, SWP_NOSIZE, SWP_SHOWWINDOW, WNDCLASSW,
    WS_EX_LAYERED, WS_EX_TOPMOST, WS_POPUP,
};

const CAPTION: &str = "华为分享 · 接收确认";

const TIMEOUT_SECS: u64 = 30;

const WM_DESTROY: u32 = 0x0002;
const WM_CLOSE: u32 = 0x0010;
const WM_GETDLGCODE: u32 = 0x0087;
const WM_KEYDOWN: u32 = 0x0100;

const WM_APP_CLOSE: u32 = 0x8001;
const DLGC_WANTALLKEYS: isize = 0x0004;
const VK_RETURN: usize = 0x0D;
const VK_ESCAPE: usize = 0x1B;
const IDC_ARROW: usize = 32512;
const SM_CXSCREEN: i32 = 0;
const SM_CYSCREEN: i32 = 1;
const SW_SHOW: i32 = 5;

const WM_PAINT: u32 = 0x000F;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_ERASEBKGND: u32 = 0x0014;

const CARD_W: i32 = 400;
const CARD_H: i32 = 176;
const BTN_H: i32 = 46;
const RADIUS: i32 = 22;

const COL_BG: u32 = 0x00FF_FFFF;
const COL_MAIN: u32 = 0x001A_1A1A;
const COL_SUB: u32 = 0x0093_8E8E;
const COL_LINE: u32 = 0x00EA_E5E5;
const COL_HOVER: u32 = 0x00F7_F2F2;
const COL_ACCENT: u32 = 0x00FF_7A00;

static CARD_DPI: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(96);

static CANVAS: std::sync::OnceLock<Mutex<Option<crate::layered::Canvas>>> =
    std::sync::OnceLock::new();
static WIN_POS: [std::sync::atomic::AtomicI32; 2] = [
    std::sync::atomic::AtomicI32::new(0),
    std::sync::atomic::AtomicI32::new(0),
];

static HOVER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

const CLASS_NAME: &str = "HWShareConfirmWnd";

static RESULT: AtomicI32 = AtomicI32::new(-1);

static REASON: AtomicI32 = AtomicI32::new(0);

fn reason_text(code: i32) -> &'static str {
    match code {
        1 => "用户点「是」",
        2 => "用户点「否」",
        3 => "超时（30 秒无人操作）",
        4 => "对端断开",
        5 => "按了 Esc",
        6 => "关闭了窗口",
        _ => "未知",
    }
}

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(std::iter::once(0)).collect()
}

#[allow(dead_code)]
fn peer_gone(stream: &TcpStream) -> bool {
    let _ = stream.set_nonblocking(true);
    let mut probe = [0u8; 1];
    let gone = match stream.peek(&mut probe) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(_) => true,
    };
    let _ = stream.set_nonblocking(false);
    gone
}

const DRAIN_MAX: usize = 64 * 1024;

#[derive(PartialEq, Eq, Clone, Copy)]
enum Peer {
    Alive,
    Eof,
    Reset,
}

fn probe(stream: &TcpStream, sink: &mut Vec<u8>) -> Peer {
    let _ = stream.set_nonblocking(true);

    let mut reader = stream;
    let mut buf = [0u8; 8192];
    let mut state = Peer::Alive;
    loop {
        if sink.len() >= DRAIN_MAX {
            break;
        }
        match stream.peek(&mut buf) {
            Ok(0) => {
                state = Peer::Eof;
                break;
            }
            Ok(n) => {
                let n = n.min(buf.len());
                match reader.read(&mut buf[..n]) {
                    Ok(0) => {
                        state = Peer::Eof;
                        break;
                    }
                    Ok(k) => sink.extend_from_slice(&buf[..k]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        state = Peer::Reset;
                        break;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                state = Peer::Reset;
                break;
            }
        }
    }
    let _ = stream.set_nonblocking(false);
    state
}

fn eof_closes() -> bool {
    !std::env::var("HWSHARE_CONFIRM_EOF_CLOSE")
        .map(|v| v.trim() == "0")
        .unwrap_or(false)
}

pub struct Answer {
    pub accepted: bool,
    pub drained: Vec<u8>,
}

impl Answer {
    fn plain(accepted: bool) -> Self {
        Self { accepted, drained: Vec::new() }
    }
}

static LINE_SUB: Mutex<String> = Mutex::new(String::new());
static LINE_MAIN: Mutex<String> = Mutex::new(String::new());

static FONT_SUB: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);
static FONT_MAIN: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);
static FONT_BTN: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

unsafe fn button_at(hwnd: HWND, x: i32, y: i32) -> usize {
    let mut rc: RECT = std::mem::zeroed();
    if GetClientRect(hwnd, &mut rc) == 0 {
        return 0;
    }
    let (w, h) = (rc.right, rc.bottom);
    let dpi = CARD_DPI.load(Ordering::SeqCst).max(96);
    let btn_h = BTN_H * dpi / 96;
    if y < h - btn_h {
        return 0;
    }
    if x < w / 2 { 1 } else { 2 }
}

unsafe fn paint_card(hwnd: HWND) {
    let Some(slot) = CANVAS.get() else { return };
    let Ok(guard) = slot.lock() else { return };
    let Some(canvas) = guard.as_ref() else { return };
    let hdc = canvas.mem;
    let (w, h) = (canvas.w, canvas.h);
    let rc = RECT { left: 0, top: 0, right: w, bottom: h };

    let dpi = CARD_DPI.load(Ordering::SeqCst).max(96);
    let px = |v: i32| v * dpi / 96;

    let btn_h = px(BTN_H);
    let btn_top = h - btn_h;

    let bg = CreateSolidBrush(COL_BG);
    FillRect(hdc, &rc, bg);
    DeleteObject(bg as _);
    SetBkMode(hdc, TRANSPARENT as i32);

    let sub = LINE_SUB.lock().map(|s| s.clone()).unwrap_or_default();
    let main = LINE_MAIN.lock().map(|s| s.clone()).unwrap_or_default();
    let text_top = px(30);
    let line_gap = px(8);

    SetTextColor(hdc, COL_SUB);
    let f_sub = FONT_SUB.load(Ordering::SeqCst);
    if f_sub != 0 {
        SelectObject(hdc, f_sub as _);
        let mut r = RECT { left: px(24), top: text_top, right: w - px(24), bottom: text_top + px(24) };
        let u16s: Vec<u16> = sub.encode_utf16().collect();
        DrawTextW(hdc, u16s.as_ptr(), u16s.len() as i32, &mut r, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    }

    SetTextColor(hdc, COL_MAIN);
    let f_main = FONT_MAIN.load(Ordering::SeqCst);
    if f_main != 0 {
        SelectObject(hdc, f_main as _);
        let top = text_top + px(24) + line_gap;
        let mut r = RECT { left: px(24), top, right: w - px(24), bottom: btn_top - px(8) };
        let u16s: Vec<u16> = main.encode_utf16().collect();
        DrawTextW(hdc, u16s.as_ptr(), u16s.len() as i32, &mut r, DT_CENTER | DT_VCENTER | 0x0010);
    }

    let line = CreateSolidBrush(COL_LINE);
    let hl = RECT { left: 0, top: btn_top, right: w, bottom: btn_top + 1 };
    FillRect(hdc, &hl, line);
    let vl = RECT { left: w / 2, top: btn_top, right: w / 2 + 1, bottom: h };
    FillRect(hdc, &vl, line);
    DeleteObject(line as _);

    let hover = HOVER.load(Ordering::SeqCst);
    for (id, label) in [(1usize, "拒绝"), (2usize, "接收")] {
        let (bx, bw) = if id == 1 { (0, w / 2) } else { (w / 2 + 1, w / 2) };
        if hover == id {
            let hb = CreateSolidBrush(COL_HOVER);
            let hr = RECT { left: bx, top: btn_top + 1, right: bx + bw, bottom: h };
            FillRect(hdc, &hr, hb);
            DeleteObject(hb as _);
        }
        let f_btn = FONT_BTN.load(Ordering::SeqCst);
        if f_btn != 0 {
            SelectObject(hdc, f_btn as _);
            SetTextColor(hdc, COL_ACCENT);
            let mut r = RECT { left: bx, top: btn_top + 1, right: bx + bw, bottom: h };
            let u16s: Vec<u16> = label.encode_utf16().collect();
            DrawTextW(hdc, u16s.as_ptr(), u16s.len() as i32, &mut r, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        }
    }

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
            paint_card(hwnd);
            0
        }

        WM_MOUSEMOVE => {
            let x = (lparam & 0xFFFF) as i32;
            let y = ((lparam >> 16) & 0xFFFF) as i32;
            let want = button_at(hwnd, x, y);
            if HOVER.swap(want, Ordering::SeqCst) != want {
                paint_card(hwnd);
            }
            0
        }
        WM_LBUTTONDOWN => {
            let x = (lparam & 0xFFFF) as i32;
            let y = ((lparam >> 16) & 0xFFFF) as i32;
            match button_at(hwnd, x, y) {
                1 => {
                    RESULT.store(0, Ordering::SeqCst);
                    REASON.store(2, Ordering::SeqCst);
                    DestroyWindow(hwnd);
                }
                2 => {
                    RESULT.store(1, Ordering::SeqCst);
                    REASON.store(1, Ordering::SeqCst);
                    DestroyWindow(hwnd);
                }
                _ => {}
            }
            0
        }
        WM_ERASEBKGND => 1,

        WM_CLOSE => {
            RESULT.store(0, Ordering::SeqCst);
            REASON.store(6, Ordering::SeqCst);
            DestroyWindow(hwnd);
            0
        }

        WM_APP_CLOSE => {
            RESULT.store(0, Ordering::SeqCst);
            DestroyWindow(hwnd);
            0
        }
        WM_KEYDOWN => {
            if wparam == VK_RETURN {
                RESULT.store(1, Ordering::SeqCst);
                REASON.store(1, Ordering::SeqCst);
                DestroyWindow(hwnd);
            } else if wparam == VK_ESCAPE {
                RESULT.store(0, Ordering::SeqCst);
                REASON.store(5, Ordering::SeqCst);
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

pub fn ask(peer: &str, count: u32, bytes: u64, watch: Option<TcpStream>) -> Answer {
    #[cfg(windows)]
    crate::tray::enable_dpi_awareness();
    if std::env::var("HWSHARE_CONFIRM")
        .map(|v| v.trim() == "0")
        .unwrap_or(false)
    {
        crate::trace::confirm_show(peer, count, bytes);
        crate::trace::confirm_answer(peer, true, "HWSHARE_CONFIRM=0 自动接收");
        return Answer::plain(true);
    }
    crate::trace::confirm_show(peer, count, bytes);

    let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    let class = wide(CLASS_NAME);
    let caption = wide(CAPTION);

    unsafe {
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.style = 0x0001 | 0x0002;
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = instance;
        wc.hCursor = LoadCursorW(std::ptr::null_mut(), IDC_ARROW as *const u16) as _;

        wc.hbrBackground = std::ptr::null_mut();
        wc.lpszClassName = class.as_ptr();
        RegisterClassW(&wc);

        let dpi = {
            let d = GetDpiForSystem();
            if d == 0 { 96 } else { d as i32 }
        };
        CARD_DPI.store(dpi, Ordering::SeqCst);

        let cw = CARD_W * dpi / 96;
        let ch = CARD_H * dpi / 96;

        let style = WS_POPUP;
        let exstyle = WS_EX_TOPMOST | WS_EX_LAYERED;
        let x = (GetSystemMetrics(SM_CXSCREEN) - cw) / 2;
        let y = (GetSystemMetrics(SM_CYSCREEN) - ch) / 2;

        RESULT.store(-1, Ordering::SeqCst);
        let hwnd = CreateWindowExW(
            exstyle,
            class.as_ptr(),
            caption.as_ptr(),
            style,
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
            crate::trace::confirm_answer(peer, true, "窗口创建失败，按接收处理");
            return Answer::plain(true);
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
        let f_sub = mk(14, FW_NORMAL as i32);
        let f_main = mk(16, FW_NORMAL as i32);
        let f_btn = mk(16, FW_BOLD as i32);
        FONT_SUB.store(f_sub as isize, Ordering::SeqCst);
        FONT_MAIN.store(f_main as isize, Ordering::SeqCst);
        FONT_BTN.store(f_btn as isize, Ordering::SeqCst);

        let mb = bytes as f64 / 1048576.0;
        let size_line = if mb < 1.0 {
            format!("{count} 个文件，共 {:.0} KB", bytes as f64 / 1024.0)
        } else {
            format!("{count} 个文件，共 {mb:.1} MB")
        };
        if let Ok(mut slot) = LINE_SUB.lock() {
            *slot = format!("来自 {peer}");
        }
        if let Ok(mut slot) = LINE_MAIN.lock() {
            *slot = format!("{size_line}，是否接收？");
        }

        paint_card(hwnd);
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);

        SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
        );
        BringWindowToTop(hwnd);
        SetForegroundWindow(hwnd);
        FlashWindow(hwnd, 1);
        SetFocus(hwnd);

        let drained: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&drained);
        let close_on_eof = eof_closes();
        let hwnd_bits = hwnd as usize;
        let deadline = Instant::now() + Duration::from_secs(TIMEOUT_SECS);
        let guard = std::thread::spawn(move || {
            let hwnd = hwnd_bits as HWND;
            loop {
                std::thread::sleep(Duration::from_millis(200));
                if RESULT.load(Ordering::SeqCst) != -1 {
                    return;
                }
                let peer = {
                    let mut slot = sink.lock().unwrap_or_else(|e| e.into_inner());
                    match watch.as_ref() {
                        Some(stream) => probe(stream, &mut slot),
                        None => Peer::Alive,
                    }
                };

                let close = match peer {
                    Peer::Reset => true,
                    Peer::Eof => close_on_eof,
                    Peer::Alive => false,
                };
                if close || Instant::now() >= deadline {
                    REASON.store(if close { 4 } else { 3 }, Ordering::SeqCst);
                    PostMessageW(hwnd, WM_APP_CLOSE, 0, 0);
                    return;
                }
            }
        });

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        let _ = guard.join();

        for f in [f_sub, f_main, f_btn] {
            if !f.is_null() {
                DeleteObject(f as _);
            }
        }
        let yes = RESULT.load(Ordering::SeqCst) == 1;

        let drained: Vec<u8> = {
            let mut slot = drained.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *slot)
        };
        eprintln!(
            "[确认] {} → {}{}",
            reason_text(REASON.load(Ordering::SeqCst)),
            if yes { "接收" } else { "拒绝" },
            if drained.is_empty() {
                String::new()
            } else {
                format!("（等待期间收到 {} 字节，已还回通道）", drained.len())
            }
        );
        if !drained.is_empty() {
            crate::trace::note(
                "control",
                &format!(
                    "确认等待期间控制通道到达 {} 字节（将来解密记录，已原样还回）",
                    drained.len()
                ),
            );
        }
        crate::trace::confirm_answer(peer, yes, reason_text(REASON.load(Ordering::SeqCst)));
        Answer { accepted: yes, drained }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_is_30s() {
        assert_eq!(super::TIMEOUT_SECS, 30);
    }

    #[test]
    fn probe_drains_data_then_sees_eof() {
        use std::io::Write;
        use std::net::{Shutdown, TcpListener};
        use std::time::Instant;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        server.set_nonblocking(false).unwrap();

        client.write_all(&[0xAA, 0xBB, 0xCC]).unwrap();
        let mut sink = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        while sink.is_empty() && Instant::now() < deadline {
            let _ = probe(&server, &mut sink);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(sink, vec![0xAA, 0xBB, 0xCC], "探测要把可读数据读出来");

        client.shutdown(Shutdown::Write).unwrap();
        let mut state = Peer::Alive;
        let deadline = Instant::now() + Duration::from_secs(2);
        while state != Peer::Eof && Instant::now() < deadline {
            state = probe(&server, &mut sink);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(state == Peer::Eof, "读空之后必须能看见 FIN");
        drop(client);
    }
}
