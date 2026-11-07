//! 动态加载 gdiplus，画抗锯齿圆弧（加载失败时调用方退回折线）。

#![cfg(windows)]

use crate::ui::text::wide;
use std::ffi::c_void;
use std::sync::OnceLock;

use windows_sys::Win32::Graphics::Gdi::HDC;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

type GpStatus = i32;
type GpGraphics = *mut c_void;
type GpPen = *mut c_void;

#[repr(C)]
struct StartupInput {
    version: u32,
    callback: *mut c_void,
    suppress_bg: i32,
    suppress_codecs: i32,
}

type FnStartup =
    unsafe extern "system" fn(*mut usize, *const StartupInput, *mut c_void) -> GpStatus;
type FnFromHdc = unsafe extern "system" fn(HDC, *mut GpGraphics) -> GpStatus;
type FnDeleteGraphics = unsafe extern "system" fn(GpGraphics) -> GpStatus;
type FnSetSmoothing = unsafe extern "system" fn(GpGraphics, i32) -> GpStatus;
type FnCreatePen = unsafe extern "system" fn(u32, f32, i32, *mut GpPen) -> GpStatus;
type FnDeletePen = unsafe extern "system" fn(GpPen) -> GpStatus;
type FnSetCap = unsafe extern "system" fn(GpPen, i32) -> GpStatus;
type FnDrawArc =
    unsafe extern "system" fn(GpGraphics, GpPen, f32, f32, f32, f32, f32, f32) -> GpStatus;

struct Api {
    from_hdc: FnFromHdc,
    delete_graphics: FnDeleteGraphics,
    set_smoothing: FnSetSmoothing,
    create_pen: FnCreatePen,
    delete_pen: FnDeletePen,
    set_start_cap: FnSetCap,
    set_end_cap: FnSetCap,
    draw_arc: FnDrawArc,
}

const SMOOTHING_ANTIALIAS: i32 = 4;
const LINE_CAP_ROUND: i32 = 2;
const UNIT_PIXEL: i32 = 2;

fn ansi(s: &str) -> Vec<u8> {
    s.bytes().chain(std::iter::once(0)).collect()
}

fn api() -> Option<&'static Api> {
    static CELL: OnceLock<Option<Api>> = OnceLock::new();
    CELL.get_or_init(|| unsafe { load() }).as_ref()
}

unsafe fn load() -> Option<Api> {
    let lib = LoadLibraryW(wide("gdiplus.dll").as_ptr());
    if lib.is_null() {
        return None;
    }
    let sym = |name: &str| GetProcAddress(lib, ansi(name).as_ptr());

    let startup: FnStartup = std::mem::transmute(sym("GdiplusStartup")?);
    let from_hdc: FnFromHdc = std::mem::transmute(sym("GdipCreateFromHDC")?);
    let delete_graphics: FnDeleteGraphics = std::mem::transmute(sym("GdipDeleteGraphics")?);
    let set_smoothing: FnSetSmoothing = std::mem::transmute(sym("GdipSetSmoothingMode")?);
    let create_pen: FnCreatePen = std::mem::transmute(sym("GdipCreatePen1")?);
    let delete_pen: FnDeletePen = std::mem::transmute(sym("GdipDeletePen")?);
    let set_start_cap: FnSetCap = std::mem::transmute(sym("GdipSetPenStartCap")?);
    let set_end_cap: FnSetCap = std::mem::transmute(sym("GdipSetPenEndCap")?);
    let draw_arc: FnDrawArc = std::mem::transmute(sym("GdipDrawArc")?);

    let input = StartupInput {
        version: 1,
        callback: std::ptr::null_mut(),
        suppress_bg: 0,
        suppress_codecs: 0,
    };
    let mut token: usize = 0;
    if startup(&mut token, &input, std::ptr::null_mut()) != 0 {
        return None;
    }

    Some(Api {
        from_hdc,
        delete_graphics,
        set_smoothing,
        create_pen,
        delete_pen,
        set_start_cap,
        set_end_cap,
        draw_arc,
    })
}

pub fn colorref_to_argb(c: u32) -> u32 {
    let r = c & 0xFF;
    let g = (c >> 8) & 0xFF;
    let b = (c >> 16) & 0xFF;
    0xFF00_0000 | (r << 16) | (g << 8) | b
}

#[allow(clippy::too_many_arguments)]
pub fn draw_arc_aa(
    hdc: HDC,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    start_deg: f32,
    sweep_deg: f32,
    width: i32,
    argb: u32,
) -> bool {
    let Some(a) = api() else { return false };
    unsafe {
        let mut g: GpGraphics = std::ptr::null_mut();
        if (a.from_hdc)(hdc, &mut g) != 0 {
            return false;
        }
        (a.set_smoothing)(g, SMOOTHING_ANTIALIAS);

        let mut pen: GpPen = std::ptr::null_mut();
        let ok = (a.create_pen)(argb, width as f32, UNIT_PIXEL, &mut pen) == 0;
        if ok {
            (a.set_start_cap)(pen, LINE_CAP_ROUND);
            (a.set_end_cap)(pen, LINE_CAP_ROUND);
            (a.draw_arc)(
                g,
                pen,
                x as f32,
                y as f32,
                w as f32,
                h as f32,
                start_deg,
                sweep_deg,
            );
            (a.delete_pen)(pen);
        }
        (a.delete_graphics)(g);
        ok
    }
}
