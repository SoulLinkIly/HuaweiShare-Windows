#![cfg(windows)]
use std::ffi::c_void;

use windows_sys::Win32::Foundation::{HWND, POINT, SIZE};
use windows_sys::Win32::Graphics::Gdi::{
    CreateCompatibleDC, CreateDIBSection, GetDC, ReleaseDC, SelectObject, BI_RGB, BITMAPINFO,
    BITMAPINFOHEADER, BLENDFUNCTION, DIB_RGB_COLORS, HBITMAP, HDC,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    UpdateLayeredWindow, UPDATE_LAYERED_WINDOW_FLAGS, ULW_ALPHA,
};

unsafe impl Send for Canvas {}

pub struct Canvas {
    pub mem: HDC,
    pub bits: *mut u8,
    pub w: i32,
    pub h: i32,
    dib: HBITMAP,
}

impl Canvas {
    pub unsafe fn new(w: i32, h: i32) -> Option<Self> {
        if w <= 0 || h <= 0 {
            return None;
        }
        let screen = GetDC(std::ptr::null_mut());
        let mut bmi: BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = w;
        bmi.bmiHeader.biHeight = -h;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;

        let mut bits: *mut c_void = std::ptr::null_mut();
        let dib = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &mut bits, std::ptr::null_mut(), 0);
        let mem = CreateCompatibleDC(screen);
        ReleaseDC(std::ptr::null_mut(), screen);
        if dib.is_null() || mem.is_null() || bits.is_null() {
            return None;
        }
        SelectObject(mem, dib);
        Some(Canvas { mem, bits: bits as *mut u8, w, h, dib })
    }

    pub unsafe fn commit(&self, hwnd: HWND, x: i32, y: i32, radius: i32) {
        let r = radius.max(0);
        for yy in 0..self.h {
            for xx in 0..self.w {
                let base = ((yy * self.w + xx) * 4) as usize;
                let a = corner_alpha(xx, yy, self.w, self.h, r) as u32;
                if a == 255 {
                    *self.bits.add(base + 3) = 255;
                    continue;
                }
                for c in 0..3 {
                    let v = *self.bits.add(base + c) as u32;
                    *self.bits.add(base + c) = ((v * a + 127) / 255) as u8;
                }
                *self.bits.add(base + 3) = a as u8;
            }
        }

        let mut pt_dst = POINT { x, y };
        let size = SIZE { cx: self.w, cy: self.h };
        let pt_src = POINT { x: 0, y: 0 };
        let blend = BLENDFUNCTION {
            BlendOp: 0,
            BlendFlags: 0,
            SourceConstantAlpha: 255,
            AlphaFormat: 1,
        };
        let screen_dc = windows_sys::Win32::Graphics::Gdi::GetDC(std::ptr::null_mut());
        UpdateLayeredWindow(
            hwnd,
            screen_dc,
            &mut pt_dst,
            &size,
            self.mem,
            &pt_src,
            0,
            &blend,
            ULW_ALPHA as UPDATE_LAYERED_WINDOW_FLAGS,
        );
        windows_sys::Win32::Graphics::Gdi::ReleaseDC(std::ptr::null_mut(), screen_dc);
    }

    pub unsafe fn destroy(&mut self) {
        if !self.dib.is_null() {
            windows_sys::Win32::Graphics::Gdi::DeleteObject(self.dib as _);
            self.dib = std::ptr::null_mut();
        }
        if !self.mem.is_null() {
            windows_sys::Win32::Graphics::Gdi::DeleteDC(self.mem);
            self.mem = std::ptr::null_mut();
        }
    }
}

impl Drop for Canvas {
    fn drop(&mut self) {
        unsafe { self.destroy() };
    }
}

fn corner_alpha(x: i32, y: i32, w: i32, h: i32, r: i32) -> u8 {
    if r <= 0 {
        return 255;
    }
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
