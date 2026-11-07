#![cfg(windows)]

//! 分层窗口（WS_EX_LAYERED）的 32 位 DIB 画布。
//!
//! 三张卡片都用它：`Canvas::new` 建一张 ARGB 位图，GDI 往上画，`commit` 一次性推给窗口。
//!
//! 两个要点：
//! 1. **圆角 alpha 只算一次**。改尺寸或圆角时才重建掩码；之后每帧仍要遍历全图把
//!    alpha 复位成 255，真正的圆角混合才只处理四个角上的 `partial` 像素。
//! 2. **淡入淡出只作用于内容，不作用于白色底盘**。整帧乘 `SourceConstantAlpha`
//!    会让底盘跟着一起变透明，所以常驻浮窗改用 `fade_content` 在 CPU 侧把内容颜色
//!    往底盘色插值，提交时 `SourceConstantAlpha` 恒为 255，底盘始终完全不透明。
//!    确认框 / 通知不做淡入淡出，同样恒提交 255。

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
    /// 卡片相对整幅位图的内缩量。带投影的卡片窗口比卡片本身大一圈，
    /// 圆角要按「卡片矩形」而不是「窗口矩形」算，否则圆角会跑到窗口四角去。
    pub pad: i32,
    /// 自己管 alpha：`commit` 不再每帧把 alpha 重置成 255。
    /// 启用方必须在每次重画前 `reset_alpha`，否则上一帧的透明区会带过来。
    pub manual_alpha: bool,
    dib: HBITMAP,
    /// 每像素的圆角 alpha，`w*h` 字节，卡片内为 255、圆角边缘为渐变值。
    mask: Vec<u8>,
    /// 掩码里 alpha 不是 255 的像素下标（只含卡片矩形内的圆角像素），按行优先。
    partial: Vec<u32>,
    mask_radius: i32,
    mask_pad: i32,
    /// 圆角混合前的原始 RGB。`commit` 会反复对圆角像素做「颜色 × alpha」，
    /// 不存一份原色的话，每提交一帧就暗一层（淡入淡出多发几帧，四个角就黑了）。
    snapshot: Vec<u8>,
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
            if !mem.is_null() {
                windows_sys::Win32::Graphics::Gdi::DeleteDC(mem);
            }
            if !dib.is_null() {
                windows_sys::Win32::Graphics::Gdi::DeleteObject(dib as _);
            }
            return None;
        }
        SelectObject(mem, dib);
        Some(Canvas {
            mem,
            bits: bits as *mut u8,
            w,
            h,
            pad: 0,
            manual_alpha: false,
            dib,
            mask: Vec::new(),
            partial: Vec::new(),
            mask_radius: -1,
            mask_pad: -1,
            snapshot: Vec::new(),
        })
    }

    /// 平整底色：整幅 alpha 复位成 255（GDI 画完不保证 alpha 字节是什么）。
    /// 只有 `manual_alpha` 的卡片需要自己调。
    pub unsafe fn reset_alpha(&mut self) {
        let n = (self.w * self.h) as usize;
        for i in 0..n {
            *self.bits.add(i * 4 + 3) = 255;
        }
    }

    /// 把一块矩形内的 alpha 统一设成 `a`（自动裁到画布内）。
    ///
    /// 用途：`manual_alpha` 的画布做**局部**重绘之后补 alpha。GDI 的 `FillRect` /
    /// `DrawText` 在 32 位 DIB 上会把 alpha 字节写成 0，全量重画可以事后统一
    /// `reset_alpha`，但只重画一小块（比如倒计时条每帧推进）时，那块不补回来就会被
    /// `UpdateLayeredWindow` 当成透明，跟底下的白一混就成了淡色——同一根条出现深浅
    /// 两截，看着像用了两个颜色。
    pub unsafe fn set_alpha_rect(&mut self, x: i32, y: i32, w: i32, h: i32, a: u8) {
        let x0 = x.clamp(0, self.w);
        let y0 = y.clamp(0, self.h);
        let x1 = (x.saturating_add(w)).clamp(0, self.w);
        let y1 = (y.saturating_add(h)).clamp(0, self.h);
        if x1 <= x0 || y1 <= y0 {
            return;
        }
        let bits = self.bits;
        for yy in y0..y1 {
            let row = (yy * self.w) as usize * 4;
            for xx in x0..x1 {
                *bits.add(row + xx as usize * 4 + 3) = a;
            }
        }
    }

    /// 记一份当前 RGB，供 `commit` 重做圆角混合时取原色。内容不变就不用重复调。
    pub fn freeze(&mut self) {
        let n = (self.w * self.h * 4) as usize;
        self.snapshot.resize(n, 0);
        unsafe { std::ptr::copy_nonoverlapping(self.bits, self.snapshot.as_mut_ptr(), n) };
    }

    /// 在卡片矩形外侧画一圈黑色半透明投影，越远越淡。
    ///
    /// 只写 alpha 与 RGB=0（预乘后仍是 0），所以逐帧重复调用也不会累积变暗。
    /// 卡片矩形**内部**的像素一律不碰——那里交给圆角掩码和正常绘制。
    pub unsafe fn paint_shadow(&mut self, radius: i32, offset_y: i32, max_alpha: u8) {
        let pad = self.pad;
        if pad <= 0 {
            return;
        }
        let (w, h) = (self.w, self.h);
        let x1 = pad as f32;
        let y1 = pad as f32;
        let x2 = (w - pad) as f32;
        let y2 = (h - pad) as f32;
        let r = radius.max(0) as f32;
        let blur = pad as f32;
        let oy = offset_y as f32;
        let bits = self.bits;
        for y in 0..h {
            let py = y as f32 + 0.5 - oy;
            for x in 0..w {
                if x >= pad && x < w - pad && y >= pad && y < h - pad {
                    continue;
                }
                let px = x as f32 + 0.5;
                let d = round_rect_sdf(px, py, x1, y1, x2, y2, r);
                let a = if d >= blur {
                    0
                } else {
                    let t = 1.0 - d.max(0.0) / blur;
                    (max_alpha as f32 * t * t) as u8
                };
                let base = ((y * w + x) * 4) as usize;
                *bits.add(base) = 0;
                *bits.add(base + 1) = 0;
                *bits.add(base + 2) = 0;
                *bits.add(base + 3) = a;
            }
        }
    }

    /// 重建圆角掩码。只有 `radius` 或 `pad` 变化时才会真正计算。
    ///
    /// 掩码按「卡片矩形」（内缩 `pad`）算，所以带投影的窗口不会在窗口四角被切圆。
    /// 卡片矩形以外的像素不进 `partial`：那一片由 `paint_shadow` 全权负责。
    fn rebuild_mask(&mut self, radius: i32) {
        let r = radius.max(0);
        let pad = self.pad.max(0);
        if r == self.mask_radius && pad == self.mask_pad && self.mask.len() == (self.w * self.h) as usize {
            return;
        }
        let (w, h) = (self.w, self.h);
        let n = (w * h) as usize;
        self.mask.clear();
        self.mask.resize(n, 255);
        self.partial.clear();
        self.mask_radius = r;
        self.mask_pad = pad;
        if r <= 0 {
            return;
        }
        let cw = w - 2 * pad;
        let ch = h - 2 * pad;
        for y in pad..(h - pad) {
            for x in pad..(w - pad) {
                let a = corner_alpha(x - pad, y - pad, cw, ch, r);
                if a != 255 {
                    let i = (y * w + x) as usize;
                    self.mask[i] = a;
                    self.partial.push(i as u32);
                }
            }
        }
    }

    /// 只让「卡片内容」参与淡入淡出：把每像素颜色按 `alpha` 向底盘色 `bg` 插值。
    ///
    /// 底盘像素本来就等于 `bg`，插值后不变，所以提交时整帧仍可用
    /// `SourceConstantAlpha = 255`，白色底盘从第一帧起就完全不透明；
    /// 文字、图标、进度环、描边等内容则从「与底盘同色」渐变到本色。
    /// `bg` 为 COLORREF（0x00BBGGRR），DIB 像素内存是 BGRA 字节序。
    pub unsafe fn fade_content(&mut self, bg: u32, alpha: u8) {
        if alpha >= 255 {
            return;
        }
        let a = alpha as i32;
        let inv = 255 - a;
        let base = [
            ((bg >> 16) & 0xFF) as i32, // B
            ((bg >> 8) & 0xFF) as i32,  // G
            (bg & 0xFF) as i32,         // R
        ];
        let n = (self.w * self.h) as usize;
        let bits = self.bits;
        for i in 0..n {
            let p = i * 4;
            for c in 0..3 {
                let v = *bits.add(p + c) as i32;
                *bits.add(p + c) = ((base[c] * inv + v * a + 127) / 255) as u8;
            }
        }
    }

    /// 把画布推送到窗口左上角 `(x, y)`，`alpha` 是整帧不透明度（0..=255）。
    pub unsafe fn commit(&mut self, hwnd: HWND, x: i32, y: i32, radius: i32, alpha: u8) {
        self.rebuild_mask(radius);

        let n = (self.w * self.h) as usize;
        let bits = self.bits;

        // GDI 画图不保证保留 alpha 字节，每帧重置一次；这是单字节的紧凑写入，
        // 比逐像素算圆角便宜两个数量级。自己管 alpha 的卡片（带投影的那种）
        // 由调用方在重画前复位，这里不能动——否则阴影会被抹平。
        if !self.manual_alpha {
            for i in 0..n {
                *bits.add(i * 4 + 3) = 255;
            }
        }
        // 圆角像素要用「原始颜色」重新混合：上一帧提交时颜色已经乘过一次 alpha，
        // 直接再乘会一帧比一帧暗。
        if self.snapshot.len() == n * 4 {
            for &pi in &self.partial {
                let base = pi as usize * 4;
                for c in 0..3 {
                    *bits.add(base + c) = self.snapshot[base + c];
                }
            }
        }
        for &pi in &self.partial {
            let i = pi as usize;
            let a = self.mask[i] as u32;
            let base = i * 4;
            for c in 0..3 {
                let v = *bits.add(base + c) as u32;
                *bits.add(base + c) = ((v * a + 127) / 255) as u8;
            }
            *bits.add(base + 3) = a as u8;
        }

        let mut pt_dst = POINT { x, y };
        let size = SIZE { cx: self.w, cy: self.h };
        let pt_src = POINT { x: 0, y: 0 };
        let blend = BLENDFUNCTION {
            BlendOp: 0,
            BlendFlags: 0,
            // AC_SRC_ALPHA 之下这个值会乘到每个像素的 alpha 上。
            // 三张卡片都传 255：淡入淡出已由 fade_content 在 CPU 侧完成。
            SourceConstantAlpha: alpha,
            AlphaFormat: 1,
        };
        let screen_dc = GetDC(std::ptr::null_mut());
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
        ReleaseDC(std::ptr::null_mut(), screen_dc);
    }

    pub unsafe fn destroy(&mut self) {
        if !self.mem.is_null() {
            windows_sys::Win32::Graphics::Gdi::DeleteDC(self.mem);
            self.mem = std::ptr::null_mut();
        }
        if !self.dib.is_null() {
            windows_sys::Win32::Graphics::Gdi::DeleteObject(self.dib as _);
            self.dib = std::ptr::null_mut();
        }
    }
}

impl Drop for Canvas {
    fn drop(&mut self) {
        unsafe { self.destroy() };
    }
}

/// 取「画布句柄 + 尺寸」。卡片在绘制前都要做同一段 let-else 解包，
/// `confirm` / `notice` 各抄了三行，统一到这里。
pub fn canvas_info(
    slot: Option<&std::sync::Mutex<Option<Canvas>>>,
) -> Option<(HDC, i32, i32)> {
    let slot = slot?;
    let Ok(mut guard) = slot.lock() else {
        return None;
    };
    let canvas = guard.as_mut()?;
    Some((canvas.mem, canvas.w, canvas.h))
}

/// 装/换画布。旧画布在赋值时被 Drop 掉（释放 DC 与 DIB）。
pub fn install_canvas(
    slot: &std::sync::OnceLock<std::sync::Mutex<Option<Canvas>>>,
    canvas: Option<Canvas>,
) {
    let mut guard = slot
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *guard = canvas;
}

/// 把画布刷到屏幕上。绘制阶段只借了 `hdc`，提交时重新取一次画布，
/// 避免让整个 `paint_card` 都抱着锁（里面有大量 GDI 调用）。
pub unsafe fn commit_canvas(
    slot: &std::sync::OnceLock<std::sync::Mutex<Option<Canvas>>>,
    hwnd: HWND,
    x: i32,
    y: i32,
    radius: i32,
    alpha: u8,
) {
    let Some(slot) = slot.get() else { return };
    let Ok(mut guard) = slot.lock() else { return };
    let Some(canvas) = guard.as_mut() else { return };
    canvas.commit(hwnd, x, y, radius, alpha);
}

/// 点到圆角矩形的有符号距离：内部为负、边界为 0、外部为正。
/// 投影用它算「离卡片有多远」，比逐圈描边省事，也不会有台阶。
pub fn round_rect_sdf(px: f32, py: f32, x1: f32, y1: f32, x2: f32, y2: f32, r: f32) -> f32 {
    let cx = (x1 + x2) * 0.5;
    let cy = (y1 + y2) * 0.5;
    let hx = ((x2 - x1) * 0.5 - r).max(0.0);
    let hy = ((y2 - y1) * 0.5 - r).max(0.0);
    let qx = (px - cx).abs() - hx;
    let qy = (py - cy).abs() - hy;
    let ox = qx.max(0.0);
    let oy = qy.max(0.0);
    (ox * ox + oy * oy).sqrt() + qx.max(qy).min(0.0) - r
}

pub fn corner_alpha(x: i32, y: i32, w: i32, h: i32, r: i32) -> u8 {    if r <= 0 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corners_fade_out_center_is_opaque() {
        assert_eq!(corner_alpha(0, 0, 100, 50, 10), 0, "最外角完全透明");
        assert_eq!(corner_alpha(50, 25, 100, 50, 10), 255, "正中不透明");
        assert_eq!(corner_alpha(0, 25, 100, 50, 10), 255, "左边中段不透明");
    }

    #[test]
    fn zero_radius_is_a_plain_rectangle() {
        for (x, y) in [(0, 0), (0, 9), (9, 0), (5, 5)] {
            assert_eq!(corner_alpha(x, y, 10, 10, 0), 255);
        }
    }

    #[test]
    fn sdf_matches_the_rect_it_describes() {
        // 10,10 到 110,60 的矩形，圆角 8。
        let d = |x: f32, y: f32| round_rect_sdf(x, y, 10.0, 10.0, 110.0, 60.0, 8.0);
        assert!(d(60.0, 35.0) < -20.0, "正中该是「深在内部」");
        assert!(d(5.0, 35.0) > 0.0 && d(5.0, 35.0) < 6.0, "左边 5px 外");
        assert!(d(120.0, 35.0) > 9.0, "右边 10px 外");
        // 圆角处：直角位置 (10,10) 距离圆心 (18,18) 约 11.3，减去半径 8 ≈ 3.3。
        let corner = d(10.0, 10.0);
        assert!((corner - 3.31).abs() < 0.2, "圆角外该比直角更远，实际 {corner}");
    }
}
