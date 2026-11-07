//! GDI 绘制小工具。
//!
//! 以前每画一个圆/圆角矩形都要写六行 `CreateSolidBrush` + `CreatePen` +
//! 两次 `SelectObject` + 两次 `DeleteObject`，三张卡片里重复了几十遍，
//! 而且一旦漏了 `SelectObject` 还原就会污染后续绘制。

use windows_sys::Win32::Graphics::Gdi::{
    CreatePen, CreateSolidBrush, DeleteObject, Ellipse, FillRect, GetStockObject, RoundRect,
    SelectObject, HDC, NULL_BRUSH,
};

use windows_sys::Win32::Foundation::RECT;

fn rect_of(x1: i32, y1: i32, x2: i32, y2: i32) -> RECT {
    RECT { left: x1, top: y1, right: x2, bottom: y2 }
}

/// 铺底色。
pub unsafe fn fill(hdc: HDC, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) {
    let rc = rect_of(x1, y1, x2, y2);
    let brush = CreateSolidBrush(color);
    FillRect(hdc, &rc, brush);
    DeleteObject(brush as _);
}

/// 实心圆（也是"圆角矩形的极端情况"最常用的形态）。
pub unsafe fn circle(hdc: HDC, cx: i32, cy: i32, r: i32, color: u32) {
    let brush = CreateSolidBrush(color);
    let pen = CreatePen(0, 1, color);
    let ob = SelectObject(hdc, brush as _);
    let op = SelectObject(hdc, pen as _);
    Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(brush as _);
    DeleteObject(pen as _);
}

/// 实心圆角矩形（描边与填充同色，避免边缘出现 1px 异色）。
pub unsafe fn round_fill(hdc: HDC, x1: i32, y1: i32, x2: i32, y2: i32, radius: i32, color: u32) {
    let brush = CreateSolidBrush(color);
    let pen = CreatePen(0, 1, color);
    let ob = SelectObject(hdc, brush as _);
    let op = SelectObject(hdc, pen as _);
    RoundRect(hdc, x1, y1, x2, y2, radius, radius);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(brush as _);
    DeleteObject(pen as _);
}

/// 空心圆角矩形（只有描边）。
pub unsafe fn round_stroke(
    hdc: HDC,
    x1: i32,
    y1: i32,
    x2: i32,
    y2: i32,
    radius: i32,
    color: u32,
    width: i32,
) {
    let pen = CreatePen(0, width.max(1), color);
    let null = GetStockObject(NULL_BRUSH);
    let op = SelectObject(hdc, pen as _);
    let ob = SelectObject(hdc, null);
    RoundRect(hdc, x1, y1, x2, y2, radius, radius);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(pen as _);
}

/// 空心圆。
pub unsafe fn circle_stroke(hdc: HDC, cx: i32, cy: i32, r: i32, color: u32, width: i32) {
    let pen = CreatePen(0, width.max(1), color);
    let null = GetStockObject(NULL_BRUSH);
    let op = SelectObject(hdc, pen as _);
    let ob = SelectObject(hdc, null);
    Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(pen as _);
}

/// 填充色与描边色不同的圆角矩形（文件图标那种「浅底 + 灰边」）。
pub unsafe fn round_fill_stroke(
    hdc: HDC,
    x1: i32,
    y1: i32,
    x2: i32,
    y2: i32,
    radius: i32,
    fill_color: u32,
    stroke: u32,
) {
    let brush = CreateSolidBrush(fill_color);
    let pen = CreatePen(0, 1, stroke);
    let ob = SelectObject(hdc, brush as _);
    let op = SelectObject(hdc, pen as _);
    RoundRect(hdc, x1, y1, x2, y2, radius, radius);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(brush as _);
    DeleteObject(pen as _);
}

/// 填充色与描边色不同的圆。
pub unsafe fn circle_fill_stroke(hdc: HDC, cx: i32, cy: i32, r: i32, fill_color: u32, stroke: u32) {
    let brush = CreateSolidBrush(fill_color);
    let pen = CreatePen(0, 1, stroke);
    let ob = SelectObject(hdc, brush as _);
    let op = SelectObject(hdc, pen as _);
    Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(brush as _);
    DeleteObject(pen as _);
}

/// 一条横线（1px）。用于分区，别用 `FillRect` 手写。
pub unsafe fn hline(hdc: HDC, x1: i32, x2: i32, y: i32, color: u32) {
    fill(hdc, x1, y, x2, y + 1, color);
}
