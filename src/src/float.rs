//! 浮窗几何：贴边吸附、拖拽越界保护、位置持久化。

#![cfg(windows)]

use std::path::PathBuf;
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{POINT, RECT};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetCursorPos, SystemParametersInfoW};

pub const PEEK: i32 = 4;

pub const SNAP: i32 = 18;

const TUCK_EXTRA: i32 = 30;

const SPI_GETWORKAREA: u32 = 0x0030;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Edge {
    None,
    Left,
    Right,
    Top,
    Bottom,
}

impl Edge {
    pub fn code(self) -> u8 {
        match self {
            Edge::None => 0,
            Edge::Left => 1,
            Edge::Right => 2,
            Edge::Top => 3,
            Edge::Bottom => 4,
        }
    }

    pub fn from_code(code: u8) -> Edge {
        match code {
            1 => Edge::Left,
            2 => Edge::Right,
            3 => Edge::Top,
            4 => Edge::Bottom,
            _ => Edge::None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Layout {
    pub x: i32,
    pub y: i32,
    pub edge: Edge,
}

#[derive(Clone, Copy)]
struct DragState {

    grab_x: i32,
    grab_y: i32,
    w: i32,
    h: i32,
    x: i32,
    y: i32,
    edge: Edge,
}

static DRAG: Mutex<Option<DragState>> = Mutex::new(None);

static ANCHOR: Mutex<Option<(i32, i32)>> = Mutex::new(None);

static LAST_SAVED: Mutex<Option<Layout>> = Mutex::new(None);

pub fn work_area() -> (i32, i32, i32, i32) {
    let mut rc: RECT = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &mut rc as *mut RECT as *mut _, 0)
    };
    if ok == 0 {
        (0, 0, 1280, 800)
    } else {
        (rc.left, rc.top, rc.right, rc.bottom)
    }
}

pub fn clamp_to_work_area(x: i32, y: i32, w: i32, h: i32) -> (i32, i32) {
    let (left, top, right, bottom) = work_area();
    (
        x.clamp(left - w / 2, right - w / 2),
        y.clamp(top, bottom - h / 2),
    )
}

pub fn cursor() -> (i32, i32) {
    let mut pt = POINT { x: 0, y: 0 };
    unsafe {
        GetCursorPos(&mut pt);
    }
    (pt.x, pt.y)
}

pub fn initial_pos(w: i32, h: i32, dpi: i32) -> (i32, i32) {
    let (_, top, right, _) = work_area();
    if let Some((x, y)) = *ANCHOR.lock().unwrap_or_else(|e| e.into_inner()) {
        return clamp_to_work_area(x, y, w, h);
    }
    let margin = 24 * dpi / 96;
    (right - w - margin, top + margin)
}

pub fn remember(x: i32, y: i32) {
    if let Ok(mut slot) = ANCHOR.lock() {
        *slot = Some((x, y));
    }
}

fn layout_path() -> PathBuf {
    crate::store::path("window.json")
}

fn parse_layout(text: &str) -> Option<Layout> {
    let value: serde_json::Value =
        serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(text)).ok()?;
    let x = value.get("x")?.as_i64()? as i32;
    let y = value.get("y")?.as_i64()? as i32;
    let edge = Edge::from_code(value.get("edge").and_then(|e| e.as_u64()).unwrap_or(0) as u8);
    Some(Layout { x, y, edge })
}

pub fn load_layout() -> Option<Layout> {
    let text = std::fs::read_to_string(layout_path()).ok()?;
    parse_layout(&text)
}

pub fn save_layout(x: i32, y: i32, edge: Edge) {
    remember(x, y);
    let layout = Layout { x, y, edge };
    if let Ok(mut slot) = LAST_SAVED.lock() {
        if *slot == Some(layout) {
            return;
        }
        *slot = Some(layout);
    }
    let path = layout_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let text = format!("{{\"x\":{},\"y\":{},\"edge\":{}}}", layout.x, layout.y, layout.edge.code());
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, text).is_ok() && std::fs::rename(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

pub fn is_dragging() -> bool {
    DRAG.lock().map(|g| g.is_some()).unwrap_or(false)
}

pub fn drag_start(mouse: (i32, i32), pos: (i32, i32), size: (i32, i32)) {
    if let Ok(mut slot) = DRAG.lock() {
        *slot = Some(DragState {
            grab_x: mouse.0 - pos.0,
            grab_y: mouse.1 - pos.1,
            w: size.0,
            h: size.1,
            x: pos.0,
            y: pos.1,
            edge: Edge::None,
        });
    }
}

pub fn drag_update(mouse: (i32, i32)) -> Option<(i32, i32, Edge)> {
    let mut guard = DRAG.lock().ok()?;
    let state = guard.as_mut()?;
    let want_x = mouse.0 - state.grab_x;
    let want_y = mouse.1 - state.grab_y;
    let area = work_area();
    let (left, top, right, bottom) = area;

    let (x, h_edge, h_pen) = axis(want_x, state.w, left, right, Edge::Left, Edge::Right);
    let (y, v_edge, v_pen) = axis(want_y, state.h, top, bottom, Edge::Top, Edge::Bottom);

    let edge = if (v_edge == Edge::None) || (h_edge != Edge::None && h_pen >= v_pen) {
        h_edge
    } else {
        v_edge
    };

    let (x, y) = keep_other_axis(edge, x, y, state.w, state.h, area);
    state.x = x;
    state.y = y;
    state.edge = edge;
    Some((x, y, edge))
}

fn keep_other_axis(
    edge: Edge,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    area: (i32, i32, i32, i32),
) -> (i32, i32) {
    let (left, top, right, bottom) = area;
    let max_x = (right - w).max(left);
    let max_y = (bottom - h).max(top);
    match edge {
        Edge::Left | Edge::Right => (x, y.clamp(top, max_y)),
        Edge::Top | Edge::Bottom => (x.clamp(left, max_x), y),
        Edge::None => (x, y),
    }
}

fn axis(want: i32, size: i32, lo: i32, hi: i32, near: Edge, far: Edge) -> (i32, Edge, i32) {
    if want <= lo + SNAP {
        let pen = lo - want;
        if pen >= TUCK_EXTRA {
            let x = want.max(lo - size + PEEK);
            return (x, near, pen);
        }
        return (lo, Edge::None, 0);
    }
    if want + size >= hi - SNAP {
        let pen = (want + size) - hi;
        if pen >= TUCK_EXTRA {
            let x = want.min(hi - PEEK);
            return (x, far, pen);
        }
        return (hi - size, Edge::None, 0);
    }
    (want, Edge::None, 0)
}

pub fn drag_end() -> Edge {
    let edge = DRAG
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.edge))
        .unwrap_or(Edge::None);
    if let Ok(mut slot) = DRAG.lock() {
        *slot = None;
    }
    edge
}

pub fn tucked_pos(edge: Edge, x: i32, y: i32, w: i32, h: i32, peek: i32) -> (i32, i32) {
    let (left, top, right, bottom) = work_area();
    match edge {
        Edge::Left => (left - w + peek, y),
        Edge::Right => (right - peek, y),
        Edge::Top => (x, top - h + peek),
        Edge::Bottom => (x, bottom - peek),
        Edge::None => (x, y),
    }
}

pub fn expanded_pos(edge: Edge, x: i32, y: i32, w: i32, h: i32) -> (i32, i32) {
    let (left, top, right, bottom) = work_area();
    match edge {
        Edge::Left => (left, y.clamp(top, bottom - h)),
        Edge::Right => (right - w, y.clamp(top, bottom - h)),
        Edge::Top => (x.clamp(left, right - w), top),
        Edge::Bottom => (x.clamp(left, right - w), bottom - h),
        Edge::None => (x, y),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_code_roundtrip() {
        for e in [Edge::None, Edge::Left, Edge::Right, Edge::Top, Edge::Bottom] {
            assert_eq!(Edge::from_code(e.code()), e);
        }
    }

    #[test]
    fn parses_saved_layout() {
        assert_eq!(
            parse_layout(r#"{"x":1200,"y":40,"edge":2}"#),
            Some(Layout { x: 1200, y: 40, edge: Edge::Right })
        );

        assert_eq!(
            parse_layout("\u{feff}{\"x\":-8,\"y\":0,\"edge\":1}").unwrap().edge,
            Edge::Left
        );

        assert_eq!(parse_layout(r#"{"x":1,"y":2}"#).unwrap().edge, Edge::None);

        assert_eq!(parse_layout("not json"), None);
        assert_eq!(parse_layout(r#"{"x":"1","y":2}"#), None);
        assert_eq!(parse_layout(r#"{"y":2}"#), None);
    }

    #[test]
    fn clamp_keeps_window_on_screen() {
        let (left, top, right, bottom) = work_area();
        let (w, h) = (344, 108);

        assert_eq!(clamp_to_work_area(999_999, -999_999, w, h), (right - w / 2, top));
        assert_eq!(clamp_to_work_area(-999_999, 999_999, w, h), (left - w / 2, bottom - h / 2));
    }

    #[test]
    fn snap_then_tuck_on_left() {

        let (x, edge, _) = axis(10, 570, 0, 2560, Edge::Left, Edge::Right);
        assert_eq!((x, edge), (0, Edge::None));

        let (x, edge, pen) = axis(-40, 570, 0, 2560, Edge::Left, Edge::Right);
        assert_eq!((x, edge, pen), (-40, Edge::Left, 40));

        let (x, edge, _) = axis(-2000, 570, 0, 2560, Edge::Left, Edge::Right);
        assert_eq!((x, edge), (PEEK - 570, Edge::Left));

        assert_eq!(axis(800, 570, 0, 2560, Edge::Left, Edge::Right), (800, Edge::None, 0));
    }

    #[test]
    fn snap_then_tuck_on_right() {
        let (x, edge, _) = axis(2560 - 570 + 8, 570, 0, 2560, Edge::Left, Edge::Right);
        assert_eq!((x, edge), (2560 - 570, Edge::None));
        let (x, edge, pen) = axis(2560 - 570 + 40, 570, 0, 2560, Edge::Left, Edge::Right);
        assert_eq!((x, edge, pen), (2560 - 570 + 40, Edge::Right, 40));

        let (x, edge, _) = axis(9999, 570, 0, 2560, Edge::Left, Edge::Right);
        assert_eq!((x, edge), (2560 - PEEK, Edge::Right));
    }

    #[test]
    fn vertical_edges_tuck_to_one_edge() {

        let (y, edge, pen) = axis(-50, 300, 0, 1600, Edge::Top, Edge::Bottom);
        assert_eq!((y, edge, pen), (-50, Edge::Top, 50));
        let (y, edge, _) = axis(-9999, 300, 0, 1600, Edge::Top, Edge::Bottom);
        assert_eq!((y, edge), (PEEK - 300, Edge::Top));
        let (y, edge, _) = axis(9999, 300, 0, 1600, Edge::Top, Edge::Bottom);
        assert_eq!((y, edge), (1600 - PEEK, Edge::Bottom));
    }

    #[test]
    fn corner_drag_keeps_other_axis_visible() {
        let area = (0, 0, 2560, 1440);
        let (w, h) = (344, 108);

        let (x, he, _) = axis(2560 - w + 2000, w, 0, 2560, Edge::Left, Edge::Right);
        let (y, ve, _) = axis(-60, h, 0, 1440, Edge::Top, Edge::Bottom);
        assert_eq!(he, Edge::Right);
        assert_eq!(ve, Edge::Top);
        let (x, y) = keep_other_axis(Edge::Right, x, y, w, h, area);
        assert_eq!(x, 2560 - PEEK, "横向缩到只剩一条边");
        assert_eq!(y, 0, "纵向必须完整可见，否则只剩角上 4×4");

        let (x, he, _) = axis(-2000, w, 0, 2560, Edge::Left, Edge::Right);
        let (y, ve, _) = axis(1440 - h + 60, h, 0, 1440, Edge::Top, Edge::Bottom);
        assert_eq!(he, Edge::Left);
        assert_eq!(ve, Edge::Bottom);
        let (x, y) = keep_other_axis(Edge::Left, x, y, w, h, area);
        assert_eq!(x, PEEK - w, "左缩进只露一条边");
        assert_eq!(y, 1440 - h);

        let (x, y) = keep_other_axis(Edge::Top, 3000, PEEK - h, w, h, area);
        assert_eq!((x, y), (2216, PEEK - h));

        let (x, y) = keep_other_axis(Edge::Right, 0, 0, 5000, 5000, area);
        assert_eq!((x, y), (0, 0));
    }
}
