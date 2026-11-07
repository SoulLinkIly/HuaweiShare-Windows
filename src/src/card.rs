//! 常驻浮窗：进度卡与「把文件拖进这里」投放面板。
//! 100 ms 心跳驱动重绘，贴边动画由独立的 16 ms `ANIM_TIMER` 驱动，界面状态见 `Phase` / `Panel`。

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicIsize, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use crate::layered::Canvas;
use crate::ui::draw as ui_draw;
use crate::ui::text::truncate;
use crate::ui::theme::{
    ACCENT as COL_ACCENT, ASK as COL_ASK, BG as COL_BG, BORDER as COL_BORDER, BTN_BG as COL_BTN_BG,
    BTN_HOVER_BG as COL_BTN_HOVER_BG, BTN_TEXT as COL_BTN_TEXT, ERROR as COL_ERROR,
    FILE_BODY as COL_FILE_BODY, FILE_LINE as COL_FILE_LINE, HINT as COL_HINT,
    ICON_BG as COL_ICON_BG, LINE as COL_TRACK, MAIN as COL_MAIN, MEDIA as COL_MEDIA, SUB as COL_SUB,
};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CreatePen, CreateSolidBrush, DeleteObject, DrawTextW, Ellipse, EndPaint,
    ExtCreatePen, FillRect, GetStockObject, InvalidateRect, Polygon, Polyline, SelectObject,
    SetBkMode, SetTextColor, UpdateWindow, DT_CENTER, DT_LEFT, DT_SINGLELINE, DT_VCENTER,
    FW_BOLD, FW_NORMAL, HDC, LOGBRUSH, NULL_BRUSH, PAINTSTRUCT, PS_GEOMETRIC, TRANSPARENT
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{ReleaseCapture, SetCapture};
use windows_sys::Win32::UI::Shell::{DragAcceptFiles, DragFinish, DragQueryFileW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetCursorPos, GetDesktopWindow,
    GetMessageW, KillTimer, PostQuitMessage, SetTimer, SetWindowPos,
    ShowWindow, TranslateMessage, MSG, SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER,
    WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP,
};

const CARD_W: i32 = 344;
const CARD_H: i32 = 108;
const RING_CX: i32 = 54;
const RING_CY: i32 = 54;
const RING_R: i32 = 32;
const RING_W: i32 = 7;

const BTN_W: i32 = 58;
const BTN_H: i32 = 24;
const BTN_RIGHT: i32 = 14;
const BTN_BOTTOM: i32 = 13;

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
const WM_DPICHANGED: u32 = 0x02E0;
const WM_DESTROY: u32 = 0x0002;
const SW_SHOWNOACTIVATE: i32 = 4;
const SW_HIDE: i32 = 0;
const TIMER_ID: usize = 1;

const ANIM_TIMER: usize = 2;

/// 浮窗的窗口类名。`register_class` 与 `CreateWindowExW` 必须用同一个。
const CLASS: &str = "HWShareCard";

const ANIM_MS: u32 = 300;

const ANIM_IN_PART: f32 = 0.35;

const RESTORE_HOLD_MS: u32 = 3000;

/// 浮窗处于哪个阶段。以前是一个裸 u8，读写处散落着 `== 2`、`!= 0` 这种魔法值，
/// 想确认"这套组合合不合法"只能去翻所有分支；现在类型里就写着。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Phase {
    /// 不可见（或正在淡出）。
    Hidden = 0,
    /// 可见：按 `Panel` 决定画投放面板还是进度卡。
    Active = 1,
    /// 传完了，停留 3 秒展示结果。
    Done = 2,
    /// 等对方点接收。
    Waiting = 3,
    /// 失败或已取消，停留 3 秒。
    Failed = 4,
}

impl Phase {
    fn code(self) -> u8 {
        self as u8
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn from_code(v: u8) -> Phase {
        match v {
            1 => Phase::Active,
            2 => Phase::Done,
            3 => Phase::Waiting,
            4 => Phase::Failed,
            _ => Phase::Hidden,
        }
    }
}

/// 可见时画什么。
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Panel {
    /// 环形进度 + 取消按钮。
    Progress = 0,
    /// 「把文件拖进这里」的投放面板。
    Drop = 1,
}

/// 多目标轮播视图：目标名、已传字节、总字节、速度（KB/s）。
/// progress 每次进度更新推送一组，浮窗心跳每 3 秒切到下一份。
pub type View = (String, u64, u64, u32);

/// 结果卡展示完之后去哪。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum After {
    /// 回到常驻投放面板。
    DropPanel,
    /// 收起。被动接收/发送的常态就是这一种。
    Hidden,
}

/// 只根据快照决定归宿，便于单测（不需要真的建窗口）。
fn after_done(back: Option<Restore>) -> After {
    match back {
        // 传输是从用户钉住的投放面板发起的：传完把面板还给他。
        Some(r) if r.pinned => After::DropPanel,
        // 其余情况（浮窗原本不可见、或只是临时展开）一律收起。
        _ => After::Hidden,
    }
}

/// 一次传输结束之后要回到的「常驻形态」。
///
/// 以前收尾是写死切回投放面板并把 `PINNED` 置真：哪怕这次传输是被动接收、
/// 浮窗原本根本不可见，传完之后屏幕上也永久多出一块「把文件拖进这里」。
/// 现在进传输前记一份，结束后照原样还回去。
#[derive(Clone, Copy, PartialEq, Eq)]
struct Restore {
    panel: Panel,
    pinned: bool,
}

/// 浮窗的全部视图模型。
///
/// 以前这些字段是 20 多个互不相干的 `static`：传输线程写 `PCT`，UI 线程读
/// `PCT`，谁也说不清「phase 与 panel 是不是一起变」。现在只有一把锁，
/// 跨线程的读写都在 [`with_model`] 里完成，剩下的 `static` 都是纯 UI 线程的
/// 运行时状态（窗口句柄、动画、DPI、字体缓存）。
struct Model {
    phase: Phase,
    panel: Panel,
    /// 投放面板是不是用户「钉住」的常驻态（托盘菜单 / 双击叫出来的）。
    pinned: bool,
    /// 进入传输前的常驻形态；没有正在进行的传输时为 `None`。
    restore: Option<Restore>,
    pct: u32,
    received: u64,
    total: u64,
    /// 当前显示目标的速度（KB/s）。唯一来源是 `progress` 推来的视图。
    speed_kb: u32,
    name: String,
    /// 图标用媒体样式还是文件样式，由 `progress` 按真实文件名决定。
    media: bool,
    /// 本批文件数 > 1。与「多目标」是两件事，过去共用一个 `MULTI` 出过 bug。
    outgoing: bool,
    preparing: bool,
    canceled: bool,
    hover_cancel: bool,
    views: Vec<View>,
    carousel_at: u32,
    carousel_ix: u32,
    view_dirty: bool,
    done_at: u32,
}

impl Model {
    const fn new() -> Self {
        Self {
            phase: Phase::Hidden,
            panel: Panel::Progress,
            pinned: false,
            restore: None,
            pct: 0,
            received: 0,
            total: 0,
            speed_kb: 0,
            name: String::new(),
            media: false,
            outgoing: false,
            preparing: false,
            canceled: false,
            hover_cancel: false,
            views: Vec::new(),
            carousel_at: 0,
            carousel_ix: 0,
            view_dirty: false,
            done_at: 0,
        }
    }
}

static MODEL: Mutex<Model> = Mutex::new(Model::new());

fn with_model<R>(f: impl FnOnce(&mut Model) -> R) -> R {
    let mut guard = MODEL.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

const CAROUSEL_MS: u32 = 3000;

static STARTED: AtomicU8 = AtomicU8::new(0);
static DPI: AtomicU32 = AtomicU32::new(96);

static LAST_STATE: AtomicU8 = AtomicU8::new(u8::MAX);
static LAST_PCT: AtomicU32 = AtomicU32::new(u32::MAX);
static LAST_SPEED: AtomicU32 = AtomicU32::new(u32::MAX);
static LAST_MODE: AtomicU8 = AtomicU8::new(u8::MAX);

/// 贴边相关的三个量必须一起变才有意义（倒计时到期要同时清掉、强制展开结束也一样），
/// 所以合成一个结构体，用一把锁保证原子性。以前是三个原子量各改各的，
/// 「传输中闪一下」就是因为缩回动画和强制展开互相不知道对方存在。
#[derive(Clone, Copy, PartialEq, Eq)]
struct EdgeState {
    /// 停靠在哪条边；`None` = 自由浮动。
    edge: crate::float::Edge,
    /// 缩回边的时刻（ms，0 = 没有倒计时）。
    restore_at: u32,
    /// 强制展开到此刻（ms，0 = 不强制）。
    hold_until: u32,
}

static EDGE_STATE: Mutex<EdgeState> = Mutex::new(EdgeState {
    edge: crate::float::Edge::None,
    restore_at: 0,
    hold_until: 0,
});

fn with_edge<R>(f: impl FnOnce(&mut EdgeState) -> R) -> R {
    let mut guard = EDGE_STATE.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

fn parked_edge() -> crate::float::Edge {
    with_edge(|s| s.edge)
}

fn park(edge: crate::float::Edge) {
    with_edge(|s| s.edge = edge);
}

fn unpark() -> crate::float::Edge {
    with_edge(|s| std::mem::replace(&mut s.edge, crate::float::Edge::None))
}

static STARTUP_RESTORE: AtomicBool = AtomicBool::new(false);

/// 双击托盘要立刻收起：定时器下一拍直接隐藏，不走淡出。
static HIDE_NOW: AtomicBool = AtomicBool::new(false);

/// 托盘（或重复启动的另一个实例）要求「把浮窗拿出来」。
///
/// 只置标志、不直接挪窗口：`move_to` 改的是 UI 线程自己那份 `WIN_POS`，
/// 从别的线程 `SetWindowPos` 会和心跳抢位置，看起来就是抖一下。真正的移动
/// 统一放到 `WM_TIMER` 里做。
static REVEAL: AtomicBool = AtomicBool::new(false);

static FADE: AtomicU32 = AtomicU32::new(255);

static FADE_TO: AtomicU32 = AtomicU32::new(255);

static VISIBLE: AtomicBool = AtomicBool::new(false);

static LAST_ALPHA: AtomicU32 = AtomicU32::new(u32::MAX);

/// 每 100 ms 心跳推进一拍，96 让淡入/淡出各 3 拍完成（约 300 ms）。
/// 原来是 42（7 拍约 700 ms）；底盘不再跟着透明后，停留太久会显得拖沓。
const FADE_STEP: u32 = 96;

static ANIM_ON: AtomicBool = AtomicBool::new(false);
static ANIM_T0: AtomicU32 = AtomicU32::new(0);
static ANIM_EDGE: AtomicU8 = AtomicU8::new(0);

static ANIM_FROM: [AtomicI32; 2] = [AtomicI32::new(0), AtomicI32::new(0)];
static ANIM_FULL: [AtomicI32; 2] = [AtomicI32::new(0), AtomicI32::new(0)];
static ANIM_REST: [AtomicI32; 2] = [AtomicI32::new(0), AtomicI32::new(0)];
/// 浮窗自己的画布。GDI 绘制与提交都在浮窗线程上，锁竞争只可能发生在重建时。
static CANVAS: Mutex<Option<Canvas>> = Mutex::new(None);

static CARD_HWND: AtomicIsize = AtomicIsize::new(0);

/// 100 ms 心跳只在窗口可见/有任务时运行，彻底隐藏后停掉，别让空闲进程每 100 ms 醒一次。
static TIMER_ON: AtomicBool = AtomicBool::new(false);

static LAST_REFRESH_MS: AtomicU32 = AtomicU32::new(0);
static WIN_POS: [AtomicI32; 2] = [AtomicI32::new(0), AtomicI32::new(0)];
static WIN_SIZE: [AtomicI32; 2] = [AtomicI32::new(0), AtomicI32::new(0)];

static TARGET_VIEW: Mutex<Option<crate::peers::TargetView>> = Mutex::new(None);
static LAST_TARGET_REV: AtomicU64 = AtomicU64::new(u64::MAX);

fn now_ms() -> u32 {
    crate::clock::now_millis() as u32
}

/// 把一份目标视图写进模型（调用方已持锁）。
fn apply_view(v: &View, m: &mut Model) {
    m.name = v.0.clone();
    m.received = v.1;
    m.total = v.2;
    m.pct = if v.2 > 0 {
        (v.1 as f64 * 10000.0 / v.2 as f64).min(10000.0) as u32
    } else {
        0
    };
    m.speed_kb = v.3;
}

/// progress 推来的最新视图。单份时直接显示；多份时启动 / 维持 3 秒轮播。
pub fn set_views(views: Vec<View>) {
    with_model(|m| {
        let was_multi = m.views.len() > 1;
        let multi = views.len() > 1;
        m.views = views;
        if !multi {
            m.carousel_at = 0;
            m.carousel_ix = 0;
            if let Some(v) = m.views.first().cloned() {
                apply_view(&v, m);
            }
        } else {
            if !was_multi {
                m.carousel_ix = 0;
                m.carousel_at = now_ms().wrapping_add(CAROUSEL_MS);
            }
            let ix = (m.carousel_ix as usize).min(m.views.len() - 1);
            m.carousel_ix = ix as u32;
            let v = m.views[ix].clone();
            apply_view(&v, m);
        }
        m.view_dirty = true;
    });
}

/// 到点切到下一个目标。只在进度卡可见时轮播，避免结果卡上的名字乱跳。
fn tick_carousel(now: u32) -> bool {
    if !matches!(phase(), Phase::Active | Phase::Waiting) || panel() != Panel::Progress {
        return false;
    }
    with_model(|m| {
        if m.views.len() <= 1 || !reached(m.carousel_at) {
            return false;
        }
        let next = (m.carousel_ix as usize + 1) % m.views.len();
        m.carousel_ix = next as u32;
        m.carousel_at = now.wrapping_add(CAROUSEL_MS);
        let v = m.views[next].clone();
        apply_view(&v, m);
        true
    })
}

pub fn is_media_name(name: &str) -> bool {
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

/// 由 progress 显式指定图标类型：标题换成目标名后不能再拿标题猜文件类型。
pub fn set_media(v: bool) {
    with_model(|m| m.media = v);
}

pub fn rename(name: &str) {
    with_model(|m| m.name = name.to_string());
}

fn phase() -> Phase {
    with_model(|m| m.phase)
}

fn panel() -> Panel {
    with_model(|m| m.panel)
}

fn pct() -> u32 {
    with_model(|m| m.pct)
}

fn speed_kb() -> u32 {
    with_model(|m| m.speed_kb)
}

fn received() -> u64 {
    with_model(|m| m.received)
}

fn total() -> u64 {
    with_model(|m| m.total)
}

fn display_name() -> String {
    with_model(|m| m.name.clone())
}

fn media_icon() -> bool {
    with_model(|m| m.media)
}

fn hover_cancel() -> bool {
    with_model(|m| m.hover_cancel)
}

fn set_hover_cancel(v: bool) -> bool {
    with_model(|m| std::mem::replace(&mut m.hover_cancel, v))
}

fn outgoing() -> bool {
    with_model(|m| m.outgoing)
}

fn canceled() -> bool {
    with_model(|m| m.canceled)
}

fn is_preparing() -> bool {
    with_model(|m| m.preparing)
}

fn done_at() -> u32 {
    with_model(|m| m.done_at)
}

pub fn set_outgoing(ours: bool) {
    with_model(|m| m.outgoing = ours);
}

/// 从「投放面板」或隐藏状态切到进度卡。
///
/// 进度层每次更新都会调它，所以必须**幂等**：面板已经是进度卡时什么都不做，
/// 别把已传字节清零。以前多目标分支用的是 `state() != 1` 判断，而拖文件进来
/// 时浮窗正是 `Active`，条件恒不成立，于是面板永远停在投放态、进度一个像素都不画。
pub fn show_progress(name: &str) {
    if phase() == Phase::Hidden || panel() == Panel::Drop {
        start(name);
    }
}

/// 打开一次传输的显示：记下常驻形态，清干净上一批的进度，切到进度卡。
fn open(name: &str, to: Phase, prep: bool) {
    with_model(|m| {
        // 只在「从空闲进入传输」时拍快照；同一批的后续 start/waiting 不覆盖。
        if !matches!(m.phase, Phase::Active | Phase::Waiting) || m.panel == Panel::Drop {
            m.restore = Some(Restore {
                panel: m.panel,
                pinned: m.pinned,
            });
        }
        // 传输期间不算「用户钉住的投放面板」：否则各种收尾路径会把面板叫回来。
        m.pinned = false;
        m.phase = to;
        m.panel = Panel::Progress;
        m.preparing = prep;
        m.name = name.to_string();
        m.pct = 0;
        m.received = 0;
        m.total = 0;
        m.speed_kb = 0;
        m.done_at = 0;
        m.canceled = false;
        m.hover_cancel = false;
        m.views.clear();
        m.carousel_at = 0;
        m.carousel_ix = 0;
    });
    cancel_hold();
    cancel_restore_tuck();
    ensure_thread();
    arm_timer();
}

pub fn start(name: &str) {
    open(name, Phase::Active, false);
}

pub fn waiting(name: &str) {
    open(name, Phase::Waiting, false);
}

pub fn preparing(name: &str) {
    open(name, Phase::Waiting, true);
}

pub fn update(received: u64, total: u64) {
    with_model(|m| {
        if m.phase != Phase::Active {
            return;
        }
        m.received = received;
        m.total = total;
        if total > 0 {
            m.pct = (received as f64 * 10000.0 / total as f64).min(10000.0) as u32;
        }
    });
}

/// 传输结束。`pinned` 在开传时已经清掉，这里只需记住结果卡的时刻。
pub fn finish() {
    if phase() == Phase::Hidden || canceled() {
        return;
    }
    with_model(|m| {
        m.phase = Phase::Done;
        m.done_at = now_ms();
        m.pinned = false;
    });
    hold_expanded_for(RESTORE_HOLD_MS);
}

pub fn fail() {
    if matches!(phase(), Phase::Hidden | Phase::Done) || canceled() {
        return;
    }
    with_model(|m| {
        m.phase = Phase::Failed;
        m.done_at = now_ms();
        m.pinned = false;
    });
    hold_expanded_for(RESTORE_HOLD_MS);
}

/// 异常收尾：只处理「正在传输」的浮窗，已经结束/已隐藏的不再动。
///
/// 给 Drop 守卫调用，所以必须幂等——历史上这里靠调用方手写成对的
/// `fail()` + `hide()`，漏一处就是「卡在半屏」。现在只有这一个入口。
pub fn abort() {
    if panel() == Panel::Progress && matches!(phase(), Phase::Active | Phase::Waiting) {
        fail();
    }
}

/// 收起浮窗（不改变常驻形态）。结果卡正在展示时不受影响。
pub fn hide_idle() {
    if matches!(phase(), Phase::Done | Phase::Failed) {
        return;
    }
    with_model(|m| {
        m.phase = Phase::Hidden;
        m.pinned = false;
    });
}

/// 让投放面板常驻显示（托盘菜单 / 双击托盘）。
pub fn show_drop_panel() {
    with_model(|m| {
        m.panel = Panel::Drop;
        m.pinned = true;
        m.phase = Phase::Active;
        m.hover_cancel = false;
    });
    cancel_hold();
    ensure_thread();
    arm_timer();
}

/// 让心跳跑起来。窗口还没建好时直接返回，建好那一侧会再调一次。
fn arm_timer() {
    let hwnd = CARD_HWND.load(Ordering::SeqCst);
    if hwnd == 0 {
        return;
    }
    if TIMER_ON.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe {
        SetTimer(hwnd as HWND, TIMER_ID, 100, None);
    }
}

fn disarm_timer() {
    TIMER_ON.store(false, Ordering::SeqCst);
    let hwnd = CARD_HWND.load(Ordering::SeqCst);
    if hwnd != 0 {
        unsafe {
            KillTimer(hwnd as HWND, TIMER_ID);
        }
    }
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

    // 窗口类注册、DPI 取值都走公共骨架；浮窗额外要双击消息（CS_DBLCLKS）。
    crate::ui::popup::register_class(CLASS, Some(wndproc), crate::ui::popup::CS_DBLCLKS);
    let dpi = crate::ui::popup::system_dpi();
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
    park(restore_edge);
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

    set_canvas(Canvas::new(cw, ch));
    WIN_POS[0].store(x, Ordering::SeqCst);
    WIN_POS[1].store(y, Ordering::SeqCst);
    crate::float::remember(x, y);
    WIN_SIZE[0].store(cw, Ordering::SeqCst);
    WIN_SIZE[1].store(ch, Ordering::SeqCst);

    CARD_HWND.store(hwnd as isize, Ordering::SeqCst);
    commit(hwnd);
    arm_timer();
    let mut msg: MSG = std::mem::zeroed();
    while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    KillTimer(hwnd, TIMER_ID);
    TIMER_ON.store(false, Ordering::SeqCst);
    DestroyWindow(hwnd);
    set_canvas(None);
    CARD_HWND.store(0, Ordering::SeqCst);
}

/// 换掉画布：旧 Canvas 在这里析构（Drop 里释放 DC 与 DIB）。
fn set_canvas(next: Option<Canvas>) {
    if let Ok(mut slot) = CANVAS.lock() {
        *slot = next;
    }
}


unsafe fn commit(hwnd: HWND) {
    let mut guard = CANVAS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(canvas) = guard.as_mut() else { return };
    let (w, h) = (canvas.w, canvas.h);
    if w <= 0 || h <= 0 {
        return;
    }
    let hdc = canvas.mem;

    match panel() {
        Panel::Drop => draw_drop(hdc, w, h),
        Panel::Progress => draw_progress(hdc, w, h, phase()),
    }

    let radius = crate::ui::theme::RADIUS;
    let x = WIN_POS[0].load(Ordering::SeqCst);
    let y = WIN_POS[1].load(Ordering::SeqCst);
    // 白色底盘不参与淡入淡出：CPU 侧只把内容颜色往底盘色插值，
    // 整帧恒以 255 提交，底盘从第一帧起就完全不透明，圆角仍交给合成器。
    canvas.fade_content(COL_BG, FADE.load(Ordering::SeqCst).min(255) as u8);
    canvas.commit(
        hwnd,
        x,
        y,
        crate::ui::theme::px(radius, DPI.load(Ordering::SeqCst) as i32),
        255,
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

/// 卡片上唯一可点的两个位置（关闭叉 / 取消按钮），绘制和命中共用同一份几何。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Hit {
    None,
    Close,
    Cancel,
}

fn inside(r: (i32, i32, i32, i32), x: i32, y: i32) -> bool {
    x >= r.0 && x < r.2 && y >= r.1 && y < r.3
}

fn hit_test(x: i32, y: i32) -> Hit {
    if panel() == Panel::Drop {
        let w = WIN_SIZE[0].load(Ordering::SeqCst);
        if w <= 0 {
            return Hit::None;
        }
        if inside(close_rect(w), x, y) {
            Hit::Close
        } else {
            Hit::None
        }
    } else {
        if !matches!(phase(), Phase::Active | Phase::Waiting) {
            return Hit::None;
        }
        if inside(cancel_rect(), x, y) {
            Hit::Cancel
        } else {
            Hit::None
        }
    }
}

unsafe fn cursor_hover_hit() -> bool {
    let mut pt = POINT { x: 0, y: 0 };
    if GetCursorPos(&mut pt) == 0 {
        return false;
    }
    hit_test(
        pt.x - WIN_POS[0].load(Ordering::SeqCst),
        pt.y - WIN_POS[1].load(Ordering::SeqCst),
    ) != Hit::None
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
    let edge = parked_edge();
    if edge == crate::float::Edge::None
        || crate::float::is_dragging()
        || phase() == Phase::Hidden
        || !VISIBLE.load(Ordering::SeqCst)
    {
        return;
    }
    // 传输中要一直留在外面：正在跑的"缩回边"动画、以及 3 秒倒计时都立刻作废，
    // 否则会先缩一下再弹回来，看起来就是闪一下。
    let busy = busy_transfer();
    if busy {
        if ANIM_ON.swap(false, Ordering::SeqCst) {
            KillTimer(hwnd, ANIM_TIMER);
        }
        cancel_restore_tuck();
    } else if ANIM_ON.load(Ordering::SeqCst) || with_edge(|s| s.restore_at) != 0 {
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

    // 传输中（进度卡 / 等待确认）和刚传完的 3 秒里，不管鼠标在哪都展开，
    // 否则贴边时看不见进度、也看不见"已完成 / 失败"。
    let peek = crate::float::PEEK;
    let want = if busy || hold_expanded() || inside {
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
    park(edge);
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
    with_edge(|s| s.restore_at = if due == 0 { 1 } else { due });
}

fn cancel_restore_tuck() {
    with_edge(|s| s.restore_at = 0);
}

/// `at` 这个时刻到了没有（0 表示没设定）。用回绕比较，避免 49 天溢出。
fn reached(at: u32) -> bool {
    at != 0 && now_ms().wrapping_sub(at) < 0x8000_0000
}

/// 到期返回真（并把倒计时清掉，避免重复触发）。
fn restore_tuck_due() -> bool {
    with_edge(|s| {
        if !reached(s.restore_at) {
            return false;
        }
        s.restore_at = 0;
        true
    })
}

fn busy_transfer() -> bool {
    phase() == Phase::Waiting || (phase() == Phase::Active && panel() == Panel::Progress)
}

/// 还在"必须展开"的窗口里。注意是**未到期**，之前这里跟 `restore_tuck_due` 抄了同一个
/// 比较方向，导致 3 秒展示期其实是靠"淡出恰好在同一时刻开始"才没露馅。
fn hold_expanded() -> bool {
    with_edge(|s| s.hold_until != 0 && !reached(s.hold_until))
}

fn hold_expanded_for(ms: u32) {
    let due = now_ms().wrapping_add(ms);
    with_edge(|s| s.hold_until = if due == 0 { 1 } else { due });
}

fn cancel_hold() {
    with_edge(|s| s.hold_until = 0);
}

/// 拖到另一块缩放率不同的屏幕上：按新 DPI 重建画布与字体。
/// 之前只在建窗时取一次 `GetDpiForSystem`，跨屏移动后整张卡还是旧尺寸，字会糊。
unsafe fn resize_for_dpi(hwnd: HWND, dpi: i32, lparam: LPARAM) {
    if dpi <= 0 {
        return;
    }
    let old = DPI.swap(dpi as u32, Ordering::SeqCst);
    if old == dpi as u32 {
        return;
    }
    let suggested = &*(lparam as *const RECT);
    let cw = crate::ui::theme::px(CARD_W, dpi);
    let ch = crate::ui::theme::px(CARD_H, dpi);

    set_canvas(Canvas::new(cw, ch));
    WIN_SIZE[0].store(cw, Ordering::SeqCst);
    WIN_SIZE[1].store(ch, Ordering::SeqCst);
    WIN_POS[0].store(suggested.left, Ordering::SeqCst);
    WIN_POS[1].store(suggested.top, Ordering::SeqCst);
    SetWindowPos(
        hwnd,
        std::ptr::null_mut(),
        suggested.left,
        suggested.top,
        cw,
        ch,
        SWP_NOZORDER | SWP_NOACTIVATE,
    );

    // 字体是按像素高度缓存的，DPI 变了必须丢掉重建，否则还是旧字号。
    for slot in FONTS.iter() {
        let f = slot.swap(0, Ordering::SeqCst);
        if f != 0 {
            DeleteObject(f as _);
        }
    }
    commit(hwnd);
}

/// 隐藏后把刚才露在屏幕上的那条边重画一遍，避免分层窗口留下残影。
unsafe fn repaint_strip() {
    let w = WIN_SIZE[0].load(Ordering::SeqCst);
    let h = WIN_SIZE[1].load(Ordering::SeqCst);
    let (x, y) = (
        WIN_POS[0].load(Ordering::SeqCst),
        WIN_POS[1].load(Ordering::SeqCst),
    );
    let (left, top, right, bottom) = crate::float::work_area();
    let rect = RECT {
        left: x.max(left),
        top: y.max(top),
        right: (x + w).min(right),
        bottom: (y + h).min(bottom),
    };
    if rect.right <= rect.left || rect.bottom <= rect.top {
        return;
    }
    let desktop = GetDesktopWindow();
    InvalidateRect(desktop, &rect, 1);
    UpdateWindow(desktop);
}

unsafe fn start_restore_tuck(hwnd: HWND) {
    cancel_restore_tuck();
    let edge = parked_edge();
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

/// 展开到完整位置，但**保留**停靠边，让 3 秒后能自己缩回原来那条边。
unsafe fn show_expanded_keeping_edge(hwnd: HWND) {
    if ANIM_ON.swap(false, Ordering::SeqCst) {
        KillTimer(hwnd, ANIM_TIMER);
    }
    let edge = parked_edge();
    if edge == crate::float::Edge::None {
        show_expanded(hwnd);
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
}

/// 把缩在屏幕边上的浮窗整个展开，并重新给 3 秒后自动缩回。
///
/// 和启动时那条路径（`show_expanded_keeping_edge` + `arm_restore_tuck`）刻意保持一致：
/// 用户想要的是"让我看一眼"，不是把浮窗永久钉在桌面上。
unsafe fn reveal_now(hwnd: HWND) {
    if phase() == Phase::Hidden || !VISIBLE.load(Ordering::SeqCst) || busy_transfer() {
        return;
    }
    if parked_edge() == crate::float::Edge::None {
        // 自由浮动，本来就在外面。
        return;
    }
    show_expanded_keeping_edge(hwnd);
    hold_expanded_for(RESTORE_HOLD_MS);
    arm_restore_tuck();
}

unsafe fn show_expanded(hwnd: HWND) {

    if ANIM_ON.swap(false, Ordering::SeqCst) {
        KillTimer(hwnd, ANIM_TIMER);
    }

    cancel_restore_tuck();
    let edge = unpark();
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
    let already = with_model(|m| std::mem::replace(&mut m.canceled, true));
    if already {
        return;
    }
    if outgoing() {
        crate::outbound::request_cancel_send();
        crate::tray::log_line("[取消] 浮窗按钮：已请求取消发送");
    } else {
        crate::receive::request_cancel_recv();
        crate::tray::log_line("[取消] 浮窗按钮：已请求取消接收");
    }
    with_model(|m| {
        m.hover_cancel = false;
        m.phase = Phase::Failed;
        m.done_at = now_ms();
    });
    hold_expanded_for(RESTORE_HOLD_MS);
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
    let f = crate::ui::font::ui(height, weight);
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

    ui_draw::round_fill(hdc, x0, y0, x0 + s, y0 + s, px(7), COL_MEDIA);

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

    ui_draw::round_fill_stroke(hdc, fx, fy, fx + fw, fy + fh, px(6), COL_FILE_BODY, COL_FILE_LINE);

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
    ui_draw::circle_fill_stroke(hdc, cx, cy, r, COL_BG, COL_FILE_LINE);

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
    ui_draw::circle(hdc, cx, cy, r, COL_ERROR);

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

unsafe fn draw_progress(hdc: HDC, vw: i32, vh: i32, state: Phase) {
    let done = state == Phase::Done;
    let failed = state == Phase::Failed;
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

        ui_draw::circle(hdc, cx, cy, r, COL_ACCENT);

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

        let pct = pct().min(10000);
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

        if media_icon() {
            draw_media_icon(hdc, cx, cy, &px);
        } else {
            draw_file_icon(hdc, cx, cy, &px);
        }
    }

    let name = display_name();
    let shown = truncate(&name, 16);

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
        format!("已完成 · {}", human(total()))
    } else if failed {

        "传输失败".to_string()
    } else {
        let waiting = state == Phase::Waiting;
        let sp = speed_kb();
        if waiting {
            if is_preparing() {
                "正在准备中…".to_string()
            } else {
                "等待对方接收…".to_string()
            }
        } else if sp > 0 {
            format!(
                "{} / {} · {:.1} MB/s",
                human(received()),
                human(total()),
                sp as f64 / 1024.0
            )
        } else {
            format!(
                "{} / {}",
                human(received()),
                human(total())
            )
        }
    };
    let mut r1 = RECT { left, top: px(40), right, bottom: px(60) };
    let u1: Vec<u16> = sub.encode_utf16().collect();
    DrawTextW(hdc, u1.as_ptr(), u1.len() as i32, &mut r1, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    let f2 = font(2, px(22), FW_BOLD as i32);
    SelectObject(hdc, f2 as _);
    SetTextColor(hdc, COL_ACCENT);
    let waiting = state == Phase::Waiting;
    let pct_text = if done {
        "100%".to_string()
    } else if waiting || failed {

        String::new()
    } else {
        format!("{:.0}%", pct() as f64 / 100.0)
    };

    if !pct_text.is_empty() {
        let mut r2 = RECT { left, top: px(62), right, bottom: px(96) };
        let u2: Vec<u16> = pct_text.encode_utf16().collect();
        DrawTextW(hdc, u2.as_ptr(), u2.len() as i32, &mut r2, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
    }

    if !done && !failed && state != Phase::Hidden {
        let (bx1, by1, bx2, by2) = cancel_rect();
        let hover = hover_cancel();
        let bg_col = if hover { COL_BTN_HOVER_BG } else { COL_BTN_BG };
        ui_draw::round_fill(hdc, bx1, by1, bx2, by2, px(12), bg_col);
        if hover {
            ui_draw::round_stroke(
                hdc,
                bx1 + px(2),
                by1 + px(2),
                bx2 - px(2),
                by2 - px(2),
                px(10),
                COL_BG,
                px(1),
            );
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

/// 当前勾选的发送目标（可多台）。命中缓存时直接用，省掉一次锁 + 排序。
fn current_targets() -> Vec<crate::peers::PeerInfo> {
    let cached = TARGET_VIEW
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|v| v.selected.clone()));
    match cached {
        Some(list) if !list.is_empty() => list,
        _ => crate::peers::targets(),
    }
}

fn refresh_target_view() -> bool {
    let view = crate::peers::view(crate::peers::LIST_TTL);
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

unsafe fn draw_drop(hdc: HDC, vw: i32, vh: i32) {
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

    ui_draw::round_stroke(
        hdc,
        px(1),
        px(1),
        vw - px(1),
        vh - px(1),
        px(crate::ui::theme::RADIUS - 2),
        COL_BORDER,
        px(1),
    );

    let cxx = px(54);
    let cyy = px(54);
    let r = px(32);
    ui_draw::circle(hdc, cxx, cyy, r, COL_ICON_BG);

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

    let targets = current_targets();
    let sub = match targets.as_slice() {
        [] => "未选发送目标 · 托盘里挑一台".to_string(),
        [one] if !crate::peers::is_online(one) => {
            format!("{}（离线）", truncate(&one.name, 12))
        }
        [one]
            if crate::peers::verdict(&one.host) == Some(crate::peers::Verdict::Closed) =>
        {
            format!("{} 上次拒收了（可能没开华为分享）", truncate(&one.name, 12))
        }
        [one] => format!("发送给 {}", truncate(&one.name, 12)),
        [first, rest @ ..] => format!(
            "同时发送给 {} 等 {} 台",
            truncate(&first.name, 8),
            rest.len() + 1
        ),
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
        if hover_cancel() { COL_MAIN } else { COL_HINT },
    );
    let (x1, y1, x2, y2) = close_rect(vw);
    let mut r4 = RECT { left: x1, top: y1, right: x2, bottom: y2 };
    let t4: Vec<u16> = "✕".encode_utf16().collect();
    DrawTextW(hdc, t4.as_ptr(), t4.len() as i32, &mut r4, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
    SelectObject(hdc, old);
}

unsafe fn handle_drop(hdrop: *mut std::ffi::c_void) {
    let t_drop = std::time::Instant::now();
    let count = DragQueryFileW(hdrop, u32::MAX, std::ptr::null_mut(), 0);

    crate::tray::log_line(&format!("[drop] 收到 {count} 个路径"));
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
    crate::tray::log_line(&format!(
        "[drop] 取完路径 {} 个，耗时 {} ms",
        paths.len(),
        t_drop.elapsed().as_millis()
    ));
    if paths.is_empty() {
        return;
    }

    let targets = current_targets();
    if targets.is_empty() {
        crate::tray::alert(
            "还没选发送目标",
            "右键托盘图标 →「发送目标」里勾一台或多台。\n\n\
             列表里没有设备的话：先在手机上打开「华为分享」并保持亮屏，\
             等菜单里出现设备名再勾。",
        );
        return;
    }

    crate::tray::log_line(&format!(
        "[drop] 目标已定（{} 台：{}），准备发送，累计 {} ms",
        targets.len(),
        targets
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join("、"),
        t_drop.elapsed().as_millis()
    ));

    let count = targets.len();
    if let Err(e) = crate::dispatch::send_many(targets, paths, crate::tray::device_name()) {
        crate::tray::alert("发送失败", &e);
    } else if count > 1 {
        crate::tray::log_line(&format!("[drop] 已并发发往 {count} 台设备"));
    }
}

pub fn toggle_drop() {
    if phase() != Phase::Hidden {
        // 收起：先清 pinned，否则收尾逻辑会按「用户钉住的面板」把它叫回来。
        with_model(|m| {
            m.pinned = false;
            m.phase = Phase::Hidden;
        });
        // 贴边时窗口大部分在屏幕外，光靠淡出 + SW_HIDE 会留一条残影。
        HIDE_NOW.store(true, Ordering::SeqCst);
        return;
    }
    HIDE_NOW.store(false, Ordering::SeqCst);
    show_drop_panel();
}

pub fn hide_drop() {
    with_model(|m| {
        m.pinned = false;
        m.phase = Phase::Hidden;
    });
    HIDE_NOW.store(true, Ordering::SeqCst);
}

pub fn show_drop() {
    if phase() == Phase::Hidden {
        HIDE_NOW.store(false, Ordering::SeqCst);
        show_drop_panel();
        return;
    }
    // 已经可见，但很可能正缩在屏幕边上（只露一条边）。以前这里「可见就什么都不做」，
    // 于是重复双击 exe 时气泡说「已经帮你叫回来」，浮窗却一动不动。
    // 现在请求心跳把它整个展开，并重新起 3 秒倒计时——和启动时"先展开看 3 秒再缩回"同一套。
    REVEAL.store(true, Ordering::SeqCst);
    ensure_thread();
    arm_timer();
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
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

            if HIDE_NOW.swap(false, Ordering::SeqCst) {
                cancel_restore_tuck();
                with_model(|m| m.restore = None);
                cancel_hold();
                FADE.store(0, Ordering::SeqCst);
                FADE_TO.store(0, Ordering::SeqCst);
                if VISIBLE.swap(false, Ordering::SeqCst) {
                    ShowWindow(hwnd, SW_HIDE);
                    repaint_strip();
                }
                disarm_timer();
            }

            // 每 100 ms 重建视图（排序 + clone 整个列表）纯属浪费：
            // 只有 peers 变过（revision）或过了 1 秒（在线/离线会随时间变化）才需要。
            let now = now_ms();
            let view_dirty = with_model(|m| std::mem::replace(&mut m.view_dirty, false));
            let carousel_changed = tick_carousel(now);
            let stale = now.wrapping_sub(LAST_REFRESH_MS.load(Ordering::SeqCst)) >= 1000;
            let target_changed =
                if stale || crate::peers::revision() != LAST_TARGET_REV.load(Ordering::SeqCst) {
                    LAST_REFRESH_MS.store(now, Ordering::SeqCst);
                    refresh_target_view()
                } else {
                    false
                };
            let mut state = phase();

            if matches!(state, Phase::Done | Phase::Failed) {
                let t = done_at();
                if t != 0 && now.saturating_sub(t) > RESTORE_HOLD_MS {
                    // 结果卡展示完：回到进入传输前的形态。
                    // 以前这里无条件切回投放面板并把 pinned 置真，于是哪怕只是
                    // 被动接收了一个文件，屏幕上也会永久多出一块「把文件拖进这里」。
                    let back = with_model(|m| {
                        m.done_at = 0;
                        m.restore.take()
                    });
                    let keep_panel = after_done(back) == After::DropPanel;
                    with_model(|m| {
                        if keep_panel {
                            m.panel = Panel::Drop;
                            m.pinned = true;
                            m.phase = Phase::Active;
                            m.hover_cancel = false;
                        } else {
                            m.phase = Phase::Hidden;
                        }
                    });
                    FADE_TO.store(if keep_panel { 255 } else { 0 }, Ordering::SeqCst);
                    state = phase();
                    if keep_panel {
                        ensure_thread();
                        arm_timer();
                    }
                }
            }

            if state != Phase::Hidden && !VISIBLE.load(Ordering::SeqCst) {

                if STARTUP_RESTORE.swap(false, Ordering::SeqCst) {
                    arm_restore_tuck();
                } else if parked_edge() != crate::float::Edge::None {
                    // 上次是缩在边上的：先展开给你看，3 秒后再自己缩回去。
                    show_expanded_keeping_edge(hwnd);
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

                if !busy_transfer()
                    && !crate::float::is_dragging()
                    && panel() == Panel::Drop
                    && VISIBLE.load(Ordering::SeqCst)
                    && phase() != Phase::Hidden
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
                if state == Phase::Hidden && VISIBLE.swap(false, Ordering::SeqCst) {
                    ShowWindow(hwnd, SW_HIDE);
                    if TIMER_ON.swap(false, Ordering::SeqCst) {
                        KillTimer(hwnd, TIMER_ID);
                    }
                }
            }

            let pct = pct();
            let sp = speed_kb();
            let mode = panel() as u8;
            let prev_state = LAST_STATE.swap(state.code(), Ordering::SeqCst);
            let prev_pct = LAST_PCT.swap(pct, Ordering::SeqCst);
            let prev_sp = LAST_SPEED.swap(sp, Ordering::SeqCst);
            let prev_mode = LAST_MODE.swap(mode, Ordering::SeqCst);

            let hover = cursor_hover_hit();
            let prev_hover = set_hover_cancel(hover);
            let prev_alpha = LAST_ALPHA.swap(next, Ordering::SeqCst);

            if state == Phase::Hidden {

                if VISIBLE.load(Ordering::SeqCst) && FADE_TO.load(Ordering::SeqCst) != 0 {
                    FADE_TO.store(0, Ordering::SeqCst);
                }
            } else if prev_state != state.code()
                || prev_pct != pct
                || prev_sp != sp
                || prev_hover != hover
                || prev_mode != mode
                || prev_alpha != next
                || view_dirty
                || carousel_changed
                || target_changed
            {
                commit(hwnd);
            }
            tuck_tick(hwnd);
            if REVEAL.swap(false, Ordering::SeqCst) {
                reveal_now(hwnd);
            }
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
            let inside = hit_test(x, y) != Hit::None;

            if set_hover_cancel(inside) != inside {
                commit(hwnd);
            }
            0
        }
        WM_LBUTTONDOWN => {
            let (x, y) = (lo_word(lparam), lo_word(lparam >> 16));
            match hit_test(x, y) {
                Hit::Close => hide_idle(),
                Hit::Cancel => request_cancel(),
                Hit::None => {
                    if phase() != Phase::Hidden {
                        start_drag(hwnd);
                    }
                }
            }
            0
        }
        WM_RBUTTONUP => {

            if panel() == Panel::Drop && phase() != Phase::Hidden {
                crate::tray::send_clipboard_now(hwnd);
            }
            0
        }
        WM_LBUTTONDBLCLK => {

            if panel() == Panel::Drop && phase() != Phase::Hidden {
                crate::tray::open_or_pick_dest(hwnd);
            }
            0
        }
        WM_DROPFILES => {
            if panel() == Panel::Drop {
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
        WM_DPICHANGED => {
            let dpi = ((wparam >> 16) & 0xFFFF) as i32;
            resize_for_dpi(hwnd, dpi, lparam);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_codes_roundtrip() {
        for p in [
            Phase::Hidden,
            Phase::Active,
            Phase::Done,
            Phase::Waiting,
            Phase::Failed,
        ] {
            assert_eq!(Phase::from_code(p.code()), p);
        }
        assert_eq!(Phase::from_code(9), Phase::Hidden, "未知值一律当隐藏");
    }

    #[test]
    fn state_numbers_stay_stable() {
        // progress / tray 只按数字判断，别因为重构改了对外语义。
        assert_eq!(Phase::Hidden.code(), 0);
        assert_eq!(Phase::Active.code(), 1);
        assert_eq!(Phase::Done.code(), 2);
        assert_eq!(Phase::Waiting.code(), 3);
        assert_eq!(Phase::Failed.code(), 4);
    }

    #[test]
    fn parked_edge_survives_take() {
        park(crate::float::Edge::Right);
        assert_eq!(parked_edge(), crate::float::Edge::Right);
        assert_eq!(unpark(), crate::float::Edge::Right);
        assert_eq!(parked_edge(), crate::float::Edge::None, "取走后就不再是最外层");
        park(crate::float::Edge::None);
    }

    #[test]
    fn done_goes_back_to_where_it_came_from() {
        // 从钉住的投放面板发起：传完把面板还回去。
        assert_eq!(
            after_done(Some(Restore { panel: Panel::Drop, pinned: true })),
            After::DropPanel
        );
        // 被动接收（浮窗原本不可见）：收起，而不是留一块面板在屏幕上。
        assert_eq!(
            after_done(Some(Restore { panel: Panel::Progress, pinned: false })),
            After::Hidden
        );
        // 老路径没拍快照时也不能把面板叫回来。
        assert_eq!(after_done(None), After::Hidden);
    }

    #[test]
    fn restore_countdown_fires_once() {
        cancel_restore_tuck();
        assert!(!restore_tuck_due(), "没起倒计时时不该触发");

        arm_restore_tuck();
        assert!(!restore_tuck_due(), "刚起时还没到期");

        // 直接把到期时刻挪到过去，模拟 3 秒已过。
        with_edge(|s| s.restore_at = now_ms().wrapping_sub(10));
        assert!(restore_tuck_due(), "过期应当触发");
        assert!(!restore_tuck_due(), "触发一次后必须清掉，不能连发");
    }

    #[test]
    fn hold_window_expires() {
        cancel_hold();
        assert!(!hold_expanded());

        hold_expanded_for(RESTORE_HOLD_MS);
        assert!(hold_expanded());

        with_edge(|s| s.hold_until = now_ms().wrapping_sub(1));
        assert!(!hold_expanded(), "过了期限就不再强制展开");
        cancel_hold();
    }
}
