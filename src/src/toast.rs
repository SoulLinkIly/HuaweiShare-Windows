#![cfg(windows)]

//! 右下角提示条。
//!
//! 系统托盘气泡有两件事管不了：Win11 的专注助手/通知设置能把整条吞掉（实测就被
//! 吞过一次），样式也完全交给系统——Win10 与 Win11 两套长相，用不上本项目的配色。
//! 所以这里自己画一条：右下角、最多叠三条、五秒自动消失、鼠标停上去暂停、点一下关掉。
//!
//! 只接管「轻提示」（`tray::notify` 那条通道）。需要用户点「好」才能继续的错误仍然
//! 走 `alert` 的居中模态卡——那种场景要的是拦一下，不是飘一下。
//!
//! **谁该发提示**（这条以前没人管，结果发送成功有提示、接收成功一条都没有）：
//!
//! - 用户没盯着屏幕、但结果需要他知道的：收发完成、收发失败、取消、排队 → 飘一条；
//! - 需要用户马上做决定的（没勾目标、启动就失败）→ 走 `alert` 居中拦一下；
//! - 用户自己刚做的动作（亲手点了「拒绝」）→ 不飘，复述一遍纯属噪音；
//! - 同一件事只飘一条：一次接收里既有文件又有剪贴板时，由
//!   `receive::toast_for` 合成一句，不许各模块各弹一张互相打脸的卡。
//!
//! 分工：生产者只做「入队 + `PostThreadMessageW` 叫醒」，一个常驻线程负责建窗、
//! 绘制、计时、销毁。不把绘制塞进托盘窗口线程，是为了不让通知拖慢菜单响应。
//!
//! 不做的事（明确取舍）：不进系统通知中心（关掉就没了，历史去 `transfers.log` 看）、
//! 不读系统勿扰状态（真要静音请设 `HWSHARE_TOAST=0` 回到系统气泡）。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    DeleteObject, DrawTextW, GetMonitorInfoW, MonitorFromPoint, SelectObject, SetBkMode,
    SetTextColor, DT_END_ELLIPSIS, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER, MONITORINFO,
    MONITOR_DEFAULTTOPRIMARY, TRANSPARENT,
};
use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{TrackMouseEvent, TRACKMOUSEEVENT};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, GetSystemMetrics,
    GetWindowLongPtrW, PeekMessageW, PostThreadMessageW, SetTimer, SetWindowLongPtrW, SetWindowPos,
    ShowWindow, TranslateMessage, MSG, SWP_NOACTIVATE, SW_SHOWNOACTIVATE,
};

use crate::layered::Canvas;
use crate::ui::draw as ui_draw;
use crate::ui::font::{ui as ui_font, WEIGHT_NORMAL};
use crate::ui::popup;
use crate::ui::theme;

const CLASS: &str = "HWShareToast";

/// 卡片尺寸（逻辑像素，按 DPI 换算）。宽度取 364：够放两行中文正文又不至于
/// 盖住右下角的桌面图标区。
const CARD_W: i32 = 364;
const CARD_H: i32 = 84;
/// 卡片四周留给投影的透明边。窗口比卡片大两倍这个值，圆角与投影都按「卡片矩形」算。
const SHADOW_PAD: i32 = 14;
const MARGIN: i32 = 20;
const GAP: i32 = 12;
const RADIUS_LOGICAL: i32 = 14;
/// 左侧强调条宽度。
const BAR_W: i32 = 3;
/// 强调条上下内缩（逻辑像素）。
const BAR_INSET: i32 = 19;

/// 卡片底色/描边/文字。这三组是提示条自己的取色，比 `theme::SUB` 深一档——
/// 12px 浅灰在 100% 缩放的屏上就是糊成一片，正文必须够黑才看得清。
const CARD_BG: u32 = 0x00FF_FFFF;
const CARD_BG_HOVER: u32 = 0x00FD_FA_FB;
const CARD_BORDER: u32 = 0x00EC_E2_E7;
/// #14101A
const TEXT_TITLE: u32 = 0x001A_10_14;
/// #45404B，白底上约 9:1。14px 的雅黑小字经灰度抗锯齿会整体发灰，
/// 颜色必须比「看起来合适」再深一档，实际读起来才不费劲。
const TEXT_BODY: u32 = 0x004B_40_45;
/// 倒计时条直接用强调色，不再自己另定一个蓝。
///
/// 之前这里是 #1565D8，而浮窗、确认框、通知卡用的是 `theme::ACCENT` #007AFF——
/// 同屏两种蓝，看着像两套设计。强调色全程序只能有一个。
const BAR_COLOR: u32 = theme::ACCENT;

const FONT_TITLE: i32 = 16;
const FONT_BODY: i32 = 15;
/// 投影不透明度上限（0..=255）。34 ≈ 13%，浅色桌面上有层次又不显脏。
const SHADOW_ALPHA: u8 = 34;
/// 投影垂直偏移：光从上方来，影子略微向下。
const SHADOW_OFFSET_Y: i32 = 2;

/// 同屏最多几条。再多就看不清了，而且会从屏幕底部往上铺满半个桌面。
const MAX_ON_SCREEN: usize = 3;
/// 排队上限。超出丢最旧的——通知不是日志，丢掉一条不影响正确性。
const PENDING_MAX: usize = 16;

const TTL: Duration = Duration::from_millis(5200);
const FADE_IN: Duration = Duration::from_millis(140);
const FADE_OUT: Duration = Duration::from_millis(200);
/// 鼠标移开后至少再留这么久，免得一移开就看不见了。
const MIN_AFTER_HOVER: Duration = Duration::from_millis(400);
const TICK_MS: u32 = 30;

const EX_STYLE: u32 = 0x0000_0008   // WS_EX_TOPMOST
    | 0x0008_0000                    // WS_EX_LAYERED
    | 0x0000_0080                    // WS_EX_TOOLWINDOW：不进 Alt-Tab
    | 0x0800_0000; // WS_EX_NOACTIVATE：绝不抢焦点

const WM_ERASEBKGND: u32 = 0x0014;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_MOUSELEAVE: u32 = 0x02A3;
const WM_TIMER: u32 = 0x0113;
const WM_DESTROY: u32 = 0x0002;
/// 叫醒提示线程。放 `WM_APP` 之后，避免和窗口自己的消息撞号。
const WM_TOAST_WAKE: u32 = 0x8000 + 0x31;

const GWLP_USERDATA: i32 = -21;
const TME_LEAVE: u32 = 0x0000_0002;
const SWP_NOZORDER: u32 = 0x0004;
const HWND_TOPMOST: HWND = -1isize as HWND;

// ---------------------------------------------------------------- 队列

struct Item {
    title: String,
    body: String,
}

impl Item {
    fn same(&self, other: &Item) -> bool {
        self.title == other.title && self.body == other.body
    }
}

#[derive(Default)]
struct Pending {
    items: VecDeque<Item>,
}

impl Pending {
    /// 入队。返回 `false` 表示「已经有一条一模一样的」，生产方什么都不用做。
    ///
    /// 去重是真需求：勾选目标、切接收目录这类操作会被连点，同一个提示连飘三条
    /// 既难看又盖住后面真正重要的那条。
    fn push(&mut self, item: Item) -> bool {
        if self.items.iter().any(|i| i.same(&item)) {
            return false;
        }
        if self.items.len() >= PENDING_MAX {
            self.items.pop_front();
        }
        self.items.push_back(item);
        true
    }

    fn pop(&mut self) -> Option<Item> {
        self.items.pop_front()
    }
}

static PENDING: Mutex<Pending> = Mutex::new(Pending { items: VecDeque::new() });
/// 提示线程 id。0 表示还没起来（或起不来）。
static THREAD: AtomicU32 = AtomicU32::new(0);
static BOOTED: AtomicBool = AtomicBool::new(false);
/// 建窗失败过一次就记下来：之后所有提示直接回落到系统气泡，不在死路上反复撞。
static BROKEN: AtomicBool = AtomicBool::new(false);
/// 当前在屏的窗口。存 `isize` 而不是 `HWND`：`*mut c_void` 不是 `Send`，
/// 塞不进静态量。只在提示线程里读写。
static SHOWING: Mutex<Vec<isize>> = Mutex::new(Vec::new());

// ---------------------------------------------------------------- 对外

/// 投递一条提示。返回 `false` 表示「这条没接」，调用方应回落到系统气泡。
pub fn push(title: &str, body: &str) -> bool {
    if !enabled() || BROKEN.load(Ordering::SeqCst) {
        return false;
    }
    if !boot() {
        return false;
    }
    if let Ok(mut q) = PENDING.lock() {
        q.push(Item { title: title.to_string(), body: body.to_string() });
    }
    let tid = THREAD.load(Ordering::SeqCst);
    if tid == 0 {
        return false;
    }
    unsafe { PostThreadMessageW(tid, WM_TOAST_WAKE, 0, 0) };
    true
}

/// `HWSHARE_TOAST=0` 关掉自绘提示，退回系统气泡。留这个开关是因为总有人
/// 更信任系统通知（比如要靠通知中心回溯）。
fn enabled() -> bool {
    !matches!(std::env::var("HWSHARE_TOAST"), Ok(v) if v.trim() == "0")
}

/// 起一次提示线程；已经起过就直接返回。
fn boot() -> bool {
    if BOOTED.swap(true, Ordering::SeqCst) {
        // 已经起过：等它把线程 id 填上（正常是瞬间的事）。
        for _ in 0..200 {
            if THREAD.load(Ordering::SeqCst) != 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        return false;
    }

    // 线程起来就立刻回一个「就绪」，不等消息循环结束——循环是不退出的。
    // （第一版写成循环结束后才 send，boot 必然超时，于是每条提示都静悄悄
    //  回落到系统气泡，看起来像「新功能没生效」。）
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    let spawned = std::thread::Builder::new()
        .name("hwshare-toast".to_string())
        .spawn(move || {
            if !run(tx) {
                BROKEN.store(true, Ordering::SeqCst);
            }
        });
    if spawned.is_err() {
        BROKEN.store(true, Ordering::SeqCst);
        return false;
    }
    rx.recv_timeout(Duration::from_millis(300)).unwrap_or(false)
}

// ---------------------------------------------------------------- 线程

fn run(ready: std::sync::mpsc::Sender<bool>) -> bool {
    crate::tray::enable_dpi_awareness();
    popup::register_class(CLASS, Some(wndproc), 0);

    // 先逼出本线程的消息队列，再公布线程 id——否则 PostThreadMessage 会打到空处。
    // 必须用 `PeekMessageW`（非阻塞）：`GetMessageW` 会一直等到有消息才返回，
    // 线程就卡在这儿，「就绪」信号永远发不出去。
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, 0);
    }
    THREAD.store(unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() }, Ordering::SeqCst);
    let _ = ready.send(true);
    unsafe { SetTimer(std::ptr::null_mut(), 0, TICK_MS, None) };

    loop {
        let mut msg: MSG = unsafe { std::mem::zeroed() };
        let got = unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) };
        if got <= 0 {
            break;
        }
        match msg.message {
            WM_TOAST_WAKE => tick(),
            WM_TIMER => tick(),
            _ => unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            },
        }
    }
    true
}

fn tick() {
    let now = Instant::now();
    let work = work_area();

    let snapshot: Vec<isize> = SHOWING.lock().map(|l| l.clone()).unwrap_or_default();
    for (index, &raw) in snapshot.iter().enumerate() {
        let hwnd = raw as HWND;
        let state = state_of(hwnd);
        if state.is_null() {
            continue;
        }
        let st = unsafe { &mut *state };

        // 上面哪条消失了，剩下的要贴回底部——每帧按当前序号重算位置。
        let (x, y) = slot_rect(work, st.w, st.h, index, st.dpi);
        if x != st.x || y != st.y {
            st.x = x;
            st.y = y;
            unsafe {
                SetWindowPos(hwnd, std::ptr::null_mut(), x, y, st.w, st.h, SWP_NOZORDER | SWP_NOACTIVATE);
            }
        }

        // 悬停时把 deadline 一段段往前顶，等价于冻结剩余时间。
        // 放在 tick 里而不是只靠 mousemove：鼠标停住不动时不会有新消息，
        // 若只在事件里续期，卡片照样会自己溜走。
        if st.hovered {
            if let Some(f) = st.frozen {
                st.deadline = now + f;
            }
        }
        if st.closing.is_none() && !st.hovered && now >= st.deadline {
            st.closing = Some(now);
        }
        let alpha = st.alpha(now);
        // 只有「淡出结束」才销毁。淡入的第一帧 alpha 也是 0，早先按 `alpha == 0`
        // 判定，结果每张卡片刚建出来就被自己删掉，屏幕上什么也看不到。
        if st.closing.is_some() && alpha == 0 {
            unsafe { DestroyWindow(hwnd) };
            continue;
        }
        // 只有「刚重画过」或「不透明度变了」才推位图。停留期间唯一的动静是进度条。
        let mut push = false;
        if st.dirty {
            render(st, now);
            st.dirty = false;
            push = true;
        }
        // 倒计时条按整像素推进：TTL 5.2s 走完一条 70px 的条，大约 70ms 挪一格，
        // 30ms 的时钟下就是两三帧重画一次，既有动感又不至于每帧重传位图。
        let ratio = bar_ratio(st.remaining(now));
        let bar_px = (bar_span(st.dpi, st.h) as f32 * ratio).round() as i32;
        if bar_px != st.bar_px {
            if let Some(canvas) = st.canvas.as_mut() {
                unsafe { paint_bar(canvas, st.dpi, st.h, st.hovered, ratio) };
            }
            st.bar_px = bar_px;
            push = true;
        }
        if st.last_alpha != alpha {
            push = true;
        }
        if push {
            if let Some(canvas) = st.canvas.as_mut() {
                let radius = theme::px(RADIUS_LOGICAL, st.dpi);
                unsafe { canvas.commit(hwnd, st.x, st.y, radius, alpha) };
                st.last_alpha = alpha;
            }
        }
    }

    // 空出位置就把队列里的搬上来。
    let on_screen = SHOWING.lock().map(|l| l.len()).unwrap_or(0);
    for slot in on_screen..MAX_ON_SCREEN {
        let item = PENDING.lock().ok().and_then(|mut q| q.pop());
        let Some(item) = item else { break };
        show(item, slot);
    }
}

fn show(item: Item, index: usize) {
    let dpi = popup::system_dpi();
    let win_w = CARD_W + SHADOW_PAD * 2;
    let win_h = CARD_H + SHADOW_PAD * 2;
    let w = theme::px(win_w, dpi);
    let h = theme::px(win_h, dpi);
    let (x, y) = slot_rect(work_area(), w, h, index, dpi);

    let Some(win) = popup::create_layered(
        CLASS,
        "华为分享",
        (win_w, win_h),
        EX_STYLE,
        popup::Placement::At(x, y),
    ) else {
        // 建不出窗口就别死撑：置位后调用方回落到系统气泡。
        BROKEN.store(true, Ordering::SeqCst);
        crate::report::log("[提示] 自绘提示窗创建失败，已退回系统气泡");
        return;
    };

    let st_title = item.title.clone();
    let font_title = unsafe { ui_font(theme::px(FONT_TITLE, dpi), WEIGHT_NORMAL) };
    let font_body = unsafe { ui_font(theme::px(FONT_BODY, dpi), WEIGHT_NORMAL) };
    let now = Instant::now();
    let mut canvas = unsafe { Canvas::new(win.w, win.h) };
    if let Some(c) = canvas.as_mut() {
        c.pad = theme::px(SHADOW_PAD, dpi);
        c.manual_alpha = true;
    }
    let mut st = Box::new(CardState {
        canvas,
        title: item.title,
        body: item.body,
        dpi,
        w: win.w,
        h: win.h,
        x: win.x,
        y: win.y,
        born: now,
        deadline: now + TTL,
        closing: None,
        hovered: false,
        dirty: true,
        last_alpha: 0,
        bar_px: -1,
        frozen: None,
        font_title: font_title as isize,
        font_body: font_body as isize,
    });
    st.apply_real_dpi(win.hwnd);

    unsafe {
        SetWindowLongPtrW(win.hwnd, GWLP_USERDATA, Box::into_raw(st) as isize);
        ShowWindow(win.hwnd, SW_SHOWNOACTIVATE);
    }
    crate::trace::note("toast", &format!("显示提示：{}", st_title));
    if let Ok(mut list) = SHOWING.lock() {
        list.push(win.hwnd as isize);
    }
    tick();
}

fn state_of(hwnd: HWND) -> *mut CardState {
    unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut CardState }
}

struct CardState {
    canvas: Option<Canvas>,
    title: String,
    body: String,
    dpi: i32,
    w: i32,
    h: i32,
    x: i32,
    y: i32,
    born: Instant,
    deadline: Instant,
    closing: Option<Instant>,
    hovered: bool,
    dirty: bool,
    /// 上一帧提交时的不透明度。没变化就不必再推一次位图——
    /// 停留的那五秒里每 30ms 重传一张 392×128 的位图纯属浪费。
    last_alpha: u8,
    /// 上一次画的倒计时条像素高度。只有整像素变化才重画，
    /// 否则每 30ms 刷一次整窗，白烧 CPU。
    bar_px: i32,
    /// 鼠标移上来那一刻冻结的剩余时长，移开后从这里接着走。
    frozen: Option<Duration>,
    font_title: isize,
    font_body: isize,
}

impl CardState {
    /// 窗口落在别的缩放比例的显示器上时，按那块屏的 DPI 重算尺寸。
    /// 不这么做，副屏 150% 上会得到一张小一号、字还发虚的卡片。
    fn apply_real_dpi(&mut self, hwnd: HWND) {
        let real = unsafe { GetDpiForWindow(hwnd) } as i32;
        if real <= 0 || real == self.dpi {
            return;
        }
        let w = theme::px(CARD_W + SHADOW_PAD * 2, real);
        let h = theme::px(CARD_H + SHADOW_PAD * 2, real);
        self.dpi = real;
        self.w = w;
        self.h = h;
        self.canvas = unsafe { Canvas::new(w, h) };
        if let Some(c) = self.canvas.as_mut() {
            c.pad = theme::px(SHADOW_PAD, real);
            c.manual_alpha = true;
        }
        self.dirty = true;
        self.last_alpha = 0;

        unsafe {
            for f in [self.font_title, self.font_body] {
                if f != 0 {
                    DeleteObject(f as _);
                }
            }
        }
        self.font_title = unsafe { ui_font(theme::px(FONT_TITLE, real), WEIGHT_NORMAL) } as isize;
        self.font_body = unsafe { ui_font(theme::px(FONT_BODY, real), WEIGHT_NORMAL) } as isize;
        let (x, y) = slot_rect(work_area(), w, h, 0, real);
        self.x = x;
        self.y = y;
        unsafe {
            SetWindowPos(hwnd, HWND_TOPMOST, x, y, w, h, SWP_NOACTIVATE);
        }
    }

    /// 还剩多久自动收。悬停期间 `deadline` 被冻住，所以这里也跟着停。
    fn remaining(&self, now: Instant) -> Duration {
        if self.closing.is_some() {
            return Duration::ZERO;
        }
        self.deadline.saturating_duration_since(now)
    }

    fn alpha(&self, now: Instant) -> u8 {        if let Some(start) = self.closing {
            let e = now.saturating_duration_since(start).as_millis();
            let total = FADE_OUT.as_millis().max(1);
            if e >= total {
                return 0;
            }
            return (255 * (total - e) / total) as u8;
        }
        let e = now.saturating_duration_since(self.born).as_millis();
        let total = FADE_IN.as_millis().max(1);
        if e < total {
            (255 * e / total) as u8
        } else {
            255
        }
    }
}

// ---------------------------------------------------------------- 绘制

/// 剩余时间占 TTL 的比例，0..=1。抽成纯函数好测。
fn bar_ratio(remain: Duration) -> f32 {
    let total = TTL.as_millis().max(1) as f32;
    (remain.as_millis() as f32 / total).clamp(0.0, 1.0)
}

/// 倒计时条可用高度（物理像素）：卡片内高减去上下内缩。
fn bar_span(dpi: i32, h_win: i32) -> i32 {
    let pad = theme::px(SHADOW_PAD, dpi);
    let inset = theme::px(BAR_INSET, dpi);
    ((h_win - 2 * pad) - 2 * inset).max(0)
}

/// 重画左侧倒计时条这一小块。
///
/// 蓝色锚在**底部**，顶边随剩余时间往下退，收到没有时正好开始淡出。
/// 只碰这条竖条的矩形，不重画文字——所以动画期间每帧的代价就是几十次 FillRect。
unsafe fn paint_bar(canvas: &mut Canvas, dpi: i32, h_win: i32, hovered: bool, ratio: f32) {
    let hdc = canvas.mem;
    let px = |v: i32| theme::px(v, dpi);
    let pad = px(SHADOW_PAD);
    let x = pad + px(14);
    let w = px(BAR_W);
    let top = pad + px(BAR_INSET);
    let bottom = h_win - pad - px(BAR_INSET);
    let bg = if hovered { CARD_BG_HOVER } else { CARD_BG };

    // 先把整条擦回底色，再画蓝色那一段，避免上一帧的蓝留在下面。
    ui_draw::fill(hdc, x, top, x + w, bottom, bg);
    let h = ((bottom - top) as f32 * ratio).round() as i32;
    if h > 0 {
        // 锚在**底部**：蓝色顶边往下退，像水位下降。锚顶部时蓝色的底边往上收，
        // 看起来是「往上漏」，跟「还剩多久」的直觉反了。
        ui_draw::fill(hdc, x, bottom - h, x + w, bottom, BAR_COLOR);
    }
    // 上面两次 FillRect 把这几列的 alpha 写成了 0，补回不透明。全量重画时
    // `reset_alpha` 会兜住，但 tick 里只重画这一小块，不补就会被当成半透明，
    // 蓝条和白底混成淡蓝——一根条出现深浅两截，正是「两种蓝」的来源。
    canvas.set_alpha_rect(x, top, w, bottom - top, 255);
}

/// 画一张卡片。
///
/// 三层，从下往上：投影（黑，alpha 渐变）→ 卡片（白底 + 圆角）→ 内容。
/// 投影不靠描边凑，而是逐像素按到圆角矩形的距离算 alpha，所以边缘是连续渐变的。
fn render(st: &mut CardState, now: Instant) {
    // 先取值再借画布：`st` 一被 `as_mut` 借走，就不能再读它的字段了。
    let hovered = st.hovered;
    let ratio = bar_ratio(st.remaining(now));
    let bar_px = (bar_span(st.dpi, st.h) as f32 * ratio).round() as i32;
    let Some(canvas) = st.canvas.as_mut() else { return };
    let (w, h) = (canvas.w, canvas.h);
    let hdc = canvas.mem;
    let dpi = st.dpi;
    let px = |v: i32| theme::px(v, dpi);

    let pad = px(SHADOW_PAD);
    let (x1, y1, x2, y2) = (pad, pad, w - pad, h - pad);
    let radius = px(RADIUS_LOGICAL);

    unsafe {
        // 整幅先垫黑：投影区底色是黑，alpha 稍后由 paint_shadow 补上。
        ui_draw::fill(hdc, 0, 0, w, h, 0x0000_0000);

        let bg = if hovered { CARD_BG_HOVER } else { CARD_BG };
        // 底盘铺成**直角**矩形，圆角交给掩码裁。若改用 RoundRect 直接画白圆角，
        // 圆角外侧那圈像素仍是黑底，被掩码做成半透明后就成了卡片四周的脏边。
        ui_draw::fill(hdc, x1, y1, x2, y2, bg);

        // 左侧倒计时条：蓝的部分就是还能停留多久，走完即开始淡出。
        paint_bar(canvas, dpi, h, hovered, ratio);

        // 1px 描边压在底色上，浅色桌面上也能看出卡片边界。
        ui_draw::round_stroke(hdc, x1, y1, x2, y2, radius * 2, CARD_BORDER, 1);

        SetBkMode(hdc, TRANSPARENT as i32);

        let text_left = x1 + px(28);
        let text_right = x2 - px(20);

        SelectObject(hdc, st.font_title as _);
        SetTextColor(hdc, TEXT_TITLE);
        let mut r0 = RECT { left: text_left, top: y1 + px(12), right: text_right, bottom: y1 + px(38) };
        let u0: Vec<u16> = st.title.encode_utf16().collect();
        DrawTextW(hdc, u0.as_ptr(), u0.len() as i32, &mut r0, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);

        SelectObject(hdc, st.font_body as _);
        SetTextColor(hdc, TEXT_BODY);
        // 正文只留一行：提示条是一眼扫过的东西，两行反而把卡片撑高、字又要缩小。
        // 放不下的尾部用省略号收——完整内容在 transfers.log 里。
        let mut r1 = RECT { left: text_left, top: y1 + px(39), right: text_right, bottom: y2 - px(11) };
        let u1: Vec<u16> = st.body.encode_utf16().collect();
        DrawTextW(hdc, u1.as_ptr(), u1.len() as i32, &mut r1, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);

        // 关键：alpha 必须在这一步才复位。GDI 的 FillRect / DrawText 在 32 位 DIB 上
        // 会把 alpha 字节写成 0，若复位放在绘制之前，文字就成了透明的——表现出来
        // 就是「有些字淡得像没画上」。放到这里，内容已经画完，复位不会抹掉任何东西，
        // 随后 paint_shadow 再按距离把卡片外侧的 alpha 压下去。
        canvas.reset_alpha();
        canvas.paint_shadow(radius, px(SHADOW_OFFSET_Y), SHADOW_ALPHA);
        // 存一份原色，供 commit 反复重做圆角混合。
        canvas.freeze();
    }
    st.bar_px = bar_px;
}

// ---------------------------------------------------------------- 位置

/// 右下角第 `index` 条窗口的位置（从 0 起，0 最靠底）。
///
/// 传进来的是**窗口**尺寸（卡片 + 两侧投影留白），摆位却要按**卡片**算，
/// 所以右下各让出一个 `pad`：窗口比卡片多出来的透明边不该把卡片从桌边推开。
///
/// 纯函数：多显示器与任务栏位置全靠传进来的工作区，好测也好改。
fn slot_rect(work: (i32, i32, i32, i32), w: i32, h: i32, index: usize, dpi: i32) -> (i32, i32) {
    let (left, top, right, bottom) = work;
    let pad = theme::px(SHADOW_PAD, dpi);
    let margin = theme::px(MARGIN, dpi);
    let gap = theme::px(GAP, dpi);
    let card_h = h - 2 * pad;
    let x = right - w + pad - margin;
    let y = bottom - h + pad - margin - index as i32 * (card_h + gap);
    (x.max(left), y.max(top))
}

/// 鼠标所在那块显示器的工作区（排除任务栏）。任务栏在上/左/右都能贴对。
fn work_area() -> (i32, i32, i32, i32) {
    unsafe {
        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        let mon = MonitorFromPoint(pt, MONITOR_DEFAULTTOPRIMARY);
        let mut info: MONITORINFO = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        if GetMonitorInfoW(mon, &mut info) != 0 {
            let r = info.rcWork;
            return (r.left, r.top, r.right, r.bottom);
        }
        // 兜底：主屏整块。宁可压一点任务栏，也别把提示画到屏幕外。
        (0, 0, GetSystemMetrics(0), GetSystemMetrics(1))
    }
}

// ---------------------------------------------------------------- 窗口过程

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_MOUSEMOVE => {
            let state = state_of(hwnd);
            if !state.is_null() {
                let st = &mut *state;
                if !st.hovered {
                    st.hovered = true;
                    st.dirty = true;
                    // 冻住剩余时间，而不是把 deadline 一直往后推：
                    // 进度条应该停在原地，否则鼠标一上去就弹回满格，看着像倒退。
                    st.frozen = Some(st.deadline.saturating_duration_since(Instant::now()));
                }
                let mut track = TRACKMOUSEEVENT {
                    cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
                    dwFlags: TME_LEAVE,
                    hwndTrack: hwnd,
                    dwHoverTime: 0,
                };
                TrackMouseEvent(&mut track);
            }
            0
        }
        WM_MOUSELEAVE => {
            let state = state_of(hwnd);
            if !state.is_null() {
                let st = &mut *state;
                st.hovered = false;
                st.dirty = true;
                // 从冻结点接着走，进度条不会跳。留 400ms 下限，免得刚移开就消失。
                let remain = st.frozen.take().unwrap_or(TTL);
                st.deadline = Instant::now() + remain.max(MIN_AFTER_HOVER);
            }
            0
        }
        WM_LBUTTONDOWN => {
            // 点一下立刻收：不该逼用户等它自己飘走。
            let state = state_of(hwnd);
            if !state.is_null() {
                let st = &mut *state;
                if st.closing.is_none() {
                    st.closing = Some(Instant::now());
                }
            }
            0
        }
        WM_ERASEBKGND => 1,
        WM_DESTROY => {
            let state = state_of(hwnd);
            if !state.is_null() {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                let st = Box::from_raw(state);
                for f in [st.font_title, st.font_body] {
                    if f != 0 {
                        DeleteObject(f as _);
                    }
                }
            }
            if let Ok(mut list) = SHOWING.lock() {
                list.retain(|h| *h != hwnd as isize);
            }
            0
        }
        _ => windows_sys::Win32::UI::WindowsAndMessaging::DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(t: &str, b: &str) -> Item {
        Item { title: t.to_string(), body: b.to_string() }
    }

    #[test]
    fn same_text_is_dropped_once() {
        let mut q = Pending::default();
        assert!(q.push(item("接收目录已更新", "D:\\收")));
        assert!(!q.push(item("接收目录已更新", "D:\\收")), "连点两次只该飘一条");
        assert!(q.push(item("接收目录已更新", "E:\\收")), "内容不同就是两条");
        assert_eq!(q.items.len(), 2);
    }

    #[test]
    fn queue_drops_the_oldest_beyond_cap() {
        let mut q = Pending::default();
        for i in 0..(PENDING_MAX + 5) {
            q.push(item("t", &format!("第 {i} 条")));
        }
        assert_eq!(q.items.len(), PENDING_MAX, "上限必须收住，否则会攒一堆过期提示");
        assert_eq!(q.items.front().unwrap().body, "第 5 条", "丢的是最旧的");
    }

    #[test]
    fn slots_stack_upward_from_bottom_right() {
        let work = (0, 0, 1920, 1040);
        // 传进去的是窗口尺寸，卡片本身比窗口小一圈（投影留白）。
        let (w, h) = (CARD_W + SHADOW_PAD * 2, CARD_H + SHADOW_PAD * 2);
        let (x0, y0) = slot_rect(work, w, h, 0, 96);
        assert_eq!(x0 + SHADOW_PAD + CARD_W, 1920 - MARGIN, "贴的是卡片的边，不是窗口的边");
        assert_eq!(y0 + SHADOW_PAD + CARD_H, 1040 - MARGIN, "同上：投影留白不占边距");

        let (_, y1) = slot_rect(work, w, h, 1, 96);
        assert_eq!(y0 - y1, CARD_H + GAP, "第二条要落在第一条正上方，间距按卡片高度算");

        // 150% 屏：边距、间距、投影留白一起放大，不能还按 96 DPI 的数值贴边。
        let (w, h) = (w * 3 / 2, h * 3 / 2);
        let (x, y) = slot_rect(work, w, h, 1, 144);
        assert_eq!(x, 1920 - w + SHADOW_PAD * 3 / 2 - MARGIN * 3 / 2);
        assert_eq!(y, 1040 - h + SHADOW_PAD * 3 / 2 - MARGIN * 3 / 2 - (CARD_H * 3 / 2 + GAP * 3 / 2));
    }

    #[test]
    fn slot_never_leaves_a_short_work_area() {
        // 极端情况：工作区比窗口还小（缩放很大的小屏）。别把坐标算成负数。
        let work = (0, 0, 300, 200);
        let (x, y) = slot_rect(work, CARD_W + SHADOW_PAD * 2, CARD_H + SHADOW_PAD * 2, 2, 96);
        assert_eq!((x, y), (0, 0));
    }





    #[test]
    fn bar_ratio_runs_from_full_to_empty() {
        assert_eq!(bar_ratio(TTL), 1.0, "刚出现是满格");
        assert!((bar_ratio(TTL / 2) - 0.5).abs() < 0.01, "过半时约一半");
        assert_eq!(bar_ratio(Duration::ZERO), 0.0, "时间用完条也空了");
        assert_eq!(bar_ratio(TTL * 3), 1.0, "意外多给的时间不能画出超长的条");
    }

    #[test]
    fn fade_in_reaches_full_then_fades_out_to_zero() {
        let now = Instant::now();
        let mk = |born_offset: Duration, closing: Option<Duration>| CardState {
            canvas: None,
            title: String::new(),
            body: String::new(),
            dpi: 96,
            w: CARD_W,
            h: CARD_H,
            x: 0,
            y: 0,
            born: now - born_offset,
            deadline: now,
            closing: closing.map(|d| now - d),
            hovered: false,
            dirty: false,
            last_alpha: 0,
            bar_px: -1,
            frozen: None,
            font_title: 0,
            font_body: 0,
        };
        assert_eq!(mk(Duration::ZERO, None).alpha(now), 0, "刚出现是全透明");
        assert_eq!(mk(FADE_IN, None).alpha(now), 255, "淡入结束是实心");
        assert_eq!(mk(TTL, None).alpha(now), 255, "停留期间不变");
        let half = FADE_OUT / 2;
        let mid = mk(TTL, Some(half)).alpha(now);
        assert!(mid > 0 && mid < 255, "淡出是渐变的，实际 {mid}");
        assert_eq!(mk(TTL, Some(FADE_OUT)).alpha(now), 0, "淡出结束必须归零，否则窗口收不掉");
    }
}
