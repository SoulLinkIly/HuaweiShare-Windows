//! 托盘右键菜单：构建菜单、设备行的文字、以及「开机自启动」「关于」这两项。
//!
//! 从 `tray.rs` 拆出来，避免一个文件里同时塞着图标、菜单、对话框和剪贴板四件事。
//!
//! 「发送目标」是二级菜单，里面每台设备一个勾选项，**可以同时勾多台**。
//! 注意 Windows 菜单点一下就整体关闭，所以勾完一台菜单会收起，再右键打开勾下一台；
//! 勾选状态会一直保留在 `peers::TARGETS` 里。

use crate::ui::text::wide;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{HWND, POINT};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use super::{context_text, log_line, message_box, notify, refresh_tooltip};

pub(super) const ID_OPEN: usize = 1001;
pub(super) const ID_ABOUT: usize = 1004;
pub(super) const ID_PICK_DIR: usize = 1008;

pub(super) const ID_AUTOSTART: usize = 1010;
pub(super) const ID_HISTORY_FILE: usize = 1011;

pub(super) const ID_SEND_BASE: usize = 1200;

pub(super) const ID_TARGET_BASE: usize = 1400;

pub(super) const MENU_PEER_CAP: usize = 64;

pub(super) const ID_TARGET_RESCAN: usize = 1464;
pub(super) const ID_TARGET_CLEAR: usize = 1465;

pub(super) const ID_TARGET_HINT: usize = 1466;

pub(super) const ID_SEND_NONE: usize = 1299;

pub(super) const ID_CLIP_BASE: usize = 1300;
pub(super) const ID_CLIP_NONE: usize = 1399;
pub(super) const ID_QUIT: usize = 1099;

pub(super) static MENU_PEERS: Mutex<Vec<crate::peers::PeerInfo>> = Mutex::new(Vec::new());

pub(super) fn kind_text(kind: &str) -> &'static str {
    match kind {
        "phone" => "手机",
        "tablet" => "平板",
        "computer" => "电脑",
        _ => "",
    }
}

pub(super) fn peer_name(p: &crate::peers::PeerInfo) -> String {
    let kind = kind_text(&p.kind);
    if kind.is_empty() {
        p.name.clone()
    } else {
        format!("{}（{}）", p.name, kind)
    }
}

/// 菜单里的一行设备：`名字（手机 · 离线）`。
///
/// 离线只写「离线」，不写「N 分钟前」——用户要的是能不能发，
/// 不是上次见到它是几点；超过 `LIST_TTL` 它自己会从列表里消失。
pub(super) fn peer_line(p: &crate::peers::PeerInfo) -> String {
    let online = p.seen.elapsed() <= crate::peers::ONLINE_WINDOW;
    let kind = kind_text(&p.kind);
    let mut detail: Vec<String> = Vec::new();
    if !kind.is_empty() {
        detail.push(kind.to_string());
    }
    if !online {
        detail.push("离线".to_string());
    } else {
        if !p.accepts {
            detail.push("对方关了华为分享".to_string());
        }
        if crate::peers::verdict(&p.host) == Some(crate::peers::Verdict::Closed) {
            detail.push("上次被拒".to_string());
        }
    }
    let line = if detail.is_empty() {
        p.name.clone()
    } else {
        format!("{}（{}）", p.name, detail.join(" · "))
    };
    menu_text(&line)
}

pub(super) fn menu_text(s: &str) -> String {
    s.replace('&', "&&")
        .replace('\t', " ")
        .replace('\n', " ")
        .replace('\r', " ")
}

/// 「发送目标」那一行的标题，也用在托盘提示里。`prefix` 是「发送目标：」或「发送给 」。
pub(super) fn target_summary(selected: &[crate::peers::PeerInfo], prefix: &str) -> String {
    match selected {
        [] => format!("{prefix}未选择"),
        [one] => {
            if one.seen.elapsed() <= crate::peers::ONLINE_WINDOW {
                format!("{prefix}{}", one.name)
            } else {
                format!("{prefix}{}（离线）", one.name)
            }
        }
        [first, rest @ ..] => format!("{prefix}{} 等 {} 台", first.name, rest.len() + 1),
    }
}

pub(super) unsafe fn build_menu() -> HMENU {
    let menu = CreatePopupMenu();
    if menu.is_null() {
        return menu;
    }

    let view = crate::peers::view(crate::peers::LIST_TTL);
    let peers = view.peers;
    let chosen = view.selected;

    if let Ok(mut slot) = MENU_PEERS.lock() {
        *slot = peers.clone();
    }

    // 「发送目标」二级菜单：每台设备一个勾选项，可以同时勾多台。
    let target_menu = CreatePopupMenu();
    if peers.is_empty() {
        AppendMenuW(
            target_menu,
            MF_STRING | MF_GRAYED,
            ID_TARGET_HINT,
            wide("未发现设备").as_ptr(),
        );
        AppendMenuW(
            target_menu,
            MF_STRING | MF_GRAYED,
            ID_TARGET_HINT,
            wide("① 手机/平板打开「华为分享」").as_ptr(),
        );
        AppendMenuW(
            target_menu,
            MF_STRING | MF_GRAYED,
            ID_TARGET_HINT,
            wide("② 保持亮屏，与本机同一 Wi-Fi").as_ptr(),
        );
    } else {
        for (index, peer) in peers.iter().enumerate() {
            let checked = chosen.iter().any(|c| c.host == peer.host);
            let offline = !crate::peers::is_online(peer);
            // 离线的勾不上（勾了也发不出去），但已经勾上的要留成可点的，
            // 否则设备一息屏用户就没法把它从目标里去掉。
            let flags = MF_STRING
                | if checked { MF_CHECKED } else { 0 }
                | if offline && !checked { MF_GRAYED } else { 0 };
            AppendMenuW(
                target_menu,
                flags,
                ID_TARGET_BASE + index,
                wide(&peer_line(peer)).as_ptr(),
            );
        }
    }
    AppendMenuW(target_menu, MF_SEPARATOR, 0, std::ptr::null());
    AppendMenuW(
        target_menu,
        MF_STRING,
        ID_TARGET_RESCAN,
        wide("重新扫描局域网").as_ptr(),
    );
    if !chosen.is_empty() {
        AppendMenuW(
            target_menu,
            MF_STRING,
            ID_TARGET_CLEAR,
            wide("清除选择（不指定目标）").as_ptr(),
        );
    }

    let mut label = target_summary(&chosen, "发送目标：");
    // 代选的不是用户选的：菜单上必须说清楚，否则"我没选过它啊"就是事故现场。
    if !chosen.is_empty() && crate::peers::auto_picked() {
        label.push_str("（自动）");
    }
    AppendMenuW(
        menu,
        MF_POPUP | MF_STRING,
        target_menu as usize,
        wide(&label).as_ptr(),
    );
    AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
    AppendMenuW(menu, MF_STRING, ID_OPEN, wide("打开接收文件夹").as_ptr());
    AppendMenuW(menu, MF_STRING, ID_PICK_DIR, wide("选择接收文件夹…").as_ptr());

    let submenu = CreatePopupMenu();
    if peers.is_empty() {
        AppendMenuW(
            submenu,
            MF_STRING | MF_GRAYED,
            ID_SEND_NONE,
            wide("未发现设备 · 先打开手机分享").as_ptr(),
        );
    } else {
        for (index, peer) in peers.iter().enumerate() {
            let flags = MF_STRING
                | if crate::peers::is_online(peer) {
                    0
                } else {
                    MF_GRAYED
                };
            AppendMenuW(
                submenu,
                flags,
                ID_SEND_BASE + index,
                wide(&peer_line(peer)).as_ptr(),
            );
        }
    }
    AppendMenuW(
        menu,
        MF_POPUP | MF_STRING,
        submenu as usize,
        wide("发送文件到手机").as_ptr(),
    );

    let clip_menu = CreatePopupMenu();
    if peers.is_empty() {
        AppendMenuW(
            clip_menu,
            MF_STRING | MF_GRAYED,
            ID_CLIP_NONE,
            wide("未发现设备 · 先打开手机分享").as_ptr(),
        );
    } else {
        for (index, peer) in peers.iter().enumerate() {
            let flags = MF_STRING
                | if crate::peers::is_online(peer) {
                    0
                } else {
                    MF_GRAYED
                };
            AppendMenuW(
                clip_menu,
                flags,
                ID_CLIP_BASE + index,
                wide(&peer_line(peer)).as_ptr(),
            );
        }
    }
    let clip_flags = MF_POPUP | MF_STRING | if peers.is_empty() { MF_GRAYED } else { 0 };
    AppendMenuW(
        menu,
        clip_flags,
        clip_menu as usize,
        wide("发送剪贴板文本").as_ptr(),
    );

    AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());

    let startup = crate::autostart::status();
    let startup_flags = MF_STRING | if startup.on() { MF_CHECKED } else { 0 };
    AppendMenuW(
        menu,
        startup_flags,
        ID_AUTOSTART,
        wide(&crate::autostart::menu_label(startup)).as_ptr(),
    );
    AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());

    // 传输记录不在菜单里摊开：一行一条，打开文件自己看（记事本/Excel 都行）。
    AppendMenuW(
        menu,
        MF_STRING,
        ID_HISTORY_FILE,
        wide("打开传输日志").as_ptr(),
    );

    AppendMenuW(menu, MF_STRING, ID_ABOUT, wide("关于").as_ptr());
    AppendMenuW(menu, MF_STRING, ID_QUIT, wide("退出").as_ptr());

    menu
}

pub(super) unsafe fn show_menu(hwnd: HWND) {
    refresh_tooltip();
    let menu = build_menu();
    if menu.is_null() {
        return;
    }
    let mut pt = POINT { x: 0, y: 0 };
    GetCursorPos(&mut pt);

    SetForegroundWindow(hwnd);
    let cmd = TrackPopupMenu(
        menu,
        TPM_RIGHTBUTTON | TPM_RETURNCMD,
        pt.x,
        pt.y,
        0,
        hwnd,
        std::ptr::null(),
    );
    DestroyMenu(menu);

    if cmd != 0 {
        super::run_command(hwnd, cmd as usize);
    }
}

pub(super) unsafe fn toggle_autostart(hwnd: HWND) {
    match crate::autostart::toggle() {
        Ok(true) => notify(
            "开机自启动",
            "已开启：下次登录 Windows 时自动启动，浮窗停在上次退出时的位置",
        ),
        Ok(false) => notify("开机自启动", "已关闭：登录时不再自动启动"),
        Err(e) => {
            log_line(&format!("[自启动] 切换失败：{e}"));
            message_box(hwnd, &format!("设置开机自启动失败：\n{e}"), MB_OK | MB_ICONWARNING);
        }
    }
}

pub(super) unsafe fn show_about(hwnd: HWND) {
    let ctx = context_text();
    let text = format!(
        "华为分享  v{}\n\n设备名：{}\n保存到：{}\n本机地址：{}\n\n制作者：LCH\n项目主页：https://github.com/SoulLinkIly/HuaweiShare-Windows\n\n第三方互操作性实现，与华为公司无隶属关系。\n按 GPL-3.0 分发，详见随附的 LICENSE。",
        env!("CARGO_PKG_VERSION"),
        ctx.name,
        ctx.dest,
        ctx.local
    );
    MessageBoxW(
        hwnd,
        wide(&text).as_ptr(),
        wide("关于 华为分享").as_ptr(),
        MB_OK | MB_ICONINFORMATION,
    );
}
