//! 字体：浮窗 / 确认框 / 通知卡 / 右下角提示条**全部**走 [`ui`]，一个字体族、一种渲染方式。
//!
//! 为什么只有一个入口：以前提示条用「圆润」那一档（优先 HarmonyOS Sans），三张卡片用
//! 微软雅黑。同一块屏幕上两种字形，标题的「横」粗细都不一样，看着像两个程序的界面。
//! 字体回退是**整段生效**的：只要字体族不同，标点宽度、数字宽度、字重都会跟着变，
//! 这没法靠调字号补回来。
//!
//! 默认选谁：微软雅黑 UI。理由是装机率——Win8 起随系统预装，Win10/11 是标配，中文
//! 桌面软件（微信、QQ、WPS）几乎都用它；它的 hinting 也是中文字体里最完整的，小字号
//! 最不容易发虚。鸿蒙 / MiSans 这些手机厂字体观感更圆，但桌面装机率极低，拿它当默认
//! 会让「装了的人一个样、没装的人另一个样」，正是要避免的分叉。想用的话设
//! `HWSHARE_FONT` 点名即可，不用改代码。

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::LPARAM;
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, EnumFontFamiliesExW, GetDC, GetTextFaceW, ReleaseDC, SelectObject,
    CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS, DEFAULT_CHARSET, DEFAULT_PITCH, FF_DONTCARE,
    GB2312_CHARSET, LOGFONTW, OUT_DEFAULT_PRECIS, TEXTMETRICW,
};

/// 常规字重（`FW_NORMAL`）。
pub const WEIGHT_NORMAL: i32 = 400;
/// 加粗（`FW_BOLD`）。
pub const WEIGHT_BOLD: i32 = 700;

/// 字体族的回退顺序。前两个是 Windows 自带、覆盖 Vista 至今所有中文系统；
/// 后面三个只在「精简系统把雅黑删了」这种极端情况才会用到。
///
/// 顺序即优先级，**不是**按系统枚举顺序——枚举出来的次序跟注册表安装时间有关，
/// 换台机器就变，不能依赖。
const FAMILIES: &[&str] = &[
    // Win8 起自带；Win10/11 中文界面默认就是它。
    "Microsoft YaHei UI",
    // Vista / Win7 只有这个不带 UI 的变体，度量基本一致。
    "Microsoft YaHei",
    // 下面的只做兜底：万一雅黑被精简掉了，至少落到一个像样的黑体，
    // 而不是让 GDI 自己映射到宋体（宋体在 15px 下笔画细得像掉渣）。
    "HarmonyOS Sans SC",
    "MiSans",
    "SimHei",
];

/// 系统里装了的字体族名，只枚举一次。
static FACES: OnceLock<Vec<String>> = OnceLock::new();
/// 按 [`FAMILIES`] 优先级挑出来的那个；`None` 表示一个都没装。
static PICKED: OnceLock<Option<&'static str>> = OnceLock::new();
/// 定下来的字体族名（可能是环境变量指定的）。
static CHOSEN: OnceLock<String> = OnceLock::new();
/// 实际生效的字体只写一行日志，别每建一次字体就刷一条。
static LOGGED: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn collect(
    lf: *const LOGFONTW,
    _tm: *const TEXTMETRICW,
    _ty: u32,
    lp: LPARAM,
) -> i32 {
    let out = &mut *(lp as *mut Vec<String>);
    let p = (*lf).lfFaceName.as_ptr();
    let mut n = 0usize;
    while n < 32 && *p.add(n) != 0 {
        n += 1;
    }
    out.push(String::from_utf16_lossy(std::slice::from_raw_parts(p, n)));
    1
}

fn installed_faces() -> &'static [String] {
    FACES.get_or_init(|| {
        let mut names: Vec<String> = Vec::new();
        unsafe {
            // 用屏幕 DC 枚举：字体是机器级的，跟哪个窗口无关。
            let hdc = GetDC(std::ptr::null_mut());
            if hdc.is_null() {
                return names;
            }
            let mut lf: LOGFONTW = std::mem::zeroed();
            // 必须是 DEFAULT_CHARSET：中文字体的 charset 五花八门（GB2312 / 136 / 1），
            // 按 GB2312 筛会漏掉 HarmonyOS Sans 这类只声明 DEFAULT 的。
            lf.lfCharSet = DEFAULT_CHARSET as u8;
            EnumFontFamiliesExW(hdc, &lf, Some(collect), &mut names as *mut _ as LPARAM, 0);
            ReleaseDC(std::ptr::null_mut(), hdc);
        }
        names
    })
}

/// 从「系统里有哪些」和「我们想要哪些」里挑第一个命中的。大小写不敏感——
/// 字体族名在注册表里的写法不一定和文档一致（`HarmonyOS Sans SC` vs `harmonyos sans sc`）。
fn pick<'a>(have: &[String], want: &[&'a str]) -> Option<&'a str> {
    want.iter()
        .copied()
        .find(|w| have.iter().any(|f| f.eq_ignore_ascii_case(w)))
}

/// 按优先级挑一个装了的。一个都没有就返回 `None`，交给 `theme::FACE` 让 GDI 映射。
fn picked_face() -> Option<&'static str> {
    *PICKED.get_or_init(|| pick(installed_faces(), FAMILIES))
}

/// 最终用哪个字体族，按优先级决定：
///
/// 1. `HWSHARE_FONT`（兼容旧名 `HWSHARE_TOAST_FACE`）——想换成鸿蒙、MiSans、思源
///    或者任何装了的中文字体，点名就行，不用等我们改代码；
/// 2. [`FAMILIES`] 里第一个装了的；
/// 3. `theme::FACE`（雅黑 UI），再交给 GDI 映射。
fn chosen_face() -> &'static str {
    CHOSEN.get_or_init(|| {
        for key in ["HWSHARE_FONT", "HWSHARE_TOAST_FACE"] {
            if let Ok(v) = std::env::var(key) {
                let v = v.trim();
                if !v.is_empty() {
                    return v.to_string();
                }
            }
        }
        picked_face()
            .unwrap_or(crate::ui::theme::FACE)
            .to_string()
    })
}

/// 首次建字体时，把「想要谁」和「GDI 实际给了谁」一起记下来。
///
/// 字体名打错、或者系统里确实没有，`CreateFontW` 不会失败——它悄悄替换成某个默认
/// 字体。用户反馈「字还是糊 / 字形不对」时，这一行日志能直接看出是不是被替换了。
unsafe fn log_actual(hf: *mut c_void) {
    if LOGGED.swap(true, Ordering::SeqCst) {
        return;
    }
    let want = chosen_face();
    let hdc = GetDC(std::ptr::null_mut());
    if hdc.is_null() {
        return;
    }
    let old = SelectObject(hdc, hf);
    let mut nb = [0u16; 64];
    let n = GetTextFaceW(hdc, 64, nb.as_mut_ptr());
    SelectObject(hdc, old);
    ReleaseDC(std::ptr::null_mut(), hdc);
    // 返回的是**含结尾 0** 的长度，直接切片会让名字末尾带个 \0，比较永远不等。
    let end = (n.max(0) as usize).min(64);
    let end = end.min(nb.iter().position(|&c| c == 0).unwrap_or(end));
    let actual = String::from_utf16_lossy(&nb[..end]);
    if actual.eq_ignore_ascii_case(want) {
        crate::report::log(&format!("[提示] 字体：{actual}"));
    } else {
        crate::report::log(&format!(
            "[提示] 字体：{want} 取不到，系统换成了 {actual}"
        ));
    }
}

/// 全程序唯一的建字体入口。`px` 是**已按 DPI 缩放过的**物理像素高度
/// （调用方用 `ui::theme::px` 换算）。
///
/// 渲染质量固定 `CLEARTYPE_QUALITY`：这几块界面都是不透明白底（提示条的投影在卡片
/// 外侧，文字区不受影响），正是次像素渲染擅长的场景。同一字号下比灰度抗锯齿饱满
/// 一圈——小字发虚有一半是灰度 AA 把边缘磨掉的。
///
/// 调用方负责在 DPI 变化时 `DeleteObject` 掉旧句柄——GDI 不会自动回收。
pub unsafe fn ui(px: i32, weight: i32) -> *mut c_void {
    let face = chosen_face();
    let name: Vec<u16> = face.encode_utf16().chain(std::iter::once(0)).collect();
    let hf = CreateFontW(
        -px.max(1),
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
        CLEARTYPE_QUALITY as u32,
        (DEFAULT_PITCH | FF_DONTCARE) as u32,
        name.as_ptr(),
    );
    log_actual(hf);
    hf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weights_match_win32() {
        // 这两个值来自 wingdi.h 的 FW_NORMAL / FW_BOLD，别凭印象改。
        assert_eq!(WEIGHT_NORMAL, 400);
        assert_eq!(WEIGHT_BOLD, 700);
    }

    fn have(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn prefers_the_font_everyone_has() {
        // 雅黑是默认答案：装了鸿蒙也还是选雅黑，否则同屏两台机器两种字形。
        assert_eq!(
            pick(&have(&["HarmonyOS Sans SC", "Microsoft YaHei UI"]), FAMILIES),
            Some("Microsoft YaHei UI")
        );
        assert_eq!(
            pick(&have(&["MiSans", "Microsoft YaHei"]), FAMILIES),
            Some("Microsoft YaHei")
        );
    }

    #[test]
    fn falls_back_when_yahei_is_missing() {
        // 精简系统把雅黑删了：至少落到一个像样的黑体，别让 GDI 映射成宋体。
        assert_eq!(
            pick(&have(&["HarmonyOS Sans SC", "SimSun"]), FAMILIES),
            Some("HarmonyOS Sans SC")
        );
        assert_eq!(
            pick(&have(&["SimHei", "SimSun"]), FAMILIES),
            Some("SimHei")
        );
    }

    #[test]
    fn picks_by_priority_not_by_install_order() {
        // 枚举顺序跟注册表安装时间有关，换台机器就变；结果必须只看 FAMILIES 的顺序。
        assert_eq!(
            pick(&have(&["SimHei", "Microsoft YaHei", "Microsoft YaHei UI"]), FAMILIES),
            Some("Microsoft YaHei UI")
        );
    }

    #[test]
    fn picks_nothing_when_none_are_installed() {
        // 极端系统（精简版 / 早期 Win7）：一个都没有，交给 theme::FACE，
        // 再由 GDI 自己映射（实测会落到宋体，中文仍能显示）。
        assert_eq!(pick(&have(&["SimSun", "Arial"]), FAMILIES), None);
    }

    #[test]
    fn face_matching_ignores_case() {
        assert_eq!(
            pick(&have(&["microsoft yahei ui"]), FAMILIES),
            Some("Microsoft YaHei UI"),
            "族名大小写不同也得认出来"
        );
    }
}
