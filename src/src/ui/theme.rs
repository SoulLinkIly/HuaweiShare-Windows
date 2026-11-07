//! 全局视觉常量。
//!
//! 三张卡片（常驻浮窗 / 接收确认 / 一次性通知）共用一套颜色与圆角，
//! 只保留尺寸差异（浮窗小、对话框大），避免各自定义后慢慢漂移。

/// 卡片底色（也是图标内部使用的「留白」色）。
pub const BG: u32 = 0x00FF_FFFF;
/// 主要文字。
pub const MAIN: u32 = 0x001A_1A1A;
/// 次要文字。
pub const SUB: u32 = 0x0093_8E8E;
/// 分隔线 / 进度轨道。
pub const LINE: u32 = 0x00EA_E5E5;
/// 按钮悬停底色。
pub const HOVER: u32 = 0x00F7_F2F2;
/// 强调色（进度环、百分比、主按钮文字、提示条左侧倒计时条）。
///
/// #0067C0，取自 Windows 11 自带的强调色板（accent_dark_1）。用系统同源的蓝有两个
/// 好处：一是它在白底上够沉，3px 的竖条不会刺眼；二是它跟资源管理器、设置页里的
/// 蓝是同一个观感，不会显得「外来」。
///
/// 曾经是 #007AFF（iOS 蓝）——太亮，白底上像荧光笔。另外提示条一度自己另定了一个
/// #1565D8，同一个屏幕上出现两种蓝，看着像两套设计。强调色只能有一个。
pub const ACCENT: u32 = 0x00C0_67_00;
/// 失败红。
pub const ERROR: u32 = 0x0030_3BFF;

pub const MEDIA: u32 = 0x0035_C734;
pub const FILE_BODY: u32 = 0x00F6_F5F7;
pub const FILE_LINE: u32 = 0x00D6_D4DA;
pub const ASK: u32 = 0x0078_747D;

/// 投放面板的圆形图标底。
pub const ICON_BG: u32 = 0x00FF_F2EA;
/// 投放面板描边。
pub const BORDER: u32 = 0x00E6_E2E9;
/// 关闭叉。
pub const HINT: u32 = 0x00B4_B0B8;

pub const BTN_BG: u32 = 0x00E1_DDF9;
pub const BTN_TEXT: u32 = 0x007A_70C2;
pub const BTN_HOVER_BG: u32 = 0x00EA_E7FC;

/// 卡片圆角（96 dpi 下的逻辑像素）。三张卡片统一。
pub const RADIUS: i32 = 22;

/// 界面字体。
pub const FACE: &str = "Microsoft YaHei UI";

/// 逻辑像素 → 物理像素。
pub fn px(v: i32, dpi: i32) -> i32 {
    v * dpi.max(96) / 96
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn px_scales_with_dpi() {
        assert_eq!(px(20, 96), 20);
        assert_eq!(px(20, 120), 25);
        assert_eq!(px(20, 0), 20, "dpi 取不到时按 96 处理，不能除出 0");
    }

    #[test]
    fn palette_is_consistent() {
        // 三张卡片过去各有一份 COL_SUB，值不一样；现在只有一个来源。
        assert_eq!(SUB, 0x0093_8E8E);
        assert_eq!(RADIUS, 22);
    }
}
