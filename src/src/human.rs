//! 给用户看的数字格式。
//!
//! 收发两侧的完成提示都要报体积，以前各写一套 `"{:.1} MB"`：一张 500 KB 的图会
//! 显示成「0.0 MB」，一段剪贴板文本也是「0.0 MB」。看着像什么都没传过去，正是
//! 这类提示最容易挨骂的地方。所以按量级换单位，全程序只留这一份实现。

/// 字节数 → 人能读的大小：`512 B` / `48.3 KB` / `1.2 MB` / `3.4 GB`。
pub fn bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let v = n as f64;
    if v >= GB {
        format!("{:.2} GB", v / GB)
    } else if v >= MB {
        format!("{:.1} MB", v / MB)
    } else if v >= KB {
        format!("{:.1} KB", v / KB)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use super::bytes;

    #[test]
    fn picks_a_unit_that_never_rounds_to_zero() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(512), "512 B");
        // 这条是重点：500 KB 曾经显示成「0.0 MB」，像什么都没发过去。
        assert_eq!(bytes(512 * 1024), "512.0 KB");
        assert_eq!(bytes(1024 * 1024), "1.0 MB");
        assert_eq!(bytes(13 * 1024 * 1024), "13.0 MB");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
    }

    #[test]
    fn boundary_steps_up_a_unit() {
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1024), "1.0 KB");
        assert_eq!(bytes(1024 * 1024 - 1), "1024.0 KB", "差 1 字节仍按 KB 记");
    }
}
