//! 字符串 → 宽字符 / 单行截断。Win32 的 `*W` 接口全要 NUL 结尾的 UTF-16。

/// NUL 结尾的 UTF-16，直接传给 `CreateWindowExW` / `AppendMenuW`（类名、标题、菜单）。
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 超过 `max` 个字符就截断并补一个省略号；截断处尾随空格会去掉（避免 "名字 …"）。
pub fn truncate(s: &str, max: usize) -> String {
    if max == 0 || s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    while out.ends_with(' ') {
        out.pop();
    }
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_is_nul_terminated() {
        let w = wide("华为Hi");
        assert_eq!(w.last().copied(), Some(0));
        assert_eq!(w.len(), 5, "华/为/H/i = 4 个码元 + NUL");
    }

    #[test]
    fn truncate_keeps_short_strings() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcde", 5), "abcde");
    }

    #[test]
    fn truncate_makes_room_for_ellipsis() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("ab   cd", 4), "ab…", "截断点的尾随空格要去掉");
        assert_eq!(truncate("中文名字很长", 3), "中文…");
    }
}
