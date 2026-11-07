//! 接收侧的「剪贴板文本」：名叫 `Huawei Share.txt` 的文件不落盘，直接进系统剪贴板。
//!
//! 三条纪律，改之前先看清：
//! 1. 只认 basename（`子目录/Huawei Share.txt` 也算），忽略大小写与首尾空白；
//!    不做前缀/模糊匹配——多认一个名字，就可能把用户的真实文件吞掉。
//! 2. 全程内存：不调 `create_part_atomic`，不产生 `.part`，不产生任何临时文件。
//! 3. 任何失败只影响「这次有没有复制成功」，绝不让传输本身失败：字节已经按协议
//!    收完，剪贴板只是附带投递。

use super::ClipInfo;

/// 单条文本最多在内存里留多少。超过就停止缓冲（仍继续计数），
/// 既不撑爆接收进程，也不影响协议收尾。
pub(super) const MAX_BYTES: usize = 4 * 1024 * 1024;

/// 华为分享「分享文本」时用的固定文件名。
pub(super) const TARGET_NAME: &str = "Huawei Share.txt";

/// 这个清单项是不是「剪贴板文本」。
pub(super) fn is_target(name: &str) -> bool {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
    base.eq_ignore_ascii_case(TARGET_NAME)
}

/// 字节 → 文本。第二个返回值表示解码是否有损（只用于日志，不影响投递）。
pub(super) fn decode(bytes: &[u8]) -> (String, bool) {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return match std::str::from_utf8(rest) {
            Ok(text) => (text.to_string(), false),
            Err(_) => (String::from_utf8_lossy(rest).to_string(), true),
        };
    }
    // 带 BOM 的 UTF-16：记事本与部分鸿蒙版本会这么存文本。
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return decode_utf16(rest, true);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return decode_utf16(rest, false);
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_string(), false),
        // 非 UTF-8 最常见的是 GBK。没有码表就不猜，按 UTF-8 有损处理：
        // 内容还在，用户能看出哪儿不对，好过整段丢掉。
        Err(_) => (String::from_utf8_lossy(bytes).to_string(), true),
    }
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> (String, bool) {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect();
    let mut lossy = bytes.len() % 2 != 0;
    let mut text = String::with_capacity(units.len());
    for decoded in char::decode_utf16(units) {
        match decoded {
            Ok(ch) => text.push(ch),
            Err(_) => {
                text.push('\u{FFFD}');
                lossy = true;
            }
        }
    }
    (text, lossy)
}

/// 把收到的字节投递到剪贴板，返回结果（写日志、落历史备注都用它）。
///
/// `overflow` 为真表示内容超过 [`MAX_BYTES`]，缓冲已被丢弃；
/// `received` 是协议层实际收到的字节数，用于统计与历史记录。
pub(super) fn deliver(raw: &[u8], overflow: bool, received: u64) -> ClipInfo {
    let bytes = received as usize;

    if overflow {
        let reason = format!("文本超过 {} MiB，未写入剪贴板", MAX_BYTES / 1048576);
        crate::trace::note("file#1", &reason);
        crate::report::log(&format!("[剪贴板] {reason}"));
        return ClipInfo { bytes, chars: 0, ok: false, skipped: false, reason };
    }

    let (text, lossy) = decode(raw);
    let chars = text.chars().count();
    if text.trim().is_empty() {
        // 空文本不改写剪贴板：用户手上原有的内容比「空」更有价值。
        let reason = "内容为空，未改写剪贴板".to_string();
        crate::trace::note("file#1", &reason);
        crate::report::log(&format!("[剪贴板] {reason}"));
        // `skipped`：这不是失败，是「没什么可放的」。收尾提示据此不报警。
        return ClipInfo { bytes, chars, ok: false, skipped: true, reason };
    }

    match copy_to_clipboard(&text) {
        Ok(()) => {
            let note = if lossy { "（编码不是 UTF-8，已按有损方式解码）" } else { "" };
            crate::trace::note("file#1", &format!("已把 {chars} 个字符写入剪贴板{note}"));
            crate::report::log(&format!("[剪贴板] 已复制 {chars} 个字符{note}"));
            ClipInfo { bytes, chars, ok: true, skipped: false, reason: String::new() }
        }
        Err(e) => {
            crate::trace::note("file#1", &format!("写剪贴板失败：{e}"));
            crate::report::log(&format!("[剪贴板] 写入失败：{e}"));
            let reason = format!("剪贴板写入失败：{e}");
            ClipInfo { bytes, chars, ok: false, skipped: false, reason }
        }
    }
}

/// 真正写系统剪贴板。失败只返回原因，由 [`deliver`] 记进 `ClipInfo`，
/// **不在这里弹提示**——一次接收可能同时有文件和文本，两条提示会互相打脸，
/// 该由会话出口（`receive::toast_for`）合成一条。
#[cfg(windows)]
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    crate::clipboard::write_text(text)
}

#[cfg(not(windows))]
fn copy_to_clipboard(_text: &str) -> Result<(), String> {
    Err("当前平台不支持剪贴板".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_basename_counts() {
        assert!(is_target("Huawei Share.txt"));
        assert!(is_target("huawei share.TXT"), "Windows 上文件名不区分大小写");
        assert!(is_target("  子目录/Huawei Share.txt  "), "带路径也要认");
        assert!(is_target(r"C:\a\b\Huawei Share.txt"));

        assert!(!is_target("Huawei Share.txt.bak"));
        assert!(!is_target("我的 Huawei Share.txt"));
        assert!(!is_target("HuaweiShare.txt"));
        assert!(!is_target("Huawei Share.txt/"), "目录名不是文件");
        assert!(!is_target(""));
    }

    #[test]
    fn decode_handles_bom_and_plain_utf8() {
        assert_eq!(decode("你好".as_bytes()).0, "你好");
        assert!(!decode("你好".as_bytes()).1);
        assert_eq!(decode(&[0xEF, 0xBB, 0xBF, b'h', b'i']).0, "hi", "UTF-8 BOM 要去掉");
        assert_eq!(decode(&[0xEF, 0xBB, 0xBF, b'h', b'i']).1, false);
    }

    #[test]
    fn decode_handles_both_utf16_orders() {
        let mut le = vec![0xFF, 0xFE];
        for unit in "文本".encode_utf16() {
            le.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(decode(&le).0, "文本");

        let mut be = vec![0xFE, 0xFF];
        for unit in "文本".encode_utf16() {
            be.extend_from_slice(&unit.to_be_bytes());
        }
        assert_eq!(decode(&be).0, "文本");

        let odd = [0xFF, 0xFE, 0x41];
        assert!(decode(&odd).1, "半个 u16 要标记为有损");
    }

    #[test]
    fn decode_never_panics_on_garbage() {
        let (text, lossy) = decode(&[0xFF, 0xFE, 0x00, 0xD8, 0x41, 0x00]);
        assert!(lossy, "孤立代理项必须走有损");
        assert!(text.contains('\u{FFFD}'), "{text}");
        assert!(decode(&[0x80, 0x81, 0x82]).1, "非法 UTF-8 走有损");
    }

    #[test]
    fn overflow_and_empty_report_reasons() {
        let big = deliver(&[], true, 5 * 1024 * 1024);
        assert!(!big.ok);
        assert!(big.reason.contains("4 MiB"), "{}", big.reason);
        assert_eq!(big.bytes, 5 * 1024 * 1024);

        let empty = deliver(b"   \r\n", false, 5);
        assert!(!empty.ok, "空白内容不许覆盖用户剪贴板");
        assert!(empty.skipped, "空内容只是「没什么可放」，不是失败");
        assert!(empty.reason.contains("为空"), "{}", empty.reason);
        assert!(!big.skipped, "超限是真的没投递成功");
    }
}
