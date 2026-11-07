//! 接收流程编排：opening 握手 → 会话轮询落盘 → 记历史（确认结果由调用方传入）。

mod cancel;
mod clip;
mod dfile;
mod manifest;
mod opening_payload;
mod paths;

use cancel::{RECV_CANCEL_TAG, RECV_CANCEL_WAIT, clear_recv_cancel, recv_cancel_requested, take_pending_cancel};
#[cfg(test)]
use cancel::{describe_control_body, describe_wire_frame, hex_head};
use dfile::run_session_once;
use dfile::wire::dump_tlvs;
use manifest::{ack_manifest, merge_manifest};
#[cfg(test)]
use manifest::MAX_MANIFEST;
use opening_payload::accept_connection_inner;
use paths::{ActiveFile, Finished, create_part_atomic};
#[cfg(test)]
use paths::{part_path, safe_rel_segments, sanitize, unique_path};

pub use cancel::{record_drained, request_cancel_recv};

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::channel::Channel;
use crate::{Error, Result};

const POLL: Duration = Duration::from_micros(500);

const DRAIN_LIMIT: usize = 64;

const DRAIN_BUDGET: Duration = Duration::from_millis(30);
const PEER_META_FRAME: u32 = 0xFFFF_0002;
const PEER_META_ACK_FRAME: u32 = 0xFFFF_0008;
const PEER_META_ACK_JSON: &[u8] = b"META_DEVICE_INFO_ACK\0";
const CHANNEL_BYTES: u32 = 0xFFFF_0004;

pub struct Session {
    pub file_count: u32,
    pub folders: u32,
    pub total_bytes: u64,
    pub session_key: [u8; 32],
    pub device_hash: Vec<u8>,
    pub peer: String,
    pub accepted: bool,

    pub peer_apple: bool,
}

/// 一次「剪贴板文本」投递的结果。
///
/// 这类文件不落盘，所以它不会出现在 `saved` 里；但历史、日志、CLI 输出都得
/// 知道这次到底收到了什么、复制成没成。
#[derive(Debug, Clone)]
pub struct ClipInfo {
    /// 协议层收到的字节数
    pub bytes: usize,
    /// 解码后的字符数（没投递成功时为 0）
    pub chars: usize,
    /// 是否真的写进了剪贴板
    pub ok: bool,
    /// 没写成功的原因；成功时为空串
    pub reason: String,
    /// 跳过（内容为空）：既不算成功也不算失败，收尾时不该报警。
    pub skipped: bool,
}

pub struct ReceiveResult {
    pub saved: Vec<PathBuf>,
    pub bytes: u64,
    /// 会话里收到的剪贴板文本（不落盘）。`None` 表示这次没有这种文件。
    pub clip: Option<ClipInfo>,
}

pub fn accept_connection(
    channel: &mut Channel,
    private: &rsa::RsaPrivateKey,
    accept: bool,
    timeout: Duration,
) -> Result<Session> {
    let local = channel.local_ip().unwrap_or_default();

    if channel.label() == "chan" {
        channel.set_label("control");
    }
    let result = accept_connection_inner(channel, private, accept, timeout);
    match &result {
        Ok(session) => crate::trace::session_start(
            "recv",
            &session.peer,
            &local,
            session.file_count as usize,
            session.total_bytes,
        ),
        Err(e) => crate::trace::note("control", &format!("认证/握手失败: {e}")),
    }
    result
}

pub fn run_session(
    session: &Session,
    control: &mut Channel,
    destination: &Path,
    display_name: &str,
    timeout: Duration,
) -> Result<ReceiveResult> {
    let started = Instant::now();

    let progress = Arc::new(AtomicU64::new(0));
    let outcome = run_session_once(session, control, destination, display_name, timeout, &progress);
    let received = progress.load(Ordering::Relaxed);

    let outcome = outcome.map_err(|e| {
        let msg = e.to_string();
        if received == 0 || msg.contains("已收") || msg.contains("取消") {
            return e;
        }
        let suffix = format!("（已收 {:.1} MB）", received as f64 / 1048576.0);

        match e {
            Error::Io(m) => Error::Io(format!("{m}{suffix}")),
            Error::Network(m) => Error::Network(format!("{m}{suffix}")),
            Error::Rejected(m) => Error::Rejected(format!("{m}{suffix}")),
            other => Error::Protocol(format!("{other}{suffix}")),
        }
    });
    let mut files: Vec<(String, u64)> = match &outcome {
        Ok(result) => result
            .saved
            .iter()
            .filter_map(|p| {
                let name = p.file_name()?.to_string_lossy().to_string();
                let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                Some((name, size))
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    // 剪贴板文本没有文件可列，但历史里得留一行：用户要知道这次收到的是一段
    // 文字，而不是「什么都没收到」。
    let mut clip_note = String::new();
    if let Ok(result) = &outcome {
        if let Some(info) = &result.clip {
            files.push((clip::TARGET_NAME.to_string(), info.bytes as u64));
            clip_note = if info.ok {
                format!("已复制到剪贴板（{} 字）", info.chars)
            } else {
                info.reason.clone()
            };
        }
    }
    match &outcome {
        Ok(result) => crate::history::record(
            "recv",
            &session.peer,
            &files,
            result.bytes,
            started.elapsed(),
            true,
            &clip_note,
        ),
        Err(e) => crate::history::record(
            "recv",
            &session.peer,
            &files,
            received,
            started.elapsed(),
            false,
            &e.to_string(),
        ),
    }
    let names: Vec<String> = files.iter().map(|(n, _)| n.clone()).collect();
    let dur = started.elapsed().as_millis();
    match &outcome {
        Ok(result) if session.accepted => {
            crate::trace::session_end(true, result.bytes, &names, "done", dur)
        }
        Ok(_) => crate::trace::session_end(true, 0, &names, "rejected", dur),
        Err(e) => crate::trace::session_end(false, received, &names, &e.to_string(), dur),
    }
    outcome
}

/// 一次接收结束后，右下角提示条该说什么。`None` 表示**不该打扰用户**。
///
/// 这是接收侧唯一的提示出口。以前这里什么都没有：发送收到结果会飘「发送完成」，
/// 接收收完了却只在历史里记一笔——用户看着浮窗走完就消失，文件去哪了、收了多少
/// 完全没有反馈，两端体验不对称。分散在各处的提示（剪贴板那条）又会在同一件事上
/// 说出互相矛盾的两句。所以规则集中在这里，一次接收最多一条：
///
/// | 情况 | 提示 |
/// |---|---|
/// | 成功，收到文件/文本 | 「接收完成」+ 数量与体积 |
/// | 成功，但剪贴板没写进去（还有文件） | 「接收完成」，正文注明剪贴板未更新 |
/// | 成功，但只收到一段没法投递的文本 | 「接收失败！」+ 原因（等于什么都没拿到） |
/// | 用户自己点了「拒绝」 | 不提示（他刚点的，再飘一条是噪音；历史里仍有记录） |
/// | 成功但一个字节也没收到 | 不提示（对端发了个空清单，没必要报告「收到 0 个」） |
/// | 中断/取消/网络错误 | 「接收失败！」或「已取消接收」+ 原因 |
pub fn toast_for(
    peer: &str,
    accepted: bool,
    result: Option<&ReceiveResult>,
    err: Option<&Error>,
) -> Option<(String, String)> {
    // `peer` 是 `ip:端口`。端口对用户没意义（手机每次重开分享都会换），只留地址。
    let ip = peer.rsplit_once(':').map(|(host, _)| host).unwrap_or(peer);

    if let Some(e) = err {
        return Some((
            e.kind().title_for(true).to_string(),
            // 原因在前、来源在后：正文只有一行，放不下时被省略号吃掉的是末尾，
            // 而「为什么没成」比「哪台设备」更值钱。
            format!("{} · 来自 {ip}", strip_result_word(&e.user_message())),
        ));
    }

    let result = result?;
    if !accepted {
        return None;
    }

    let files = result.saved.len();
    let clip = result.clip.as_ref();
    let clip_ok = clip.is_some_and(|c| c.ok);
    let clip_bad = clip.is_some_and(|c| !c.ok && !c.skipped);

    // 什么都没拿到（空清单，或只有一段空文本）：不值得弹。
    if files == 0 && !clip_ok && !clip_bad {
        return None;
    }
    // 只有一段投递不出去的文本 —— 用户期待的是剪贴板里的字，没拿到就是失败。
    if files == 0 && clip_bad {
        return Some((
            "接收失败！".to_string(),
            format!(
                "{} · 来自 {ip}",
                clip.map(|c| c.reason.as_str()).unwrap_or("")
            ),
        ));
    }

    let mut body = if files > 0 {
        format!(
            "收到 {files} 个文件 · {}",
            crate::human::bytes(result.bytes)
        )
    } else {
        String::new()
    };
    if clip_ok {
        let chars = clip.map(|c| c.chars).unwrap_or(0);
        if body.is_empty() {
            body = format!("剪贴板已更新（{chars} 字）");
        } else {
            body.push_str(&format!(" + 剪贴板 {chars} 字"));
        }
    }
    if clip_bad && files > 0 {
        // 正文只有一行，放不下完整原因；结论（剪贴板没更新）在这儿，细节在日志里。
        body.push_str("（剪贴板未更新）");
    }
    body.push_str(&format!(" · 来自 {ip}"));

    Some(("接收完成".to_string(), body))
}

/// 底层消息经常自带「接收失败：」前缀（`channel.rs` 是给日志/历史写的）。
/// 标题已经说过一次了，留在正文里既重复，又把真正有用的原因挤到省略号后面。
fn strip_result_word(msg: &str) -> &str {
    for prefix in ["接收失败：", "接收失败:", "发送失败：", "发送失败:"] {
        if let Some(rest) = msg.strip_prefix(prefix) {
            return rest.trim_start();
        }
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tlv_encode;
    use crate::transfer;

    #[test]
    fn sanitize_strips_paths() {
        assert_eq!(sanitize("../../etc/passwd"), "passwd");
        assert_eq!(sanitize(r"C:\Windows\a.txt"), "a.txt");
        assert_eq!(sanitize("a<b>c.txt"), "a_b_c.txt");
        assert_eq!(sanitize(".."), "received.bin");
    }

    #[test]
    fn safe_rel_segments_blocks_traversal() {

        assert_eq!(
            safe_rel_segments("测试/7/app-debug (1).apk"),
            vec!["测试", "7", "app-debug (1).apk"]
        );

        assert_eq!(safe_rel_segments("../../etc/passwd"), vec!["etc", "passwd"]);

        assert_eq!(safe_rel_segments("a/../../b.txt"), vec!["a", "b.txt"]);

        assert!(safe_rel_segments("../../../").is_empty());

        assert_eq!(safe_rel_segments("C:/Windows/a.txt"), vec!["Windows", "a.txt"]);

        assert_eq!(safe_rel_segments("/abs/path.txt"), vec!["abs", "path.txt"]);

        assert!(safe_rel_segments("").is_empty());
        assert!(safe_rel_segments("../..").is_empty());

        assert_eq!(safe_rel_segments("a/CON.txt"), vec!["a", "_CON.txt"]);
    }

    #[test]
    fn sanitize_handles_windows_quirks() {
        assert_eq!(sanitize("CON.txt"), "_CON.txt");
        assert_eq!(sanitize("com1"), "_com1");
        assert_eq!(sanitize("LPT9.log"), "_LPT9.log");
        assert_eq!(sanitize("A.TXT. "), "A.TXT");
        assert_eq!(sanitize("COM10.txt"), "COM10.txt", "两位数不是保留名");
        let long = "啊".repeat(300);
        assert_eq!(sanitize(&long).chars().count(), 120);
    }

    #[test]
    fn unique_path_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("hwshare-unique-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a.txt"));
        std::fs::write(dir.join("a.txt"), b"first").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (1).txt"));

        std::fs::write(part_path(&dir.join("a (1).txt")), b"half").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (2).txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_same_name_gets_distinct_parts() {
        use std::io::Write;

        let dir = std::env::temp_dir().join(format!("hwshare-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        const N: usize = 8;
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let d = dir.clone();
                std::thread::spawn(move || {
                    let (_target, part, mut f) =
                        create_part_atomic(&d, "same.txt").expect("抢占 .part 失败");

                    writeln!(f, "writer {i}").unwrap();
                    drop(f);
                    part
                })
            })
            .collect();

        let parts: std::collections::HashSet<_> = handles
            .into_iter()
            .map(|h| h.join().expect("子线程 panic"))
            .collect();

        assert_eq!(parts.len(), N, "不同会话抢到了同一个 .part：{:?}", parts);

        for p in &parts {
            let text = std::fs::read_to_string(p).unwrap();
            assert!(text.starts_with("writer "), "{:?} 内容被覆盖", p);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_caps_entry_count() {
        fn entry(id: u16, name: &str) -> Vec<u8> {
            let mut unit = Vec::new();
            unit.extend_from_slice(&id.to_be_bytes());
            unit.extend_from_slice(&100u64.to_be_bytes());
            unit.extend_from_slice(&(name.len() as u16).to_be_bytes());
            unit.extend_from_slice(name.as_bytes());
            unit
        }

        let mut payload = vec![0u8, 0u8];
        let total = MAX_MANIFEST + 50;
        for i in 0..total {
            let id = (i % 60000) as u16 + 1;
            payload.extend(entry(id, "f.txt"));
        }

        let mut expected = Vec::new();
        let mut empty = Vec::new();
        let added = merge_manifest(&mut expected, &mut empty, &payload);
        assert_eq!(expected.len(), MAX_MANIFEST, "必须停在 MAX_MANIFEST");
        assert_eq!(added, MAX_MANIFEST);
        assert!(expected.len() <= total);
    }

    #[test]
    fn manifest_merges_multiple_frames() {
        fn entry(id: u16, size: u64, name: &str) -> Vec<u8> {
            let mut unit = Vec::new();
            unit.extend_from_slice(&id.to_be_bytes());
            unit.extend_from_slice(&size.to_be_bytes());
            unit.extend_from_slice(&(name.len() as u16).to_be_bytes());
            unit.extend_from_slice(name.as_bytes());
            unit
        }
        let mut frame1 = vec![0u8, 2];
        frame1.extend(entry(1, 100, "a.txt"));
        let mut frame2 = vec![0u8, 2];
        frame2.extend(entry(1, 100, "dup.txt"));
        frame2.extend(entry(2, 200, "b.bin"));
        frame2.extend(entry(3, 0, "empty.txt"));
        frame2.extend(entry(4, 10, "  "));

        let mut expected = Vec::new();
        let mut empty = Vec::new();
        assert_eq!(merge_manifest(&mut expected, &mut empty, &frame1), 1);
        assert_eq!(merge_manifest(&mut expected, &mut empty, &frame2), 1);
        assert_eq!(expected.len(), 2);
        assert_eq!(expected[1].0, 2);
        assert_eq!(expected[1].1, 200);
        assert_eq!(expected[1].2, "b.bin");

        assert_eq!(empty.len(), 1);
        assert_eq!(empty[0].0, 3);
    }

    #[test]
    fn describes_drained_cancel_frame() {
        let key = [7u8; 32];
        let body = tlv_encode(1, &tlv_encode(1, b"senderCancel").unwrap()).unwrap();
        let wire_frame = transfer::seal_encrypted_frame(&[0u8; 16], &key, &body, 1).unwrap();
        let text = describe_wire_frame(9, &wire_frame, &key);
        assert!(text.contains("senderCancel"), "没认出取消命令: {text}");
    }

    #[test]
    fn describing_garbage_never_panics() {
        let key = [0u8; 32];
        assert!(describe_wire_frame(21, &[0u8; 32], &key).contains("module=21"));
        let text = describe_control_body(b"not a tlv at all");
        assert!(text.starts_with("明文"), "{text}");
        assert!(hex_head(&[0xAB; 100]).ends_with('…'));
    }

    // ------------------------------------------------ 收尾提示文案

    fn ok_result(files: usize, bytes: u64, clip: Option<ClipInfo>) -> ReceiveResult {
        ReceiveResult {
            saved: (0..files)
                .map(|i| PathBuf::from(format!("C:/收/{i}.jpg")))
                .collect(),
            bytes,
            clip,
        }
    }

    fn clip(ok: bool, skipped: bool, chars: usize, reason: &str) -> ClipInfo {
        ClipInfo {
            bytes: 20,
            chars,
            ok,
            reason: reason.to_string(),
            skipped,
        }
    }

    #[test]
    fn success_reports_what_arrived() {
        let r = ok_result(3, 13 * 1024 * 1024, None);
        let (title, body) = toast_for("192.168.1.9:5684", true, Some(&r), None).unwrap();
        assert_eq!(title, "接收完成");
        // 端口不进正文（手机会换端口），但设备地址要在。
        assert_eq!(body, "收到 3 个文件 · 13.0 MB · 来自 192.168.1.9");
    }

    #[test]
    fn small_transfers_never_read_as_zero_megabytes() {
        let r = ok_result(1, 512 * 1024, None);
        let (_, body) = toast_for("10.0.0.2:1", true, Some(&r), None).unwrap();
        assert!(body.contains("512.0 KB"), "{body}");
    }

    #[test]
    fn clip_text_only_says_clipboard_updated() {
        let r = ok_result(0, 40, Some(clip(true, false, 128, "")));
        let (title, body) = toast_for("10.0.0.2:1", true, Some(&r), None).unwrap();
        assert_eq!(title, "接收完成");
        assert_eq!(body, "剪贴板已更新（128 字） · 来自 10.0.0.2");
    }

    #[test]
    fn files_plus_clip_mention_both() {
        let r = ok_result(2, 2048, Some(clip(true, false, 9, "")));
        let (_, body) = toast_for("10.0.0.2:1", true, Some(&r), None).unwrap();
        assert_eq!(body, "收到 2 个文件 · 2.0 KB + 剪贴板 9 字 · 来自 10.0.0.2");
    }

    #[test]
    fn clip_failure_alone_is_a_failure_but_not_when_files_arrived() {
        // 只收到一段没写进剪贴板的文本：等于什么都没拿到。
        let only_text = ok_result(0, 80, Some(clip(false, false, 0, "剪贴板写入失败：被占用")));
        let (title, body) = toast_for("10.0.0.2:1", true, Some(&only_text), None).unwrap();
        assert_eq!(title, "接收失败！");
        assert!(body.contains("被占用"), "{body}");

        // 文件都收到了，剪贴板只是附带：结论仍是成功，尾注提一句。
        let with_files = ok_result(4, 4096, Some(clip(false, false, 0, "被占用")));
        let (title, body) = toast_for("10.0.0.2:1", true, Some(&with_files), None).unwrap();
        assert_eq!(title, "接收完成");
        assert!(body.contains("（剪贴板未更新）"), "{body}");
    }

    #[test]
    fn empty_text_is_not_an_error() {
        let r = ok_result(1, 300, Some(clip(false, true, 0, "内容为空，未改写剪贴板")));
        let (title, body) = toast_for("10.0.0.2:1", true, Some(&r), None).unwrap();
        assert_eq!(title, "接收完成");
        assert!(!body.contains("剪贴板未更新"), "空文本不算出错: {body}");
    }

    #[test]
    fn rejection_and_empty_session_stay_silent() {
        // 用户自己点了「拒绝」——刚点的，再飘一条是噪音。
        let rejected = ok_result(0, 0, None);
        assert!(toast_for("10.0.0.2:1", false, Some(&rejected), None).is_none());
        // 成功但一个字节也没收到：不弹「收到 0 个文件」。
        assert!(toast_for("10.0.0.2:1", true, Some(&rejected), None).is_none());
    }

    #[test]
    fn errors_use_receive_wording_not_send_wording() {
        let net = Error::Network("连接被对方提前关闭".into());
        let (title, body) = toast_for("10.0.0.2:1", true, None, Some(&net)).unwrap();
        assert_eq!(title, "接收失败！", "接收侧不能报「发送失败」");
        assert_eq!(body, "连接被对方提前关闭 · 来自 10.0.0.2");

        let cancel = Error::Cancelled("对方取消了这次分享".into());
        let (title, _) = toast_for("10.0.0.2:1", true, None, Some(&cancel)).unwrap();
        assert_eq!(title, "已取消接收");
    }

    #[test]
    fn duplicated_result_word_is_stripped_from_the_body() {
        // `channel.rs` 拼出来的原话就带这个前缀，实测会显示成
        // 「接收失败！/ 192.168.1.5：接收失败：对方中断了分享…」，一句话两遍。
        let e = Error::Network("接收失败：对方中断了分享（已收 72.8 MB）".into());
        let (_, body) = toast_for("192.168.1.5:5684", true, None, Some(&e)).unwrap();
        assert_eq!(body, "对方中断了分享（已收 72.8 MB） · 来自 192.168.1.5");
        assert_eq!(strip_result_word("没有前缀"), "没有前缀");
    }
}
