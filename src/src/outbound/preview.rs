//! 发送前的 net_info 应答、预览载荷与本地时间格式化。

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::channel::Channel;
use crate::transfer;
use crate::{Error, Result};
use std::path::Path;
use super::*;

pub(super) fn file_ms(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or_else(|| crate::clock::now_millis())
}

pub(super) fn net_info_reply(local: &str) -> Result<Vec<u8>> {
    let mut fields = Vec::new();
    fields.extend(crate::tlv_encode(1, b"")?);
    fields.extend(crate::tlv_encode(2, b"")?);
    fields.extend(crate::tlv_encode(3, b"true")?);
    fields.extend(crate::tlv_encode(4, local.as_bytes())?);
    crate::tlv_encode(5, &fields)
}

pub(super) fn net_info_offer(local: &str) -> Result<Vec<u8>> {
    let mut fields = Vec::new();
    fields.extend(crate::tlv_encode(1, b"")?);
    fields.extend(crate::tlv_encode(2, b"")?);
    fields.extend(crate::tlv_encode(3, b"")?);
    fields.extend(crate::tlv_encode(4, local.as_bytes())?);
    crate::tlv_encode(4, &fields)
}

pub(super) fn build_preview_payload(files: &[Outgoing]) -> Result<Vec<u8>> {
    let names: Vec<String> = files.iter().map(|f| f.name.clone()).collect();
    let joined = names.join("|");

    let stamps: Vec<String> = files.iter().map(|f| file_ms(&f.path).to_string()).collect();
    let details: Vec<String> = files
        .iter()
        .map(|f| format!("\"{}\"", crate::clock::format_unix_ms_wire(file_ms(&f.path))))
        .collect();
    let metadata = format!(
        r#"{{"date_added":[{}],"date_taken":[{}],"detail_time":[{}]}}"#,
        stamps.join(","),
        stamps.join(","),
        details.join(",")
    );
    let mut inner = crate::tlv_encode(11, joined.as_bytes())?;
    inner.extend(crate::tlv_encode(13, metadata.as_bytes())?);
    crate::tlv_encode(8, &inner)
}

pub(super) fn send_preview(
    chan: &mut Channel,
    byte_key: &[u8],
    session_key: &[u8],
    device_hash: &[u8],
    files: &[Outgoing],
    log: &dyn Fn(&str),
    cancel: &AtomicBool,
    peer: &PeerState,
    send_frame: bool,
    timeout_ms: u64,
    strict: bool,
) -> Result<()> {

    if send_frame {

        let body = build_preview_payload(files)?;

        let inner = transfer::encrypted_envelope(device_hash, session_key, &body)?;
        peer.preview_ok.store(false, Ordering::SeqCst);
        chan.transmit(&transfer::bytes_frame(byte_key, &inner, 0)?)?;
    } else {
        log("预览已提前发送（CH17 之前），这里只等 previewOK");
    }

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while Instant::now() < deadline {

        if cancelled(cancel) {
            crate::trace::note("byte", "预览等待中收到取消，停止发送");
            return Err(cancel_error(cancel));
        }

        if peer.preview_ok.load(Ordering::SeqCst) {
            log("预览已确认（控制通道 previewOK），开始传输");
            return Ok(());
        }
        let Some((_seq, plain)) =
            transfer::try_read_bytes_frame(chan, byte_key, Duration::from_millis(200))?
        else {
            continue;
        };
        let wire_frame = crate::frame_encode_lenient(9, 0, 0, &plain)?;
        let Ok(body) = transfer::open_channel_frame(&wire_frame, session_key) else {
            continue;
        };
        for (tag, value) in transfer::tlv_list(&body)? {
            if tag != 1 {
                continue;
            }
            for (field, data) in transfer::tlv_list(&value)? {
                if field == 8 && data == b"previewOK" {
                    log("预览已确认，开始传输");
                    return Ok(());
                }

            }
        }
    }

    if strict {

        return Err(Error::Protocol("预览未获确认".into()));
    }

    log("对端未回 previewOK（非媒体文件常见），继续传输");
    Ok(())
}
