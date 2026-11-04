use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::channel::Channel;
use crate::transfer;
use crate::{Error, Result};
use std::path::Path;
use super::*;

pub(super) fn utd_for(name: &str) -> &'static str {
    match name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("jpg") | Some("jpeg") => "general.jpeg",
        Some("png") => "general.png",
        Some("gif") => "general.gif",
        Some("bmp") => "general.bmp",
        Some("webp") => "general.webp",
        Some("heic") | Some("heif") => "general.heic",
        Some("mp4") => "general.mp4",
        Some("pdf") => "general.pdf",
        Some("txt") | Some("log") | Some("md") => "general.plain-text",
        Some("zip") => "general.zip",
        Some("apk") => "general.android.package-archive",
        _ => "general.bin",
    }
}

pub(super) const PREVIEW_THUMB_BUDGET: usize = 2 * 1024 * 1024;

pub(super) const THUMB_SOURCE_MAX: u64 = 32 * 1024 * 1024;

pub(super) fn thumbnail_data_url(path: &Path, budget: &mut usize) -> String {
    if *budget == 0 {
        return String::new();
    }
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() <= THUMB_SOURCE_MAX => {}
        _ => return String::new(),
    }

    let Ok(reader) = image::ImageReader::open(path) else {
        return String::new();
    };
    let Ok(reader) = reader.with_guessed_format() else {
        return String::new();
    };
    let Ok(img) = reader.decode() else {
        return String::new();
    };
    let thumb = img.thumbnail(600, 600).to_rgb8();
    let mut buf = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, 70);
    if encoder
        .encode(
            thumb.as_raw(),
            thumb.width(),
            thumb.height(),
            image::ExtendedColorType::Rgb8,
        )
        .is_err()
    {
        return String::new();
    }
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&buf);
    *budget = budget.saturating_sub(b64.len());
    format!("data:image/jpeg;base64,{b64}")
}

pub(super) fn preview_meta(files: &[Outgoing]) -> String {
    let mut budget = PREVIEW_THUMB_BUDGET;
    let items: Vec<String> = files
        .iter()
        .map(|f| {
            let utd = utd_for(&f.name);
            let thumb = thumbnail_data_url(&f.path, &mut budget);
            format!(
                r#"{{"utd":"{utd}","thumbnail":"{thumb}","thumbnailType":1,"properties":{{"duration":"0"}},"category":5}}"#
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

pub(super) fn file_ms(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        })
}

pub(super) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub(super) fn format_detail_time(ms: u64) -> String {
    const OFFSET: i64 = 8 * 3600;
    let secs = (ms / 1000) as i64 + OFFSET;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}:{m:02}:{d:02} {:02}:{:02}:{:02}",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
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
        .map(|f| format!("\"{}\"", format_detail_time(file_ms(&f.path))))
        .collect();
    let metadata = format!(
        r#"{{"date_added":[{}],"date_taken":[{}],"detail_time":[{}]}}"#,
        stamps.join(","),
        stamps.join(","),
        details.join(",")
    );
    let mut inner = crate::tlv_encode(11, joined.as_bytes())?;
    if std::env::var("HWSHARE_PREVIEW_META").ok().as_deref() == Some("1") {
        inner.extend(crate::tlv_encode(12, preview_meta(files).as_bytes())?);
    }
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
    send_frame: bool,
    timeout_ms: u64,
    strict: bool,
) -> Result<()> {
    let skip_all = std::env::var("HWSHARE_PREVIEW").ok().as_deref() == Some("0");
    if send_frame && !skip_all {
        let cap: usize = std::env::var("HWSHARE_PREVIEW_CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(usize::MAX);
        let shown = &files[..files.len().min(cap)];
        let body = build_preview_payload(shown)?;
        let inner = transfer::encrypted_envelope(device_hash, session_key, &body)?;
        PREVIEW_OK.store(false, Ordering::SeqCst);
        chan.transmit(&transfer::bytes_frame(byte_key, &inner, 0)?)?;
    } else if skip_all {
        log("按 HWSHARE_PREVIEW=0 跳过预览帧");
    } else {
        log("预览已提前发送（CH17 之前），这里只等 previewOK");
    }

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while Instant::now() < deadline {
        if cancelled(cancel) {
            crate::trace::note("byte", "预览等待中收到取消，停止发送");
            return Err(cancel_error());
        }
        if PREVIEW_OK.load(Ordering::SeqCst) {
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
