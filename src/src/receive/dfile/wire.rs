//! 接收侧要回给对端的帧，以及协议诊断输出。
//!
//! 全是纯函数：给参数就拼字节，不读全局状态、不碰磁盘，改协议时只看这一处。

use super::*;

pub(super) fn take_chars(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

pub(super) fn decode_session_key(value: &serde_json::Value) -> Result<[u8; 32]> {
    use base64::Engine;
    let raw_key = base64::engine::general_purpose::STANDARD
        .decode(value["SESSION_KEY"].as_str().unwrap_or(""))
        .map_err(|_| Error::Format)?;
    if raw_key.len() != 32 {
        return Err(Error::Format);
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&raw_key);
    Ok(k)
}

pub(super) fn file_channel_reply(port: u16, local_ip: &str, peer_ch: Option<u64>) -> String {
    let pkg = crate::auth::PKG_NAME;
    match peer_ch {
        Some(peer_ch) => format!(
            r#"{{"MY_CHANNEL_ID":1,"PEER_CHANNEL_ID":{peer_ch},"P2P_PORT":{port},"MY_IP":"{local_ip}","CODE":1538,"STREAM_TYPE":255,"PKG_NAME":"{pkg}","BUSINESS_TYPE":3,"API_VERSION":0,"TRANS_CAPABILITY":0,"UDP_CHANNEL_CAPABILITY":0}}"#
        ),
        None => format!(
            r#"{{"MY_CHANNEL_ID":1,"P2P_PORT":{port},"MY_IP":"{local_ip}","CODE":1538,"STREAM_TYPE":255,"PKG_NAME":"{pkg}","BUSINESS_TYPE":3,"API_VERSION":0,"TRANS_CAPABILITY":0,"UDP_CHANNEL_CAPABILITY":0}}"#
        ),
    }
}

pub(super) fn is_name_list_frame(b: &[u8]) -> bool {
    if b.len() < 1000 {
        return false;
    }
    let Ok(fields) = tlv_list(b) else { return false };
    fields.len() == 1 && fields[0].0 == 8 && fields[0].1.len() > 500
}

pub(crate) fn dump_tlvs(prefix: &str, data: &[u8], depth: usize) {
    let Ok(fields) = tlv_list(data) else {
        eprintln!("{prefix}(非 TLV, {} 字节) {:02X?}", data.len(), &data[..data.len().min(48)]);
        return;
    };
    if fields.is_empty() {
        eprintln!("{prefix}(空 TLV) {:02X?}", &data[..data.len().min(48)]);
        return;
    }
    for (tag, value) in fields {
        let head = &value[..value.len().min(40)];
        let printable = std::str::from_utf8(&value)
            .ok()
            .filter(|s| s.chars().all(|c| !c.is_control() || c == '\n'))
            .filter(|s| s.len() <= 120);
        match printable {
            Some(s) => eprintln!("{prefix}{tag}: {}B = {s:?}", value.len()),
            None => eprintln!("{prefix}{tag}: {}B  {:02X?}", value.len(), head),
        }

        if depth < 3 {
            if let Ok(inner) = tlv_list(&value) {
                if !inner.is_empty() {
                    let used: usize = inner.iter().map(|(_, v)| v.len() + 2).sum();
                    if used == value.len() {
                        dump_tlvs(&format!("{prefix}    "), &value, depth + 1);
                    }
                }
            }
        }
    }
}

pub(super) fn idle_limit() -> Duration {

    let secs: u64 = crate::env::num("HWSHARE_IDLE_SECS", 8);
    Duration::from_secs(if secs >= 5 { secs } else { 8 })
}

pub(super) fn send_progress_frame(
    chan: &mut Channel,
    byte_key: &[u8; 32],
    device_hash: &[u8],
    session_key: &[u8],
    declared_total: u64,
    received: u64,
    seq: &mut u32,
    warned: &mut bool,
) -> Result<()> {
    let total = declared_total.max(1);
    let pct = received as f64 * 100.0 / total as f64;
    let text = format!("dfileRecvPercent#{pct:.6}");
    let plain = crate::tlv_encode(1, &crate::tlv_encode(9, text.as_bytes())?)?;
    let env = transfer::seal_encrypted_frame(device_hash, session_key, &plain, *seq as u64)?;
    let wire_frame = transfer::bytes_frame(byte_key, &env[FRAME_HEADER_SIZE..], *seq)?;
    match chan.transmit(&wire_frame) {
        Ok(()) => crate::trace::note("byte", &format!("已发进度帧 #{seq} {text}")),
        Err(e) => {
            if !*warned {
                *warned = true;
                crate::trace::note("byte", &format!("进度帧发送失败：{e}"));
            }
        }
    }
    *seq += 1;
    Ok(())
}

pub(super) fn log_settings(payload: &[u8], debug: bool) {
    let ok = payload.len() >= 100
        && u16::from_be_bytes([payload[2], payload[3]]) == 2
        && (u32::from_be_bytes([payload[20], payload[21], payload[22], payload[23]]) & 0x100) != 0
        && payload[91] == 1
        && (u32::from_be_bytes([payload[96], payload[97], payload[98], payload[99]]) & 1) != 0;
    if !ok && debug {
        eprintln!("[dfile] settings 字段与预期不同（继续）: {:02X?}", &payload[..payload.len().min(32)]);
    }

    if payload.len() >= 100 {
        let mtu = u16::from_be_bytes([payload[0], payload[1]]);
        let ctype = u16::from_be_bytes([payload[2], payload[3]]);
        let ver = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let abm = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let cap = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let dfs = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let caps = u32::from_be_bytes([payload[20], payload[21], payload[22], payload[23]]);
        let note = format!(
            "[对端 settings·发送端] mtu={mtu} ctype={ctype} ver={ver} abm=0x{abm:X} cap=0x{cap:X} dfs={dfs} caps=0x{caps:X} len={}",
            payload.len()
        );
        eprintln!("{note}");
        crate::trace::note("file#1", &note);

        let cipher = transfer::negotiate_cipher(
            transfer::settings_cipher_caps(payload),
        );
        crate::trace::note("file#1", &format!("会话密码 → {cipher:?}"));
    }
}

pub(super) fn build_congest_frame() -> Vec<u8> {
    let mut congest = Vec::with_capacity(32);
    congest.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 24]);
    congest.extend_from_slice(&[
        0x00, 0x00, 0x01, 0xb0, 0x00, 0x00, 0x01, 0xb0, 0xff, 0xff, 0xff, 0xea,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    congest
}

pub(super) fn build_byte_handshake_ack(peer_apple: bool, pkg: &str, node: &str) -> Vec<u8> {
    let response = if peer_apple {
        format!(
            r#"{{"API_VERSION":2,"CODE":1,"DEVICE_ID":"","MTU_SIZE":4194304,"PKG_NAME":"{pkg}","TRANS_CAPABILITY":0}}"#
        )
    } else {
        format!(
            r#"{{"CODE":1,"API_VERSION":2,"MTU_SIZE":1048576,"DEVICE_ID":"{node}","PKG_NAME":"{pkg}","TRANS_CAPABILITY":0,"AUTH_STATE":""}}"#
        )
    };
    let mut body = response.into_bytes();
    body.push(0);
    body
}

pub(super) fn build_meta_info_json(display_name: &str, device_hash: &[u8]) -> String {
    let node = crate::hex_lower(&crate::sha256(device_hash));
    let device_type = crate::outbound::DEVICE_TYPE_ID;   // u32 = 12
    format!(
        r#"{{"DEVICE_NAME":"{display_name}","DEVICE_TYPE_ID":{device_type},"FLAG":100,"META_AUTH_CAPA":1,"META_NODE_ID":"{node}","TOKEN_ID":"0000000000000000000000000000000000000000000000000000000000000001"}}"#
    )
}

pub(super) fn build_tag5_reply(local_ip: &str) -> Result<Vec<u8>> {
    let mut fields = Vec::new();
    fields.extend(tlv_encode(1, b"")?);
    fields.extend(tlv_encode(2, b"")?);
    fields.extend(tlv_encode(3, b"true")?);

    if !local_ip.is_empty() {
        fields.extend(tlv_encode(4, local_ip.as_bytes())?);
    }
    let reply = tlv_encode(5, &fields)?;
    Ok(reply)
}

pub(super) fn format_manifest_list(expected_files: &[(u16, u64, String)]) -> String {
    expected_files
        .iter()
        .map(|(id, size, name)| format!("{id}:{name}:{size}"))
        .collect::<Vec<String>>()
        .join(",")
}

pub(super) fn build_p2p_reply(local_ip: &str, port: u16) -> Vec<u8> {
    let reply = format!(
        r#"{{"CODE":3,"P2P_IP":"{local_ip}","P2P_PORT":{port},"PROTOCOL_TYPE":4}}"#
    );
    let mut body = reply.into_bytes();
    body.push(0);
    body
}
