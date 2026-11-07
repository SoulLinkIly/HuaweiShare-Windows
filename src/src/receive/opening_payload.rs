//! 处理 opening：建链握手与 opening ACK，并解析 offer 里的文件数、目录数、总大小。

use super::*;
use std::time::Duration;

use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;

use crate::auth;
use crate::channel::Channel;
use crate::crypto;
use crate::transfer::{self, tlv_list};
use crate::{aesgcm_encrypt_n16, frame_encode, tlv_encode, varint_encode, Error, Result,
            FRAME_HEADER_SIZE};

pub(super) const MODULE_AUTH: u32 = 1;

pub(super) const MAX_AUTH_ROUNDS: u32 = 6;

fn take_chars(text: &[u8], n: usize) -> String {
    String::from_utf8_lossy(text).chars().take(n).collect()
}

pub(super) fn frame_module(wire_frame: &[u8]) -> u32 {
    match wire_frame.get(4..8) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

pub(super) fn build_opening_ack(private: &rsa::RsaPrivateKey) -> Result<Vec<u8>> {
    let public_der = crypto::public_der(private).map_err(Error::Crypto)?;
    let identity = crate::identity_v2(&public_der)?;
    let ack = format!(
        r#"{{"CODE":4,"DEVICE_ID":"{id}","PEER_NETWORK_ID":"{id}","API_VERSION":2,"PKG_NAME":"{pkg}","SRC_BUS_NAME":"ohos.InterConnection.iShare","DST_BUS_NAME":"IShareEcologyAuthSession","REQ_ID":"0","MTU_SIZE":39968,"ROUTE_TYPE":2}}"#,
        id = identity.to_lowercase(),
        pkg = crate::auth::PKG_NAME
    );
    let mut payload = ack.into_bytes();
    payload.push(0);
    frame_encode(8, 0, 1, &payload)
}

pub(super) struct OfferFields {
    pub count: u32,
    pub folders: u32,
    pub total: u64,
    pub send_type: u32,
    pub tag3: u32,
    pub tag6: u32,
}

pub(super) fn parse_offer(tlv: &[u8]) -> Result<OfferFields> {
    let mut out = OfferFields {
        count: 0,
        folders: 0,
        total: 0,
        send_type: 0,
        tag3: 0,
        tag6: 0,
    };
    for (tag, value) in tlv_list(tlv)? {
        let num: u32 = String::from_utf8_lossy(&value).parse().unwrap_or(0);
        match tag {
            1 => out.send_type = num,
            3 => out.tag3 = num,
            4 => out.total = String::from_utf8_lossy(&value).parse().unwrap_or(0),
            5 => out.folders = num,
            6 => out.tag6 = num,
            _ => {}
        }
    }
    out.count = out.tag3.max(out.tag6);
    Ok(out)
}

pub(super) fn accept_connection_inner(
    channel: &mut Channel,
    private: &rsa::RsaPrivateKey,
    accept: bool,
    timeout: Duration,
) -> Result<Session> {
    let debug = crate::env::present("HWSHARE_DEBUG");
    macro_rules! dbg_step {
        ($($arg:tt)*) => {
            if crate::trace::enabled() {

                crate::trace::note_conn("control", channel.conn(), &format!($($arg)*));
            }
            if debug { eprintln!("[rust-recv] {}", format!($($arg)*)); }
        };
    }

    dbg_step!("等待 opening");
    let mut opening_payload = channel.read_channel_frame(timeout)?;
    let mut auth_round = 0u32;

    let request: serde_json::Value = loop {
        dbg_step!("收到 opening ({} 字节)", opening_payload.len());
        let module = frame_module(&opening_payload);
        let body = &opening_payload[FRAME_HEADER_SIZE..];
        let text = body.strip_suffix(&[0]).unwrap_or(body);
        let req: serde_json::Value = match serde_json::from_slice(text) {
            Ok(v) => v,
            Err(_) => {
                let snippet: String = take_chars(text, 200);
                dbg_step!("开场不是 JSON（module={module}）: {snippet}");
                return Err(Error::Format);
            }
        };

        if req["CODE"] == 4 {
            break req;
        }

        if req.get("AUTH_START_STATE").is_some() || module == MODULE_AUTH {
            auth_round += 1;
            dbg_step!(
                "认证帧 #{auth_round}（module={module}），已丢弃: {}",
                take_chars(text, 400)
            );
            crate::trace::note_conn(
                "control",
                channel.conn(),
                &format!("丢弃认证帧 #{auth_round}（华为账号链路，与本实现无关）"),
            );
            if auth_round > MAX_AUTH_ROUNDS {

                return Err(Error::Protocol(format!(
                    "认证帧连发 {MAX_AUTH_ROUNDS} 轮仍未进入建链，断开等重连"
                )));
            }
            opening_payload = channel.read_channel_frame(timeout)?;
            continue;
        }

        let snippet: String = take_chars(text, 200);
        return Err(Error::Protocol(format!(
            "不支持的开场请求（{} 字节，module={module}）: {snippet}",
            opening_payload.len()
        )));
    };

    let peer_apple = request["PKG_NAME"].as_str() == Some("com.huawei.nearby");
    if peer_apple {
        dbg_step!("对端是 Apple 客户端（iPad 当发送方）");
    }

    let public_der = crypto::public_der(private).map_err(Error::Crypto)?;
    let ack_frame = build_opening_ack(private)?;
    dbg_step!("发 opening ACK: {} 字节, 头={:02X?}", ack_frame.len(), &ack_frame[..24]);
    channel.transmit(&ack_frame)?;

    let device_hash = crate::device_hash(&public_der)?.into_bytes();

    dbg_step!("已回 opening ACK，等能力协商");
    let capability_request = match channel.read_channel_frame(timeout) {
        Ok(v) => { dbg_step!("能力帧 {} 字节", v.len()); v }
        Err(e) => { dbg_step!("能力帧读取失败: {e:?}"); return Err(e); }
    };
    dbg_step!("收到能力帧");
    let (mode, cap_body) = auth::open_envelope(&capability_request)?;
    if mode != 0 {
        return Err(Error::Format);
    }
    let _ = auth::require_tlv(&cap_body, 2)?;
    channel.transmit(&auth::seal_handshake_envelope(&device_hash, &tlv_encode(3, &tlv_encode(1, b"")?)?, 0)?)?;

    dbg_step!("已回能力，等对端公钥");
    let public_request = channel.read_channel_frame(timeout)?;
    dbg_step!("收到公钥帧");
    let (mode, pub_body) = auth::open_envelope(&public_request)?;
    if mode != 0 {
        return Err(Error::Format);
    }
    let peer_der = auth::require_tlv(auth::require_tlv(&pub_body, 6)?, 1)?;
    let peer_key = RsaPublicKey::from_public_key_der(peer_der)
        .map_err(|e| Error::Crypto(format!("对端公钥解析失败: {e}")))?;

    channel.transmit(&auth::seal_handshake_envelope(
        &device_hash,
        &tlv_encode(6, &tlv_encode(2, &public_der)?)?,
        0,
    )?)?;

    dbg_step!("已回公钥，等挑战");
    let challenge_frame = channel.read_channel_frame(timeout)?;
    dbg_step!("收到挑战帧");
    let (mode, ciphertext) = auth::open_envelope(&challenge_frame)?;
    if mode != 3 {
        return Err(Error::Format);
    }
    let decrypted = crypto::oaep_decrypt(private, &ciphertext, false).map_err(Error::Crypto)?;
    let auth_challenge_payload = auth::require_tlv(auth::require_tlv(&decrypted, 6)?, 3)?;
    if auth_challenge_payload.len() != 48 {
        return Err(Error::Format);
    }

    let mut session_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut session_key);
    let encrypted = aesgcm_encrypt_n16(&auth_challenge_payload[16..48], &auth_challenge_payload[0..16], &session_key)?;
    let wrapped = crypto::oaep_encrypt(
        &peer_key,
        &tlv_encode(6, &tlv_encode(4, &encrypted)?)?,
        false,
    )
    .map_err(Error::Crypto)?;

    let mut meta_bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut meta_bytes);
    let metadata = tlv_encode(1, &meta_bytes)?;
    let mut envelope = Vec::new();
    envelope.extend_from_slice(&device_hash);
    envelope.extend_from_slice(&[0x81, 0xE5, 0x83]);
    envelope.extend(varint_encode(metadata.len() as u64)?);
    envelope.extend_from_slice(&metadata);
    envelope.extend(varint_encode(wrapped.len() as u64)?);
    envelope.extend_from_slice(&wrapped);
    channel.transmit(&frame_encode(9, 0, 0, &envelope)?)?;

    dbg_step!("已回挑战回应，等 offer");
    let offer_frame = channel.read_channel_frame(Duration::from_secs(24))?;
    dbg_step!("收到 offer ({} 字节)", offer_frame.len());
    let plain = transfer::open_channel_frame(&offer_frame, &session_key)?;
    let offer_tlv = auth::require_tlv(&plain, 7)?;
    if debug {
        eprintln!("[offer] 解密后 {} 字节", plain.len());
        dump_tlvs("[offer] ", offer_tlv, 0);
    }
    let parsed = parse_offer(offer_tlv)?;
    let count = parsed.count;
    let folders = parsed.folders;
    let total = parsed.total;
    if debug {
        eprintln!(
            "[offer] 解析：type={} count={count}（tag3={} tag6={}） folders={folders} total={total}",
            parsed.send_type, parsed.tag3, parsed.tag6
        );
    }

    Ok(Session {
        file_count: count,
        folders,
        total_bytes: total,
        session_key,
        device_hash,
        peer: channel.peer().to_string(),
        accepted: accept,
        peer_apple,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(tag3: &str, tag5: &str, tag6: &str, total: &str) -> Vec<u8> {
        let mut fields = Vec::new();
        for (tag, value) in [
            (1u64, "4"),
            (2, "TEST-PC"),
            (3, tag3),
            (4, total),
            (5, tag5),
            (6, tag6),
            (7, "{}"),
        ] {
            fields.extend(tlv_encode(tag, value.as_bytes()).unwrap());
        }
        fields
    }

    #[test]
    fn folder_offer_counts_by_tag6() {
        let parsed = parse_offer(&offer("0", "1", "101", "304335")).unwrap();
        assert_eq!(parsed.count, 101);
        assert_eq!(parsed.folders, 1);
        assert_eq!(parsed.total, 304335);
        assert_eq!(parsed.send_type, 4);
    }

    #[test]
    fn plain_offer_counts_by_tag3() {
        let parsed = parse_offer(&offer("7", "0", "7", "4096")).unwrap();
        assert_eq!(parsed.count, 7);
        assert_eq!(parsed.folders, 0);
    }

    #[test]
    fn missing_count_tags_stay_zero() {
        let parsed = parse_offer(&offer("0", "0", "0", "0")).unwrap();
        assert_eq!(parsed.count, 0);
    }
}
