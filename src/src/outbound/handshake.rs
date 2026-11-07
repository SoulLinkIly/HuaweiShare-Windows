//! 发送侧握手细节：字节握手、文件通道请求、逻辑地址与元数据。

use base64::Engine;
use rand::RngCore;

use crate::channel::Channel;
use crate::transfer;
use crate::Result;
use super::*;

pub(super) const CHANNEL_BYTES: u32 = 0xFFFF_0004;
pub(super) const PEER_META_FRAME: u32 = 0xFFFF_0002;
pub(super) const PEER_META_ACK_FRAME: u32 = 0xFFFF_0008;
pub(super) const PEER_META_ACK_JSON: &[u8] = b"META_DEVICE_INFO_ACK\0";

pub(super) const BYTES_FLAG_REQUEST: u32 = 0x94;

pub(super) fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub(super) fn is_private_ipv4(ip: &str) -> bool {
    match ip.parse::<std::net::Ipv4Addr>() {
        Ok(addr) => {
            let o = addr.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
                || o[0] == 127
        }
        Err(_) => false,
    }
}

pub(super) fn byte_handshake(
    session_key: &[u8],
    identity: &str,
    node_id: &str,
    byte_key: &[u8],
    kind: transfer::PeerKind,
) -> Result<Vec<u8>> {

    let device_id = if kind.is_apple() { node_id } else { identity };
    let (client_bus, tc, bt, flags) = if kind.is_apple() {
        (
            format!("IShareSenderBytesSession_{identity}"),
            19u32,
            2u32,
            0x90u32,
        )
    } else {
        ("IShareSenderBytesSession".to_string(), 0u32, 1u32, BYTES_FLAG_REQUEST)
    };
    let payload = format!(
        r#"{{"CODE":1,"API_VERSION":2,"BUS_NAME":"IShareReceiverBytesSession","CLIENT_BUS_NAME":"{client_bus}","PKG_NAME":"{pkg}","MTU_SIZE":4194304,"TRANS_CAPABILITY":{tc},"ROUTE_TYPE":2,"DEVICE_ID":"{device_id}","BUSINESS_TYPE":{bt},"TRANS_FLAGS":2,"SESSION_KEY":"{key}"}}"#,
        key = b64(byte_key),
        pkg = crate::auth::PKG_NAME
    );
    let mut body = payload.into_bytes();
    body.push(0);
    let wire_frame = transfer::seal_channel_frame(
        session_key,
        (crate::FRAME_MAGIC_WORD, 6, rand_seq(), flags, 0),
        &body,
        0,
    )?;
    Ok(wire_frame[crate::FRAME_HEADER_SIZE..].to_vec())
}

pub(super) fn file_channel_request(
    local: &str,
    identity: &str,
    node_id: &str,
    file_key: &[u8],
    kind: transfer::PeerKind,
) -> Result<Vec<u8>> {
    let key = b64(file_key);

    let device_id = if kind.is_apple() { node_id } else { identity };

    let udp_tail = if kind.is_apple() {
        r#","UDP_CHANNEL_CAPABILITY":0"#
    } else {
        ""
    };

    let payload = if kind.is_apple() {
        format!(
            r#"{{"MY_CHANNEL_ID":2,"MY_IP":"{local}","DEVICE_ID":"{device_id}","CODE":1538,"API_VERSION":2,"CHANNEL_TYPE":1,"STREAM_TYPE":0,"UDP_CONN_TYPE":1,"BUS_NAME":"IShareReceiverFileSession","BUSINESS_TYPE":3,"CLIENT_BUS_NAME":"IShareSenderFileSession_{identity}","PKG_NAME":"{pkg}","TRANS_CAPABILITY":19{udp_tail},"SESSION_KEY":"{key}"}}"#,
            pkg = crate::auth::PKG_NAME
        )
    } else {
        format!(
            r#"{{"MY_CHANNEL_ID":1,"MY_IP":"{local}","DEVICE_ID":"{device_id}","CODE":1538,"API_VERSION":2,"BUSINESS_TYPE":3,"STREAM_TYPE":255,"CHANNEL_TYPE":1,"UDP_CONN_TYPE":1,"BUS_NAME":"IShareReceiverFileSession","CLIENT_BUS_NAME":"IShareSenderFileSession","PKG_NAME":"{pkg}","TRANS_CAPABILITY":0,"SESSION_KEY":"{key}"}}"#,
            pkg = crate::auth::PKG_NAME
        )
    };
    let mut body = payload.into_bytes();
    body.push(0);
    Ok(body)
}

pub(super) fn logical_addr(local: &str) -> Result<Vec<u8>> {
    crate::tlv_encode(10, &crate::tlv_encode(1, local.as_bytes())?)
}

pub(super) fn send_meta(
    channel: &mut Channel,
    key: &[u8],
    display_name: &str,
    node_id: &str,
    sequence: &mut u64,
    kind: transfer::PeerKind,
    peer_header: Option<(u32, u32, u64, u32, u32)>,
) -> Result<()> {
    let mut raw = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let inner_seq = match (kind, peer_header) {
        (transfer::PeerKind::Harmony, Some(h)) => h.2,
        _ => u64::from_le_bytes(raw),
    };

    let info_header = match (kind, peer_header) {
        (transfer::PeerKind::Harmony, Some(h)) => h,
        _ => (PEER_META_FRAME, 5, inner_seq, 0, 0),
    };
    let info = if kind.is_apple() {
        format!(
            r#"{{"DEVICE_NAME":"{display_name}","DEVICE_TYPE_ID":{DEVICE_TYPE_ID},"FLAG":100,"META_AUTH_CAPA":1,"META_NODE_ID":"{node_id}","TOKEN_ID":"0000000000000000000000000000000000000000000000000000000000000001"}}"#
        )
    } else {
        format!(
            r#"{{"DEVICE_NAME":"{display_name}","DEVICE_TYPE_ID":{DEVICE_TYPE_ID},"META_NODE_ID":"{node_id}","FLAG":100}}"#
        )
    };
    channel.transmit(&transfer::seal_channel_frame(
        key,
        info_header,
        info.as_bytes(),
        *sequence,
    )?)?;
    *sequence += 1;
    channel.transmit(&transfer::seal_channel_frame(
        key,
        (PEER_META_ACK_FRAME, 5, inner_seq, 0, 0),
        PEER_META_ACK_JSON,
        *sequence,
    )?)?;
    *sequence += 1;
    Ok(())
}
