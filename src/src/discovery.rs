//! 局域网发现：UDP 5684 上的 CoAP 风格 beacon / query / ACK。
//! 能否接收分享看 `capabilityBitmap` 的掩码值 256，解析结果只有接收 / 不接收两态。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use rand::RngCore;
use serde_json::Value;

use crate::{Error, Result};

pub const PORT: u16 = 5684;

pub const MULTICAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);

static SCAN_NOW: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn request_scan() {
    SCAN_NOW.store(true, std::sync::atomic::Ordering::Relaxed);
}

pub fn take_scan_request() -> bool {
    SCAN_NOW.swap(false, std::sync::atomic::Ordering::Relaxed)
}
pub const SHARE_CAPABILITY_BIT: u64 = 256;

#[derive(Debug, Clone)]
pub struct Peer {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub name: String,
    pub brand: String,
    pub kind: String,
    pub last_seen: Instant,
    /// 对端 `capabilityBitmap` 里有没有 256 位 —— 有才代表「它现在会接收分享」。
    pub accepts: bool,
}

pub fn is_discovery_packet(data: &[u8]) -> bool {
    data.len() >= 32 && data.windows(15).any(|w| w == b"device_discover")
}

pub fn discovery_beacon(local_ip: &str, port: u16, identity: &str, name: &str, discovering: bool) -> Vec<u8> {

    let seq_no = (rand::random::<u16>()) as u32;
    let device_id = format!(r#"{{"UDID":"{identity}"}}"#);
    let mode = if discovering { 1 } else { 10 };

    let mut json = if discovering {
        format!(
            concat!(
                r#"{{"deviceId":{},"devicename":{},"type":{},"hicomversion":"","mode":{},"#,
                r#""deviceHash":"","serviceData":"port:{},","extendServiceData":"summary:{},nbVer:9,OH:1,icon:1,abl:31,rssi:-58","#,
                r#""wlanIp":"{}","capabilityBitmap":[{}],"bType":5,"seqNo":{}"#
            ),
            json_string(&device_id),
            json_string(crate::clip_chars(name, 60)),
            DEVICE_TYPE_PC,
            mode,
            port,
            summary_hex(identity),
            local_ip,
            CAPABILITY_BITS,
            seq_no
        )
    } else {
        format!(
            concat!(
                r#"{{"deviceId":{},"devicename":{},"type":{},"hicomversion":"","mode":{},"#,
                r#""deviceHash":"","serviceData":"port:{},","extendServiceData":"osType:2,nbVer:9,rssi:-58,abl:8","#,
                r#""wlanIp":"{}","capabilityBitmap":[{}],"bType":5,"seqNo":{}"#
            ),
            json_string(&device_id),
            json_string(crate::clip_chars(name, 60)),
            DEVICE_TYPE_PC,
            mode,
            port,
            local_ip,
            CAPABILITY_BITS,
            seq_no
        )
    };
    json.push('}');

    let mut out = Vec::with_capacity(32 + json.len());
    if discovering {
        out.extend_from_slice(&[0x50, 0x02]);
        out.extend_from_slice(&(rand::random::<u16>()).to_be_bytes());
        push_option(&mut out, 3, local_ip.as_bytes());
        push_option(&mut out, 8, b"device_discover");
        out.push(0xFF);
    } else {
        let mut token = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut token);
        out.extend_from_slice(&[0x42, 0x02]);
        out.extend_from_slice(&token);
        out.extend_from_slice(&[0xBD, 0x02]);
        out.extend_from_slice(b"device_discover");
        out.extend_from_slice(&[0x11, 0x32]);
        out.push(0xFF);
    }
    out.extend_from_slice(json.as_bytes());
    crate::trace::discovery_build(local_ip, port, name, DEVICE_TYPE_PC);
    out
}

fn push_option(out: &mut Vec<u8>, delta: u8, value: &[u8]) {
    let len = value.len();
    if len < 13 {
        out.push((delta << 4) | len as u8);
    } else {
        out.push((delta << 4) | 13);
        out.push((len - 13) as u8);
    }
    out.extend_from_slice(value);
}

pub fn advertisement_query_harmony(local_ip: &str, port: u16, identity: &str, name: &str) -> Vec<u8> {
    let mut token = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut token);
    let seq_no = (rand::random::<u16>()) as u32;
    let device_id = format!(r#"{{"UDID":"{identity}"}}"#);
    let json = format!(
        concat!(
            r#"{{"deviceId":{},"devicename":{},"type":{},"hicomversion":"","mode":1,"#,
            r#""deviceHash":"","serviceData":"port:{},","extendServiceData":"osType:2,nbVer:9,rssi:-58,abl:8","#,
            r#""wlanIp":"{}","capabilityBitmap":[{}],"bType":5,"seqNo":{},"#,
            r#""coapUri":"coap://{}/device_discover""#
        ),
        json_string(&device_id),
        json_string(crate::clip_chars(name, 60)),
        DEVICE_TYPE_PC,
        port,
        local_ip,
        CAPABILITY_BITS,
        seq_no,
        local_ip
    ) + "}";

    let mut out = Vec::with_capacity(32 + json.len());
    out.extend_from_slice(&[0x42, 0x02]);
    out.extend_from_slice(&token);
    out.extend_from_slice(&[0xBD, 0x02]);
    out.extend_from_slice(b"device_discover");
    out.extend_from_slice(&[0x11, 0x32]);
    out.push(0xFF);
    out.extend_from_slice(json.as_bytes());
    out
}

fn summary_hex(identity: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(identity.as_bytes());
    hasher.finalize().iter().map(|b| format!("{b:02X}")).collect()
}

const CAPABILITY_BITS: u64 = 455;

const DEVICE_TYPE_PC: u32 = 12;

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn parse_options(data: &[u8]) -> Result<(usize, HashMap<u64, Vec<u8>>)> {
    let mut offset = 0usize;
    let mut number = 0u64;
    let mut options: HashMap<u64, Vec<u8>> = HashMap::new();

    let read_extended = |nibble: u8, offset: &mut usize| -> Result<u64> {
        match nibble {
            n if n < 13 => Ok(n as u64),
            13 => {
                if *offset >= data.len() {
                    return Err(Error::Truncated);
                }
                let v = data[*offset] as u64 + 13;
                *offset += 1;
                Ok(v)
            }
            14 => {
                if *offset + 2 > data.len() {
                    return Err(Error::Truncated);
                }
                let v = u16::from_be_bytes([data[*offset], data[*offset + 1]]) as u64 + 269;
                *offset += 2;
                Ok(v)
            }
            _ => Err(Error::Format),
        }
    };

    while offset < data.len() && data[offset] != 0xFF {
        let initial = data[offset];
        offset += 1;
        number += read_extended(initial >> 4, &mut offset)?;
        let length = read_extended(initial & 0x0F, &mut offset)? as usize;
        if offset + length > data.len() || options.len() >= 16 {
            return Err(Error::Truncated);
        }
        options.insert(number, data[offset..offset + length].to_vec());
        offset += length;
    }
    Ok((offset, options))
}

/// 对端用 CON（首字节 0x4x）发来的应答必须回 4 字节 ACK，否则会按 0 s / 1.2 s / 3.5 s
/// 重传三次。实测补上这个 ACK 后，一次 query 只收到一个应答。
pub fn discovery_ack(message_id: [u8; 2]) -> [u8; 4] {
    [0x60, 0x00, message_id[0], message_id[1]]
}

pub fn parse_discovery_beacon(data: &[u8], host: &str, local_network: Ipv4Addr, local_prefix: u8) -> Result<(Peer, bool, [u8; 2])> {
    let src: Ipv4Addr = host.parse().map_err(|_| Error::Format)?;
    if src == local_network || !same_subnet(src, local_network, local_prefix) {
        return Err(Error::Protocol("源地址不在本网段".into()));
    }
    if data.len() < 4 || data[0] >> 6 != 1 || (data[0] & 0x0F) > 8 {
        return Err(Error::Format);
    }
    let message_type = (data[0] >> 4) & 3;
    let token_size = (data[0] & 0x0F) as usize;
    if message_type > 1 || data[1] != 2 || 4 + token_size > data.len() {
        return Err(Error::Format);
    }

    let mut offset = 4 + token_size;
    let (payload_marker, options) = parse_options(&data[offset..])?;
    offset += payload_marker;

    match options.get(&11) {
        Some(v) if v == b"device_discover" => {}
        _ => return Err(Error::Format),
    }
    if offset >= data.len() {
        return Err(Error::Truncated);
    }
    let mut payload = &data[offset + 1..];
    if payload.last() == Some(&0) {
        payload = &payload[..payload.len() - 1];
    }

    let value: Value = serde_json::from_slice(payload).map_err(|_| Error::Format)?;
    let obj = value.as_object().ok_or(Error::Format)?;

    if obj.get("wlanIp").and_then(|v| v.as_str()) != Some(host) {
        return Err(Error::Protocol("广播地址与源 IP 不一致".into()));
    }
    if obj.get("bType").and_then(|v| v.as_u64()) != Some(5) {
        return Err(Error::Format);
    }

    let caps = obj
        .get("capabilityBitmap")
        .and_then(|v| v.as_array())
        .ok_or(Error::Format)?;
    if caps.is_empty() || caps.len() > 4 {
        return Err(Error::Format);
    }
    let first_cap = caps[0].as_u64().unwrap_or(0);

    let kind = match obj.get("type").and_then(|v| v.as_u64()) {
        Some(12) => "computer",
        Some(14) => "phone",
        Some(17) => "tablet",
        _ => "unknown",
    };

    // 没有 256 位不代表这是非法包：手机在「关闭」或「仅分享过但没加你」时照样回设备信息，
    // 只是明说「我不接收」。这种设备要留在列表里，标记成不可发送，而不是当垃圾包丢掉。
    let accepts = first_cap & SHARE_CAPABILITY_BIT != 0;

    let service = obj.get("serviceData").and_then(|v| v.as_str()).unwrap_or("");
    let port = service
        .split(',')
        .find_map(|item| item.trim().strip_prefix("port:"))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(Error::Format)?;

    let name = obj.get("devicename").and_then(|v| v.as_str()).unwrap_or("Huawei").to_string();
    let device_id = obj
        .get("deviceId")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.get("UDID").and_then(|u| u.as_str()).map(|s| s.to_string()))
        .unwrap_or_else(|| format!("{host}:{port}"));

    let peer = Peer {
        id: device_id,
        host: host.to_string(),
        port,
        name,
        brand: "Huawei".to_string(),
        kind: kind.to_string(),
        last_seen: Instant::now(),
        accepts,
    };

    let confirmable = message_type == 0;
    let message_id = [data[2], data[3]];
    crate::trace::discovery_rx(&peer);
    Ok((peer, confirmable, message_id))
}

fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = if prefix >= 32 { u32::MAX } else { u32::MAX << (32 - prefix) };
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

pub struct DiscoverySocket {
    socket: UdpSocket,
    pub local_ip: Ipv4Addr,
}

impl DiscoverySocket {
    pub fn bind(local_ip: Ipv4Addr) -> Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(local_ip), PORT))
            .map_err(|e| Error::Io(format!("绑定 {local_ip}:{PORT} 失败: {e}")))?;
        socket
            .set_broadcast(true)
            .map_err(|e| Error::Io(format!("开启广播失败: {e}")))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(400)))
            .map_err(|e| Error::Io(e.to_string()))?;
        let _ = socket.join_multicast_v4(&MULTICAST, &local_ip);
        Ok(Self { socket, local_ip })
    }

    pub fn transmit(&self, target: &str, data: &[u8]) -> Result<()> {
        let dest = match target {
            "broadcast" => SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), PORT),
            "multicast" => SocketAddr::new(IpAddr::V4(MULTICAST), PORT),
            ip => SocketAddr::new(ip.parse().map_err(|_| Error::Argument)?, PORT),
        };
        self.socket
            .send_to(data, dest)
            .map_err(|e| Error::Io(format!("发送广播失败: {e}")))?;
        crate::trace::discovery_tx(target, data);
        Ok(())
    }

    pub fn recv(&self) -> Option<(String, Vec<u8>)> {
        let mut buf = vec![0u8; 8192];
        match self.socket.recv_from(&mut buf) {
            Ok((n, addr)) => {
                buf.truncate(n);
                crate::trace::discovery_rx_raw(&addr.ip().to_string(), &buf);
                Some((addr.ip().to_string(), buf))
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_packet_is_not_discovery() {

        assert!(!is_discovery_packet(&[0x60, 0x00, 0xF5, 0x8E]));
        assert!(!is_discovery_packet(&[]));

        let pkt = discovery_beacon("192.168.1.5", 41234, "AABB", "PC", true);
        assert!(is_discovery_packet(&pkt));
        let answer = discovery_beacon("192.168.1.5", 41234, "AABB", "PC", false);
        assert!(is_discovery_packet(&answer));

        assert!(!is_discovery_packet(&vec![0u8; 100]));
    }

    #[test]
    fn advertisement_shape() {

        let query = discovery_beacon("192.168.1.5", 41234, "AABBCCDDEEFF", "我的电脑", true);
        assert_eq!(&query[0..2], &[0x50, 0x02]);
        assert!(query.windows(15).any(|w| w == b"device_discover"));
        assert_eq!(*query.last().unwrap(), b'}');
        let text = String::from_utf8_lossy(&query);
        assert!(text.contains(r#""wlanIp":"192.168.1.5""#));
        assert!(text.contains(r#""mode":1"#));
        assert!(text.contains("summary:"));

        assert!(text.contains(r#""type":12"#));

        let answer = discovery_beacon("192.168.1.5", 41234, "AABBCCDDEEFF", "我的电脑", false);
        assert_eq!(&answer[0..2], &[0x42, 0x02]);
        let text = String::from_utf8_lossy(&answer);
        assert!(text.contains(r#""mode":10"#));
        assert!(text.contains("osType:2"));
    }

    #[test]
    fn json_escaping() {
        assert_eq!(json_string(r#"a"b"#), r#""a\"b""#);
    }

    #[test]
    fn ack_frame_shape() {
        // 与手机回我们的 ACK（`60 00 d8 3c`）同形：type=ACK(2)、零长度、回显 message id
        let ack = discovery_ack([0xD8, 0x3C]);
        assert_eq!(ack, [0x60, 0x00, 0xD8, 0x3C]);
        assert_eq!((ack[0] >> 4) & 3, 2);
        assert_eq!(ack[1], 0x00);
    }

    #[test]
    fn subnet_match() {
        let a: Ipv4Addr = "192.168.1.5".parse().unwrap();
        let b: Ipv4Addr = "192.168.1.9".parse().unwrap();
        let c: Ipv4Addr = "192.168.2.9".parse().unwrap();
        assert!(same_subnet(a, b, 24));
        assert!(!same_subnet(a, c, 24));
    }
}
