use rand::RngCore;

use crate::auth::{unpack_envelope, unwrap_tlv};
use crate::{
    aesgcm_decrypt, aesgcm_decrypt_n16, aesgcm_encrypt, aesgcm_encrypt_n16, frame_encode,
    tlv_encode, varint_decode, varint_encode, Error, Result, FRAME_HEADER_SIZE, MAGIC,
};

pub fn tlvs(data: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
    let mut items = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        if items.len() >= 32 {
            return Err(Error::Format);
        }
        let tag = varint_decode(data, &mut offset)?;
        let size = varint_decode(data, &mut offset)? as usize;
        if size > data.len().saturating_sub(offset) {
            return Err(Error::Truncated);
        }
        items.push((tag, data[offset..offset + size].to_vec()));
        offset += size;
    }
    Ok(items)
}

pub fn tlv_get(data: &[u8], tag: u64) -> Result<Option<Vec<u8>>> {
    Ok(tlvs(data)?.into_iter().find(|(t, _)| *t == tag).map(|(_, v)| v))
}

pub fn encrypted_frame(device_hash: &[u8], key: &[u8], body: &[u8], sequence: u64) -> Result<Vec<u8>> {
    let envelope = encrypted_envelope(device_hash, key, body)?;
    frame_encode(9, sequence, 0, &envelope)
}

pub fn encrypted_envelope(device_hash: &[u8], key: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let metadata = tlv_encode(1, &nonce)?;
    let ciphertext = aesgcm_encrypt_n16(key, &nonce, body)?;

    let mut envelope = Vec::new();
    envelope.extend_from_slice(device_hash);
    envelope.extend_from_slice(&[0x81, 0xE5, 0x82]);
    envelope.extend(varint_encode(metadata.len() as u64)?);
    envelope.extend_from_slice(&metadata);
    envelope.extend(varint_encode(ciphertext.len() as u64)?);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub fn decrypt_frame(frame: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let (mode, ciphertext) = unpack_envelope(frame)?;
    if mode != 2 {
        return Err(Error::Format);
    }

    let payload = &frame[FRAME_HEADER_SIZE..];
    let mut offset = 16usize;
    let mut meta_len = 0u64;
    for _ in 0..4 {
        meta_len = varint_decode(payload, &mut offset)?;
    }
    if offset + meta_len as usize > payload.len() {
        return Err(Error::Truncated);
    }
    let metadata = &payload[offset..offset + meta_len as usize];
    let nonce = unwrap_tlv(metadata, 1)?;
    if nonce.len() != 12 && nonce.len() != 16 {
        return Err(Error::Format);
    }
    if nonce.len() == 16 {
        aesgcm_decrypt_n16(key, nonce, &ciphertext)
    } else {
        aesgcm_decrypt(key, nonce, &ciphertext)
    }
}

pub fn channel_frame(key: &[u8], header: (u32, u32, u64, u32, u32), plain: &[u8], sequence: u64) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let sealed = aesgcm_encrypt(key, &nonce, plain)?;

    let mut payload = Vec::with_capacity(12 + sealed.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&sealed);

    let mut inner = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
    inner.extend_from_slice(&header.0.to_le_bytes());
    inner.extend_from_slice(&header.1.to_le_bytes());
    inner.extend_from_slice(&header.2.to_le_bytes());
    inner.extend_from_slice(&header.3.to_le_bytes());
    inner.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    inner.extend_from_slice(&payload);

    frame_encode(21, sequence, 0, &inner)
}

pub fn dfile_kind_name(kind: u8) -> &'static str {
    match kind {
        1 => "LIST",
        2 => "ACK",
        3 => "REQ",
        4 => "DATA",
        5 => "DATA_ACK",
        6 => "DONE",
        7 => "DONE_ACK",
        8 => "SETTINGS",
        9 => "RST",
        10 => "FLOW",
        11 => "CONGEST",
        12 => "PEER_OFF",
        13 => "BACKPRESSURE",
        22 => "BIG_FRAME",
        _ => "UNKNOWN",
    }
}

pub fn decode_channel(data: &[u8], key: &[u8]) -> Result<((u32, u32, u64, u32, u32), Vec<u8>)> {
    if data.len() < 2 * FRAME_HEADER_SIZE + 28 {
        return Err(Error::Truncated);
    }
    let outer_module = u32::from_le_bytes(data[4..8].try_into().map_err(|_| Error::Truncated)?);
    let outer_len = u32::from_le_bytes(data[20..24].try_into().map_err(|_| Error::Truncated)?) as usize;
    if outer_module != 21 || outer_len != data.len() - FRAME_HEADER_SIZE {
        return Err(Error::Format);
    }

    let inner = &data[FRAME_HEADER_SIZE..];
    let header = (
        u32::from_le_bytes(inner[0..4].try_into().map_err(|_| Error::Truncated)?),
        u32::from_le_bytes(inner[4..8].try_into().map_err(|_| Error::Truncated)?),
        u64::from_le_bytes(inner[8..16].try_into().map_err(|_| Error::Truncated)?),
        u32::from_le_bytes(inner[16..20].try_into().map_err(|_| Error::Truncated)?),
        u32::from_le_bytes(inner[20..24].try_into().map_err(|_| Error::Truncated)?),
    );
    if header.4 as usize != data.len() - 2 * FRAME_HEADER_SIZE {
        return Err(Error::Format);
    }

    let nonce = &inner[24..36];
    let sealed = &inner[36..];
    let plain = aesgcm_decrypt(key, nonce, sealed)?;
    Ok((header, plain))
}

pub fn dfile_packet(kind: u8, flags: u8, session: u16, transaction: u16, payload: &[u8]) -> Result<Vec<u8>> {
    if !(1..=14).contains(&kind) || transaction > u16::MAX || payload.len() > u16::MAX as usize {
        return Err(Error::Argument);
    }
    let mut out = Vec::with_capacity(8 + payload.len());
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&session.to_be_bytes());
    out.extend_from_slice(&transaction.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn dfile_settings(encrypt_headers: bool) -> Vec<u8> {
    dfile_settings_with(encrypt_headers, 1472)
}

pub fn dfile_settings_with(encrypt_headers: bool, data_frame_size: u16) -> Vec<u8> {
    dfile_settings_full(encrypt_headers, 1472, data_frame_size)
}

#[derive(Clone, Copy, Debug)]
pub struct SettingsProfile {
    pub encrypt_headers: bool,
    pub mtu: u16,
    pub connection_type: u16,
    pub version: u32,
    pub abm_capability: u32,
    pub capability: u32,
    pub data_frame_size: u32,
    pub caps_check: u32,
    pub tail: (u32, u32),
}

impl SettingsProfile {
    pub fn verified(encrypt_headers: bool, mtu: u16, data_frame_size: u16) -> Self {
        Self {
            encrypt_headers,
            mtu,
            connection_type: 2,
            version: 1,
            abm_capability: 0,
            capability: 0,
            data_frame_size: data_frame_size as u32,
            caps_check: if encrypt_headers { 0x100 } else { 0 },
            tail: (0, 1),
        }
    }

    pub fn handset(encrypt_headers: bool) -> Self {
        Self {
            encrypt_headers,
            mtu: 1472,
            connection_type: 2,
            version: 1,
            abm_capability: 0,
            capability: 0x40,
            data_frame_size: 65535,
            caps_check: 0x36C,
            tail: (10, 7),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(100);
        payload.extend_from_slice(&self.mtu.to_be_bytes());
        payload.extend_from_slice(&self.connection_type.to_be_bytes());
        payload.extend_from_slice(&self.version.to_be_bytes());
        payload.extend_from_slice(&self.abm_capability.to_be_bytes());
        payload.extend_from_slice(&self.capability.to_be_bytes());
        payload.extend_from_slice(&self.data_frame_size.to_be_bytes());
        payload.extend_from_slice(&self.caps_check.to_be_bytes());
        payload.extend_from_slice(&[0u8; 67]);
        payload.push(u8::from(self.encrypt_headers));
        payload.extend_from_slice(&self.tail.0.to_be_bytes());
        payload.extend_from_slice(&self.tail.1.to_be_bytes());

        let mut out = Vec::with_capacity(8 + payload.len());
        out.push(8);
        out.push(0);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }
}

pub fn dfile_settings_full(encrypt_headers: bool, mtu: u16, data_frame_size: u16) -> Vec<u8> {
    SettingsProfile::verified(encrypt_headers, mtu, data_frame_size).encode()
}

pub fn parse_dfile_header(data: &[u8]) -> Result<(u8, u8, u16, u16, usize)> {
    if data.len() < 8 {
        return Err(Error::Truncated);
    }
    let kind = data[0];
    let flags = data[1];
    let session = u16::from_be_bytes([data[2], data[3]]);
    let transaction = u16::from_be_bytes([data[4], data[5]]);
    let size = u16::from_be_bytes([data[6], data[7]]) as usize;

    if !(1..=31).contains(&kind) {
        return Err(Error::Format);
    }
    Ok((kind, flags, session, transaction, size))
}

pub fn channel_magic() -> u32 {
    MAGIC
}

pub const DFILE_AAD: &[u8] = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

pub fn dfile_encrypt_control(key: &[u8], packet: &[u8]) -> Result<Vec<u8>> {
    if packet.len() < 8 {
        return Err(Error::Truncated);
    }
    let (kind, flags, session, transaction, size) = parse_dfile_header(packet)?;
    if size != packet.len() - 8 {
        return Err(Error::Format);
    }

    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0);

    let mut plain = Vec::with_capacity(8 + packet.len());
    plain.extend_from_slice(&stamp.to_be_bytes());
    plain.extend_from_slice(packet);

    let mut sealed = crate::aes128gcm_encrypt_aad(key, &nonce, &plain, DFILE_AAD)?;
    sealed.extend_from_slice(&nonce);

    let mut out = Vec::with_capacity(8 + sealed.len());
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&session.to_be_bytes());
    out.extend_from_slice(&transaction.to_be_bytes());
    out.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

pub fn dfile_decrypt_control(key: &[u8], header: (u8, u8, u16, u16), payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() < 44 {
        return Err(Error::Truncated);
    }
    let split = payload.len() - 12;
    let nonce = &payload[split..];
    let sealed = &payload[..split];
    let plain = crate::aes128gcm_decrypt_aad(key, nonce, sealed, DFILE_AAD)?;
    if plain.len() < 16 {
        return Err(Error::Truncated);
    }
    let inner = parse_dfile_header(&plain[8..])?;
    if (inner.0, inner.1, inner.2, inner.3) != header || inner.4 != plain.len() - 16 {
        return Err(Error::Format);
    }
    Ok(plain[8..].to_vec())
}

pub const DFILE_MAX_CONTENT: usize = 65535 - 50;

pub fn dfile_data_chunk(key: &[u8], content: &[u8], sequence: u32, flags: u8, file_id: u16) -> Result<Vec<u8>> {
    if content.is_empty() || content.len() > DFILE_MAX_CONTENT || !matches!(flags, 0 | 1 | 3) || file_id == 0 {
        return Err(Error::Argument);
    }
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let mut plain = Vec::with_capacity(8 + content.len());
    plain.extend_from_slice(&file_id.to_be_bytes());
    plain.extend_from_slice(&sequence.to_be_bytes());
    plain.extend_from_slice(&1u16.to_be_bytes());
    plain.extend_from_slice(content);

    let sealed = crate::aes128gcm_encrypt_aad(key, &nonce, &plain, DFILE_AAD)?;

    let mut payload = Vec::with_capacity(6 + sealed.len() + 12);
    payload.extend_from_slice(&file_id.to_be_bytes());
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.extend_from_slice(&sealed);
    payload.extend_from_slice(&nonce);

    dfile_packet(4, flags, 0, 1, &payload)
}

pub fn dfile_parse_chunk(key: &[u8], payload: &[u8]) -> Result<(u16, u32, Vec<u8>)> {
    if payload.len() < 6 + 16 + 12 {
        return Err(Error::Truncated);
    }
    let file_id = u16::from_be_bytes([payload[0], payload[1]]);
    let sequence = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
    let rest = &payload[6..];
    let split = rest.len() - 12;
    let sealed = &rest[..split];
    let nonce = &rest[split..];
    let plain = crate::aes128gcm_decrypt_aad(key, nonce, sealed, DFILE_AAD)?;
    if plain.len() < 8 {
        return Err(Error::Truncated);
    }
    Ok((file_id, sequence, plain[8..].to_vec()))
}

pub fn build_headers(entries: &[(u16, u64, Vec<u8>)]) -> Result<Vec<Vec<u8>>> {
    if entries.is_empty() || entries.len() > 512 {
        return Err(Error::Argument);
    }
    let count = entries.len() as u16;
    let mut frames = Vec::new();
    let mut payload = count.to_be_bytes().to_vec();

    for (file_id, size, name) in entries {
        if *file_id == 0 || name.is_empty() || name.len() > 255 {
            return Err(Error::Protocol(format!(
                "文件清单条目不合法：id={file_id} 名字长度={}",
                name.len()
            )));
        }
        let mut unit = Vec::with_capacity(12 + name.len());
        unit.extend_from_slice(&file_id.to_be_bytes());
        unit.extend_from_slice(&size.to_be_bytes());
        unit.extend_from_slice(&(name.len() as u16).to_be_bytes());
        unit.extend_from_slice(name);

        if payload.len() + unit.len() > 1400 {
            frames.push(dfile_packet(1, 0, 0, 1, &payload)?);
            payload = count.to_be_bytes().to_vec();
        }
        payload.extend_from_slice(&unit);
    }
    frames.push(dfile_packet(1, 0, 0, 1, &payload)?);
    Ok(frames)
}

pub fn parse_headers(payload: &[u8], expected_count: u16) -> Result<Vec<(u16, u64, Vec<u8>)>> {
    if payload.len() < 14 || u16::from_be_bytes([payload[0], payload[1]]) != expected_count {
        return Err(Error::Format);
    }
    let mut offset = 2usize;
    let mut out = Vec::new();
    while offset < payload.len() {
        if payload.len() - offset < 12 {
            return Err(Error::Truncated);
        }
        let file_id = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let size = u64::from_be_bytes(payload[offset + 2..offset + 10].try_into().map_err(|_| Error::Truncated)?);
        let length = u16::from_be_bytes([payload[offset + 10], payload[offset + 11]]) as usize;
        offset += 12;
        if offset + length > payload.len() {
            return Err(Error::Truncated);
        }
        let name = payload[offset..offset + length].to_vec();
        offset += length;
        if !(1..=16).contains(&file_id) || out.iter().any(|(id, _, _)| *id == file_id) {
            return Err(Error::Format);
        }
        out.push((file_id, size, name));
    }
    Ok(out)
}

pub const BYTES_MAGIC: u32 = 0xBABE_FACE;

pub fn bytes_frame(key: &[u8], plain: &[u8], sequence: u32) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&sequence.to_le_bytes());
    rand::rngs::OsRng.fill_bytes(&mut nonce[4..12]);

    let sealed = crate::aesgcm_encrypt(key, &nonce, plain)?;
    let mut payload = Vec::with_capacity(12 + sealed.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&sealed);

    let mut out = Vec::with_capacity(16 + payload.len());
    out.extend_from_slice(&BYTES_MAGIC.to_le_bytes());
    out.extend_from_slice(&sequence.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn try_read_bytes_frame(
    channel: &mut crate::channel::Channel,
    key: &[u8],
    timeout: std::time::Duration,
) -> Result<Option<(u32, Vec<u8>)>> {
    use std::time::Instant;

    const HEADER: usize = 16;
    const MAX_SIZE: usize = 8 * 1024 * 1024;
    let deadline = Instant::now() + timeout;

    loop {
        if channel.buffered_len() >= HEADER {
            let head = channel.peek(HEADER)?;
            let magic = u32::from_le_bytes(head[0..4].try_into().map_err(|_| Error::Truncated)?);
            let sequence = u32::from_le_bytes(head[4..8].try_into().map_err(|_| Error::Truncated)?);
            let size = u32::from_le_bytes(head[12..16].try_into().map_err(|_| Error::Truncated)?) as usize;
            if magic != BYTES_MAGIC || !(13..=MAX_SIZE).contains(&size) {
                let n = channel.buffered_len().min(32);
                let dump = channel.peek(n).unwrap_or_default();
                eprintln!(
                    "[byte] 帧头异常 magic={magic:#X} size={size} 头 {n}B: {:02X?}",
                    dump
                );
                return Err(Error::Format);
            }
            if channel.buffered_len() >= HEADER + size {
                let payload = channel.take_buffered(HEADER + size, timeout)?;
                let body = &payload[HEADER..];
                let plain = crate::aesgcm_decrypt(key, &body[..12], &body[12..])?;
                return Ok(Some((sequence, plain)));
            }
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let want = if channel.buffered_len() < HEADER {
            HEADER - channel.buffered_len()
        } else {
            let head = channel.peek(HEADER)?;
            let size = u32::from_le_bytes(head[12..16].try_into().map_err(|_| Error::Truncated)?) as usize;
            (HEADER + size).saturating_sub(channel.buffered_len()).max(1)
        };
        if !channel.fill(want.min(65536), remaining)? {
            return Ok(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_verified_profile_is_byte_identical() {
        let p = dfile_settings(true);
        assert_eq!(p.len(), 108);
        assert_eq!(&p[0..8], &[8, 0, 0, 0, 0, 0, 0, 100]);
        assert_eq!(u16::from_be_bytes([p[8], p[9]]), 1472);
        assert_eq!(u32::from_be_bytes([p[20], p[21], p[22], p[23]]), 0);
        assert_eq!(u32::from_be_bytes([p[28], p[29], p[30], p[31]]), 0x100);
        assert_eq!(u32::from_be_bytes([p[100], p[101], p[102], p[103]]), 0);
        assert_eq!(u32::from_be_bytes([p[104], p[105], p[106], p[107]]), 1);
    }

    #[test]
    fn settings_handset_profile_matches_capture() {
        let p = SettingsProfile::handset(true).encode();
        assert_eq!(u32::from_be_bytes([p[20], p[21], p[22], p[23]]), 0x40);
        assert_eq!(u32::from_be_bytes([p[24], p[25], p[26], p[27]]), 65535);
        assert_eq!(u32::from_be_bytes([p[28], p[29], p[30], p[31]]), 0x36C);
        assert_eq!(u32::from_be_bytes([p[100], p[101], p[102], p[103]]), 10);
        assert_eq!(u32::from_be_bytes([p[104], p[105], p[106], p[107]]), 7);
    }

    #[test]
    fn dfile_packet_layout() {
        let p = dfile_packet(1, 0, 1, 7, b"abc").unwrap();
        assert_eq!(p.len(), 11);
        assert_eq!(p[0], 1);
        assert_eq!(u16::from_be_bytes([p[4], p[5]]), 7);
        assert_eq!(u16::from_be_bytes([p[6], p[7]]), 3);
    }

    #[test]
    fn channel_frame_roundtrip() {
        let key = [9u8; 32];
        let header = (MAGIC, 6, 42, 0x94, 0);
        let frame = channel_frame(&key, header, b"payload", 5).unwrap();
        let (got_header, plain) = decode_channel(&frame, &key).unwrap();

        assert_eq!(got_header.0, header.0);
        assert_eq!(got_header.1, header.1);
        assert_eq!(got_header.2, header.2);
        assert_eq!(got_header.3, header.3);
        assert_eq!(plain, b"payload");
    }

    #[test]
    fn control_frame_roundtrip() {
        let key = [3u8; 32];
        let hash = [7u8; 16];
        let frame = encrypted_frame(&hash, &key, b"body", 9).unwrap();
        match decrypt_frame(&frame, &key) {
            Ok(v) => assert_eq!(v, b"body"),
            Err(e) => panic!("decrypt_frame 失败: {e} (frame={} bytes)", frame.len()),
        }
    }

    #[test]
    fn dfile_control_roundtrip() {
        let key = [1u8; 32];
        let payload = vec![9u8; 120];
        let packet = dfile_packet(1, 0, 1, 0, &payload).unwrap();
        let encrypted = dfile_encrypt_control(&key, &packet).unwrap();

        let (kind, flags, session, transaction, size) = parse_dfile_header(&encrypted).unwrap();
        assert_eq!((kind, flags, session, transaction), (1, 0, 1, 0));
        assert_eq!(size, encrypted.len() - 8);

        let body = &encrypted[8..8 + size];
        let back = dfile_decrypt_control(&key, (1, 0, 1, 0), body).unwrap();
        assert_eq!(back, packet);
    }

    #[test]
    fn dfile_chunk_roundtrip() {
        let key = [2u8; 32];
        let content: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();
        let frame = dfile_data_chunk(&key, &content, 7, 1, 3).unwrap();

        let (kind, flags, session, transaction, size) = parse_dfile_header(&frame).unwrap();
        assert_eq!((kind, flags, session, transaction), (4, 1, 0, 1));
        let body = &frame[8..8 + size];

        let (file_id, sequence, got) = dfile_parse_chunk(&key, body).unwrap();
        assert_eq!((file_id, sequence), (3, 7));
        assert_eq!(got, content);
    }

    #[test]
    fn dfile_chunk_rejects_bad_input() {
        let key = [3u8; 32];
        assert!(dfile_data_chunk(&key, &[], 0, 3, 1).is_err());

        assert!(dfile_data_chunk(&key, &vec![0u8; 1423], 0, 3, 1).is_ok());
        let big = dfile_data_chunk(&key, &vec![0u8; DFILE_MAX_CONTENT], 0, 3, 1);
        assert!(big.is_ok(), "{:?}", big.err());
        assert!(dfile_data_chunk(&key, &vec![0u8; DFILE_MAX_CONTENT + 1], 0, 3, 1).is_err());
        assert!(dfile_data_chunk(&key, &vec![0u8; 10], 0, 2, 1).is_err());
        assert!(dfile_data_chunk(&key, &vec![0u8; 10], 0, 3, 0).is_err());
    }

    #[test]
    fn dfile_tamper_rejected() {
        let key = [4u8; 32];
        let frame = dfile_data_chunk(&key, b"secret", 0, 3, 1).unwrap();
        let (_, _, _, _, size) = parse_dfile_header(&frame).unwrap();
        let mut body = frame[8..8 + size].to_vec();
        let last = body.len() - 1;
        body[last] ^= 0xFF;
        assert!(dfile_parse_chunk(&key, &body).is_err());
    }

    #[test]
    fn tlvs_parse() {
        let mut buf = Vec::new();
        buf.extend(tlv_encode(1, b"a").unwrap());
        buf.extend(tlv_encode(2, b"bb").unwrap());
        let items = tlvs(&buf).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[1].0, 2);
        assert_eq!(items[1].1, b"bb");
    }
}
