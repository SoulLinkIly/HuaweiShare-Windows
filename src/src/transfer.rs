//! 传输公共层：帧加解密、TLV 列表、文件元数据与分块常量。

use rand::RngCore;

use crate::auth::{open_envelope, require_tlv};
use crate::{
    aesgcm_decrypt, aesgcm_decrypt_n16, aesgcm_encrypt, aesgcm_encrypt_n16, frame_encode,
    tlv_encode, varint_decode, varint_encode, Error, Result, FRAME_HEADER_SIZE,
};

pub fn tlv_list(data: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
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
    Ok(tlv_list(data)?.into_iter().find(|(t, _)| *t == tag).map(|(_, v)| v))
}

pub fn seal_encrypted_frame(device_hash: &[u8], key: &[u8], body: &[u8], sequence: u64) -> Result<Vec<u8>> {
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

pub fn open_channel_frame(wire_frame: &[u8], key: &[u8]) -> Result<Vec<u8>> {

    let (mode, ciphertext) = open_envelope(wire_frame)?;
    if mode != 2 {
        return Err(Error::Format);
    }

    let payload = &wire_frame[FRAME_HEADER_SIZE..];
    let mut offset = 16usize;
    let mut meta_len = 0u64;
    for _ in 0..4 {
        meta_len = varint_decode(payload, &mut offset)?;
    }
    if offset + meta_len as usize > payload.len() {
        return Err(Error::Truncated);
    }
    let metadata = &payload[offset..offset + meta_len as usize];
    let nonce = require_tlv(metadata, 1)?;
    if nonce.len() != 12 && nonce.len() != 16 {
        return Err(Error::Format);
    }
    if nonce.len() == 16 {
        aesgcm_decrypt_n16(key, nonce, &ciphertext)
    } else {
        aesgcm_decrypt(key, nonce, &ciphertext)
    }
}

pub fn note_plain(dir: &str, header: (u32, u32, u64, u32, u32), plain: &[u8]) {
    if !crate::trace::enabled() {
        return;
    }
    let text = String::from_utf8_lossy(&plain[..plain.len().min(1200)]);
    crate::trace::note(
        "control",
        &format!(
            "[plain {dir}] hdr=({:#X},{},{},{},{}) n={} text={}",
            header.0,
            header.1,
            header.2,
            header.3,
            header.4,
            plain.len(),
            text.replace('\0', ".").replace('\n', " ")
        ),
    );
}

pub fn seal_channel_frame(key: &[u8], header: (u32, u32, u64, u32, u32), plain: &[u8], sequence: u64) -> Result<Vec<u8>> {
    note_plain("tx", header, plain);
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

pub fn parse_channel_frame(data: &[u8], key: &[u8]) -> Result<((u32, u32, u64, u32, u32), Vec<u8>)> {
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
    note_plain("rx", header, &plain);
    Ok((header, plain))
}

pub fn decode_channel_headerless(
    data: &[u8],
    key: &[u8],
) -> Result<((u32, u32, u64, u32, u32), Vec<u8>)> {
    if data.len() < FRAME_HEADER_SIZE + 12 + 17 {
        return Err(Error::Truncated);
    }
    let outer_module = u32::from_le_bytes(data[4..8].try_into().map_err(|_| Error::Truncated)?);
    if outer_module != 21 {
        return Err(Error::Format);
    }
    let nonce = &data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + 12];
    let sealed = &data[FRAME_HEADER_SIZE + 12..];
    let plain = aesgcm_decrypt(key, nonce, sealed)?;
    Ok(((0xFFFF_0004, 0, 0, 0, plain.len() as u32), plain))
}

pub fn assemble_dfile_packet(kind: u8, flags: u8, session: u16, transaction: u16, payload: &[u8]) -> Result<Vec<u8>> {
    if !(1..=31).contains(&kind) || payload.len() > u16::MAX as usize {
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

pub fn build_settings_payload(encrypt_headers: bool) -> Vec<u8> {
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

    pub name: &'static str,

    pub exact_tail: Option<(u32, u32, u32)>,
}

impl SettingsProfile {

    pub fn sender_baseline(mtu: u16, data_frame_size: u16) -> Self {
        Self {
            encrypt_headers: true,
            mtu,
            connection_type: 2,
            version: 1,
            abm_capability: 0,
            capability: 0,
            data_frame_size: data_frame_size as u32,

            caps_check: 0x144,
            tail: (0, 1),
            name: "",
            exact_tail: None,
        }
    }

    pub fn receiver(encrypt_headers: bool, mtu: u16, data_frame_size: u16) -> Self {
        Self {
            encrypt_headers,
            mtu,
            connection_type: 2,
            version: 1,
            abm_capability: 0,
            capability: 0,
            data_frame_size: data_frame_size as u32,
            caps_check: if encrypt_headers { 0x100 } else { 0 },

            tail: (0, OUR_CIPHER_CAPS),
            name: "",
            exact_tail: None,
        }
    }

    pub fn phone_exact() -> Self {
        Self {
            encrypt_headers: true,
            mtu: 1472,
            connection_type: 2,
            version: 1,
            abm_capability: 0,
            capability: 0x40,
            data_frame_size: 65535,
            caps_check: 0x36C,
            tail: (10, 7),
            name: "unknown",

            exact_tail: Some((1, 10, OUR_CIPHER_CAPS)),
        }
    }

    pub fn phone_exact_with(data_frame_size: u16) -> Self {
        let mut profile = Self::phone_exact();
        profile.data_frame_size = data_frame_size as u32;
        profile
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
        match self.exact_tail {

            Some((a, b, c)) => {
                let mut name = [0u8; 65];
                let nb = self.name.as_bytes();
                let n = nb.len().min(65);
                name[..n].copy_from_slice(&nb[..n]);
                payload.extend_from_slice(&name);
                payload.push(u8::from(self.encrypt_headers));
                payload.push(0);
                payload.extend_from_slice(&a.to_le_bytes());
                payload.extend_from_slice(&b.to_le_bytes());
                payload.extend_from_slice(&c.to_le_bytes());
            }

            None => {
                payload.extend_from_slice(&[0u8; 67]);
                payload.push(u8::from(self.encrypt_headers));
                payload.extend_from_slice(&self.tail.0.to_be_bytes());
                payload.extend_from_slice(&self.tail.1.to_be_bytes());
            }
        }

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

pub fn settings_cipher_caps(payload: &[u8]) -> Option<u32> {
    if payload.len() < 4 {
        return None;
    }
    let t = &payload[payload.len() - 4..];
    let raw = [t[0], t[1], t[2], t[3]];
    Some(if payload.len() >= 103 {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

pub fn dfile_settings_full(encrypt_headers: bool, mtu: u16, data_frame_size: u16) -> Vec<u8> {
    SettingsProfile::receiver(encrypt_headers, mtu, data_frame_size).encode()
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

pub const DFILE_AAD: &[u8] = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

pub const CIPHER_CLEAR: u32 = 0x1;
pub const CIPHER_CHACHA: u32 = 0x2;
pub const CIPHER_AES: u32 = 0x4;

pub const OUR_CIPHER_CAPS: u32 = CIPHER_CLEAR | CIPHER_CHACHA | CIPHER_AES;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cipher {

    Clear,
    Aes128Gcm,
    ChaCha20Poly1305,
}

thread_local! {
    static PEER_CIPHER_CAPS: std::cell::Cell<u32> = const { std::cell::Cell::new(u32::MAX) };
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PeerKind {

    Harmony,

    Apple,
}

impl PeerKind {
    pub fn is_apple(self) -> bool {
        matches!(self, PeerKind::Apple)
    }
}

thread_local! {
    static PEER_KIND: std::cell::Cell<PeerKind> = const { std::cell::Cell::new(PeerKind::Harmony) };
}

pub fn set_peer_kind(kind: PeerKind) {
    PEER_KIND.with(|c| c.set(kind));
}

pub fn peer_kind() -> PeerKind {
    PEER_KIND.with(|c| c.get())
}

pub fn choose_cipher(peer_caps: Option<u32>) -> Cipher {
    let Some(caps) = peer_caps else {

        return if peer_kind().is_apple() {
            Cipher::ChaCha20Poly1305
        } else {
            Cipher::Aes128Gcm
        };
    };
    let has_aes = caps & CIPHER_AES != 0;
    let has_chacha = caps & CIPHER_CHACHA != 0;
    if !has_aes && has_chacha {

        Cipher::ChaCha20Poly1305
    } else if has_aes {

        Cipher::Aes128Gcm
    } else if has_chacha {
        Cipher::ChaCha20Poly1305
    } else {
        Cipher::Clear
    }
}

pub fn negotiate_cipher(peer_caps: Option<u32>) -> Cipher {
    PEER_CIPHER_CAPS.with(|c| c.set(peer_caps.unwrap_or(u32::MAX)));

    if let Some(caps) = peer_caps {
        let has_aes = caps & CIPHER_AES != 0;
        let has_chacha = caps & CIPHER_CHACHA != 0;

        if has_chacha {
            set_peer_kind(if has_aes {
                PeerKind::Harmony
            } else {
                PeerKind::Apple
            });
        }
    }

    let cipher = choose_cipher(peer_caps);
    crate::trace::note(
        "file#1",
        &format!(
            "对端 cipherCaps={} → {cipher:?}（家族 {:?}）",
            peer_caps
                .map(|c| format!("0x{c:X}"))
                .unwrap_or_else(|| "未声明".into()),
            peer_kind()
        ),
    );
    cipher
}

pub fn cipher() -> Cipher {
    let caps = PEER_CIPHER_CAPS.with(|c| c.get());
    choose_cipher(if caps == u32::MAX { None } else { Some(caps) })
}

pub fn note_peer_device(name: &str, type_id: u64) {
    let lower = name.to_ascii_lowercase();
    let apple = type_id == 20
        || lower.contains("ipad")
        || lower.contains("iphone")
        || lower.contains("macbook")
        || lower.contains("mac ");
    if apple {
        set_peer_kind(PeerKind::Apple);
    }
    crate::trace::note(
        "control",
        &format!(
            "对端设备 {name} type={type_id}{}",
            if apple { "（Apple）" } else { "" }
        ),
    );
}

pub fn peer_is_apple() -> bool {
    peer_kind().is_apple()
}

pub fn dfile_stamp() -> u64 {
    dfile_stamp_for(peer_kind())
}

fn dfile_stamp_for(kind: PeerKind) -> u64 {
    if kind.is_apple() {
        boot_micros()
    } else {
        unix_micros()
    }
}

fn boot_micros() -> u64 {
    #[cfg(windows)]
    {

        extern "system" {
            fn QueryPerformanceCounter(v: *mut i64) -> i32;
            fn QueryPerformanceFrequency(v: *mut i64) -> i32;
            fn GetTickCount64() -> u64;
        }
        unsafe {
            let mut freq: i64 = 0;
            let mut now: i64 = 0;
            if QueryPerformanceFrequency(&mut freq) != 0 && freq > 0
                && QueryPerformanceCounter(&mut now) != 0
            {
                (now as u128 * 1_000_000u128 / freq as u128) as u64
            } else {
                GetTickCount64() * 1000
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok())
            .map(|s| (s * 1e6) as u64)
            .unwrap_or(0)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        unix_micros()
    }
}

fn unix_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

fn chacha_key(key: &[u8]) -> Result<[u8; 32]> {
    if key.len() < 32 {
        return Err(Error::Argument);
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&key[..32]);
    Ok(k)
}

fn aead_seal(key: &[u8], nonce: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    match cipher() {
        Cipher::Clear => Ok(plain.to_vec()),
        Cipher::Aes128Gcm => crate::aes128gcm_encrypt_aad(key, nonce, plain, DFILE_AAD),
        Cipher::ChaCha20Poly1305 => {
            Ok(crate::chacha::aead_encrypt(&chacha_key(key)?, nonce, DFILE_AAD, plain))
        }
    }
}

fn aead_open(key: &[u8], nonce: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    match cipher() {
        Cipher::Clear => Ok(sealed.to_vec()),
        Cipher::Aes128Gcm => crate::aes128gcm_decrypt_aad(key, nonce, sealed, DFILE_AAD),
        Cipher::ChaCha20Poly1305 => crate::chacha::aead_decrypt(&chacha_key(key)?, nonce, DFILE_AAD, sealed)
            .ok_or(Error::Format),
    }
}

pub fn dfile_seal_control(key: &[u8], packet: &[u8]) -> Result<Vec<u8>> {
    if packet.len() < 8 {
        return Err(Error::Truncated);
    }
    let (kind, flags, session, transaction, size) = parse_dfile_header(packet)?;
    if size != packet.len() - 8 {
        return Err(Error::Format);
    }
    if cipher() == Cipher::Clear {
        return Ok(packet.to_vec());
    }

    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let mut plain = Vec::with_capacity(8 + packet.len());
    plain.extend_from_slice(&dfile_stamp().to_be_bytes());
    plain.extend_from_slice(packet);

    let mut sealed = aead_seal(key, &nonce, &plain)?;
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

pub fn open_control_block(key: &[u8], header: (u8, u8, u16, u16), payload: &[u8]) -> Result<Vec<u8>> {
    if cipher() == Cipher::Clear {
        let inner = parse_dfile_header(payload)?;
        if (inner.0, inner.1, inner.2, inner.3) != header {
            return Err(Error::Format);
        }
        return Ok(payload.to_vec());
    }
    if payload.len() < 44 {
        return Err(Error::Truncated);
    }
    let split = payload.len() - 12;
    let nonce = &payload[split..];
    let sealed = &payload[..split];
    let plain = aead_open(key, nonce, sealed)?;
    if plain.len() < 16 {
        return Err(Error::Truncated);
    }
    let inner = parse_dfile_header(&plain[8..])?;
    if (inner.0, inner.1, inner.2, inner.3) != header || inner.4 != plain.len() - 16 {
        return Err(Error::Format);
    }
    Ok(plain[8..].to_vec())
}

pub const DFRAME_OVERHEAD: usize = 50;

pub const DFILE_MAX_CONTENT: usize = u16::MAX as usize - DFRAME_OVERHEAD;

pub fn build_data_block(key: &[u8], content: &[u8], sequence: u32, flags: u8, file_id: u16, trans: u16) -> Result<Vec<u8>> {
    if content.is_empty() || content.len() > DFILE_MAX_CONTENT || !matches!(flags, 0 | 1 | 3) || file_id == 0 {
        return Err(Error::Argument);
    }
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let mut plain = Vec::with_capacity(8 + content.len());
    plain.extend_from_slice(&file_id.to_be_bytes());
    plain.extend_from_slice(&sequence.to_be_bytes());

    plain.extend_from_slice(&trans.to_be_bytes());
    plain.extend_from_slice(content);

    let sealed = aead_seal(key, &nonce, &plain)?;

    let mut payload = Vec::with_capacity(6 + sealed.len() + 12);
    payload.extend_from_slice(&file_id.to_be_bytes());
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.extend_from_slice(&sealed);
    payload.extend_from_slice(&nonce);

    assemble_dfile_packet(4, flags, 0, trans, &payload)
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
    let plain = aead_open(key, nonce, sealed)?;
    if plain.len() < 8 {
        return Err(Error::Truncated);
    }
    Ok((file_id, sequence, plain[8..].to_vec()))
}

pub const MAX_MANIFEST_ENTRIES: usize = 4096;

pub fn build_headers(entries: &[(u16, u64, Vec<u8>)], trans: u16) -> Result<Vec<Vec<u8>>> {
    if entries.is_empty() || entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(Error::Argument);
    }
    let count = entries.len() as u16;

    const FRAME_BUDGET: usize = 1423;

    let mut frames: Vec<Vec<u8>> = Vec::new();
    let mut payload = count.to_be_bytes().to_vec();
    let mut in_frame = 0usize;

    for (file_id, size, name) in entries {
        if *file_id == 0 || name.is_empty() || name.len() > 255 {
            return Err(Error::Argument);
        }
        let mut unit = Vec::with_capacity(12 + name.len());
        unit.extend_from_slice(&file_id.to_be_bytes());
        unit.extend_from_slice(&size.to_be_bytes());
        unit.extend_from_slice(&(name.len() as u16).to_be_bytes());
        unit.extend_from_slice(name);

        let full = payload.len() + unit.len() > FRAME_BUDGET;
        if full && in_frame > 0 {
            frames.push(assemble_dfile_packet(1, 0, 0, trans, &payload)?);
            payload = count.to_be_bytes().to_vec();
            in_frame = 0;
        }
        if payload.len() + unit.len() > FRAME_BUDGET {

            return Err(Error::Protocol(format!(
                "文件名过长：{} 字节，单条清单装不进一帧",
                name.len()
            )));
        }
        payload.extend_from_slice(&unit);
        in_frame += 1;
    }
    if in_frame > 0 {
        frames.push(assemble_dfile_packet(1, 0, 0, trans, &payload)?);
    }
    Ok(frames)
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

    const CHANNEL_FRAME_PREFIX: usize = 16;
    const MAX_SIZE: usize = 8 * 1024 * 1024;
    let deadline = Instant::now() + timeout;

    loop {
        if channel.buffered_len() >= CHANNEL_FRAME_PREFIX {
            let head = channel.peek(CHANNEL_FRAME_PREFIX)?;
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
            if channel.buffered_len() >= CHANNEL_FRAME_PREFIX + size {
                let payload = channel.take_buffered(CHANNEL_FRAME_PREFIX + size, timeout)?;
                let body = &payload[CHANNEL_FRAME_PREFIX..];
                let plain = crate::aesgcm_decrypt(key, &body[..12], &body[12..])?;
                return Ok(Some((sequence, plain)));
            }
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let want = if channel.buffered_len() < CHANNEL_FRAME_PREFIX {
            CHANNEL_FRAME_PREFIX - channel.buffered_len()
        } else {
            let head = channel.peek(CHANNEL_FRAME_PREFIX)?;
            let size = u32::from_le_bytes(head[12..16].try_into().map_err(|_| Error::Truncated)?) as usize;
            (CHANNEL_FRAME_PREFIX + size).saturating_sub(channel.buffered_len()).max(1)
        };
        if !channel.fill(want.min(65536), remaining)? {
            return Ok(None);
        }
    }
}

#[cfg(test)]
mod cipher_negotiation_tests {
    use super::*;

    #[test]
    fn apple_caps_choose_chacha() {
        assert_eq!(choose_cipher(Some(0x3)), Cipher::ChaCha20Poly1305);
    }

    #[test]
    fn phone_caps_choose_aes() {
        assert_eq!(choose_cipher(Some(0x7)), Cipher::Aes128Gcm);
    }

    #[test]
    fn caps_chacha_only_choose_chacha() {
        assert_eq!(choose_cipher(Some(0x2)), Cipher::ChaCha20Poly1305);
    }

    #[test]
    fn caps_aes_only_choose_aes() {
        assert_eq!(choose_cipher(Some(0x4)), Cipher::Aes128Gcm);
    }

    #[test]
    fn caps_clear_only_choose_plaintext() {
        assert_eq!(choose_cipher(Some(0x1)), Cipher::Clear);
    }

    #[test]
    fn missing_caps_default_to_aes() {
        assert_eq!(choose_cipher(None), Cipher::Aes128Gcm);
    }

    #[test]
    fn our_caps_cover_all_three() {
        assert_eq!(OUR_CIPHER_CAPS, 0x7);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_ids(payload: &[u8], out: &mut Vec<u16>) {
        let mut off = 2usize;
        while off + 12 <= payload.len() {
            let id = u16::from_be_bytes([payload[off], payload[off + 1]]);
            let nlen = u16::from_be_bytes([payload[off + 10], payload[off + 11]]) as usize;
            off += 12 + nlen;
            out.push(id);
        }
    }

    #[test]
    fn manifest_163_files_split_but_count_is_total() {

        let entries: Vec<(u16, u64, Vec<u8>)> = (1..=163u16)
            .map(|i| (i, 1024u64, format!("照片_{i:03}.jpg").into_bytes()))
            .collect();
        let frames = build_headers(&entries, 1).unwrap();

        assert!(frames.len() > 1, "163 条会拆成多帧");
        for f in &frames {
            let (kind, _fl, _ss, trans, size) = parse_dfile_header(f).unwrap();
            assert_eq!(kind, 1, "清单帧 kind 必须是 1");
            assert_eq!(trans, 1, "transaction 恒为 1");
            let c = u16::from_be_bytes([f[8], f[9]]);
            assert_eq!(c, 163, "每帧 count 都必须是总文件数");
            assert!(size > 0);
        }

        let mut ids = Vec::new();
        for f in &frames {
            let (_, _fl, _ss, _trans, size) = parse_dfile_header(f).unwrap();
            let payload = &f[8..8 + size];
            collect_ids(payload, &mut ids);
        }
        assert_eq!(ids.len(), 163, "跨帧累计必须是 163 条");
        assert_eq!(ids[0], 1);
        assert_eq!(*ids.last().unwrap(), 163);
    }

    #[test]
    fn manifest_chunks_by_bytes_like_ipad() {

        let entries: Vec<(u16, u64, Vec<u8>)> = (1..=512u16)
            .map(|i| (i, 1u64, vec![b'a'; 40]))
            .collect();
        let frames = build_headers(&entries, 1).expect("应按字节切帧，不应报错");
        assert!(frames.len() > 1, "512 条必须拆成多帧");
        for f in &frames {
            assert!(f.len() <= 1472, "单帧不得超过 MTU 1472，实际 {}", f.len());
            let (kind, _fl, _ss, trans, _size) = parse_dfile_header(f).unwrap();
            assert_eq!(kind, 1);
            assert_eq!(trans, 1);
            assert_eq!(u16::from_be_bytes([f[8], f[9]]), 512, "count 必须是总数");
        }
    }

    #[test]
    fn manifest_too_many_files_is_rejected() {

        let n = MAX_MANIFEST_ENTRIES + 1;
        let entries: Vec<(u16, u64, Vec<u8>)> = (0..n)
            .map(|i| ((i % 60000 + 1) as u16, 4096u64, format!("f{i:04}.bin").into_bytes()))
            .collect();
        let err = build_headers(&entries, 1).unwrap_err();
        assert!(matches!(err, Error::Argument), "超过上限应返回 Argument");
    }

    #[test]
    fn dfile_stamp_follows_peer_family() {

        let apple = dfile_stamp_for(PeerKind::Apple);
        assert!(
            apple > 0 && apple < 100_000_000_000_000,
            "Apple 档应为开机微秒，实际 {apple}"
        );
        let harmony = dfile_stamp_for(PeerKind::Harmony);
        assert!(
            harmony > 1_600_000_000_000_000,
            "鸿蒙档应为 Unix 微秒，实际 {harmony}"
        );
    }

    #[test]
    fn cipher_state_is_per_thread() {

        set_peer_kind(PeerKind::Apple);
        assert_eq!(
            negotiate_cipher(Some(CIPHER_CLEAR | CIPHER_CHACHA)),
            Cipher::ChaCha20Poly1305
        );

        std::thread::spawn(|| {
            set_peer_kind(PeerKind::Harmony);
            assert_eq!(
                negotiate_cipher(Some(CIPHER_CLEAR | CIPHER_CHACHA | CIPHER_AES)),
                Cipher::Aes128Gcm
            );
            assert!(!peer_kind().is_apple(), "子线程不该看到 Apple");
            assert_eq!(cipher(), Cipher::Aes128Gcm);
        })
        .join()
        .expect("子线程不应 panic");

        assert!(peer_kind().is_apple(), "主线程的家族被别的线程改了");
        assert_eq!(cipher(), Cipher::ChaCha20Poly1305);

        set_peer_kind(PeerKind::Harmony);
        negotiate_cipher(Some(CIPHER_CLEAR | CIPHER_CHACHA | CIPHER_AES));
    }

    #[test]
    fn negotiate_infers_apple_from_caps() {
        set_peer_kind(PeerKind::Harmony);
        assert_eq!(
            negotiate_cipher(Some(CIPHER_CLEAR | CIPHER_CHACHA)),
            Cipher::ChaCha20Poly1305
        );
        assert!(peer_kind().is_apple(), "0x3（无 AES 位）应判为 Apple");

        assert_eq!(
            negotiate_cipher(Some(CIPHER_CLEAR | CIPHER_CHACHA | CIPHER_AES)),
            Cipher::Aes128Gcm
        );
        assert!(!peer_kind().is_apple(), "0x7 不该判为 Apple");

        set_peer_kind(PeerKind::Harmony);
        negotiate_cipher(Some(CIPHER_CLEAR));
        assert!(!peer_kind().is_apple());
    }

    #[test]
    fn settings_receiver_profile_is_byte_identical() {

        let p = build_settings_payload(true);
        assert_eq!(p.len(), 108);
        assert_eq!(&p[0..8], &[8, 0, 0, 0, 0, 0, 0, 100]);
        assert_eq!(u16::from_be_bytes([p[8], p[9]]), 1472);
        assert_eq!(u32::from_be_bytes([p[20], p[21], p[22], p[23]]), 0);
        assert_eq!(u32::from_be_bytes([p[28], p[29], p[30], p[31]]), 0x100);
        assert_eq!(u32::from_be_bytes([p[100], p[101], p[102], p[103]]), 0);
        assert_eq!(
            u32::from_be_bytes([p[104], p[105], p[106], p[107]]),
            OUR_CIPHER_CAPS
        );
    }

    #[test]
    fn settings_data_frame_size_must_match_real_frames() {

        let profile = SettingsProfile::phone_exact_with(1472);
        let encoded = profile.encode();

        let dfs = u32::from_be_bytes([
            encoded[8 + 16],
            encoded[8 + 17],
            encoded[8 + 18],
            encoded[8 + 19],
        ]);
        assert_eq!(dfs, 1472, "声明值必须等于实际整帧长度");

        let base = SettingsProfile::phone_exact().encode();
        assert_eq!(encoded.len(), base.len());
        assert_ne!(encoded, base, "dfs 应该确实被替换了");
    }

    #[test]
    fn settings_phone_exact_is_byte_identical_to_device_baseline() {

        let expected = "05c000020000000100000000000000400000ffff0000036c756e6b6e6f776e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100010000000a00000007000000";
        let got = SettingsProfile::phone_exact().encode();
        assert_eq!(got.len(), 8 + 103);
        let hex: String = got[8..].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected, "发送端 settings 与手机实测不一致");
    }

    #[test]
    fn dfile_packet_layout() {
        let p = assemble_dfile_packet(1, 0, 1, 7, b"abc").unwrap();
        assert_eq!(p.len(), 11);
        assert_eq!(p[0], 1);
        assert_eq!(u16::from_be_bytes([p[4], p[5]]), 7);
        assert_eq!(u16::from_be_bytes([p[6], p[7]]), 3);
    }

    #[test]
    fn channel_frame_roundtrip() {
        let key = [9u8; 32];
        let header = (crate::FRAME_MAGIC_WORD, 6, 42, 0x94, 0);
        let wire_frame = seal_channel_frame(&key, header, b"payload", 5).unwrap();
        let (got_header, plain) = parse_channel_frame(&wire_frame, &key).unwrap();

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
        let wire_frame = seal_encrypted_frame(&hash, &key, b"body", 9).unwrap();
        match open_channel_frame(&wire_frame, &key) {
            Ok(v) => assert_eq!(v, b"body"),
            Err(e) => panic!("decrypt_frame 失败: {e} (frame={} bytes)", wire_frame.len()),
        }
    }

    #[test]
    fn dfile_control_roundtrip() {
        let key = [1u8; 32];
        let payload = vec![9u8; 120];
        let packet = assemble_dfile_packet(1, 0, 1, 0, &payload).unwrap();
        let encrypted = dfile_seal_control(&key, &packet).unwrap();

        let (kind, flags, session, transaction, size) = parse_dfile_header(&encrypted).unwrap();
        assert_eq!((kind, flags, session, transaction), (1, 0, 1, 0));
        assert_eq!(size, encrypted.len() - 8);

        let body = &encrypted[8..8 + size];
        let back = open_control_block(&key, (1, 0, 1, 0), body).unwrap();
        assert_eq!(back, packet);
    }

    #[test]
    fn dfile_chunk_roundtrip() {
        let key = [2u8; 32];
        let content: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();
        let wire_frame = build_data_block(&key, &content, 7, 1, 3, 1).unwrap();

        let (kind, flags, session, transaction, size) = parse_dfile_header(&wire_frame).unwrap();
        assert_eq!((kind, flags, session, transaction), (4, 1, 0, 1));
        let body = &wire_frame[8..8 + size];

        let (file_id, sequence, got) = dfile_parse_chunk(&key, body).unwrap();
        assert_eq!((file_id, sequence), (3, 7));
        assert_eq!(got, content);
    }

    #[test]
    fn dfile_chunk_rejects_bad_input() {
        let key = [3u8; 32];
        assert!(build_data_block(&key, &[], 0, 3, 1, 1).is_err());

        assert!(build_data_block(&key, &vec![0u8; 1423], 0, 3, 1, 1).is_ok());
        let big = build_data_block(&key, &vec![0u8; DFILE_MAX_CONTENT], 0, 3, 1, 1);
        assert!(big.is_ok(), "{:?}", big.err());
        assert!(build_data_block(&key, &vec![0u8; DFILE_MAX_CONTENT + 1], 0, 3, 1, 1).is_err());
        assert!(build_data_block(&key, &vec![0u8; 10], 0, 2, 1, 1).is_err());
        assert!(build_data_block(&key, &vec![0u8; 10], 0, 3, 0, 1).is_err());
    }

    #[test]
    fn dfile_tamper_rejected() {
        let key = [4u8; 32];
        let wire_frame = build_data_block(&key, b"secret", 0, 3, 1, 1).unwrap();
        let (_, _, _, _, size) = parse_dfile_header(&wire_frame).unwrap();
        let mut body = wire_frame[8..8 + size].to_vec();
        let last = body.len() - 1;
        body[last] ^= 0xFF;
        assert!(dfile_parse_chunk(&key, &body).is_err());
    }

    #[test]
    fn tlvs_parse() {
        let mut buf = Vec::new();
        buf.extend(tlv_encode(1, b"a").unwrap());
        buf.extend(tlv_encode(2, b"bb").unwrap());
        let items = tlv_list(&buf).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[1].0, 2);
        assert_eq!(items[1].1, b"bb");
    }

    #[test]
    fn channel_frame_layout_roundtrip() {

        let key = [7u8; 32];
        let plain = br#"{"CODE":3,"P2P_IP":"192.168.1.2","P2P_PORT":1234,"PROTOCOL_TYPE":4}"#;
        let wire_frame = seal_channel_frame(&key, (0xFFFF_0004, 16, 42, 0, 0), plain, 9).unwrap();
        let ((typ, sub, seq, fl, len), got) = parse_channel_frame(&wire_frame, &key).unwrap();
        assert_eq!((typ, sub, seq, fl), (0xFFFF_0004, 16, 42, 0));

        assert_eq!(len as usize, plain.len() + 12 + 16);
        assert_eq!(got, plain);
    }

    #[test]
    fn headerless_frame_decodes() {

        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};
        let key = [9u8; 32];
        let plain = br#"{"CODE":3,"P2P_IP":"192.168.1.9","P2P_PORT":20225,"PROTOCOL_TYPE":4}"#;
        let nonce = [3u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ct = cipher.encrypt(Nonce::from_slice(&nonce), plain.as_ref()).unwrap();

        let mut payload = nonce.to_vec();
        payload.extend_from_slice(&ct);
        let mut wire_frame = crate::frame_encode(21, 0, 0, &payload).unwrap();

        assert!(parse_channel_frame(&wire_frame, &key).is_err());

        let ((_, sub, _, _, len), got) = decode_channel_headerless(&wire_frame, &key).unwrap();
        assert_eq!(sub, 0, "类型由调用方按阶段补");
        assert_eq!(len as usize, plain.len());
        assert_eq!(got, plain);
        wire_frame.clear();
    }

    #[test]
    fn tlv_roundtrip_nested() {
        let inner = {
            let mut v = Vec::new();
            v.extend(tlv_encode(1, b"192.168.1.2").unwrap());
            v.extend(tlv_encode(2, b"").unwrap());
            v
        };
        let outer = tlv_encode(5, &inner).unwrap();
        let parsed = tlv_list(&outer).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, 5);
        let sub = tlv_list(&parsed[0].1).unwrap();
        assert_eq!(sub[0].1, b"192.168.1.2");
    }
}
