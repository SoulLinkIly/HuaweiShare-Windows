use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub mod auth;
pub mod channel;
#[cfg(windows)]
pub mod clipboard;
pub mod config;
pub mod confirm;
pub mod crypto;
pub mod discovery;
pub mod dispatch;
pub mod history;
pub mod outbound;
pub mod peers;
pub mod receive;

#[cfg(feature = "diag")]
pub mod replay;
#[cfg(feature = "diag")]
pub mod trace;

#[cfg(not(feature = "diag"))]
#[path = "trace_off.rs"]
pub mod trace;
pub mod send;
pub mod transfer;
#[cfg(feature = "diag")]
pub mod wire;
#[cfg(not(feature = "diag"))]
#[path = "wire_off.rs"]
pub mod wire;

#[cfg(windows)]
pub mod layered;

#[cfg(windows)]
pub mod gp;

#[cfg(windows)]
pub mod notice;

#[cfg(windows)]
pub mod card;

#[cfg(windows)]
pub mod overlay;

#[cfg(windows)]
pub mod dropzone;

#[cfg(windows)]
pub mod float;

#[cfg(windows)]
pub mod tray;

pub const MAGIC: u32 = 0xBABE_FACE;
pub const FRAME_HEADER_SIZE: usize = 24;
pub const FRAME_MAX_PAYLOAD: usize = 65536;
pub const VARINT_MAX: u64 = (1 << 28) - 1;
pub const GCM_KEY: usize = 32;
pub const GCM_NONCE: usize = 12;
pub const GCM_TAG: usize = 16;

const META_PREFIX: &[u8] = b"anDrop META_NODE_ID\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Range,
    Format,
    Truncated,
    Argument,
    Io(String),
    Crypto(String),
    Protocol(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Range => write!(f, "数值超出范围"),
            Error::Format => write!(f, "数据格式非法"),
            Error::Truncated => write!(f, "数据不完整"),
            Error::Argument => write!(f, "参数非法"),
            Error::Io(m) => write!(f, "IO 错误: {m}"),
            Error::Crypto(m) => write!(f, "加密错误: {m}"),

            Error::Protocol(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

pub fn varint_encode(value: u64) -> Result<Vec<u8>> {
    if value > VARINT_MAX {
        return Err(Error::Range);
    }
    let mut out = Vec::with_capacity(4);
    let mut v = value;
    while v >= 128 {
        out.push((v & 0x7F) as u8);
        v >>= 7;
    }
    out.push((v | 0x80) as u8);
    Ok(out)
}

pub fn varint_decode(data: &[u8], offset: &mut usize) -> Result<u64> {
    let mut acc: u64 = 0;
    let mut shift = 0;
    while shift < 28 {
        if *offset >= data.len() {
            return Err(Error::Truncated);
        }
        let b = data[*offset];
        *offset += 1;
        acc |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 != 0 {
            return Ok(acc);
        }
        shift += 7;
    }
    Err(Error::Format)
}

pub fn tlv_encode(tag: u64, value: &[u8]) -> Result<Vec<u8>> {
    let mut out = varint_encode(tag)?;
    out.extend_from_slice(&varint_encode(value.len() as u64)?);
    out.extend_from_slice(value);
    Ok(out)
}

pub fn tlv_find(data: &[u8], tag: u64) -> Result<Option<&[u8]>> {
    let mut off = 0usize;
    while off < data.len() {
        let t = varint_decode(data, &mut off)?;
        let n = varint_decode(data, &mut off)? as usize;
        if off + n > data.len() {
            return Err(Error::Truncated);
        }
        if t == tag {
            return Ok(Some(&data[off..off + n]));
        }
        off += n;
    }
    Ok(None)
}

pub fn frame_encode_lenient(module: u32, sequence: u64, flags: u32, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > u32::MAX as usize {
        return Err(Error::Range);
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&module.to_le_bytes());
    out.extend_from_slice(&sequence.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn frame_encode(module: u32, sequence: u64, flags: u32, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > FRAME_MAX_PAYLOAD {
        return Err(Error::Range);
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&module.to_le_bytes());
    out.extend_from_slice(&sequence.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn frame_decode(data: &[u8]) -> Result<(u32, u32, u64, u32, u32)> {
    if data.len() < FRAME_HEADER_SIZE {
        return Err(Error::Truncated);
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != MAGIC {
        return Err(Error::Format);
    }
    let module = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let sequence = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let flags = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let len = u32::from_le_bytes(data[20..24].try_into().unwrap());
    if len as usize > FRAME_MAX_PAYLOAD {
        return Err(Error::Format);
    }
    Ok((magic, module, sequence, flags, len))
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn key_hash(public_der: &[u8]) -> Result<[u8; 32]> {
    if public_der.len() < 16 {
        return Err(Error::Argument);
    }
    Ok(hmac_sha256(&public_der[..16], public_der))
}

pub fn identity_v2(public_der: &[u8]) -> Result<String> {
    let digest = key_hash(public_der)?;
    Ok(hex_upper(&digest[..6]))
}

pub fn meta_node_id(public_der: &[u8]) -> Result<String> {
    if public_der.len() < 16 {
        return Err(Error::Argument);
    }
    let mut msg = Vec::with_capacity(META_PREFIX.len() + public_der.len());
    msg.extend_from_slice(META_PREFIX);
    msg.extend_from_slice(public_der);
    Ok(hex_upper(&hmac_sha256(&public_der[..16], &msg)))
}

pub fn device_hash(public_der: &[u8]) -> Result<String> {
    let digest = key_hash(public_der)?;
    Ok(hex_upper(&digest[..8]))
}

pub fn hex_upper(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0F) as usize] as char);
    }
    s
}

pub fn aesgcm_encrypt(key: &[u8], nonce: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    if key.len() != GCM_KEY || nonce.len() != GCM_NONCE {
        return Err(Error::Argument);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), plain)
        .map_err(|_| Error::Format)
}

pub fn aesgcm_decrypt(key: &[u8], nonce: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if key.len() != GCM_KEY || nonce.len() != GCM_NONCE {
        return Err(Error::Argument);
    }
    if sealed.len() < GCM_TAG {
        return Err(Error::Truncated);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), sealed)
        .map_err(|_| Error::Format)
}

pub fn aes128gcm_encrypt_aad(key: &[u8], nonce: &[u8], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Payload;
    use aes_gcm::Aes128Gcm;

    if key.len() < 16 || nonce.len() != GCM_NONCE {
        return Err(Error::Argument);
    }
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&key[..16]));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| Error::Crypto("AES-128-GCM 加密失败".into()))
}

pub fn aes128gcm_decrypt_aad(key: &[u8], nonce: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Payload;
    use aes_gcm::Aes128Gcm;

    if key.len() < 16 || nonce.len() != GCM_NONCE {
        return Err(Error::Argument);
    }
    if sealed.len() < GCM_TAG {
        return Err(Error::Truncated);
    }
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&key[..16]));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad })
        .map_err(|_| Error::Format)
}

pub fn aesgcm_encrypt_n16(key: &[u8], nonce16: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    use aes::Aes256;
    use aes_gcm::AesGcm;
    use generic_array::typenum::U16;

    if key.len() != GCM_KEY || nonce16.len() != 16 {
        return Err(Error::Argument);
    }
    let cipher = AesGcm::<Aes256, U16>::new(Key::<AesGcm<Aes256, U16>>::from_slice(key));
    cipher
        .encrypt(Nonce::<U16>::from_slice(nonce16), plain)
        .map_err(|_| Error::Crypto("AES-GCM(16) 加密失败".into()))
}

pub fn aesgcm_decrypt_n16(key: &[u8], nonce16: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    use aes::Aes256;
    use aes_gcm::AesGcm;
    use generic_array::typenum::U16;

    if key.len() != GCM_KEY || nonce16.len() != 16 {
        return Err(Error::Argument);
    }
    if sealed.len() < GCM_TAG {
        return Err(Error::Truncated);
    }
    let cipher = AesGcm::<Aes256, U16>::new(Key::<AesGcm<Aes256, U16>>::from_slice(key));
    cipher
        .decrypt(Nonce::<U16>::from_slice(nonce16), sealed)
        .map_err(|_| Error::Format)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 255, 16383, 16384, VARINT_MAX] {
            let enc = varint_encode(v).unwrap();
            let mut off = 0;
            assert_eq!(varint_decode(&enc, &mut off).unwrap(), v);
            assert_eq!(off, enc.len());
        }
    }

    #[test]
    fn varint_range() {
        assert_eq!(varint_encode(VARINT_MAX + 1), Err(Error::Range));
    }

    #[test]
    fn tlv_nested() {
        let inner = tlv_encode(1, b"deep").unwrap();
        let outer = tlv_encode(3, &inner).unwrap();
        let mid = tlv_find(&outer, 3).unwrap().unwrap();
        assert_eq!(tlv_find(mid, 1).unwrap().unwrap(), b"deep");
    }

    #[test]
    fn frame_layout() {
        let f = frame_encode(9, 42, 0, b"abc").unwrap();
        assert_eq!(f.len(), FRAME_HEADER_SIZE + 3);
        assert_eq!(&f[0..4], &[0xCE, 0xFA, 0xBE, 0xBA]);
        assert_eq!(frame_decode(&f).unwrap(), (MAGIC, 9, 42, 0, 3));
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            hex_upper(&sha256(b"abc")),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
    }

    #[test]
    fn aes_roundtrip() {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let sealed = aesgcm_encrypt(&key, &nonce, b"hello").unwrap();
        assert_eq!(sealed.len(), 5 + GCM_TAG);
        assert_eq!(aesgcm_decrypt(&key, &nonce, &sealed).unwrap(), b"hello");
    }

    #[test]
    fn aes_tamper_rejected() {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let mut sealed = aesgcm_encrypt(&key, &nonce, b"hello").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(aesgcm_decrypt(&key, &nonce, &sealed).is_err());
    }
}

#[cfg(test)]
mod n16_tests {
    use super::*;

    #[test]
    fn gcm16_roundtrip() {
        let key = [7u8; 32];
        let nonce = [3u8; 16];
        let sealed = aesgcm_encrypt_n16(&key, &nonce, b"hello").unwrap();
        assert_eq!(sealed.len(), 5 + GCM_TAG);
        let plain = aesgcm_decrypt_n16(&key, &nonce, &sealed).unwrap();
        assert_eq!(plain, b"hello");
    }

    #[test]
    fn gcm12_roundtrip() {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let sealed = aesgcm_encrypt(&key, &nonce, b"hello").unwrap();
        assert_eq!(aesgcm_decrypt(&key, &nonce, &sealed).unwrap(), b"hello");
    }
}
