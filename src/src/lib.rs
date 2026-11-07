//! crate 根：错误类型、帧编解码、TLV、密钥派生与 AES-GCM 封装。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub mod auth;
pub mod chacha;
pub mod channel;
pub mod config;
pub mod confirm;
pub mod crypto;
pub mod discovery;
pub mod env;
pub mod history;
pub mod human;
pub mod outbound;
pub mod peers;
pub mod progress;
pub mod receive;
pub mod report;
pub mod store;
pub mod transmit;
pub mod trace;
pub mod transfer;
pub mod ui;

#[cfg(windows)]
pub mod dispatch;

#[cfg(windows)]
pub mod clipboard;

pub mod clock;

#[cfg(windows)]
pub mod layered;

#[cfg(windows)]
pub mod gp;

#[cfg(windows)]
pub mod notice;

#[cfg(windows)]
pub mod toast;

#[cfg(windows)]
pub mod card;

#[cfg(windows)]
pub mod overlay;

#[cfg(windows)]
pub mod dropzone;

#[cfg(windows)]
pub mod float;

#[cfg(windows)]
pub mod autostart;

#[cfg(windows)]
pub mod tray;

pub const FRAME_MAGIC_WORD: u32 = 0xBABE_FACE;
pub const FRAME_HEADER_SIZE: usize = 24;
/// 单帧载荷上限（数据帧）。
pub const FRAME_MAX_PAYLOAD: usize = 65536;
/// 信封通道（module 9）的帧载荷上限。
///
/// 文件清单、预览载荷是把整批元数据塞进一帧的，上千个文件轻松超过 64 KiB。
/// 这里给一个宽松但有界的上限：既能让清单通过，又不至于被一个坏长度字段骗去分配几个 G。
pub const FRAME_MAX_ENVELOPE: usize = 16 * 1024 * 1024;
/// 认证 / 控制用的信封通道模块号。
pub const ENVELOPE_MODULE: u32 = 9;
pub const VARINT_MAX: u64 = (1 << 28) - 1;
pub const GCM_KEY: usize = 32;
pub const GCM_NONCE: usize = 12;
pub const GCM_TAG: usize = 16;

const META_PREFIX_MASK: [u8; 20] = [
    0x3b, 0x34, 0x1e, 0x28, 0x35, 0x2a, 0x7a, 0x17, 0x1f, 0x0e,
    0x1b, 0x05, 0x14, 0x15, 0x1e, 0x1f, 0x05, 0x13, 0x1e, 0x5a,
];

const META_PREFIX_MASK_BYTE: u8 = 0x5a;

fn meta_prefix() -> [u8; 20] {
    let src = std::hint::black_box(META_PREFIX_MASK);
    let key = std::hint::black_box(META_PREFIX_MASK_BYTE);
    let mut out = src;
    for b in out.iter_mut() {
        *b ^= key;
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Range,
    Format,
    Truncated,
    Argument,
    Io(String),
    Crypto(String),
    Protocol(String),
    Busy,
    Rejected(String),
    Cancelled(String),
    Network(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Busy,
    Rejected,
    Cancelled,
    Network,
    Protocol,
    Local,
}

impl ErrorKind {
    /// 提示条标题。
    ///
    /// 只回答「成了没有」，不解释「为什么」——用户不关心是协议对不上还是包丢了，
    /// 他要知道的是这次发没发出去。具体原因在正文的 [`Error::user_message`] 里。
    pub fn title(self) -> &'static str {
        self.title_for(false)
    }

    /// 同上，但区分方向。
    ///
    /// 接收侧原本没有提示条，标题是写死「发送」的。收东西失败却飘一条
    /// 「发送失败！」比不提示更糟——用户会以为是自己刚才那次发送出了问题。
    /// 取消同理：发送有「已取消发送」，接收就得有「已取消接收」。
    pub fn title_for(self, recv: bool) -> &'static str {
        match (self, recv) {
            // 取消是用户自己按的，不算失败，别用红字吓人。
            (ErrorKind::Cancelled, false) => "已取消发送",
            (ErrorKind::Cancelled, true) => "已取消接收",
            (_, false) => "发送失败！",
            (_, true) => "接收失败！",
        }
    }
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Error::Busy => ErrorKind::Busy,
            Error::Rejected(_) => ErrorKind::Rejected,
            Error::Cancelled(_) => ErrorKind::Cancelled,
            Error::Network(_) | Error::Truncated => ErrorKind::Network,
            Error::Io(_) => ErrorKind::Local,
            Error::Crypto(_) | Error::Protocol(_) | Error::Format | Error::Range
            | Error::Argument => ErrorKind::Protocol,
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(self.kind(), ErrorKind::Busy | ErrorKind::Network)
    }

    pub fn user_message(&self) -> String {
        match self {
            Error::Busy => "对方还在处理上一个分享，稍后自动重试".into(),
            Error::Rejected(m) | Error::Cancelled(m) | Error::Network(m) => m.clone(),
            Error::Truncated => "连接被对方提前关闭".into(),
            Error::Io(m) => format!("本机读写失败：{m}"),
            Error::Crypto(_) => "加密协商失败，可能版本不兼容".into(),
            Error::Format => "对方回的数据看不懂，可能版本不兼容".into(),
            Error::Range | Error::Argument => "参数不对，这是程序缺陷，请反馈".into(),
            Error::Protocol(m) => m.clone(),
        }
    }
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
            Error::Busy => write!(f, "对方正忙（上一个会话还没结束）"),
            Error::Rejected(m) => write!(f, "对方拒绝: {m}"),
            Error::Cancelled(m) => write!(f, "已取消: {m}"),
            Error::Network(m) => write!(f, "网络错误: {m}"),
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

/// 组一帧（不做长度校验）。两个 `frame_encode*` 共用，以前是两份逐字节相同的拷贝。
fn frame_build(module: u32, sequence: u64, flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
    out.extend_from_slice(&FRAME_MAGIC_WORD.to_le_bytes());
    out.extend_from_slice(&module.to_le_bytes());
    out.extend_from_slice(&sequence.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// 常规帧：载荷上限 [`FRAME_MAX_PAYLOAD`]。
pub fn frame_encode(module: u32, sequence: u64, flags: u32, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > FRAME_MAX_PAYLOAD {
        return Err(Error::Range);
    }
    Ok(frame_build(module, sequence, flags, payload))
}

/// 宽松帧：只受 u32 长度字段限制。给大块元数据用（如预览、取消帧）。
pub fn frame_encode_lenient(
    module: u32,
    sequence: u64,
    flags: u32,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > FRAME_MAX_ENVELOPE {
        return Err(Error::Range);
    }
    Ok(frame_build(module, sequence, flags, payload))
}

/// 从固定偏移读一个 LE u32，长度不够返回 `None`。
///
/// 协议解析里原来到处写 `data.get(4..8).map(|b| u32::from_le_bytes(b.try_into().unwrap()))`：
/// 逻辑没错，但每个调用点都挂一条看着会 panic 的路径，读代码时要逐个确认。
pub fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes = data.get(offset..end)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(bytes);
    Some(u32::from_le_bytes(buf))
}

/// 按**字符**（不是字节）截断，不补省略号。
///
/// 设备名、文件名这类协议字段只能用这个：补 "…" 会改掉字段内容，
/// 而按字节切会把汉字切成半个。
pub fn clip_chars(text: &str, max: usize) -> &str {
    match text.char_indices().nth(max) {
        Some((idx, _)) => &text[..idx],
        None => text,
    }
}

pub fn frame_decode(data: &[u8]) -> Result<(u32, u32, u64, u32, u32)> {
    if data.len() < FRAME_HEADER_SIZE {
        return Err(Error::Truncated);
    }
    let (Some(magic), Some(module), Some(flags), Some(len)) =
        (u32_at(data, 0), u32_at(data, 4), u32_at(data, 16), u32_at(data, 20))
    else {
        return Err(Error::Truncated);
    };
    if magic != FRAME_MAGIC_WORD {
        return Err(Error::Format);
    }
    let Some(seq_bytes) = data.get(8..16) else {
        return Err(Error::Truncated);
    };
    let mut seq = [0u8; 8];
    seq.copy_from_slice(seq_bytes);
    let sequence = u64::from_le_bytes(seq);
    // 只有信封通道允许超过数据帧上限；其它模块的超大帧一律当非法输入。
    if len as usize > FRAME_MAX_PAYLOAD && module != ENVELOPE_MODULE {
        return Err(Error::Format);
    }
    if len as usize > FRAME_MAX_ENVELOPE {
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

pub fn derive_key_fingerprint(public_der: &[u8]) -> Result<[u8; 32]> {
    if public_der.len() < 16 {
        return Err(Error::Argument);
    }
    Ok(hmac_sha256(&public_der[..16], public_der))
}

pub fn identity_v2(public_der: &[u8]) -> Result<String> {
    let digest = derive_key_fingerprint(public_der)?;
    Ok(hex_upper(&digest[..6]))
}

pub fn derive_node_identifier(public_der: &[u8]) -> Result<String> {
    if public_der.len() < 16 {
        return Err(Error::Argument);
    }
    let prefix = meta_prefix();
    let mut msg = Vec::with_capacity(prefix.len() + public_der.len());
    msg.extend_from_slice(&prefix);
    msg.extend_from_slice(public_der);

    Ok(hex_lower(&hmac_sha256(&public_der[..16], &msg)))
}

pub fn device_hash(public_der: &[u8]) -> Result<String> {
    let digest = derive_key_fingerprint(public_der)?;
    Ok(hex_upper(&digest[..8]))
}

const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn hex_with_case(data: &[u8], upper: bool) -> String {
    let table: &[u8; 16] = if upper {
        HEX_DIGITS
    } else {
        HEX_LOWER
    };
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(table[(b >> 4) as usize] as char);
        s.push(table[(b & 0x0F) as usize] as char);
    }
    s
}

pub fn hex_upper(data: &[u8]) -> String {
    hex_with_case(data, true)
}

pub fn hex_lower(data: &[u8]) -> String {
    hex_with_case(data, false)
}

fn ensure_gcm_sizes(key: &[u8], nonce: &[u8], key_len: usize, nonce_len: usize, key_is_min: bool) -> Result<()> {
    let key_ok = if key_is_min {
        key.len() >= key_len
    } else {
        key.len() == key_len
    };
    if !key_ok || nonce.len() != nonce_len {
        return Err(Error::Argument);
    }
    Ok(())
}

pub fn aesgcm_encrypt(key: &[u8], nonce: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    ensure_gcm_sizes(key, nonce, GCM_KEY, GCM_NONCE, false)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), plain)
        .map_err(|_| Error::Format)
}

pub fn aesgcm_decrypt(key: &[u8], nonce: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    ensure_gcm_sizes(key, nonce, GCM_KEY, GCM_NONCE, false)?;
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

    ensure_gcm_sizes(key, nonce, 16, GCM_NONCE, true)?;
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&key[..16]));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| Error::Crypto("AES-128-GCM 加密失败".into()))
}

pub fn aes128gcm_decrypt_aad(key: &[u8], nonce: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Payload;
    use aes_gcm::Aes128Gcm;

    ensure_gcm_sizes(key, nonce, 16, GCM_NONCE, true)?;
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

    ensure_gcm_sizes(key, nonce16, GCM_KEY, 16, false)?;
    let cipher = AesGcm::<Aes256, U16>::new(Key::<AesGcm<Aes256, U16>>::from_slice(key));
    cipher
        .encrypt(Nonce::<U16>::from_slice(nonce16), plain)
        .map_err(|_| Error::Crypto("AES-GCM(16) 加密失败".into()))
}

pub fn aesgcm_decrypt_n16(key: &[u8], nonce16: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    use aes::Aes256;
    use aes_gcm::AesGcm;
    use generic_array::typenum::U16;

    ensure_gcm_sizes(key, nonce16, GCM_KEY, 16, false)?;
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
        assert_eq!(frame_decode(&f).unwrap(), (FRAME_MAGIC_WORD, 9, 42, 0, 3));
    }

    #[test]
    fn envelope_frame_may_exceed_data_limit() {
        let big = vec![0u8; FRAME_MAX_PAYLOAD + 1024];
        let f = frame_encode_lenient(ENVELOPE_MODULE, 1, 0, &big).unwrap();
        let (_, module, _, _, len) = frame_decode(&f).unwrap();
        assert_eq!(module, ENVELOPE_MODULE);
        assert_eq!(len as usize, big.len(), "信封通道的大帧必须能解出来");

        // 同样的长度换个模块号就必须被拒。
        let f = frame_encode_lenient(0x15, 1, 0, &big).unwrap();
        assert_eq!(frame_decode(&f), Err(Error::Format));
    }

    #[test]
    fn envelope_has_a_hard_ceiling() {
        let huge = vec![0u8; FRAME_MAX_ENVELOPE + 1];
        assert_eq!(frame_encode_lenient(ENVELOPE_MODULE, 1, 0, &huge), Err(Error::Range));
    }

    #[test]
    fn u32_at_respects_bounds() {
        let data = [1u8, 0, 0, 0, 2, 0, 0, 0, 9];
        assert_eq!(u32_at(&data, 0), Some(1));
        assert_eq!(u32_at(&data, 4), Some(2));
        assert_eq!(u32_at(&data, 5), Some(0x0900_0000), "正好剩 4 字节，可以读");
        assert_eq!(u32_at(&data, 6), None, "只剩 3 字节");
        assert_eq!(u32_at(&data, usize::MAX), None, "偏移溢出不能 panic");
    }

    #[test]
    fn clip_chars_counts_characters_not_bytes() {
        assert_eq!(clip_chars("华为分享", 2), "华为");
        assert_eq!(clip_chars("华为分享", 9), "华为分享", "不足时原样返回");
        assert_eq!(clip_chars("", 3), "");
        assert_eq!(clip_chars("abc", 0), "", "max=0 得到空串");
        // 混合宽度：emoji 也是一个字符，且不能切在半个码点上。
        assert_eq!(clip_chars("a我🙂b", 3), "a我🙂");
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

    #[test]
    fn busy_and_network_are_retryable() {
        assert!(Error::Busy.retryable());
        assert!(Error::Network("连不上 192.168.1.9:5684".into()).retryable());
        assert!(Error::Truncated.retryable());
    }

    #[test]
    fn rejection_and_cancel_are_final() {
        assert!(!Error::Rejected("对方取消了这次分享".into()).retryable());
        assert!(!Error::Cancelled("你取消了发送".into()).retryable());
        assert!(!Error::Io("写入失败".into()).retryable());
        assert!(!Error::Protocol("对方未回应能力协商".into()).retryable());
        assert!(!Error::Format.retryable());
    }

    #[test]
    fn user_message_never_leaks_internal_wording() {
        for e in [
            Error::Busy,
            Error::Truncated,
            Error::Format,
            Error::Range,
            Error::Argument,
            Error::Crypto("oaep".into()),
            Error::Network("连不上 1.2.3.4:5684".into()),
        ] {
            let m = e.user_message();
            assert!(!m.is_empty(), "{e:?}");
            assert!(!m.contains("os error"), "{m}");
            assert!(!m.contains("IO 错误"), "{m}");
            assert!(!m.contains("oaep"), "{m}");
        }
    }

    #[test]
    fn kinds_carry_actionable_titles() {
        // 标题只说「成了没有」。Busy / Rejected / Network / Protocol / Local 对用户
        // 都是同一件事：这次没发出去。把「协议错误」摆在标题上是给开发者看的，
        // 用户看到只会以为是自己的问题。
        for e in [
            Error::Busy,
            Error::Rejected(String::new()),
            Error::Network(String::new()),
            Error::Io(String::new()),
            Error::Format,
        ] {
            assert_eq!(e.kind().title(), "发送失败！", "{e:?}");
        }
        // 取消是用户自己按的，不能报成失败。
        assert_eq!(Error::Cancelled(String::new()).kind().title(), "已取消发送");
        assert_eq!(
            Error::Cancelled(String::new()).kind().title_for(true),
            "已取消接收"
        );
        // 接收侧不能沿用「发送失败！」，否则收失败时用户会去查自己刚发的东西。
        for e in [
            Error::Busy,
            Error::Rejected(String::new()),
            Error::Network(String::new()),
            Error::Io(String::new()),
            Error::Format,
        ] {
            assert_eq!(e.kind().title_for(true), "接收失败！", "{e:?}");
        }
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
