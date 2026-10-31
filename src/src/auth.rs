use rand::RngCore;
use rsa::RsaPrivateKey;

use crate::channel::Channel;
use crate::crypto;
use crate::{
    aesgcm_decrypt_n16, frame_encode, tlv_encode, varint_decode, varint_encode, Error, Result,
    FRAME_HEADER_SIZE,
};

pub const PKG_NAME: &str = "ohos.InterConnection.iShare";
pub const SRC_BUS: &str = "IShareEcologyAuthSession";

pub fn opening(identity: &str) -> Result<Vec<u8>> {
    let body = format!(
        r#"{{"CODE":4,"DEVICE_ID":"{id}","PEER_NETWORK_ID":"{id}","PKG_NAME":"{pkg}","SRC_BUS_NAME":"{bus}","DST_BUS_NAME":"{bus}","REQ_ID":"0","API_VERSION":2,"MTU_SIZE":39968,"ROUTE_TYPE":2}}"#,
        id = identity,
        pkg = PKG_NAME,
        bus = SRC_BUS
    );
    let mut payload = body.into_bytes();
    payload.push(0);
    frame_encode(8, 1, 0, &payload)
}

pub fn capabilities(device_hash: &[u8], os_version: &str, machine: &str) -> Result<Vec<u8>> {
    let mut fields = Vec::new();
    fields.extend(tlv_encode(1, b"1")?);
    fields.extend(tlv_encode(2, b"1.0.0")?);
    fields.extend(tlv_encode(3, os_version.as_bytes())?);
    fields.extend(tlv_encode(4, machine.as_bytes())?);
    let payload = tlv_encode(2, &fields)?;
    envelope_frame(device_hash, &payload, 2)
}

pub fn envelope_frame(device_hash: &[u8], payload: &[u8], sequence: u64) -> Result<Vec<u8>> {
    let mut envelope = Vec::with_capacity(16 + 8 + payload.len());
    envelope.extend_from_slice(device_hash);
    envelope.extend_from_slice(&[0x81, 0xE5, 0x80, 0x80]);
    envelope.extend(varint_encode(payload.len() as u64)?);
    envelope.extend_from_slice(payload);
    frame_encode(9, sequence, 0, &envelope)
}

pub fn unpack_envelope(data: &[u8]) -> Result<(u8, Vec<u8>)> {
    if data.len() < FRAME_HEADER_SIZE {
        return Err(Error::Truncated);
    }
    let module = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if module != 9 {
        return Err(Error::Format);
    }
    let payload = &data[FRAME_HEADER_SIZE..];
    if payload.len() < 16 {
        return Err(Error::Truncated);
    }

    let mut offset = 16usize;
    let mut values = [0u64; 4];
    for slot in values.iter_mut() {
        *slot = varint_decode(payload, &mut offset)?;
    }
    if values[0] != 1 || values[1] != 101 {
        return Err(Error::Format);
    }
    offset += values[3] as usize;
    if offset > payload.len() {
        return Err(Error::Truncated);
    }
    let size = varint_decode(payload, &mut offset)? as usize;
    if offset + size != payload.len() {
        return Err(Error::Format);
    }
    Ok((values[2] as u8, payload[offset..].to_vec()))
}

pub fn unwrap_tlv(data: &[u8], expected: u64) -> Result<&[u8]> {
    let mut offset = 0usize;
    let tag = varint_decode(data, &mut offset)?;
    let size = varint_decode(data, &mut offset)? as usize;
    if tag != expected || offset + size != data.len() {
        return Err(Error::Format);
    }
    Ok(&data[offset..])
}

pub struct Handshake {
    pub session_key: [u8; 32],
    pub mgf_sha1: bool,
}

fn secure_version(capability_response: &[u8]) -> Result<u8> {
    let (mode, body) = unpack_envelope(capability_response)?;
    if mode != 0 {
        return Err(Error::Format);
    }
    let fields = unwrap_tlv(&body, 3)?;
    let mut offset = 0usize;
    let tag = varint_decode(fields, &mut offset)?;
    let size = varint_decode(fields, &mut offset)? as usize;
    if tag != 1 || size > 10 || offset + size > fields.len() {
        return Err(Error::Format);
    }
    let text = &fields[offset..offset + size];
    let value = if text.is_empty() {
        0u8
    } else {
        std::str::from_utf8(text)
            .map_err(|_| Error::Format)?
            .parse::<u32>()
            .map_err(|_| Error::Format)? as u8
    };
    Ok(value & 1)
}

pub fn send_public_key(device_hash: &[u8], public_der: &[u8]) -> Result<Vec<u8>> {
    let inner = tlv_encode(1, public_der)?;
    let body = tlv_encode(6, &inner)?;
    envelope_frame(device_hash, &body, 3)
}

pub fn extract_peer_public(peer_response: &[u8]) -> Result<Vec<u8>> {
    let (mode, body) = unpack_envelope(peer_response)?;
    if mode != 0 {
        return Err(Error::Format);
    }
    let der = unwrap_tlv(unwrap_tlv(&body, 6)?, 2)?;
    Ok(der.to_vec())
}

pub fn challenge(
    channel: &mut Channel,
    device_hash: &[u8],
    peer_response: &[u8],
    capability_response: &[u8],
    private: &RsaPrivateKey,
    timeout: std::time::Duration,
) -> Result<Handshake> {
    let peer_der = extract_peer_public(peer_response)?;
    let peer_key = crypto::public_from_der(&peer_der).map_err(Error::Crypto)?;

    let mgf_sha1 = secure_version(capability_response)? == 1;

    let mut nonce = [0u8; 16];
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    rand::rngs::OsRng.fill_bytes(&mut key);

    let mut inner = Vec::with_capacity(48);
    inner.extend_from_slice(&nonce);
    inner.extend_from_slice(&key);
    let plaintext = tlv_encode(6, &tlv_encode(3, &inner)?)?;
    let ciphertext = crypto::oaep_encrypt(&peer_key, &plaintext, mgf_sha1).map_err(Error::Crypto)?;

    let mut meta_bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut meta_bytes);
    let metadata = tlv_encode(1, &meta_bytes)?;

    let mut envelope = Vec::new();
    envelope.extend_from_slice(device_hash);
    envelope.extend_from_slice(&[0x81, 0xE5, 0x83]);
    envelope.extend(varint_encode(metadata.len() as u64)?);
    envelope.extend_from_slice(&metadata);
    envelope.extend(varint_encode(ciphertext.len() as u64)?);
    envelope.extend_from_slice(&ciphertext);
    channel.send(&frame_encode(9, 4, 0, &envelope)?)?;

    let response = channel.read_frame(timeout)?;
    let (mode, body) = unpack_envelope(&response)?;
    if mode != 3 {
        return Err(Error::Protocol("期望 RSA 回应".into()));
    }
    let decrypted = crypto::oaep_decrypt(private, &body, mgf_sha1).map_err(Error::Crypto)?;
    let encrypted_session = unwrap_tlv(unwrap_tlv(&decrypted, 6)?, 4)?;
    let session = aesgcm_decrypt_n16(&key, &nonce, encrypted_session)?;
    if session.len() != 32 {
        return Err(Error::Protocol("会话密钥长度异常".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&session);
    Ok(Handshake { session_key: out, mgf_sha1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_has_null_terminator() {
        let f = opening("A1B2C3D4E5F6").unwrap();

        let body_len = f.len() - FRAME_HEADER_SIZE;
        assert!((200..400).contains(&body_len), "payload={body_len}");
        assert_eq!(*f.last().unwrap(), 0);
        assert_eq!(f[FRAME_HEADER_SIZE], b'{');
        let (_, module, seq, _, _) = crate::frame_decode(&f).unwrap();
        assert_eq!((module, seq), (8, 1));
    }

    #[test]
    fn envelope_roundtrip() {
        let hash = [0x11u8; 16];
        let payload = b"capability-body";
        let frame = envelope_frame(&hash, payload, 2).unwrap();

        let (mode, body) = unpack_envelope(&frame).unwrap();
        assert_eq!(mode, 0);
        assert_eq!(body, payload);
    }

    #[test]
    fn nested_tlv() {
        let inner = tlv_encode(2, b"key").unwrap();
        let outer = tlv_encode(6, &inner).unwrap();
        assert_eq!(unwrap_tlv(unwrap_tlv(&outer, 6).unwrap(), 2).unwrap(), b"key");
    }
}
