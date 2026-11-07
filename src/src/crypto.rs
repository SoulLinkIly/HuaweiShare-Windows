//! RSA 身份：密钥生成/加载、OAEP 加解密、公钥 DER 导出。

use rand::rngs::OsRng;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::Sha256;

pub type CryptoResult<T> = Result<T, String>;

pub fn generate() -> CryptoResult<RsaPrivateKey> {
    RsaPrivateKey::new(&mut OsRng, 2048).map_err(|e| format!("生成密钥失败: {e}"))
}

pub fn to_pem(key: &RsaPrivateKey) -> CryptoResult<String> {
    key.to_pkcs8_pem(LineEnding::LF)
        .map(|s| s.to_string())
        .map_err(|e| format!("PEM 编码失败: {e}"))
}

pub fn from_pem(pem: &str) -> CryptoResult<RsaPrivateKey> {
    let key = RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| format!("PEM 解析失败: {e}"))?;
    if key.size() != 256 {

        return Err("身份密钥必须是 RSA-2048".into());
    }
    Ok(key)
}

pub fn public_der(key: &RsaPrivateKey) -> CryptoResult<Vec<u8>> {
    key.to_public_key()
        .to_public_key_der()
        .map(|d| d.as_bytes().to_vec())
        .map_err(|e| format!("公钥编码失败: {e}"))
}

pub fn public_from_der(der: &[u8]) -> CryptoResult<RsaPublicKey> {
    use rsa::pkcs8::DecodePublicKey;
    let key = RsaPublicKey::from_public_key_der(der).map_err(|e| format!("公钥解析失败: {e}"))?;
    if key.size() != 256 {
        return Err("对端公钥必须是 RSA-2048".into());
    }
    Ok(key)
}

pub fn oaep_encrypt(public: &RsaPublicKey, plain: &[u8], mgf_sha1: bool) -> CryptoResult<Vec<u8>> {
    let result = if mgf_sha1 {
        public.encrypt(&mut OsRng, Oaep::new_with_mgf_hash::<Sha256, Sha1>(), plain)
    } else {
        public.encrypt(&mut OsRng, Oaep::new::<Sha256>(), plain)
    };
    result.map_err(|e| format!("RSA 加密失败: {e}"))
}

pub fn oaep_decrypt(key: &RsaPrivateKey, cipher: &[u8], mgf_sha1: bool) -> CryptoResult<Vec<u8>> {
    let result = if mgf_sha1 {
        key.decrypt(Oaep::new_with_mgf_hash::<Sha256, Sha1>(), cipher)
    } else {
        key.decrypt(Oaep::new::<Sha256>(), cipher)
    };
    result.map_err(|e| format!("RSA 解密失败: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_roundtrip() {
        let key = generate().unwrap();
        let pem = to_pem(&key).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let back = from_pem(&pem).unwrap();
        assert_eq!(public_der(&key).unwrap(), public_der(&back).unwrap());
    }

    #[test]
    fn oaep_both_mgf() {
        let key = generate().unwrap();
        let public = key.to_public_key();
        for mgf_sha1 in [false, true] {
            let ct = oaep_encrypt(&public, b"hello-challenge", mgf_sha1).unwrap();
            let pt = oaep_decrypt(&key, &ct, mgf_sha1).unwrap();
            assert_eq!(pt, b"hello-challenge");
        }
    }
}
