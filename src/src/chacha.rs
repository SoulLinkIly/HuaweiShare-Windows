//! 标准 ChaCha20-Poly1305（RFC 8439，12 字节 nonce），用于数据帧加密。

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for i in 0..a.len() {
        d |= a[i] ^ b[i];
    }
    d == 0
}

fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[0] = 0x6170_7865;
    s[1] = 0x3320_646e;
    s[2] = 0x7962_2d32;
    s[3] = 0x6b20_6574;
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    s[12] = counter;
    s[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    s[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    s[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());

    let mut x = s;
    for _ in 0..10 {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = x[i].wrapping_add(s[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut ctr = counter;
    let mut off = 0;
    while off < data.len() {
        let ks = chacha20_block(key, nonce, ctr);
        let n = (data.len() - off).min(64);
        for i in 0..n {
            data[off + i] ^= ks[i];
        }
        off += n;
        ctr = ctr.wrapping_add(1);
    }
}

fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let ld = |b: &[u8], o: usize| -> u32 {
        u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
    };
    let r0 = ld(key, 0) & 0x3ff_ffff;
    let r1 = (ld(key, 3) >> 2) & 0x3ff_ff03;
    let r2 = (ld(key, 6) >> 4) & 0x3ff_c0ff;
    let r3 = (ld(key, 9) >> 6) & 0x3f0_3fff;
    let r4 = (ld(key, 12) >> 8) & 0x00f_ffff;

    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u32, 0u32, 0u32, 0u32, 0u32);

    let hibit: u32 = 1 << 24;
    let mut off = 0usize;
    while off < msg.len() {
        let take = (msg.len() - off).min(16);
        let mut block = [0u8; 16];
        block[..take].copy_from_slice(&msg[off..off + take]);
        if take < 16 {
            block[take] = 1;
        }
        let b = &block;
        h0 = h0.wrapping_add(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) & 0x3ff_ffff);
        h1 = h1.wrapping_add((u32::from_le_bytes([b[3], b[4], b[5], b[6]]) >> 2) & 0x3ff_ffff);
        h2 = h2.wrapping_add((u32::from_le_bytes([b[6], b[7], b[8], b[9]]) >> 4) & 0x3ff_ffff);
        h3 = h3.wrapping_add((u32::from_le_bytes([b[9], b[10], b[11], b[12]]) >> 6) & 0x3ff_ffff);
        h4 = h4.wrapping_add((u32::from_le_bytes([b[12], b[13], b[14], b[15]]) >> 8) | hibit);
        off += take;

        let d0 = (h0 as u64 * r0 as u64)
            + (h1 as u64 * s4 as u64)
            + (h2 as u64 * s3 as u64)
            + (h3 as u64 * s2 as u64)
            + (h4 as u64 * s1 as u64);
        let mut d1 = (h0 as u64 * r1 as u64)
            + (h1 as u64 * r0 as u64)
            + (h2 as u64 * s4 as u64)
            + (h3 as u64 * s3 as u64)
            + (h4 as u64 * s2 as u64);
        let mut d2 = (h0 as u64 * r2 as u64)
            + (h1 as u64 * r1 as u64)
            + (h2 as u64 * r0 as u64)
            + (h3 as u64 * s4 as u64)
            + (h4 as u64 * s3 as u64);
        let mut d3 = (h0 as u64 * r3 as u64)
            + (h1 as u64 * r2 as u64)
            + (h2 as u64 * r1 as u64)
            + (h3 as u64 * r0 as u64)
            + (h4 as u64 * s4 as u64);
        let mut d4 = (h0 as u64 * r4 as u64)
            + (h1 as u64 * r3 as u64)
            + (h2 as u64 * r2 as u64)
            + (h3 as u64 * r1 as u64)
            + (h4 as u64 * r0 as u64);

        let mut c: u64;
        c = d0 >> 26;
        h0 = (d0 as u32) & 0x3ff_ffff;
        d1 += c;
        c = d1 >> 26;
        h1 = (d1 as u32) & 0x3ff_ffff;
        d2 += c;
        c = d2 >> 26;
        h2 = (d2 as u32) & 0x3ff_ffff;
        d3 += c;
        c = d3 >> 26;
        h3 = (d3 as u32) & 0x3ff_ffff;
        d4 += c;
        c = d4 >> 26;
        h4 = (d4 as u32) & 0x3ff_ffff;
        h0 = h0.wrapping_add((c as u32).wrapping_mul(5));
        h1 = h1.wrapping_add(h0 >> 26);
        h0 &= 0x3ff_ffff;
    }

    let mut c: u32;
    c = h1 >> 26;
    h1 &= 0x3ff_ffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ff_ffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ff_ffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ff_ffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ff_ffff;
    h1 += c;

    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x3ff_ffff;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x3ff_ffff;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x3ff_ffff;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x3ff_ffff;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    if g4 & 0x8000_0000 == 0 {
        h0 = g0;
        h1 = g1;
        h2 = g2;
        h3 = g3;
        h4 = g4;
    }

    let h0 = (h0 | (h1 << 26)) as u64;
    let h1 = ((h1 >> 6) | (h2 << 20)) as u64;
    let h2 = ((h2 >> 12) | (h3 << 14)) as u64;
    let h3 = ((h3 >> 18) | (h4 << 8)) as u64;

    let s0 = ld(key, 16) as u64;
    let s1 = ld(key, 20) as u64;
    let s2 = ld(key, 24) as u64;
    let s3 = ld(key, 28) as u64;

    let mut f: u64;
    f = h0 + s0;
    let o0 = f as u32;
    f = h1 + s1 + (f >> 32);
    let o1 = f as u32;
    f = h2 + s2 + (f >> 32);
    let o2 = f as u32;
    f = h3 + s3 + (f >> 32);
    let o3 = f as u32;

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&o0.to_le_bytes());
    out[4..8].copy_from_slice(&o1.to_le_bytes());
    out[8..12].copy_from_slice(&o2.to_le_bytes());
    out[12..16].copy_from_slice(&o3.to_le_bytes());
    out
}

fn pad16(mac: &mut Vec<u8>, len: usize) {
    let rem = len % 16;
    if rem != 0 {
        mac.extend(std::iter::repeat(0u8).take(16 - rem));
    }
}

fn poly_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block0 = chacha20_block(key, nonce, 0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&block0[..32]);
    out
}

fn poly_input(aad: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut mac_in = Vec::with_capacity(aad.len() + ct.len() + 32);
    mac_in.extend_from_slice(aad);
    pad16(&mut mac_in, aad.len());
    mac_in.extend_from_slice(ct);
    pad16(&mut mac_in, ct.len());
    mac_in.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_in.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    mac_in
}

pub fn aead_encrypt(key: &[u8; 32], nonce: &[u8], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let nonce: &[u8; 12] = <&[u8; 12]>::try_from(nonce).expect("nonce 必须 12 字节");
    let poly_key = poly_key(key, nonce);

    let mut ct = plain.to_vec();
    chacha20_xor(key, nonce, 1, &mut ct);

    let mac_in = poly_input(aad, &ct);

    let tag = poly1305(&poly_key, &mac_in);
    ct.extend_from_slice(&tag);
    ct
}

pub fn aead_decrypt(key: &[u8; 32], nonce: &[u8], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let nonce: &[u8; 12] = <&[u8; 12]>::try_from(nonce).ok()?;
    if sealed.len() < 16 {
        return None;
    }
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    let poly_key = poly_key(key, nonce);

    let mac_in = poly_input(aad, ct);

    let want = poly1305(&poly_key, &mac_in);
    if !ct_eq(&want, tag) {
        return None;
    }
    let mut pt = ct.to_vec();
    chacha20_xor(key, nonce, 1, &mut pt);
    Some(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn rfc8439_aead_vector() {
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let want_ct = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
        let want_tag = "1ae10b594f09e26a7e902ecbd0600691";

        let out = aead_encrypt(&key, &nonce, &aad, pt);
        let (ct, tag) = out.split_at(out.len() - 16);
        assert_eq!(hex(want_ct), ct, "密文不一致");
        assert_eq!(hex(want_tag), tag, "tag 不一致");

        let back = aead_decrypt(&key, &nonce, &aad, &out).expect("解密失败");
        assert_eq!(back, pt);
    }
}
