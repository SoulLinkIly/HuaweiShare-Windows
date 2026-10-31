use std::process::ExitCode;

use hwshare_core as core;

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn unhex(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        match (hex_val(bytes[i]), hex_val(bytes[i + 1])) {
            (Some(h), Some(l)) => out.push((h << 4) | l),
            _ => break,
        }
        i += 2;
    }
    out
}

fn code_of(err: core::Error) -> i32 {
    use core::Error as E;
    match err {
        E::Argument => -1,
        E::Format => -3,
        E::Truncated => -4,
        E::Range => -5,
        E::Crypto(_) => -6,
        E::Io(_) => -8,
        E::Protocol(_) => -3,
    }
}

fn fail(err: core::Error) -> ExitCode {
    println!("ERR {}", code_of(err));
    ExitCode::from(1)
}

fn parse_u64(s: &str) -> u64 {
    s.parse::<u64>().unwrap_or(0)
}

fn selftest() -> ExitCode {
    let mut failed = 0;

    for v in [0u64, 1, 127, 128, 255, 16383, 16384, core::VARINT_MAX] {
        match core::varint_encode(v) {
            Ok(enc) => {
                let mut off = 0;
                match core::varint_decode(&enc, &mut off) {
                    Ok(got) if got == v && off == enc.len() => {}
                    _ => {
                        println!("varint roundtrip fail {v}");
                        failed += 1;
                    }
                }
            }
            Err(_) => {
                println!("varint encode fail {v}");
                failed += 1;
            }
        }
    }

    let inner = core::tlv_encode(1, b"abc").unwrap();
    let outer = core::tlv_encode(3, &inner).unwrap();
    match core::tlv_find(&outer, 3).and_then(|m| core::tlv_find(m.unwrap_or(&[]), 1)) {
        Ok(Some(v)) if v == b"abc" => {}
        _ => {
            println!("tlv nested mismatch");
            failed += 1;
        }
    }

    let frame = core::frame_encode(9, 42, 0, b"xyz").unwrap();
    match core::frame_decode(&frame) {
        Ok((m, mo, s, _f, l)) if m == core::MAGIC && mo == 9 && s == 42 && l == 3 => {}
        _ => {
            println!("frame mismatch");
            failed += 1;
        }
    }

    let digest = core::hex_upper(&core::sha256(b"abc"));
    if digest != "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD" {
        println!("sha256 mismatch: {digest}");
        failed += 1;
    }

    let key = [0u8; 32];
    let mut nonce = [0u8; 12];
    nonce[0] = 1;
    match core::aesgcm_encrypt(&key, &nonce, b"hwshare-core")
        .and_then(|s| core::aesgcm_decrypt(&key, &nonce, &s))
    {
        Ok(p) if p == b"hwshare-core" => {}
        _ => {
            println!("aes roundtrip fail");
            failed += 1;
        }
    }

    if failed == 0 {
        println!("SELFTEST OK");
        ExitCode::SUCCESS
    } else {
        println!("SELFTEST FAILED ({failed})");
        ExitCode::from(1)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <command> [args]", args[0]);
        return ExitCode::from(2);
    }

    match args[1].as_str() {
        "selftest" => selftest(),

        "varint" => match core::varint_encode(parse_u64(&args[2])) {
            Ok(v) => {
                println!("{}", core::hex_upper(&v));
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        },

        "tlv" => {
            let value = unhex(&args[3]);
            match core::tlv_encode(parse_u64(&args[2]), &value) {
                Ok(v) => {
                    println!("{}", core::hex_upper(&v));
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }

        "tlvfind" => {
            let buf = unhex(&args[3]);
            match core::tlv_find(&buf, parse_u64(&args[2])) {
                Ok(Some(v)) => {
                    println!("{}", core::hex_upper(v));
                    ExitCode::SUCCESS
                }
                Ok(None) => fail(core::Error::Format),
                Err(e) => fail(e),
            }
        }

        "frame" => {
            let payload = unhex(&args[5]);
            let flags = args[4].parse::<u32>().unwrap_or(0);
            match core::frame_encode(args[2].parse::<u32>().unwrap_or(0), parse_u64(&args[3]), flags, &payload) {
                Ok(v) => {
                    println!("{}", core::hex_upper(&v));
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }

        "framedec" => {
            let buf = unhex(&args[2]);
            match core::frame_decode(&buf) {
                Ok((magic, module, seq, flags, len)) => {
                    println!("{magic} {module} {seq} {flags} {len}");
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }

        "keyhash" => {
            let der = unhex(&args[2]);
            match core::key_hash(&der) {
                Ok(d) => {
                    println!("{}", core::hex_upper(&d));
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }

        "identity" | "nodeid" | "devicehash" => {
            let der = unhex(&args[2]);
            let out = match args[1].as_str() {
                "identity" => core::identity_v2(&der),
                "nodeid" => core::meta_node_id(&der),
                _ => core::device_hash(&der),
            };
            match out {
                Ok(s) => {
                    println!("{s}");
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }

        "sha256" => {
            let data = unhex(&args[2]);
            println!("{}", core::hex_upper(&core::sha256(&data)));
            ExitCode::SUCCESS
        }

        "hmac" => {
            let key = unhex(&args[2]);
            let data = unhex(&args[3]);
            if key.is_empty() {
                return fail(core::Error::Argument);
            }
            println!("{}", core::hex_upper(&core::hmac_sha256(&key, &data)));
            ExitCode::SUCCESS
        }

        "aesenc" => {
            let key = unhex(&args[2]);
            let nonce = unhex(&args[3]);
            let data = unhex(&args[4]);
            match core::aesgcm_encrypt(&key, &nonce, &data) {
                Ok(v) => {
                    println!("{}", core::hex_upper(&v));
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }

        "aesdec" => {
            let key = unhex(&args[2]);
            let nonce = unhex(&args[3]);
            let data = unhex(&args[4]);
            match core::aesgcm_decrypt(&key, &nonce, &data) {
                Ok(v) => {
                    println!("{}", core::hex_upper(&v));
                    ExitCode::SUCCESS
                }

                Err(core::Error::Format) => {
                    println!("ERR -7");
                    ExitCode::from(1)
                }
                Err(e) => fail(e),
            }
        }

        "dfile-headers" => {
            let key = unhex(&args[2]);
            let mut entries = Vec::new();
            for (index, spec) in args[3..].iter().enumerate() {
                let Some((size_text, name)) = spec.split_once(':') else {
                    return fail(core::Error::Argument);
                };
                let Ok(size) = size_text.parse::<u64>() else {
                    return fail(core::Error::Argument);
                };
                entries.push(((index + 1) as u16, size, name.as_bytes().to_vec()));
            }
            match core::transfer::build_headers(&entries) {
                Ok(frames) => {
                    for frame in frames {
                        let encrypted = match core::transfer::dfile_encrypt_control(&key, &frame) {
                            Ok(v) => v,
                            Err(e) => return fail(e),
                        };
                        println!("{}", core::hex_upper(&encrypted));
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }

        "dfile-chunk" => {
            let key = unhex(&args[2]);
            let seq = args[3].parse::<u32>().unwrap_or(0);
            let flags = args[4].parse::<u8>().unwrap_or(3);
            let file_id = args[5].parse::<u16>().unwrap_or(1);
            let content = unhex(&args[6]);
            match core::transfer::dfile_data_chunk(&key, &content, seq, flags, file_id) {
                Ok(frame) => {
                    println!("{}", core::hex_upper(&frame));
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }

        other => {
            eprintln!("unknown command: {other}");
            ExitCode::from(2)
        }
    }
}
