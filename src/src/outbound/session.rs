//! 单次发送会话：opening → 等确认 → 数据 → 关闭。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;

use crate::channel::Channel;
use crate::crypto;
use crate::transmit::{build_offer, load_or_create_identity};
use crate::transfer;
use crate::{auth, Error, Result};
use super::*;
use super::dfile::ov;

const MAX_FILES_PER_TRANSACTION: usize = 100;

pub(super) struct Handshake {
    pub channel: Channel,
    pub key: [u8; 32],
    pub device_hash: Vec<u8>,
    pub local: String,
    pub identity: String,
    pub node_id: String,
    pub peer: transfer::PeerKind,

    pub is_tablet: bool,
}

pub(super) fn do_handshake(
    peer_ip: &str,
    peer_port: u16,
    log: &dyn Fn(&str),
) -> Result<Handshake> {
    let private = load_or_create_identity(None)?;
    let public_der = crypto::public_der(&private).map_err(Error::Crypto)?;
    let device_hash: Vec<u8> = crate::device_hash(&public_der)?.into_bytes();

    let identity = crate::identity_v2(&public_der)?;
    let node_id = crate::derive_node_identifier(&public_der)?;
    let local = local_ipv4(peer_ip)?;

    log(&format!("本机地址: {local}"));

    let mut channel = Channel::connect(peer_ip, peer_port, Duration::from_secs(8))?;
    channel.set_label("control");

    let opening = auth::opening_payload(&identity)?;
    channel.transmit(&opening)?;
    if crate::trace::enabled() {
        crate::trace::note("control", "opening 已发，等 opening ACK");
    }
    let opening_ack = channel.read_channel_frame(Duration::from_secs(10))?;
    let module = crate::u32_at(&opening_ack, 4).ok_or(Error::Truncated)?;
    let flags = crate::u32_at(&opening_ack, 16).ok_or(Error::Truncated)?;
    if module != 8 || flags != 1 {
        return Err(Error::Protocol("对方拒绝建立认证通道（可能正忙）".into()));
    }

    let peer_route_type = {
        let text = String::from_utf8_lossy(&opening_ack[crate::FRAME_HEADER_SIZE..]);
        let text = text.trim_end_matches('\0');
        text.find("\"ROUTE_TYPE\":")
            .and_then(|i| {
                text[i + 13..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse::<u32>()
                    .ok()
            })
            .unwrap_or(0)
    };
    let is_tablet = peer_route_type == 2;

    let peer = if is_tablet {
        transfer::PeerKind::Apple
    } else {
        transfer::PeerKind::Harmony
    };
    transfer::set_peer_kind(peer);
    if is_tablet {
        log("对端 ROUTE_TYPE=2，按 Apple 档处理");
    } else {
        log("对端 ROUTE_TYPE=0，按鸿蒙档处理");
    }

    const MACHINE: &str = "AMD64";
    let cap_bytes = if peer.is_apple() {
        auth::capabilities_phone(&device_hash)?
    } else {
        auth::local_capability_frame(&device_hash, "10.0", MACHINE)?
    };
    channel.transmit(&cap_bytes)?;
    if peer.is_apple() {
        log("已发 39 字节能力帧（手机形态：TLV 1/5/6，版本报空）");
    } else {
        log("已发 46 字节能力帧（鸿蒙形态）");
    }

    let t_cap = Instant::now();
    let mut capability_response = channel.read_channel_frame(Duration::from_secs(12))?;
    log(&format!(
        "能力帧 → 对方首帧：{} ms",
        t_cap.elapsed().as_millis()
    ));

    let cap_is_probe = auth::envelope_mode(&capability_response) == Some(2);
    if cap_is_probe {
        log("收到 mode=2 探针，不回显，直接发公钥");
    }

    if !cap_is_probe {
        let (cap_mode, cap_body) = auth::open_envelope(&capability_response)?;

        let has_cap_tag = transfer::tlv_list(&cap_body)?
            .iter()
            .any(|(t, _)| *t == 3);
        let is_next_recv = transfer::tlv_list(&cap_body)?
            .iter()
            .any(|(t, v)| *t == 1 && v.windows(9).any(|w| w == b"next_recv"));
        if cap_mode != 0 || (!has_cap_tag && !is_next_recv) {
            return Err(Error::Protocol("对方未回应能力协商".into()));
        }
        if is_next_recv {

            log("收到 next_recv，等预交换探针（mode=2）后再发公钥");
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut got_probe = false;
            while Instant::now() < deadline {
                match channel.try_read_frame(Duration::from_millis(200)) {
                    Ok(Some(f)) if auth::envelope_mode(&f) == Some(2) => {
                        capability_response = f;
                        got_probe = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }

            if !got_probe {
                return Err(Error::Busy);
            }
        }
    }

    channel.transmit(&auth::send_public_key(&device_hash, &public_der)?)?;

    let peer_public_response = loop {
        let wire_frame = channel.read_channel_frame(Duration::from_secs(15))?;
        if auth::envelope_mode(&wire_frame) == Some(2) {
            continue;
        }
        break wire_frame;
    };
    let challenge = auth::auth_challenge_payload(
        &mut channel,
        &device_hash,
        &peer_public_response,
        &capability_response,
        &private,
        Duration::from_secs(10),
    )?;
    let key = challenge.session_key;
    log(&format!(
        "挑战完成：mgf_sha1={} key={:02x}{:02x}...",
        challenge.mgf_sha1, key[0], key[1]
    ));
    Ok(Handshake {
        channel,
        key,
        device_hash,
        local,
        identity,
        node_id,
        peer,
        is_tablet,
    })
}

fn send_encrypted(
    ch: &mut Channel,
    dh: &[u8],
    key: &[u8],
    body: Vec<u8>,
    seq: &mut u64,
) -> Result<()> {
    ch.transmit(&transfer::seal_encrypted_frame(dh, key, &body, *seq)?)?;
    *seq += 1;
    Ok(())
}

pub(super) fn send_once(
    peer_ip: &str,
    peer_port: u16,
    paths: &[PathBuf],
    display_name: &str,
    log: &dyn Fn(&str),
    progress: &Arc<AtomicU64>,
    cancel: Arc<AtomicBool>,
) -> Result<Report> {
    let Collected { files, skipped, top_dirs, empty_dirs } = collect(paths)?;
    if skipped > 0 {
        log(&format!("已跳过 {skipped} 个空目录/非文件条目"));
    }
    if empty_dirs > 0 {
        log(&format!(
            "有 {empty_dirs} 个空文件夹没有随行（对端清单按文件传，无法表达空目录）"
        ));
    }
    if top_dirs > 0 {
        log(&format!("含 {top_dirs} 个文件夹，将按相对路径发送"));
    }
    let total: u64 = files.iter().map(|f| f.size).sum();
    let names: Vec<String> = files.iter().map(|f| f.name.clone()).collect();

    let Handshake {
        mut channel,
        key,
        device_hash,
        local,
        identity,
        node_id,
        peer,
        is_tablet,
        ..
    } = {

        ov::set_batch(files.len());
        ov::set_outgoing(true);
        ov::preparing(files.first().map(|f| f.name.as_str()).unwrap_or("正在准备"));

        do_handshake(peer_ip, peer_port, log)?
    };

    let offer = build_offer(&names, total, display_name, None, peer.is_apple(), top_dirs)?;
    channel.transmit(&transfer::seal_encrypted_frame(&device_hash, &key, &offer, 5)?)?;
    let scope_text = if top_dirs > 0 {
        format!("{top_dirs} 个文件夹 · ")
    } else {
        String::new()
    };
    if crate::trace::enabled() {
        crate::trace::note(
            "control",
            &format!(
                "offer 已发：{scope_text}{} 个文件，共 {} 字节（tag3/tag6={}）",
                names.len(),
                total,
                names.len()
            ),
        );
    }
    log(&format!(
        "已发出分享请求：{scope_text}{} 个文件，{:.1} MB",
        files.len(),
        total as f64 / 1048576.0
    ));

    let _wait_guard = SendOverlayGuard { done: false };

    ov::set_batch(files.len());

    ov::set_outgoing(true);
    ov::waiting(files.first().map(|f| f.name.as_str()).unwrap_or("正在发送"));

    let mut sequence = 6u64;
    let mut exchange_sent = false;
    let mut meta_sent = false;
    let mut preview_sent_early = false;
    let mut code3_sent = false;
    let mut file_request_sent = false;
    let mut byte_channel: Option<Channel> = None;
    let mut byte_key: Option<[u8; 32]> = None;
    let mut file_key: Option<[u8; 32]> = None;

    let deadline = Instant::now() + Duration::from_secs(120);

    while Instant::now() < deadline {

        let wire_frame = match channel.try_read_frame(Duration::from_millis(200)) {
            Ok(Some(f)) => f,
            Ok(None) => {
                if cancel.load(Ordering::Relaxed) {

                    send_sender_cancel(&mut channel, &device_hash, &key, &mut sequence);

                    std::thread::sleep(CANCEL_WAIT);
                    crate::trace::note("control", "尚未开始传输时取消：已发 senderCancel，关闭控制通道");
                    return Err(Error::Protocol("已取消发送（对方尚未接收）".into()));
                }
                continue;
            }
            Err(_) => continue,
        };
        let module = crate::u32_at(&wire_frame, 4).ok_or(Error::Truncated)?;

        if module == 9 {
            let body = match transfer::open_channel_frame(&wire_frame, &key) {
                Ok(b) => b,
                Err(_) => continue,
            };
            for (tag, value) in transfer::tlv_list(&body)? {
                match tag {
                    1 => {
                        for (_, cmd) in transfer::tlv_list(&value)? {
                            match cmd.as_slice() {
                                b"user_reject" | b"receiverCancel" => {
                                    return Err(Error::Protocol("对方拒绝了本次分享".into()))
                                }
                                b"user_confirm" => {
                                    log("对方已接受，正在建立数据通道");

                                    if !exchange_sent {
                                        send_encrypted(
                                            &mut channel,
                                            &device_hash,
                                            &key,
                                            net_info_offer(&local)?,
                                            &mut sequence,
                                        )?;
                                        send_encrypted(
                                            &mut channel,
                                            &device_hash,
                                            &key,
                                            logical_addr(&local)?,
                                            &mut sequence,
                                        )?;
                                        exchange_sent = true;
                                    }

                                    if is_tablet && !meta_sent {
                                        send_meta(
                                            &mut channel,
                                            &key,
                                            display_name,
                                            &node_id,
                                            &mut sequence,
                                            peer,
                                            None,
                                        )?;
                                        meta_sent = true;
                                        log("已主动上报 META_INFO（iPad 后发，必须我们先）");
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    4 => {
                        send_encrypted(
                            &mut channel,
                            &device_hash,
                            &key,
                            net_info_reply(&local)?,
                            &mut sequence,
                        )?;
                    }

                    10 => {
                        send_encrypted(
                            &mut channel,
                            &device_hash,
                            &key,
                            logical_addr(&local)?,
                            &mut sequence,
                        )?;
                    }
                    _ => {}
                }
            }
            continue;
        }

        let (header, plain) = match transfer::parse_channel_frame(&wire_frame, &key) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if header.0 == PEER_META_FRAME {

            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&plain) {
                let name = v.get("DEVICE_NAME").and_then(|x| x.as_str()).unwrap_or("");
                let tid = v.get("DEVICE_TYPE_ID").and_then(|x| x.as_u64()).unwrap_or(0);
                if !name.is_empty() {
                    transfer::note_peer_device(name, tid);
                    log(&format!(
                        "[对端设备] {name} DEVICE_TYPE_ID={tid}{}",
                        if transfer::peer_is_apple() { "（Apple 端）" } else { "" }
                    ));
                }
            }

            if is_tablet {
                if !meta_sent {
                    send_meta(
                        &mut channel,
                        &key,
                        display_name,
                        &node_id,
                        &mut sequence,
                        peer,
                        Some(header),
                    )?;
                    meta_sent = true;
                }
            } else {
                send_meta(
                    &mut channel,
                    &key,
                    display_name,
                    &node_id,
                    &mut sequence,
                    peer,
                    Some(header),
                )?;
            }
            continue;
        }

        if header.0 == PEER_META_ACK_FRAME && !code3_sent {
            let (local_port, p2p_listener) = reserve_port(&local)?;

            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(180);
                while Instant::now() < deadline {
                    match p2p_listener.accept() {
                        Ok((sock, peer)) => {
                            if debug_io() {
                                eprintln!("[p2p] 收到回连 {peer}，已关闭");
                            }
                            drop(sock);
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(20)),
                    }
                }
            });
            let payload = format!(
                r#"{{"CODE":3,"P2P_IP":"{local}","P2P_PORT":{local_port},"PROTOCOL_TYPE":4}}"#
            );
            let mut body = payload.into_bytes();
            body.push(0);
            channel.transmit(&transfer::seal_channel_frame(
                &key,
                (CHANNEL_BYTES, 16, rand_seq(), 0, 0),
                &body,
                sequence,
            )?)?;
            sequence += 1;
            code3_sent = true;
            continue;
        }

        let value: serde_json::Value = match serde_json::from_slice(
            plain.strip_suffix(&[0]).unwrap_or(&plain),
        ) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if header.0 == CHANNEL_BYTES && header.1 == 16 && header.3 == 1 {
            let ip = value["P2P_IP"].as_str().unwrap_or("").to_string();
            let port = value["P2P_PORT"].as_u64().unwrap_or(0) as u16;
            if !is_private_ipv4(&ip) || port == 0 {
                return Err(Error::Format);
            }
            let mut chan = Channel::connect(&ip, port, Duration::from_secs(8))?;
            chan.set_label("byte");
            let mut bkey = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bkey);
            chan.transmit(&byte_handshake(&key, &identity, &node_id, &bkey, peer)?)?;

            let raw = chan.read_channel_frame(Duration::from_secs(8))?;
            let wrapped = crate::frame_encode(21, 0, 0, &raw)?;
            let (ack_header, ack_plain) = transfer::parse_channel_frame(&wrapped, &key)?;
            let ack: serde_json::Value = serde_json::from_slice(
                ack_plain.strip_suffix(&[0]).unwrap_or(&ack_plain),
            )
            .map_err(|_| Error::Format)?;

            if ack_header.1 != 6 || (ack_header.3 != 0x95 && ack_header.3 != 0x91) || ack["CODE"] != 1 {
                return Err(Error::Protocol(format!(
                    "byte 通道握手被拒绝（flags=0x{:02X}）",
                    ack_header.3
                )));
            }
            if ack.get("ERR_CODE").is_some() {
                return Err(Error::Protocol(format!("byte 通道返回错误: {ack}")));
            }
            log("预览通道已建立");

            if is_tablet && !preview_sent_early {
                let body = build_preview_payload(&files)?;
                let inner = transfer::encrypted_envelope(&device_hash, &key, &body)?;
                chan.transmit(&transfer::bytes_frame(&bkey, &inner, 0)?)?;
                preview_sent_early = true;
                log("预览已发送（CH17 之前）");
            }

            byte_channel = Some(chan);
            byte_key = Some(bkey);

            let mut fkey = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut fkey);
            let payload = file_channel_request(&local, &identity, &node_id, &fkey, peer)?;
            channel.transmit(&transfer::seal_channel_frame(
                &key,
                (CHANNEL_BYTES, 17, rand_seq(), 0, 0),
                &payload,
                sequence,
            )?)?;
            sequence += 1;
            file_key = Some(fkey);
            file_request_sent = true;
            continue;
        }

        if header.0 == CHANNEL_BYTES && header.1 == 17 && header.3 == 1 && file_request_sent {
            let ip = value["MY_IP"].as_str().unwrap_or("").to_string();
            let port = value["P2P_PORT"].as_u64().unwrap_or(0) as u16;
            if !is_private_ipv4(&ip) || port == 0 {
                return Err(Error::Protocol(format!(
                    "file 通道应答不可用（MY_IP={ip:?} P2P_PORT={port} 原文={}）",
                    String::from_utf8_lossy(&plain)
                )));
            }
            let fkey = file_key.ok_or(Error::Format)?;

            let mut chan = Channel::connect(&ip, port, Duration::from_secs(8))?;
            chan.set_label("file#1");

            let chunk = chunk_size();
            let frame_size = data_frame_size(chunk);

            log(&format!("分块: {chunk} B（帧长 {frame_size}）"));
            let profile = settings_profile(peer, frame_size);
            log(&format!(
                "settings 档位: cap=0x{:X} caps=0x{:X} dfs={}{}",
                profile.capability,
                profile.caps_check,
                profile.data_frame_size,
                if peer.is_apple() { "（Apple 档）" } else { "（鸿蒙档）" }
            ));
            chan.transmit(&profile.encode())?;

            let reply = match chan.try_read_dfile(Duration::from_secs(10))? {
                Some(r) => r,
                None => return Err(Error::Protocol("对端未回应 DFile settings".into())),
            };
            let (kind, _flags, _sess, _trans, size) = transfer::parse_dfile_header(&reply)?;
            if kind != 8 {
                return Err(Error::Protocol(format!("DFile settings 应答异常 kind={kind}")));
            }
            let payload = &reply[8..8 + size];

            if payload.len() < 100 || u16::from_be_bytes([payload[2], payload[3]]) != 2 {
                return Err(Error::Protocol("对端 DFile settings 档位不兼容".into()));
            }

            if !peer.is_apple()
                && u32::from_be_bytes([payload[96], payload[97], payload[98], payload[99]]) & 1 == 0
            {
                return Err(Error::Protocol("对端 DFile 能力不支持加密传输".into()));
            }

            {
                let be16 = |i: usize| u16::from_be_bytes([payload[i], payload[i + 1]]);
                let be32 = |i: usize| {
                    u32::from_be_bytes([payload[i], payload[i + 1], payload[i + 2], payload[i + 3]])
                };
                log(&format!(
                    "[对端 settings] mtu={} ctype={} ver={} cap=0x{:X} dfs={} caps=0x{:X}",
                    be16(0),
                    be16(2),
                    be32(4),
                    be32(12),
                    be32(16),
                    be32(20)
                ));
                let peer_caps = transfer::settings_cipher_caps(payload);
                let cipher = transfer::negotiate_cipher(peer_caps);
                log(&format!(
                    "[密码协商] 对端 cipherCaps={} → {cipher:?}",
                    peer_caps
                        .map(|c| format!("0x{c:X}"))
                        .unwrap_or_else(|| "未声明".into())
                ));
            }
            log("文件通道已建立");

            let dfile_key = fkey;
            let mut pool: Vec<(Channel, [u8; 32])> = vec![(chan, dfile_key)];

            let mut bchan_slot = Some(byte_channel.take().ok_or(Error::Format)?);
            let mut bkey_slot = Some(byte_key.ok_or(Error::Format)?);

            let stop = Arc::new(AtomicBool::new(false));
            let peer_closed = Arc::new(AtomicBool::new(false));

            let fb = Arc::new(PeerState::new());
            let watcher = spawn_control_watch(
                channel,
                key,
                device_hash.clone(),
                local.clone(),
                sequence,
                cancel.clone(),
                stop.clone(),
                peer_closed.clone(),
                fb.clone(),
            );

            let result = (|| -> Result<u64> {
                let mut bchan = bchan_slot.take().ok_or(Error::Format)?;
                let bkey = bkey_slot.take().ok_or(Error::Format)?;

                let preview_wait = if is_tablet { 800 } else { 15_000 };
                send_preview(
                    &mut bchan,
                    &bkey,
                    &key,
                    &device_hash,
                    &files,
                    log,
                    &cancel,
                    &fb,
                    !preview_sent_early,
                    preview_wait,
                    !is_tablet,
                )?;
                if cancelled(&cancel) {
                    crate::trace::note("control", "预览阶段收到取消，停止发送");
                    return Err(cancel_error(&cancel));
                }

                spawn_byte_watch(bchan, bkey, key, stop.clone(), fb.clone());

                let (mut first, first_key) = pool.remove(0);

                let mut sent: u64 = 0;
                let mut group_no: u16 = 0;
                for group in files.chunks(MAX_FILES_PER_TRANSACTION) {
                    if group_no > 0 {

                        let gap: u64 = crate::env::num("HWSHARE_BATCH_GAP_MS", 500);
                        std::thread::sleep(Duration::from_millis(gap));
                    }
                    group_no += 1;
                    if files.len() > MAX_FILES_PER_TRANSACTION {
                        log(&format!(
                            "第 {group_no} 批：{} 个文件（事务 {}）",
                            group.len(),
                            group_no
                        ));
                    }

                    let mut group_files: Vec<Outgoing> = group.to_vec();
                    for (i, f) in group_files.iter_mut().enumerate() {
                        f.id = (i + 1) as u16;
                    }
                    sent += send_batch(
                        &mut first,
                        &first_key,
                        peer,
                        group_no,
                        &group_files,
                        log,
                        &cancel,
                        progress,
                        &fb,
                    )?;
                }

                let grace_ms: u64 = crate::env::num("HWSHARE_GRACE_MS", 1200);
                first.graceful_close(Duration::from_millis(grace_ms));
                Ok(sent)
            })();

            let written = result?;

            let bits = fb.peer_pct_bits.load(Ordering::SeqCst);
            let mut peer_at_100 = bits != u64::MAX && f64::from_bits(bits) >= 100.0;
            let wait_ms: u64 = if peer_at_100 {
                0
            } else if is_tablet {
                1500
            } else {
                15_000
            };

            let deadline = Instant::now() + Duration::from_millis(wait_ms);
            while Instant::now() < deadline && !peer_closed.load(Ordering::SeqCst) {
                if !peer_at_100 {
                    let cur = fb.peer_pct_bits.load(Ordering::Relaxed);
                    if cur != u64::MAX && f64::from_bits(cur) >= 100.0 {
                        peer_at_100 = true;
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            crate::trace::note(
                "control",
                if peer_closed.load(Ordering::SeqCst) {
                    "对端已先关闭连接"
                } else if peer_at_100 {
                    "对端已报 100%，立即关闭"
                } else {
                    "主动关闭连接（对端等我们关）"
                },
            );
            stop.store(true, Ordering::SeqCst);
            let _ = watcher.join();
            return Ok(Report {
                files: files.iter().map(|f| f.name.clone()).collect(),
                bytes: written,
            });
        }
    }

    Err(Error::Protocol(if !code3_sent {
        "等待手机准备通道超时（对方可能未点接受）"
    } else {
        "通道协商超时"
    }
    .into()))
}
