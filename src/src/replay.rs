use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::Value;

#[derive(Clone)]
pub struct Endpoint {
    pub ip: [u8; 4],
    pub port: u16,
}

pub struct Session {
    pub path: PathBuf,
    pub meta: Value,
    pub events: Vec<Value>,

    pub bad_lines: usize,
}

impl Session {
    pub fn sid(&self) -> &str {
        self.meta.get("sid").and_then(|v| v.as_str()).unwrap_or("?")
    }

    pub fn scope(&self) -> &str {
        self.meta
            .get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
    }

    pub fn peer_filter(&self) -> Option<&str> {
        self.meta.get("peer_filter").and_then(|v| v.as_str())
    }

    pub fn duration_ms(&self) -> u64 {
        let first = self.events.first().and_then(|e| e["t"].as_u64()).unwrap_or(0);
        let last = self.events.last().and_then(|e| e["t"].as_u64()).unwrap_or(0);
        last.saturating_sub(first) / 1000
    }

    pub fn count(&self, ev: &str) -> usize {
        self.events
            .iter()
            .filter(|e| e["ev"].as_str() == Some(ev))
            .count()
    }
}

pub fn load(path: &Path) -> Result<Session, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("读不了 {}: {e}", path.display()))?;
    let mut events = Vec::new();
    let mut meta = Value::Null;
    let mut bad = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) if v.get("ev").is_some() => {
                if v["ev"] == "capture.meta" {
                    meta = v.clone();
                }
                events.push(v);
            }
            _ => bad += 1,
        }
    }
    if events.is_empty() {
        return Err(format!("{} 里没有可识别的事件", path.display()));
    }
    if meta.is_null() {
        return Err("缺少 capture.meta（不是本工具生成的会话文件？）".into());
    }
    Ok(Session {
        path: path.to_path_buf(),
        meta,
        events,
        bad_lines: bad,
    })
}

pub fn summarize(s: &Session) -> String {
    let mut out = String::new();
    let wall = s.meta["wall"].as_u64().unwrap_or(0);
    let _ = writeln!(out, "会话   {}", s.sid());
    let _ = writeln!(out, "文件   {}", s.path.display());
    let _ = writeln!(
        out,
        "采集   {}  scope={}  pid={}  host={}",
        fmt_wall(wall),
        s.scope(),
        s.meta["pid"].as_u64().unwrap_or(0),
        s.meta["host"].as_str().unwrap_or("-")
    );
    if let Some(p) = s.peer_filter() {
        let _ = writeln!(out, "过滤   peer={p}");
    }
    let udp_tx = s.count("discovery.tx");
    let udp_rx = s.count("discovery.rx.raw");
    if udp_tx + udp_rx > 0 {
        let _ = writeln!(out, "发现   UDP 发送 {udp_tx} / 接收 {udp_rx}（原始报文）");
    }
    let _ = writeln!(
        out,
        "规模   {} 事件 / {} 帧 / {:.2} s{}",
        s.events.len(),
        s.count("frame"),
        s.duration_ms() as f64 / 1000.0,
        if s.bad_lines > 0 {
            format!(" / {} 行损坏", s.bad_lines)
        } else {
            String::new()
        }
    );

    let mut chans: Vec<(String, String, String, String, Option<(u64, u64, u64, String)>)> = Vec::new();
    for e in &s.events {
        match e["ev"].as_str() {
            Some("channel.open") => chans.push((
                e["ch"].as_str().unwrap_or("?").into(),
                e["role"].as_str().unwrap_or("?").into(),
                e["laddr"].as_str().unwrap_or("?").into(),
                e["raddr"].as_str().unwrap_or("?").into(),
                None,
            )),
            Some("channel.close") => {
                let label = e["ch"].as_str().unwrap_or("?");
                if let Some(row) = chans.iter_mut().rev().find(|c| c.0 == label && c.4.is_none()) {
                    row.4 = Some((
                        e["tx"].as_u64().unwrap_or(0),
                        e["rx"].as_u64().unwrap_or(0),
                        e["dur_ms"].as_u64().unwrap_or(0),
                        e["reason"].as_str().unwrap_or("?").into(),
                    ));
                }
            }
            _ => {}
        }
    }
    if !chans.is_empty() {
        let _ = writeln!(out, "通道");
        for (label, role, laddr, raddr, close) in &chans {
            let tail = match close {
                Some((tx, rx, dur, reason)) => format!(
                    "tx {}  rx {}  {} ms  {}",
                    human(*tx),
                    human(*rx),
                    dur,
                    reason
                ),
                None => "未关闭（文件在会话中途截断？）".into(),
            };
            let _ = writeln!(
                out,
                "  {label:<8} {role:<7} {laddr} -> {raddr}   {tail}"
            );
        }
    }

    let mut kinds: Vec<(String, usize)> = Vec::new();
    for e in &s.events {
        if e["ev"] != "frame" {
            continue;
        }
        let key = match e["proto"].as_str() {
            Some("dfile") => format!("DFILE {}", e["kind_name"].as_str().unwrap_or("?")),
            Some("babeface") => format!("BABEFACE module={}", e["module"].as_u64().unwrap_or(0)),
            _ => "RAW".to_string(),
        };
        match kinds.iter_mut().find(|(k, _)| *k == key) {
            Some((_, n)) => *n += 1,
            None => kinds.push((key, 1)),
        }
    }
    if !kinds.is_empty() {
        kinds.sort_by(|a, b| b.1.cmp(&a.1));
        let text: Vec<String> = kinds.iter().map(|(k, n)| format!("{k}×{n}")).collect();
        let _ = writeln!(out, "帧型   {}", text.join("  "));
    }

    if let Some(end) = s.events.iter().rev().find(|e| e["ev"] == "session.end") {
        let files: Vec<String> = end["files"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "结果   {}  收/发 {}  用时 {} ms  原因 {}",
            if end["ok"].as_bool().unwrap_or(false) { "成功" } else { "失败" },
            human(end["bytes"].as_u64().unwrap_or(0)),
            end["dur_ms"].as_u64().unwrap_or(0),
            end["reason"].as_str().unwrap_or("-")
        );
        if !files.is_empty() {
            let _ = writeln!(out, "文件   {}", files.join(", "));
        }
    } else if s.count("channel.open") == 0 && udp_tx + udp_rx > 0 {
        let _ = writeln!(out, "结果   — 仅发现阶段，没有 TCP 会话");
    } else {
        let _ = writeln!(out, "结果   ❌ 没有 session.end（会话未正常收尾）");
    }
    out
}

fn human(n: u64) -> String {
    if n >= 1 << 20 {
        format!("{:.2} MB", n as f64 / 1048576.0)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

fn fmt_wall(ms: u64) -> String {
    let secs = (ms / 1000) as i64;

    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{year:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[derive(Default)]
pub struct ViewOpts {
    pub channel: Option<String>,
    pub from_ms: Option<u64>,
    pub to_ms: Option<u64>,

    pub show_hex: bool,
    pub max_hex: usize,
}

pub fn render_timeline(s: &Session, o: &ViewOpts) -> String {
    let t0 = s.events.first().and_then(|e| e["t"].as_u64()).unwrap_or(0);
    let max_hex = if o.max_hex == 0 { 32 } else { o.max_hex };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# {}  sid={}  scope={}  {} 事件",
        s.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        s.sid(),
        s.scope(),
        s.events.len()
    );
    for e in &s.events {
        let ev = e["ev"].as_str().unwrap_or("?");
        let ch = e["ch"].as_str().unwrap_or("");
        if let Some(want) = &o.channel {
            let global = matches!(ev, "capture.meta" | "capture.end" | "session.start" | "session.end");
            if !global && ch != want {
                continue;
            }
        }
        let t_us = e["t"].as_u64().unwrap_or(0).saturating_sub(t0);
        if let Some(from) = o.from_ms {
            if t_us < from * 1000 {
                continue;
            }
        }
        if let Some(to) = o.to_ms {
            if t_us > to * 1000 {
                continue;
            }
        }
        let body = describe(e, o.show_hex, max_hex);
        let tag = if ch.is_empty() {
            String::new()
        } else {
            format!("[{ch}] ")
        };
        let _ = writeln!(out, "{:>9.4}s  {tag}{body}", t_us as f64 / 1_000_000.0);
    }
    out
}

fn describe(e: &Value, show_hex: bool, max_hex: usize) -> String {
    let ev = e["ev"].as_str().unwrap_or("?");
    let s = |k: &str| e[k].as_str().unwrap_or("-").to_string();
    let n = |k: &str| e[k].as_u64().unwrap_or(0);
    match ev {
        "capture.meta" => format!(
            "采集开始 tool={} scope={} peer_filter={}",
            s("tool"),
            s("scope"),
            s("peer_filter")
        ),
        "capture.end" => format!(
            "采集结束 events={} frames={} bytes={} reason={}",
            n("events"),
            n("frames"),
            n("bytes"),
            s("reason")
        ),
        "session.start" => format!(
            "会话开始 {} peer={} local={} files={} bytes={}",
            s("dir"),
            s("peer"),
            s("local"),
            n("files"),
            n("bytes")
        ),
        "session.end" => {
            let files: Vec<String> = e["files"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|x| x.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            format!(
                "会话结束 ok={} bytes={} dur={} ms reason={} files=[{}]",
                e["ok"].as_bool().unwrap_or(false),
                n("bytes"),
                n("dur_ms"),
                s("reason"),
                files.join(",")
            )
        }
        "discovery.build" => format!(
            "本地广播内容 src={} port={} name={} type={}",
            s("src"),
            n("port"),
            s("name"),
            n("type")
        ),
        "discovery.tx" => {
            let hex = e["hex"].as_str().unwrap_or("");
            if show_hex && !hex.is_empty() {
                format!(
                    "UDP 发送 dst={} {} B  {}",
                    s("dst"),
                    n("n"),
                    &hex[..hex.len().min(max_hex * 2)]
                )
            } else {
                format!("UDP 发送 dst={} {} B", s("dst"), n("n"))
            }
        }
        "discovery.rx.raw" => {
            let hex = e["hex"].as_str().unwrap_or("");
            if show_hex && !hex.is_empty() {
                format!(
                    "UDP 收到 src={} {} B  {}",
                    s("src"),
                    n("n"),
                    &hex[..hex.len().min(max_hex * 2)]
                )
            } else {
                format!("UDP 收到 src={} {} B", s("src"), n("n"))
            }
        }
        "channel.fail" => format!("通道建立失败 {}:{} {}", s("peer"), n("port"), s("error")),
        "frame.partial" => format!("残帧 {dir} {} B（对端未发完整帧）", n("n"), dir = s("dir")),
        "discovery.rx" => format!(
            "广播收到 src={} name={} kind={} port={} target={}",
            s("src"),
            s("name"),
            s("kind"),
            n("port"),
            e["target"].as_bool().unwrap_or(false)
        ),
        "channel.open" => format!(
            "通道打开 role={} {} -> {}",
            s("role"),
            s("laddr"),
            s("raddr")
        ),
        "channel.close" => format!(
            "通道关闭 tx={} rx={} dur={} ms reason={}",
            n("tx"),
            n("rx"),
            n("dur_ms"),
            s("reason")
        ),
        "confirm.show" => format!("确认弹窗 来自 {} 的 {} 个文件 / {} B", s("peer"), n("count"), n("bytes")),
        "confirm.answer" => format!(
            "确认结果 {}（{}）",
            if e["accepted"].as_bool().unwrap_or(false) { "接收" } else { "拒绝" },
            s("reason")
        ),
        "note" => format!("· {}", s("text")),
        "bytes" => {
            let dir = s("dir");
            let hex = e["hex"].as_str().unwrap_or("");
            if show_hex && !hex.is_empty() {
                format!("原始 {dir} {} B  {}", n("n"), &hex[..hex.len().min(max_hex * 2)])
            } else {
                format!("原始 {dir} {} B", n("n"))
            }
        }
        "frame" => {
            let dir = s("dir");
            let hex = e["hex"].as_str().unwrap_or("");
            let head = match e["proto"].as_str() {
                Some("dfile") => format!(
                    "DFILE {} kind={} trans={} len={}",
                    s("kind_name"),
                    n("kind"),
                    n("trans"),
                    n("len")
                ),
                Some("babeface") => format!(
                    "BABEFACE module={} seq={} flags={} len={}",
                    n("module"),
                    n("seq"),
                    n("flags"),
                    n("len")
                ),
                _ => "RAW".to_string(),
            };
            if show_hex && !hex.is_empty() {
                format!("{dir}  {head}  {}", &hex[..hex.len().min(max_hex * 2)])
            } else {
                format!("{dir}  {head}")
            }
        }
        other => format!("{other} {}", e),
    }
}

pub struct Check {
    pub ok: bool,
    pub lines: Vec<String>,
}

#[derive(Default)]
struct ChStat {
    open: usize,
    close: usize,
    tx: u64,
    rx: u64,
    tx_seen: u64,
    rx_seen: u64,
    frames: usize,
}

pub fn check(s: &Session) -> Check {
    let mut lines = Vec::new();
    let mut ok = true;
    let pass = |lines: &mut Vec<String>, msg: String| lines.push(format!("[PASS] {msg}"));
    let fail = |lines: &mut Vec<String>, msg: String, ok: &mut bool| {
        *ok = false;
        lines.push(format!("[FAIL] {msg}"));
    };

    if s.events.iter().any(|e| e["ev"] == "capture.meta") {
        pass(&mut lines, "capture.meta 存在".into());
    } else {
        fail(&mut lines, "缺少 capture.meta".into(), &mut ok);
    }
    if s.events.iter().any(|e| e["ev"] == "capture.end") {
        pass(&mut lines, "capture.end 存在（文件正常关闭）".into());
    } else {
        fail(&mut lines, "缺少 capture.end（进程可能崩溃/被强杀）".into(), &mut ok);
    }
    if s.bad_lines > 0 {
        fail(&mut lines, format!("{} 行 JSON 损坏", s.bad_lines), &mut ok);
    }

    let mut chans: Vec<(String, ChStat)> = Vec::new();
    let mut seen_bytes = 0usize;
    for e in &s.events {
        match e["ev"].as_str() {
            Some("channel.open") => {
                let label = e["ch"].as_str().unwrap_or("?").to_string();
                get_ch(&mut chans, &label).open += 1;
            }
            Some("channel.close") => {
                let label = e["ch"].as_str().unwrap_or("?").to_string();
                let c = get_ch(&mut chans, &label);
                c.close += 1;
                c.tx += e["tx"].as_u64().unwrap_or(0);
                c.rx += e["rx"].as_u64().unwrap_or(0);
            }
            Some("bytes") => {
                seen_bytes += 1;
                let label = e["ch"].as_str().unwrap_or("?").to_string();
                let c = get_ch(&mut chans, &label);
                match e["dir"].as_str() {
                    Some("tx") => c.tx_seen += e["n"].as_u64().unwrap_or(0),
                    Some("rx") => c.rx_seen += e["n"].as_u64().unwrap_or(0),
                    _ => {}
                }
            }
            Some("frame") => {
                let label = e["ch"].as_str().unwrap_or("?").to_string();
                get_ch(&mut chans, &label).frames += 1;
            }
            _ => {}
        }
    }
    for (label, c) in &chans {
        if c.open == 0 {
            continue;
        }
        if c.close == 0 {
            fail(&mut lines, format!("{label}: 有 open 没有 close"), &mut ok);
        } else if c.open != c.close {
            fail(
                &mut lines,
                format!("{label}: open {} 次但 close {} 次（同名通道复用？）", c.open, c.close),
                &mut ok,
            );
        } else {
            pass(&mut lines, format!("{label}: open/close 配对（{c} 帧）", c = c.frames));
        }
        if seen_bytes > 0 {
            if c.tx_seen == c.tx && c.rx_seen == c.rx {
                pass(
                    &mut lines,
                    format!("{label}: 字节数一致 tx={} rx={}", c.tx, c.rx),
                );
            } else {
                fail(
                    &mut lines,
                    format!(
                        "{label}: 字节数不一致 close(tx={},rx={}) vs bytes事件(tx={},rx={})",
                        c.tx, c.rx, c.tx_seen, c.rx_seen
                    ),
                    &mut ok,
                );
            }
        } else {
            lines.push(format!(
                "[WARN] {label}: 采集范围不含 bytes，无法按字节核对（只能核对帧数）"
            ));
        }
    }

    let has_start = s.events.iter().any(|e| e["ev"] == "session.start");
    let has_end = s.events.iter().any(|e| e["ev"] == "session.end");
    let udp_events = s.count("discovery.tx") + s.count("discovery.rx.raw");
    let no_tcp = s.count("channel.open") == 0;
    if has_start && has_end {
        pass(&mut lines, "session.start / session.end 成对".into());
    } else if has_start {
        fail(&mut lines, "有 session.start 但没有 session.end".into(), &mut ok);
    } else if udp_events > 0 && no_tcp {
        lines.push(format!(
            "[WARN] 没有 TCP 会话，只有 {udp_events} 条 UDP 发现事件（discover 模式属正常）"
        ));
    } else {
        fail(&mut lines, "没有 session.start（可能只采到了握手失败）".into(), &mut ok);
    }

    let mut bad_frames = 0usize;
    for e in &s.events {
        if e["ev"] != "frame" {
            continue;
        }
        if e["proto"] == "dfile" {
            let len = e["len"].as_u64().unwrap_or(0) + 8;
            if len != e["n"].as_u64().unwrap_or(0) {
                bad_frames += 1;
            }
        }
    }
    if bad_frames > 0 {
        fail(&mut lines, format!("{bad_frames} 个 DFile 帧长度与声明不符"), &mut ok);
    } else {
        pass(&mut lines, "DFile 帧长度全部自洽".into());
    }

    if s.count("frame") == 0 {
        lines.push("[WARN] 没有帧记录（scope=skeleton？）".into());
    }
    if s.events.iter().any(|e| e["ev"] == "capture.limit") {
        lines.push("[WARN] 采集触发了字节上限，后半段只有骨架/帧事件，pcap 不完整".into());
    }
    let partials = s.count("frame.partial");
    if partials > 0 {
        lines.push(format!(
            "[WARN] {partials} 条残帧（对端未发完就关闭），字节已记录但不构成完整帧"
        ));
    }
    let fails = s.count("channel.fail");
    if fails > 0 {
        lines.push(format!("[INFO] {fails} 次 TCP 建连失败（已记录原因）"));
    }

    Check { ok, lines }
}

fn get_ch<'a>(chans: &'a mut Vec<(String, ChStat)>, label: &str) -> &'a mut ChStat {
    if let Some(pos) = chans.iter().position(|(l, _)| l == label) {
        return &mut chans[pos].1;
    }
    chans.push((label.to_string(), ChStat::default()));
    &mut chans.last_mut().unwrap().1
}

pub fn write_pcap(s: &Session, out: &Path) -> Result<usize, String> {
    if s.scope() != "bytes" {
        return Err(format!(
            "当前采集范围是 {}，没有完整字节，无法导出 pcap；请用 --scope all 重新采集",
            s.scope()
        ));
    }

    struct Chan {
        label: String,
        role: String,
        client: Endpoint,
        server: Endpoint,
        open_wall: u64,
    }

    let parse_ep = |text: &str| -> Option<Endpoint> {
        let (ip, port) = text.rsplit_once(':')?;
        let oct: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
        if oct.len() != 4 {
            return None;
        }
        Some(Endpoint {
            ip: [oct[0], oct[1], oct[2], oct[3]],
            port: port.parse().ok()?,
        })
    };

    let mut chans: Vec<Chan> = Vec::new();
    for e in &s.events {
        if e["ev"] != "channel.open" {
            continue;
        }
        let local = parse_ep(e["laddr"].as_str().unwrap_or(""));
        let remote = parse_ep(e["raddr"].as_str().unwrap_or(""));
        let (Some(local), Some(remote)) = (local, remote) else {
            continue;
        };
        let role = e["role"].as_str().unwrap_or("connect").to_string();
        let (client, server) = if role == "accept" {
            (remote, local)
        } else {
            (local, remote)
        };
        chans.push(Chan {
            label: e["ch"].as_str().unwrap_or("?").to_string(),
            role,
            client,
            server,
            open_wall: e["wall"].as_u64().unwrap_or(0),
        });
    }
    if chans.is_empty() {
        let has_udp = s.events.iter().any(|e| {
            matches!(e["ev"].as_str(), Some("discovery.tx") | Some("discovery.rx.raw"))
                && e["hex"].as_str().map(|h| !h.is_empty()).unwrap_or(false)
        });
        if !has_udp {
            return Err("没有 channel.open，也没有 UDP 报文，无法重建会话".into());
        }
    }

    let mut packets: Vec<(u64, Vec<u8>)> = Vec::new();
    for (idx, ch) in chans.iter().enumerate() {
        let mut client_seq = 1000u32 + idx as u32 * 1_000_000;
        let mut server_seq = 500_000u32 + idx as u32 * 1_000_000;
        let cisn = client_seq;
        let sisn = server_seq;
        let t0 = ch.open_wall.saturating_sub(1);

        let mut push = |t: u64, from_client: bool, seq: u32, ack: u32, flags: u8, payload: &[u8]| {
            let (src, dst) = if from_client {
                (&ch.client, &ch.server)
            } else {
                (&ch.server, &ch.client)
            };
            let pkt = build_tcp_packet(src, dst, seq, ack, flags, payload);
            packets.push((t, pkt));
        };
        push(t0, true, cisn, 0, 0x02, &[]);
        push(t0, false, sisn, cisn + 1, 0x12, &[]);
        push(t0, true, cisn + 1, sisn + 1, 0x10, &[]);
        client_seq = cisn + 1;
        server_seq = sisn + 1;

        let mut data_packets = 0usize;
        let mut last_wall = ch.open_wall;
        for e in &s.events {
            if e["ev"] != "bytes" || e["ch"].as_str() != Some(ch.label.as_str()) {
                continue;
            }
            let dir = e["dir"].as_str().unwrap_or("");
            let from_client = if ch.role == "accept" {
                dir == "rx"
            } else {
                dir == "tx"
            };
            let Some(payload) = hex_decode(e["hex"].as_str().unwrap_or("")) else {
                return Err(format!(
                    "{} 的 bytes 事件 hex 不完整（scope 不是 bytes？）",
                    ch.label
                ));
            };
            let wall = e["wall"].as_u64().unwrap_or(t0);
            last_wall = last_wall.max(wall);
            let mut off = 0usize;
            while off < payload.len() {
                let n = (payload.len() - off).min(1400);
                let chunk = &payload[off..off + n];
                let (seq, ack) = if from_client {
                    (client_seq, server_seq)
                } else {
                    (server_seq, client_seq)
                };
                push(wall, from_client, seq, ack, 0x18, chunk);
                if from_client {
                    client_seq = client_seq.wrapping_add(n as u32);
                } else {
                    server_seq = server_seq.wrapping_add(n as u32);
                }
                data_packets += 1;
                off += n;
            }
        }
        let _ = data_packets;

        let fin_at = last_wall.saturating_add(1);
        push(fin_at, true, client_seq, server_seq, 0x11, &[]);
        client_seq = client_seq.wrapping_add(1);
        push(fin_at, false, server_seq, client_seq, 0x11, &[]);
        server_seq = server_seq.wrapping_add(1);
        push(fin_at, true, client_seq, server_seq, 0x10, &[]);
    }

    if let Some(local) = s.meta["local"].as_str().and_then(parse_ipv4) {
        const UDP_PORT: u16 = 5684;
        for e in &s.events {
            let ev = e["ev"].as_str().unwrap_or("");
            if ev != "discovery.tx" && ev != "discovery.rx.raw" {
                continue;
            }
            let Some(payload) = hex_decode(e["hex"].as_str().unwrap_or("")) else {
                continue;
            };
            if payload.is_empty() {
                continue;
            }
            let wall = e["wall"].as_u64().unwrap_or(0);
            let pkt = if ev == "discovery.tx" {
                let dst = match e["dst"].as_str().unwrap_or("") {
                    "broadcast" => [255, 255, 255, 255],
                    "multicast" => [224, 0, 0, 1],
                    other => match parse_ipv4(other) {
                        Some(ip) => ip,
                        None => continue,
                    },
                };
                build_udp_packet(local, dst, UDP_PORT, UDP_PORT, &payload)
            } else {
                let Some(src) = e["src"].as_str().and_then(parse_ipv4) else {
                    continue;
                };
                build_udp_packet(src, local, UDP_PORT, UDP_PORT, &payload)
            };
            packets.push((wall, pkt));
        }
    }

    packets.sort_by_key(|(t, _)| *t);

    let mut buf: Vec<u8> = Vec::with_capacity(24 + packets.iter().map(|(_, p)| p.len() + 16).sum::<usize>());

    buf.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&262_144u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    for (wall, pkt) in &packets {
        let sec = (wall / 1000) as u32;
        let usec = ((wall % 1000) * 1000) as u32;
        buf.extend_from_slice(&sec.to_le_bytes());
        buf.extend_from_slice(&usec.to_le_bytes());
        buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        buf.extend_from_slice(pkt);
    }
    std::fs::write(out, &buf).map_err(|e| format!("写 {} 失败: {e}", out.display()))?;
    Ok(packets.len())
}

fn build_tcp_packet(
    src: &Endpoint,
    dst: &Endpoint,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&src.port.to_be_bytes());
    tcp.extend_from_slice(&dst.port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(0x50);
    tcp.push(flags);
    tcp.extend_from_slice(&65535u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + tcp.len());
    pseudo.extend_from_slice(&src.ip);
    pseudo.extend_from_slice(&dst.ip);
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&tcp);
    let csum = checksum(&pseudo);
    tcp[16..18].copy_from_slice(&csum.to_be_bytes());

    let mut ip = Vec::with_capacity(20 + tcp.len());
    ip.push(0x45);
    ip.push(0);
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&0x4000u16.to_be_bytes());
    ip.push(64);
    ip.push(6);
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&src.ip);
    ip.extend_from_slice(&dst.ip);
    let csum = checksum(&ip);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    ip.extend_from_slice(&tcp);

    let mut eth = Vec::with_capacity(14 + ip.len());
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    eth.extend_from_slice(&0x0800u16.to_be_bytes());
    eth.extend_from_slice(&ip);
    eth
}

fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let oct: Vec<u8> = text.split('.').filter_map(|p| p.parse().ok()).collect();
    if oct.len() == 4 {
        Some([oct[0], oct[1], oct[2], oct[3]])
    } else {
        None
    }
}

fn build_udp_packet(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
    udp.extend_from_slice(payload);

    let mut ip = Vec::with_capacity(20 + udp.len());
    ip.push(0x45);
    ip.push(0);
    ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&0x4000u16.to_be_bytes());
    ip.push(64);
    ip.push(17);
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let csum = checksum(&ip);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    ip.extend_from_slice(&udp);

    let mut eth = Vec::with_capacity(14 + ip.len());
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    eth.extend_from_slice(&0x0800u16.to_be_bytes());
    eth.extend_from_slice(&ip);
    eth
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.ends_with("..") || text.len() % 2 != 0 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{classify, FrameKind};

    fn sample(path: &Path) {
        let lines = [
            r#"{"v":1,"ev":"capture.meta","sid":"T1","tool":"HWSHARE_WIRE_FULL","source":"test","pid":1,"wall":1760000000000,"local":"10.0.0.1","peer_filter":"10.0.0.2","scope":"bytes"}"#,
            r#"{"v":1,"ev":"session.start","sid":"T1","t":0,"wall":1760000000000,"peer":"10.0.0.2","dir":"recv","local":"10.0.0.1","files":1,"bytes":5}"#,
            r#"{"v":1,"ev":"channel.open","sid":"T1","t":100,"wall":1760000000100,"ch":"control","role":"accept","laddr":"10.0.0.1:5684","raddr":"10.0.0.2:40000"}"#,
            r#"{"v":1,"ev":"bytes","sid":"T1","t":200,"wall":1760000000200,"ch":"control","dir":"rx","n":3,"hex":"414243"}"#,
            r#"{"v":1,"ev":"bytes","sid":"T1","t":300,"wall":1760000000300,"ch":"control","dir":"tx","n":2,"hex":"7879"}"#,
            r#"{"v":1,"ev":"frame","sid":"T1","t":400,"wall":1760000000400,"ch":"control","dir":"rx","proto":"dfile","kind":8,"kind_name":"SETTINGS","flags":0,"sess":0,"trans":0,"len":0,"n":8,"hex":"0800000000000000"}"#,
            r#"{"v":1,"ev":"channel.close","sid":"T1","t":500,"wall":1760000000500,"ch":"control","tx":2,"rx":3,"dur_ms":100,"reason":"shutdown"}"#,
            r#"{"v":1,"ev":"session.end","sid":"T1","t":600,"wall":1760000000600,"ok":true,"bytes":5,"files":["a.png"],"reason":"done","dur_ms":600}"#,
            r#"{"v":1,"ev":"capture.end","sid":"T1","t":700,"wall":1760000000700,"events":9,"frames":1,"bytes":5,"reason":"done"}"#,
        ];
        std::fs::write(path, lines.join("\n")).unwrap();
    }

    #[test]
    fn loads_and_summarizes() {
        let path = std::env::temp_dir().join("hwshare-replay-test.jsonl");
        sample(&path);
        let s = load(&path).unwrap();
        assert_eq!(s.sid(), "T1");
        assert_eq!(s.events.len(), 9);
        let text = summarize(&s);
        assert!(text.contains("control"));
        assert!(text.contains("成功"));
        assert!(text.contains("SETTINGS"));
    }

    #[test]
    fn timeline_marks_relative_time() {
        let path = std::env::temp_dir().join("hwshare-replay-timeline.jsonl");
        sample(&path);
        let s = load(&path).unwrap();
        let text = render_timeline(&s, &ViewOpts::default());
        assert!(text.contains("会话开始"));
        assert!(text.contains("0.0002s") || text.contains("0.0003s"));
        assert!(text.contains("DFILE SETTINGS"));
    }

    #[test]
    fn check_matches_byte_totals() {
        let path = std::env::temp_dir().join("hwshare-replay-check.jsonl");
        sample(&path);
        let s = load(&path).unwrap();
        let c = check(&s);
        assert!(c.ok, "校验应通过: {:#?}", c.lines);
        assert!(c.lines.iter().any(|l| l.contains("字节数一致")));
    }

    #[test]
    fn pcap_has_valid_header_and_packets() {
        let path = std::env::temp_dir().join("hwshare-replay-pcap.jsonl");
        sample(&path);
        let s = load(&path).unwrap();
        let out = std::env::temp_dir().join("hwshare-replay-test.pcap");
        let n = write_pcap(&s, &out).unwrap();
        assert!(n >= 5, "至少握手 3 包 + 数据 + FIN: {n}");
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(&bytes[0..4], &0xA1B2_C3D4u32.to_le_bytes());
        assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 1);

        let first = &bytes[24 + 16..];
        let eth_len = 14usize;
        let ip_start = eth_len;
        let tcp_start = ip_start + 20;
        assert_eq!(first[tcp_start + 13] & 0x02, 0x02);
    }

    #[test]
    fn frame_kind_helper_is_shared() {
        assert_eq!(
            classify(&[8, 0, 0, 0, 0, 0, 0, 0]),
            FrameKind::Dfile { kind: 8, flags: 0, session: 0, transaction: 0, size: 0 }
        );
    }
}
