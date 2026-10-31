use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hwshare_core::channel::Listener;
use hwshare_core::replay::{self, ViewOpts};
use hwshare_core::trace::{self, Config, Scope};
use hwshare_core::{config, confirm, outbound, receive, send};

const TOOL: &str = "HWSHARE_WIRE_FULL";
const VERSION: &str = "1.0";

fn usage() {
    println!(
        r#"{TOOL} {VERSION} —— 华为分享会话级全量采集与回放

用法:
  hwshare-wirefull capture --dst <IP> [选项]     采集一次交互
  hwshare-wirefull replay <会话文件> [选项]      回放（默认时间轴）
  hwshare-wirefull info   <会话文件>             只看摘要
  hwshare-wirefull check  <会话文件>             完整性校验

capture:
  --dst <IP>            目标 IP（手机/平板）。必填
  --src <IP>            源 IP（本机）。默认自动探测到 --dst 的出口地址
  --mode listen|send|spawn
                        listen（默认）本机监听，等对方连进来
                        send 本机主动发送（需 --file）
                        spawn 拉起 hwshare.exe（含托盘/发现），采集它的会话
  --port <N>            listen 监听端口 / send 目标端口（默认 5684）
  --file <路径>         send 要发送的文件，可重复
  --name <名字>         本机显示名（默认 COMPUTERNAME）
  --dest <目录>         listen 接收目录（默认 config.json 里的 dest）
  --out <文件>          会话文件（默认 %LOCALAPPDATA%\HWShareWin\sessions\capture-<sid>.jsonl）
  --scope skeleton|frame|bytes|all
                        采集范围，默认 all（bytes）。bytes 体积≈传输量×2
  --max-mb <N>          字节上限，超过后停记 bytes（默认 512，0=不限）
  --duration <秒>       listen 等待上限 / spawn 运行上限（默认 listen 300，spawn 0=不限）
  --confirm             listen 收到请求时弹确认框（默认自动接收）
  --keep                listen 连续接收多个会话（默认收一个就退出）
  --exe <路径>          spawn 使用的 hwshare.exe（默认与本工具同目录）
  -- <参数...>          spawn 传给 hwshare 的参数（默认 serve）

replay:
  --pcap <文件>         把字节流重建成 pcap（需 scope=bytes，Wireshark 可直接打开）
  --hex                 打印帧/字节的 hex（默认只打头字段）
  --max-hex <N>         每条最多打印 N 字节 hex（默认 32）
  --channel <名字>      只看某条通道（control / byte / file#1 …）
  --from <毫秒>         从第 N 毫秒开始
  --to <毫秒>           到第 N 毫秒结束

示例:
  hwshare-wirefull capture --dst 192.168.1.10 --src 192.168.1.20 --out d:\cap.jsonl
  hwshare-wirefull capture --dst 192.168.1.10 --mode send --file d:\a.png
  hwshare-wirefull replay d:\cap.jsonl --hex --max-hex 64
  hwshare-wirefull replay d:\cap.jsonl --pcap d:\cap.pcap
  hwshare-wirefull check d:\cap.jsonl
"#
    );
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("capture") => cmd_capture(&args[1..]),
        Some("replay") => cmd_replay(&args[1..]),
        Some("info") => cmd_info(&args[1..]),
        Some("check") => cmd_check(&args[1..]),
        Some("-h") | Some("--help") | Some("help") | None => {
            usage();
            std::process::ExitCode::SUCCESS
        }
        Some("--version") | Some("version") => {
            println!("{TOOL} {VERSION}");
            std::process::ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("[错误] 未知子命令: {other}");
            usage();
            std::process::ExitCode::from(2)
        }
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn flags(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn is_ipv4(text: &str) -> bool {
    text.parse::<Ipv4Addr>().is_ok()
}

fn local_ipv4(dst: &str) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(SocketAddr::new(
        IpAddr::V4(dst.parse().ok()?),
        5684,
    ))
    .ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v) => Some(v),
        _ => None,
    }
}

fn default_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".into())
}

fn default_out(sid: &str) -> PathBuf {
    trace::default_dir().join(format!("capture-{sid}.jsonl"))
}

fn resolve_out(value: Option<&str>, sid: &str) -> PathBuf {
    match value {
        Some(p) if !p.trim().is_empty() => {
            let path = PathBuf::from(p);
            if path.is_dir() {
                path.join(format!("capture-{sid}.jsonl"))
            } else {
                path
            }
        }
        _ => default_out(sid),
    }
}

fn cmd_capture(args: &[String]) -> std::process::ExitCode {
    let Some(dst) = flag(args, "--dst") else {
        eprintln!("[错误] 缺少 --dst <IP>（目标设备地址）");
        return std::process::ExitCode::from(2);
    };
    if !is_ipv4(dst) {
        eprintln!("[错误] --dst 不是合法 IPv4: {dst}");
        return std::process::ExitCode::from(2);
    }
    let mode = flag(args, "--mode").unwrap_or("listen");
    let scope = flag(args, "--scope")
        .and_then(Scope::parse)
        .unwrap_or(Scope::Bytes);
    let sid = trace::make_session_id();
    let out = resolve_out(flag(args, "--out"), &sid);
    let max_mb: u64 = flag(args, "--max-mb")
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);
    let src = match flag(args, "--src") {
        Some(s) if is_ipv4(s) => s.to_string(),
        Some(s) => {
            eprintln!("[错误] --src 不是合法 IPv4: {s}");
            return std::process::ExitCode::from(2);
        }
        None => match local_ipv4(dst) {
            Some(ip) => ip.to_string(),
            None => {
                eprintln!("[错误] 探测不到到 {dst} 的本机地址，请显式指定 --src");
                return std::process::ExitCode::from(2);
            }
        },
    };

    let spawn_mode = mode == "spawn";
    if !spawn_mode {
        let cfg = Config {
            path: out.clone(),
            peer: Some(dst.to_string()),
            local: Some(src.clone()),
            scope,
            session_id: sid.clone(),
            source: "wirefull".into(),
            max_bytes: max_mb.saturating_mul(1024 * 1024),
        };
        if let Err(e) = trace::start(cfg) {
            eprintln!("[错误] 无法创建会话文件 {}: {e}", out.display());
            return std::process::ExitCode::from(1);
        }
    }

    println!("{TOOL} {VERSION}");
    println!("  源 IP    {src}");
    println!("  目标 IP  {dst}");
    println!("  模式     {mode}");
    println!("  范围     {}", scope.as_str());
    println!("  输出     {}", out.display());
    if scope == Scope::Bytes {
        println!("  提示     全量字节约为传输量的 2 倍（hex），大文件请留意磁盘");
    }
    println!();

    let code = match mode {
        "listen" => capture_listen(args, dst, &src, scope),
        "send" => capture_send(args, dst),
        "spawn" => capture_spawn(args, dst, &src, scope, &out, &sid, max_mb),
        other => {
            eprintln!("[错误] 未知 --mode: {other}（listen / send / spawn）");
            Err(())
        }
    };

    if !spawn_mode {
        let reason = if code.is_ok() { "capture-finished" } else { "capture-failed" };
        trace::finish(reason);
    }
    if let Ok(meta) = std::fs::metadata(&out) {
        println!("\n[采集] {} （{:.1} KB）", out.display(), meta.len() as f64 / 1024.0);
        println!("[回放] hwshare-wirefull replay \"{}\"", out.display());
        println!("[校验] hwshare-wirefull check  \"{}\"", out.display());
    }
    match code {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(()) => std::process::ExitCode::from(1),
    }
}

fn capture_listen(args: &[String], dst: &str, src: &str, _scope: Scope) -> Result<(), ()> {
    let port: u16 = flag(args, "--port").and_then(|s| s.parse().ok()).unwrap_or(5684);
    let duration: u64 = flag(args, "--duration")
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let do_confirm = has(args, "--confirm");
    let keep = has(args, "--keep");
    let dest = flag(args, "--dest")
        .map(PathBuf::from)
        .unwrap_or_else(config::current);
    let name = flag(args, "--name").map(|s| s.to_string()).unwrap_or_else(default_name);

    let listener = Listener::bind(src, port).map_err(|e| {
        eprintln!("[错误] {e}");
    })?;
    println!("[监听] {src}:{}，目标 {dst}", listener.port);
    println!("[保存] {}", dest.display());
    let private = send::load_or_create_identity(None).map_err(|e| {
        eprintln!("[错误] 读取身份失败: {e}");
    })?;

    let deadline = Instant::now() + Duration::from_secs(duration);
    while Instant::now() < deadline {
        let wait = (deadline - Instant::now()).min(Duration::from_secs(1));
        let mut channel = match listener.accept(wait) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let peer_ip = channel.peer().to_string();
        if peer_ip != dst {
            println!("[跳过] {peer_ip} 不是目标 {dst}");
            trace::note("control", &format!("忽略非目标连接 {peer_ip}"));
            continue;
        }
        println!("[接入] {peer_ip}");

        let session = match receive::accept_connection(
            &mut channel,
            &private,
            true,
            Duration::from_secs(30),
        ) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[失败] 握手: {e}");
                continue;
            }
        };
        let mut session = session;
        println!(
            "[请求] {} 个文件，{:.1} MB",
            session.file_count,
            session.total_bytes as f64 / 1048576.0
        );
        if do_confirm {
            let answer = confirm::ask(
                &session.peer,
                session.file_count,
                session.total_bytes,
                channel.try_clone_stream().ok(),
            );
            session.accepted = answer.accepted;
            receive::record_drained(&mut channel, &session, answer.drained);
        } else {
            println!("[确认] 自动接收（--confirm 可改为弹窗）");
            session.accepted = true;
        }

        match receive::run_session(
            &session,
            &mut channel,
            &dest,
            &name,
            Duration::from_secs(600),
        ) {
            Ok(result) => {
                if session.accepted {
                    println!(
                        "[完成] {} 个文件，{:.1} MB",
                        result.saved.len(),
                        result.bytes as f64 / 1048576.0
                    );
                    for p in &result.saved {
                        println!("  {}", p.display());
                    }
                } else {
                    println!("[拒绝] 已拒绝 {} 的请求", session.peer);
                }
            }
            Err(e) => eprintln!("[失败] {e}"),
        }
        if !keep {
            break;
        }
    }
    Ok(())
}

fn capture_send(args: &[String], dst: &str) -> Result<(), ()> {
    let files: Vec<PathBuf> = flags(args, "--file").into_iter().map(PathBuf::from).collect();
    if files.is_empty() {
        eprintln!("[错误] send 模式需要 --file <路径>");
        return Err(());
    }
    let port: u16 = flag(args, "--port").and_then(|s| s.parse().ok()).unwrap_or(5684);
    let name = flag(args, "--name").map(|s| s.to_string()).unwrap_or_else(default_name);
    println!("[发送] {} → {dst}:{port}", files.len());
    match outbound::send(dst, port, &files, &name, &|line| println!("{line}")) {
        Ok(report) => {
            println!(
                "[完成] {} 个文件，{:.1} MB",
                report.files.len(),
                report.bytes as f64 / 1048576.0
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("[失败] {e}");
            Err(())
        }
    }
}

fn capture_spawn(
    args: &[String],
    dst: &str,
    src: &str,
    scope: Scope,
    out: &Path,
    _sid: &str,
    max_mb: u64,
) -> Result<(), ()> {
    let exe = flag(args, "--exe")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("hwshare.exe")))
        })
        .ok_or_else(|| eprintln!("[错误] 找不到 hwshare.exe，请用 --exe 指定"))?;
    if !exe.is_file() {
        eprintln!("[错误] 不存在: {}", exe.display());
        return Err(());
    }

    let mut child_args: Vec<String> = match args.iter().position(|a| a == "--") {
        Some(pos) => args[pos + 1..].to_vec(),
        None => vec!["serve".into()],
    };
    if child_args.is_empty() {
        child_args.push("serve".into());
    }
    let duration: u64 = flag(args, "--duration")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    println!("[拉起] {} {}", exe.display(), child_args.join(" "));
    let mut cmd = Command::new(&exe);
    cmd.args(&child_args)
        .env("HWSHARE_TRACE", "1")
        .env("HWSHARE_TRACE_OUT", out)
        .env("HWSHARE_TRACE_PEER", dst)
        .env("HWSHARE_TRACE_LOCAL", src)
        .env("HWSHARE_TRACE_SCOPE", scope.as_str())
        .env("HWSHARE_TRACE_MAX_MB", max_mb.to_string())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = cmd.spawn().map_err(|e| {
        eprintln!("[错误] 拉起失败: {e}");
    })?;

    let stop = Instant::now() + Duration::from_secs(if duration == 0 { 86_400 } else { duration });
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                println!("[退出] 子进程 {}", status);
                return if status.success() { Ok(()) } else { Err(()) };
            }
            Ok(None) => {
                if Instant::now() >= stop {
                    println!("[超时] 结束子进程");
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => {
                eprintln!("[错误] 等待子进程失败: {e}");
                return Err(());
            }
        }
    }
}

fn cmd_replay(args: &[String]) -> std::process::ExitCode {
    let Some(path) = args.first().filter(|a| !a.starts_with("--")) else {
        eprintln!("[错误] 用法: hwshare-wirefull replay <会话文件> [--pcap out] [--hex]");
        return std::process::ExitCode::from(2);
    };
    let session = match replay::load(Path::new(path)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[错误] {e}");
            return std::process::ExitCode::from(1);
        }
    };

    if let Some(pcap) = flag(args, "--pcap") {
        match replay::write_pcap(&session, Path::new(pcap)) {
            Ok(n) => {
                println!("[pcap] {} 个报文 → {pcap}", n);
                println!("[提示] Wireshark 打开后可用「跟踪 TCP 流」看到完整载荷");
                return std::process::ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("[错误] {e}");
                return std::process::ExitCode::from(1);
            }
        }
    }

    print!("{}", replay::summarize(&session));
    println!();
    let opts = ViewOpts {
        channel: flag(args, "--channel").map(|s| s.to_string()),
        from_ms: flag(args, "--from").and_then(|s| s.parse().ok()),
        to_ms: flag(args, "--to").and_then(|s| s.parse().ok()),
        show_hex: has(args, "--hex"),
        max_hex: flag(args, "--max-hex")
            .and_then(|s| s.parse().ok())
            .unwrap_or(32),
    };
    print!("{}", replay::render_timeline(&session, &opts));
    println!("\n[提示] --hex 看字节，--channel file#1 只看数据面，--pcap x.pcap 导出给 Wireshark");
    std::process::ExitCode::SUCCESS
}

fn cmd_info(args: &[String]) -> std::process::ExitCode {
    let Some(path) = args.first() else {
        eprintln!("[错误] 用法: hwshare-wirefull info <会话文件>");
        return std::process::ExitCode::from(2);
    };
    match replay::load(Path::new(path)) {
        Ok(s) => {
            print!("{}", replay::summarize(&s));
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[错误] {e}");
            std::process::ExitCode::from(1)
        }
    }
}

fn cmd_check(args: &[String]) -> std::process::ExitCode {
    let Some(path) = args.first() else {
        eprintln!("[错误] 用法: hwshare-wirefull check <会话文件>");
        return std::process::ExitCode::from(2);
    };
    match replay::load(Path::new(path)) {
        Ok(s) => {
            print!("{}", replay::summarize(&s));
            println!();
            let result = replay::check(&s);
            for line in &result.lines {
                println!("{line}");
            }
            println!(
                "\n结论: {}",
                if result.ok { "PASS 可完整还原" } else { "FAIL 记录不完整" }
            );
            if result.ok {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("[错误] {e}");
            std::process::ExitCode::from(1)
        }
    }
}
