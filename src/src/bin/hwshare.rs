#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use hwshare_core::channel::{Channel, Listener};
use hwshare_core::{discovery, receive, send};

fn usage() {
    eprintln!(
        r#"华为分享 {}

用法:
  直接双击 exe（不带参数）              = tray，等同打开托盘
  华为分享 discover [--seconds N]        扫描附近的华为设备
  华为分享 send <文件...> --to IP[:PORT] [--name 名]
                                         把文件发给手机（完整传输）
  华为分享 clip --to IP[:PORT]            把剪贴板文本当 txt 发给手机
  华为分享 listen [--port N]              被动接收一次连接并解析 offer
  华为分享 serve [--dest 目录] [--name 名] [--port N] [--no-discovery]
                                         常驻（控制台，看得到日志）
  华为分享 tray  [--dest 目录] [--name 名] 常驻（系统托盘，隐藏控制台）
  华为分享 selftest                       协议自检

说明: 收发数据面均已实现；接收在 HarmonyOS 7 真机上验证过。

接收目录: 不给 --dest 时读配置（托盘菜单「选择接收文件夹…」可改，存
%LOCALAPPDATA%\HWShareWin\config.json），默认 下载\HWShare；--dest 只对本次运行生效。
"#,

        env!("CARGO_PKG_VERSION")
    );
}

#[cfg(all(windows, not(debug_assertions)))]
fn ensure_console() {
    let sub = std::env::args().nth(1).unwrap_or_default();

    let needs = !matches!(sub.as_str(), "" | "tray");
    if !needs {
        return;
    }
    unsafe {
        use windows_sys::Win32::System::Console::{AllocConsole, AttachConsole, ATTACH_PARENT_PROCESS};
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            AllocConsole();
        }
    }
}

#[cfg(not(all(windows, not(debug_assertions))))]
fn ensure_console() {}

fn main() -> ExitCode {
    ensure_console();

    if std::env::args().any(|a| a == "--trace")
        && std::env::var("HWSHARE_TRACE").is_err()
    {
        std::env::set_var("HWSHARE_TRACE", "1");
    }

    if std::env::args().any(|a| a == "--trace-full") {
        std::env::set_var("HWSHARE_TRACE", "1");
        std::env::set_var("HWSHARE_WIRE_FULL", "1");
    }

    hwshare_core::trace::init_from_env();
    let code = run();
    hwshare_core::trace::finish("process-exit");
    code
}

fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("discover") => cmd_discover(&args[2..]),
        Some("send") => cmd_send(&args[2..]),
        Some("clip") => cmd_clip(&args[2..]),
        Some("listen") => cmd_listen(&args[2..]),
        Some("serve") => cmd_serve(&args[2..]),
        Some("tray") => cmd_tray(&args[2..], false),
        Some("selftest") => cmd_selftest(),

        Some("preview") => {
            if args.get(2).map(String::as_str) == Some("drop") {
                hwshare_core::dropzone::toggle();

                let secs = std::env::var("HWSHARE_PREVIEW_SECS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(10);
                std::thread::sleep(Duration::from_secs(secs));
                hwshare_core::dropzone::hide();
                println!("预览结束（拖放浮窗）");
                return ExitCode::SUCCESS;
            }

            if args.get(2).map(String::as_str) == Some("overlay") {
                let pname = args
                    .get(4)
                    .map(String::as_str)
                    .unwrap_or("vid-300mb.mp4");
                hwshare_core::overlay::start(pname);
                let total = 314_572_800u64;
                if args.get(3).map(String::as_str) == Some("wait") {
                    hwshare_core::overlay::waiting(args.get(4).map(String::as_str).unwrap_or("vid-300mb.mp4"));
                    std::thread::sleep(Duration::from_secs(10));
                    hwshare_core::overlay::hide();
                    println!("预览结束（等待态）");
                    return ExitCode::SUCCESS;
                }
                match args.get(3).and_then(|s| s.parse::<u64>().ok()) {
                    Some(pct) => {
                        hwshare_core::overlay::update(total * pct / 100, total);
                        std::thread::sleep(Duration::from_secs(10));
                    }
                    None => {
                        for i in 0..=62u64 {
                            hwshare_core::overlay::update(total * i / 100, total);
                            std::thread::sleep(Duration::from_millis(90));
                        }
                        std::thread::sleep(Duration::from_secs(2));
                    }
                }
                hwshare_core::overlay::finish();
                std::thread::sleep(Duration::from_secs(2));
                println!("预览结束（浮层）");
            } else if args.get(2).map(String::as_str) == Some("alert") {
                hwshare_core::notice::show(
                    "启动失败",
                    "端口 5684 已被其它程序占用。\n\n请先关闭占用端口的程序，或在命令里加 --port 指定别的端口。",
                );
                println!("预览结束（提示框）");
            } else if matches!(args.get(2).map(String::as_str), Some("ok") | Some("fail")) {
                let ok = args.get(2).map(String::as_str) == Some("ok");
                let name = args.get(3).map(String::as_str).unwrap_or("vid-300mb.mp4");
                let total = 314_572_800u64;
                hwshare_core::overlay::set_outgoing(false);
                hwshare_core::overlay::set_multi(1);
                hwshare_core::overlay::start(name);
                hwshare_core::overlay::update(total * 38 / 100, total);
                if ok {
                    hwshare_core::overlay::finish();
                } else {
                    hwshare_core::overlay::fail();
                }
                std::thread::sleep(Duration::from_secs(8));
                println!("预览结束（{}）", if ok { "成功态" } else { "失败态" });
                return ExitCode::SUCCESS;
            } else {
                let answer =
                    hwshare_core::confirm::ask("测试手机", 1, 314572800, None);
                println!("预览结束，accepted={}", answer.accepted);
            }
            ExitCode::SUCCESS
        }

        None => cmd_tray(&[], true),
        _ => {
            usage();
            ExitCode::from(1)
        }
    }
}

fn local_ipv4() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn cmd_discover(args: &[String]) -> ExitCode {
    let seconds: u64 = flag_value(args, "--seconds").and_then(|s| s.parse().ok()).unwrap_or(15);
    let Some(local) = local_ipv4() else {
        eprintln!("[错误] 找不到可用的局域网地址，请先连上 Wi-Fi");
        return ExitCode::from(1);
    };

    println!("本机地址: {local}");

    let socket = match discovery::DiscoverySocket::bind(local) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[错误] {e}");
            return ExitCode::from(1);
        }
    };

    let private = match send::load_or_create_identity(None) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[错误] 身份密钥: {e}");
            return ExitCode::from(1);
        }
    };
    let public_der = match hwshare_core::crypto::public_der(&private) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[错误] {e}");
            return ExitCode::from(1);
        }
    };
    let identity = hwshare_core::identity_v2(&public_der).unwrap_or_default();

    let packet = discovery::advertisement(&local.to_string(), 5684, &identity, "Windows PC", true);
    let prefix = 24u8;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut peers: Vec<discovery::Peer> = Vec::new();
    let mut last_broadcast = Instant::now() - Duration::from_secs(10);

    println!("扫描中（{seconds} 秒）...\n");
    while Instant::now() < deadline {
        if last_broadcast.elapsed() >= Duration::from_millis(900) {
            let _ = socket.send("broadcast", &packet);
            let _ = socket.send("multicast", &packet);
            last_broadcast = Instant::now();
        }
        let Some((host, data)) = socket.recv() else { continue };
        if host == local.to_string() {
            continue;
        }
        match discovery::decode_advertisement(&data, &host, local, prefix) {
            Ok((peer, _confirmable, _mid)) => {
                if !peers.iter().any(|p| p.id == peer.id) {
                    println!("发现: {} ({}, {}) @ {}:{}", peer.name, peer.brand, peer.kind, peer.host, peer.port);
                    peers.push(peer);
                }
            }
            Err(_) => {}
        }
    }

    if peers.is_empty() {
        println!("\n没有发现设备。请确认手机已打开华为分享、与电脑同一 Wi-Fi。");
        return ExitCode::from(1);
    }
    println!("\n共发现 {} 台设备", peers.len());
    ExitCode::SUCCESS
}

fn find_peer_port(target: &str, seconds: u64) -> Option<u16> {
    let local = local_ipv4()?;
    let socket = discovery::DiscoverySocket::bind(local).ok()?;
    let private = send::load_or_create_identity(None).ok()?;
    let public_der = hwshare_core::crypto::public_der(&private).ok()?;
    let identity = hwshare_core::identity_v2(&public_der).unwrap_or_default();
    let packet = discovery::advertisement(&local.to_string(), 5684, &identity, "Windows PC", true);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut last = Instant::now() - Duration::from_secs(10);
    while Instant::now() < deadline {
        if last.elapsed() >= Duration::from_millis(800) {
            let _ = socket.send("broadcast", &packet);
            let _ = socket.send("multicast", &packet);
            last = Instant::now();
        }
        let Some((host, data)) = socket.recv() else { continue };
        if host == local.to_string() || host != target {
            continue;
        }
        if let Ok((peer, _, _)) = discovery::decode_advertisement(&data, &host, local, 24) {
            if peer.port > 0 {
                return Some(peer.port);
            }
        }
    }
    None
}

fn cmd_send(args: &[String]) -> ExitCode {
    if let Some(secs) = std::env::var("HWSHARE_CANCEL_AFTER")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
    {
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs_f64(secs));
            eprintln!("[取消] {secs:.1} 秒到点，请求取消发送");
            hwshare_core::outbound::request_cancel_send();
        });
    }
    let files: Vec<PathBuf> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .filter(|a| !a.contains(':') || PathBuf::from(a).exists())
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();

    if files.is_empty() {
        eprintln!("[错误] 没有找到可发送的文件");
        return ExitCode::from(1);
    }

    let Some(target) = flag_value(args, "--to") else {
        eprintln!("[错误] 需要 --to <手机IP:端口>（先用 hwshare discover 查看）");
        return ExitCode::from(1);
    };
    let (ip, port) = match target.rsplit_once(':') {
        Some((ip, port)) => match port.parse::<u16>() {
            Ok(port) => (ip.to_string(), port),
            Err(_) => {
                eprintln!("[错误] 端口无效");
                return ExitCode::from(1);
            }
        },
        None => {
            println!("未指定端口，正在向 {target} 扫描端口...");
            match find_peer_port(target, 8) {
                Some(port) => {
                    println!("手机端口: {port}");
                    (target.to_string(), port)
                }
                None => {
                    eprintln!("[错误] 8 秒内没扫到 {target} 的广播，请确认华为分享已开启");
                    return ExitCode::from(1);
                }
            }
        }
    };

    let total: u64 = files
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    println!(
        "待发送 {} 个文件，共 {:.1} MB → {target}",
        files.len(),
        total as f64 / 1048576.0
    );

    let display_name = flag_value(args, "--name").unwrap_or("Windows PC");
    let log = |line: &str| println!("  {line}");
    match hwshare_core::outbound::send(&ip, port, &files, display_name, &log) {
        Ok(report) => {
            println!(
                "\n[完成] 已发送 {} 个文件，{:.1} MB",
                report.files.len(),
                report.bytes as f64 / 1048576.0
            );
            for name in &report.files {
                println!("   {name}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[失败] {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_clip(args: &[String]) -> ExitCode {
    let Some(text) = hwshare_core::clipboard::read_text() else {
        eprintln!("[错误] 剪贴板里没有文本（图片/文件请用 send）");
        return ExitCode::from(1);
    };
    let Some(target) = flag_value(args, "--to") else {
        eprintln!("[错误] 需要 --to <手机IP[:端口]>（先用 hwshare discover 查看）");
        return ExitCode::from(1);
    };
    let (ip, port) = match target.rsplit_once(':') {
        Some((ip, port)) => match port.parse::<u16>() {
            Ok(port) => (ip.to_string(), port),
            Err(_) => {
                eprintln!("[错误] 端口无效");
                return ExitCode::from(1);
            }
        },
        None => {
            println!("未指定端口，正在向 {target} 扫描端口...");
            match find_peer_port(target, 8) {
                Some(port) => (target.to_string(), port),
                None => {
                    eprintln!("[错误] 8 秒内没扫到 {target} 的广播，请确认华为分享已开启");
                    return ExitCode::from(1);
                }
            }
        }
    };
    let path = match hwshare_core::clipboard::write_temp(&text) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("[错误] 写临时文件失败: {e}");
            return ExitCode::from(1);
        }
    };
    println!(
        "剪贴板 {} 字符：{}",
        text.chars().count(),
        hwshare_core::clipboard::preview(&text, 40)
    );
    let display_name = flag_value(args, "--name").unwrap_or("Windows PC");
    let log = |line: &str| println!("  {line}");
    match hwshare_core::outbound::send(&ip, port, &[path], display_name, &log) {
        Ok(report) => {
            println!(
                "\n[完成] 已发送剪贴板文本，{:.1} KB",
                report.bytes as f64 / 1024.0
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[失败] {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_listen(args: &[String]) -> ExitCode {
    let port: u16 = flag_value(args, "--port").and_then(|s| s.parse().ok()).unwrap_or(0);
    let Some(local) = local_ipv4() else {
        eprintln!("[错误] 找不到可用的局域网地址");
        return ExitCode::from(1);
    };

    let listener = match Listener::bind(&local.to_string(), port) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[错误] {e}");
            return ExitCode::from(1);
        }
    };
    println!("监听 {}:{}，等待手机连接（一次）...", local, listener.port);

    let mut channel = match listener.accept(Duration::from_secs(120)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[错误] {e}");
            return ExitCode::from(1);
        }
    };
    println!("来自 {} 的连接", channel.peer());

    let private = match send::load_or_create_identity(None) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[错误] {e}");
            return ExitCode::from(1);
        }
    };

    match receive::accept_connection(&mut channel, &private, true, Duration::from_secs(30)) {
        Ok(mut session) => {
            println!("\n收到分享请求:");
            println!("  文件数: {}", session.file_count);
            println!("  总大小: {:.1} MB", session.total_bytes as f64 / 1048576.0);
            println!("  对端: {}", session.peer);

            let answer = hwshare_core::confirm::ask(
                &session.peer,
                session.file_count,
                session.total_bytes,
                channel.try_clone_stream().ok(),
            );
            session.accepted = answer.accepted;

            hwshare_core::receive::record_drained(&mut channel, &session, answer.drained);
            println!("  {}", if session.accepted { "已接收" } else { "已拒绝" });

            let dest = std::env::var("HWSHARE_DEST").unwrap_or_else(|_| {
                let base = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
                format!("{base}\\Downloads")
            });
            println!("  保存到: {dest}");

            match receive::run_session(
                &session,
                &mut channel,
                std::path::Path::new(&dest),
                "Windows PC",
                Duration::from_secs(600),
            ) {
                Ok(_) if !session.accepted => {
                    println!("\n[拒绝] 已拒绝本次分享，未接收任何文件");
                    ExitCode::SUCCESS
                }
                Ok(result) => {
                    println!("\n[完成] 收到 {} 个文件，共 {:.1} MB", result.saved.len(),
                             result.bytes as f64 / 1048576.0);
                    for path in &result.saved {
                        println!("  {}", path.display());
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    let msg = e.to_string();
                    println!("[中断] {msg}");
                    hwshare_core::tray::log_line(&format!("[中断] {msg}"));
                    if std::env::var_os("HWSHARE_NO_ALERT").is_none() {
                        let rc = hwshare_core::tray::alert("传输中断", &msg);
                        if rc == 0 {
                            eprintln!("[提示] 弹窗未能显示（rc=0），原因见上");
                        }
                    }
                    ExitCode::from(1)
                }
            }
        }
        Err(e) => {
            eprintln!("[失败] {e}");
            ExitCode::from(1)
        }
    }
}

struct ServeConfig {
    local: String,
    name: String,
    explicit_dest: Option<PathBuf>,
    port: u16,
    no_discovery: bool,
}

fn default_device_name() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Windows PC".to_string())
}

fn serve_config(args: &[String]) -> Result<ServeConfig, String> {
    let local = local_ipv4().ok_or_else(|| "找不到可用的局域网地址".to_string())?;
    let name = flag_value(args, "--name")
        .map(str::to_string)
        .unwrap_or_else(default_device_name);
    let explicit_dest = flag_value(args, "--dest").map(PathBuf::from);
    let port = flag_value(args, "--port")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(5684);
    let no_discovery = args.iter().any(|a| a == "--no-discovery");
    Ok(ServeConfig { local: local.to_string(), name, explicit_dest, port, no_discovery })
}

fn run_service(cfg: ServeConfig, verbose: bool) -> Result<(), String> {
    let private = send::load_or_create_identity(None).map_err(|e| format!("身份密钥: {e}"))?;
    let public_der = hwshare_core::crypto::public_der(&private).map_err(|e| e.to_string())?;
    let identity = hwshare_core::identity_v2(&public_der).unwrap_or_default();

    let addr: Ipv4Addr = cfg
        .local
        .parse()
        .map_err(|_| format!("本机地址无效: {}", cfg.local))?;
    let listener = Listener::bind(&cfg.local, cfg.port).map_err(|e| format!("TCP: {e}"))?;

    let socket = if cfg.no_discovery {
        None
    } else {
        Some(discovery::DiscoverySocket::bind(addr).map_err(|e| format!("UDP: {e}"))?)
    };

    let dest_now = || {
        cfg.explicit_dest
            .clone()
            .unwrap_or_else(hwshare_core::config::current)
    };

    if verbose {
        println!("华为分享 常驻服务");
        println!("  名称   : {}", cfg.name);
        println!("  保存到 : {}", dest_now().display());
        println!("  监听   : {}:{} (UDP 广播 + TCP)", cfg.local, cfg.port);

        if let Some(p) = hwshare_core::trace::current_path() {
            println!("  采集   : {}", p.display());
        }

        if let Ok(ms) = std::env::var("HWSHARE_CONFIRM_DELAY_MS") {
            if ms.trim().parse::<u64>().map(|n| n > 0).unwrap_or(false) {
                println!("  实验   : user_confirm 延时 {} ms", ms.trim());
            }
        }
        if let Ok(t) = std::env::var("HWSHARE_TYPE") {
            println!("  实验   : 广播 type={}", t.trim());
        }
        println!("  按 Ctrl+C 退出\n");
    }

    let adv_name = cfg.name.clone();
    let adv_identity = identity.clone();
    let adv_local = cfg.local.clone();
    let adv_net = addr;
    if let Some(socket) = socket {
    std::thread::spawn(move || {
        let beacon = discovery::advertisement(&adv_local, 5684, &adv_identity, &adv_name, true);
        let answer = discovery::advertisement(&adv_local, 5684, &adv_identity, &adv_name, false);
        let mut last_broadcast = Instant::now() - Duration::from_secs(10);

        let mut last_answer: Vec<(String, Instant)> = Vec::new();
        let mut answered = 0u32;

        loop {
            if let Some((host, data)) = socket.recv() {
                if host != adv_local {
                    if !discovery::is_discovery_packet(&data) {
                        continue;
                    }

                    if let Ok((peer, _, _)) =
                        discovery::decode_advertisement(&data, &host, adv_net, 24)
                    {
                        hwshare_core::peers::upsert(&peer.name, &peer.host, peer.port, &peer.kind);
                    }
                    let due = last_answer
                        .iter()
                        .find(|(h, _)| *h == host)
                        .map(|(_, at)| at.elapsed() >= Duration::from_secs(2))
                        .unwrap_or(true);
                    if due {
                        if let Some(slot) = last_answer.iter_mut().find(|(h, _)| *h == host) {
                            slot.1 = Instant::now();
                        } else {
                            if last_answer.len() > 64 {
                                last_answer.remove(0);
                            }
                            last_answer.push((host.clone(), Instant::now()));
                        }
                        if let Err(e) = socket.send(&host, &answer) {
                            if verbose {
                                eprintln!("[应答失败] {host}: {e}");
                            }
                        } else {
                            answered += 1;
                            if verbose && (answered <= 3 || answered % 200 == 0) {
                                println!("[应答] 单播回应 {host}（累计 {answered} 次）");
                            }
                        }
                    }
                }
            }

            if last_broadcast.elapsed() >= Duration::from_millis(900) {
                let _ = socket.send("broadcast", &beacon);
                let _ = socket.send("multicast", &beacon);
                last_broadcast = Instant::now();
            }
        }
    });
    }

    let mut last_failure: Option<(String, Instant)> = None;

    loop {
        let mut channel = match listener.accept(Duration::from_secs(3600)) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let peer_text = channel.peer();
        if verbose {
            println!("[连接] 来自 {peer_text}");
        }

        match receive::accept_connection(&mut channel, &private, true, Duration::from_secs(30)) {
            Ok(mut session) => {
                if verbose {
                    println!(
                        "[请求] {} 个文件，{:.1} MB",
                        session.file_count,
                        session.total_bytes as f64 / 1048576.0
                    );
                }
                let answer = hwshare_core::confirm::ask(
                    &session.peer,
                    session.file_count,
                    session.total_bytes,
                    channel.try_clone_stream().ok(),
                );
                session.accepted = answer.accepted;
                receive::record_drained(&mut channel, &session, answer.drained);
                let dest = dest_now();
                match receive::run_session(
                    &session,
                    &mut channel,
                    &dest,
                    &cfg.name,
                    Duration::from_secs(600),
                ) {
                    Ok(result) => {
                        if verbose {
                            if session.accepted {
                                println!(
                                    "[完成] {} 个文件，{:.1} MB",
                                    result.saved.len(),
                                    result.bytes as f64 / 1048576.0
                                );
                                for p in &result.saved {
                                    println!("   {}", p.display());
                                }
                            } else {
                                println!("[拒绝] 已拒绝 {} 的分享请求", session.peer);
                            }
                        }
                        hwshare_core::tray::add_received(result.saved.len() as u64, result.bytes);
                        if !result.saved.is_empty() {
                            let names: Vec<String> = result
                                .saved
                                .iter()
                                .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                                .collect();
                            hwshare_core::tray::notify(
                                "已接收",
                                &format!(
                                    "{} · {:.1} MB",
                                    names.join("、"),
                                    result.bytes as f64 / 1048576.0
                                ),
                            );
                        }
                    }
                    Err(e) => {
                        let msg = e.to_string();

                        println!("[中断] {msg}");
                        hwshare_core::tray::log_line(&format!("[中断] {msg}"));
                        if std::env::var_os("HWSHARE_NO_ALERT").is_none() {
                            let msg = msg.clone();
                            std::thread::spawn(move || {
                                if hwshare_core::tray::alert("传输中断", &msg) == 0 {
                                    eprintln!("[提示] 弹窗未能显示（rc=0）");
                                }
                            });
                        }
                    }
                }
            }
            Err(e) => {
                let text = e.to_string();
                let repeated = last_failure
                    .as_ref()
                    .map(|(last, at)| last == &text && at.elapsed() < Duration::from_secs(60))
                    .unwrap_or(false);
                if verbose && !repeated {
                    eprintln!("[握手失败] {text}");
                }
                last_failure = Some((text, Instant::now()));
            }
        }
    }
}

fn cmd_serve(args: &[String]) -> ExitCode {
    let cfg = match serve_config(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[错误] {e}");
            return ExitCode::from(1);
        }
    };
    match run_service(cfg, true) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[错误] {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_tray(args: &[String], open_panel: bool) -> ExitCode {
    let port = flag_value(args, "--port")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(5684);
    let mutex_name: Vec<u16> = format!("Local\\HWShareTray.v2.{port}\0").encode_utf16().collect();
    let guard = unsafe {
        windows_sys::Win32::System::Threading::CreateMutexW(
            std::ptr::null(),
            1,
            mutex_name.as_ptr(),
        )
    };

    let already_running = unsafe { windows_sys::Win32::Foundation::GetLastError() } == 183;
    hwshare_core::tray::log_line("cmd_tray 进入");
    if !guard.is_null() && already_running {
        hwshare_core::tray::log_line("发现已有实例，提示后退出");
        hwshare_core::tray::alert(
            "华为分享",
            &format!(
                "端口 {port} 上已经有一个华为分享在运行。\n\n\
                 图标在任务栏右下角，可能收在 ^ 折叠区里；\n\
                 投递面板在屏幕右下角（托盘菜单「显示投递窗口」可以叫回来）。"
            ),
        );
        return ExitCode::from(0);
    }

    let cfg = match serve_config(args) {
        Ok(c) => c,
        Err(e) => {
            hwshare_core::tray::alert("华为分享", &e);
            return ExitCode::from(1);
        }
    };

    hwshare_core::tray::enable_dpi_awareness();
    let dest_text = cfg
        .explicit_dest
        .clone()
        .unwrap_or_else(hwshare_core::config::current)
        .display()
        .to_string();
    hwshare_core::tray::set_context(&cfg.name, &dest_text, &cfg.local);
    hwshare_core::tray::hide_console();

    if open_panel {
        hwshare_core::dropzone::toggle();
        hwshare_core::tray::log_line("双击启动：自动弹出投递窗口");
    }

    let verbose = std::env::var("HWSHARE_DEBUG").is_ok();
    std::thread::spawn(move || {
        if let Err(e) = run_service(cfg, verbose) {
            hwshare_core::tray::log_line(&format!("服务启动失败: {e}"));
            hwshare_core::tray::alert("启动失败", &e);
            std::process::exit(1);
        }
    });

    ExitCode::from(hwshare_core::tray::run() as u8)
}

fn cmd_selftest() -> ExitCode {
    let mut failed = 0;

    let pkt = discovery::advertisement("192.168.1.5", 41234, "AABBCCDDEEFF", "Test", true);
    match discovery::decode_advertisement(
        &pkt,
        "192.168.1.5",
        "192.168.1.1".parse().unwrap(),
        24,
    ) {
        Ok((peer, _, _)) => {
            if peer.name != "Test" || peer.port != 41234 {
                println!("广播解析字段不符: {:?}", peer);
                failed += 1;
            }
        }
        Err(e) => {
            println!("广播解析失败: {e}");
            failed += 1;
        }
    }

    match send::load_or_create_identity(None) {
        Ok(key) => {
            if hwshare_core::crypto::public_der(&key).is_err() {
                println!("公钥导出失败");
                failed += 1;
            }
        }
        Err(e) => {
            println!("身份密钥失败: {e}");
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

#[allow(dead_code)]
fn _unused(_: SocketAddr) {}

#[allow(dead_code)]
fn _unused_channel(_: Channel) {}
