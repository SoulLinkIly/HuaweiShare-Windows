use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use hwshare::channel::{Channel, Listener};
use hwshare::discovery::{self, Peer};
use hwshare::transmit;

pub fn run_gui() -> ExitCode {
    #[cfg(windows)]
    silence_stdio();
    let args: Vec<String> = std::env::args().skip(1).collect();
    hwshare::trace::init_from_env();
    let code = cmd_tray(&args);
    hwshare::trace::finish("exit");
    code
}

pub fn run_cli() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    hwshare::trace::init_from_env();
    let code = match args.get(1).map(String::as_str) {
        Some("discover") => cmd_discover(&args[2..]),
        Some("send") => cmd_send(&args[2..]),
        Some("serve") => cmd_serve(&args[2..]),
        Some("listen") => cmd_listen(&args[2..]),
        Some("-h") | Some("--help") | Some("help") => {
            usage();
            ExitCode::SUCCESS
        }
        None | Some("tray") => {
            eprintln!("[提示] 图形界面请用 hwshare.exe（双击或不带参数运行）。");
            usage();
            ExitCode::from(2)
        }
        Some(other) => {
            eprintln!("未知子命令：{other}");
            usage();
            ExitCode::from(2)
        }
    };
    hwshare::trace::finish("exit");
    code
}

#[cfg(windows)]
fn silence_stdio() {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{
        SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    };
    if let Ok(file) = std::fs::OpenOptions::new().write(true).open("NUL") {
        let handle = file.into_raw_handle();
        unsafe {
            SetStdHandle(STD_OUTPUT_HANDLE, handle);
            SetStdHandle(STD_ERROR_HANDLE, handle);
        }
    }
}

fn usage() {
    println!(
        r#"华为分享（同时支持鸿蒙手机 / 鸿蒙 7 与 iPad / iPhone）

命令行用法（hwshare-cli.exe）:
  hwshare-cli discover [--seconds N]        扫描局域网设备（默认 12 秒）
  hwshare-cli send --to <IP[:端口]> <文件...>
  hwshare-cli send --to-all <文件...>       发给所有已发现设备
  hwshare-cli serve [--dest 目录] [--name 名称] [--port 5684] [--no-discovery]
  hwshare-cli listen [--dest 目录] [--port 0]

图形界面请双击 hwshare.exe（不带参数）；它不接收命令行子命令。

发送选项:
  --name <名称>     对端看到的本机名字（send 默认 "Windows PC"；
                    serve / 图形界面 默认取计算机名 COMPUTERNAME）

环境变量:
  HWSHARE_CONFIRM=0     接收时自动接受、不弹确认框（默认弹框询问）
  HWSHARE_CONFIRM_EOF_CLOSE=0  对端断开时不立即判拒绝，照旧等满 30 秒
  HWSHARE_CHUNK=<字节>  分块大小（默认 1422 / 整帧 1472；上限 65485）
  HWSHARE_IDLE_SECS=<秒> 接收端判定"对方掉线"的空闲阈值（默认 8，最小 5）
  HWSHARE_TRACE=1       把会话采集写到 %LOCALAPPDATA%\HWShareWin\sessions
  HWSHARE_DEBUG=1       打印每帧级别的收发日志
"#
    );
}

fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().map(String::as_str);
        }
        if let Some(rest) = a.strip_prefix(&format!("{name}=")) {
            return Some(rest);
        }
    }
    None
}

fn local_ipv4() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("223.5.5.5:53").ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
        _ => None,
    }
}

fn default_device_name() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Windows PC".to_string())
}

fn default_dest() -> PathBuf {
    hwshare::config::current()
}

fn scan(local: Ipv4Addr, seconds: u64, quiet: bool) -> std::result::Result<Vec<Peer>, String> {
    let socket = discovery::DiscoverySocket::bind(local).map_err(|e| {
        format!(
            "无法绑定发现端口（UDP 5684）：{e}\n  \
             · 是不是已经有一个 hwshare 在跑？同端口只能有一个 —— 先退出托盘再扫描；\n  \
             · 或者被防火墙 / 安全软件占用。"
        )
    })?;
    let identity = match transmit::load_or_create_identity(None) {
        Ok(private) => hwshare::crypto::public_der(&private)
            .map(|der| hwshare::identity_v2(&der).unwrap_or_default())
            .unwrap_or_default(),
        Err(_) => String::new(),
    };
    let name = default_device_name();
    let beacon = discovery::discovery_beacon(&local.to_string(), 5684, &identity, &name, true);
    let harmony = discovery::advertisement_query_harmony(&local.to_string(), 5684, &identity, &name);

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut peers: Vec<Peer> = Vec::new();
    let mut last = Instant::now() - Duration::from_secs(10);
    while Instant::now() < deadline {
        if last.elapsed() >= Duration::from_millis(900) {
            let _ = socket.transmit("broadcast", &beacon);
            let _ = socket.transmit("multicast", &beacon);
            let _ = socket.transmit("broadcast", &harmony);
            let _ = socket.transmit("multicast", &harmony);
            last = Instant::now();
        }
        let Some((host, data)) = socket.recv() else { continue };
        if host == local.to_string() {
            continue;
        }
        if let Ok((peer, _, _)) = discovery::parse_discovery_beacon(&data, &host, local, 24) {
            if peers.iter().any(|p| p.id == peer.id) {
                continue;
            }
            if !quiet {
                println!(
                    "发现: {} ({}, {}) @ {}:{}",
                    peer.name, peer.brand, peer.kind, peer.host, peer.port
                );
            }
            peers.push(peer);
        }
    }
    Ok(peers)
}

fn cmd_discover(args: &[String]) -> ExitCode {
    let seconds: u64 = flag_value(args, "--seconds")
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    let Some(local) = local_ipv4() else {
        eprintln!("[错误] 找不到可用的局域网地址，请先连上 Wi-Fi");
        return ExitCode::from(1);
    };
    println!("本机地址: {local}");
    println!("扫描中（{seconds} 秒）...\n");

    let peers = match scan(local, seconds, false) {
        Ok(peers) => peers,
        Err(e) => {
            eprintln!("[错误] {e}");
            return ExitCode::from(1);
        }
    };
    if peers.is_empty() {
        println!("\n没有发现设备。请确认对端已打开「华为分享 / 鸿蒙星河互联」且与本机同一 Wi-Fi。");
        return ExitCode::from(1);
    }
    println!("\n共发现 {} 台设备", peers.len());
    ExitCode::SUCCESS
}

fn cmd_send(args: &[String]) -> ExitCode {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut missing: Vec<&String> = Vec::new();
    let mut skip_next = false;
    for a in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if matches!(a.as_str(), "--to" | "--name") {
            skip_next = true;
            continue;
        }
        if a.starts_with("--") {
            continue;
        }
        let path = PathBuf::from(a);
        if path.exists() {
            files.push(path);
        } else {
            missing.push(a);
        }
    }
    if !missing.is_empty() {
        let list: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
        eprintln!("[错误] 文件不存在：{}", list.join("、"));
        return ExitCode::from(1);
    }
    if files.is_empty() {
        eprintln!("[错误] 没有指定要发送的文件");
        return ExitCode::from(1);
    }
    let display_name = flag_value(args, "--name").unwrap_or("Windows PC");
    let log = |line: &str| println!("  {line}");

    if args.iter().any(|a| a == "--to-all") {
        let Some(local) = local_ipv4() else {
            eprintln!("[错误] 找不到可用的局域网地址");
            return ExitCode::from(1);
        };
        println!("扫描设备（10 秒）...");
        let peers = match scan(local, 10, false) {
            Ok(peers) => peers,
            Err(e) => {
                eprintln!("[错误] {e}");
                return ExitCode::from(1);
            }
        };
        if peers.is_empty() {
            eprintln!("[错误] 没有发现任何设备");
            return ExitCode::from(1);
        }
        let mut failed = 0;
        for peer in &peers {
            println!("\n=== 发送到 {}（{}:{}）===", peer.name, peer.host, peer.port);
            match hwshare::outbound::transmit(&peer.host, peer.port, &files, display_name, &log) {
                Ok(report) => println!(
                    "[完成] {} 个文件，{:.1} MB",
                    report.files.len(),
                    report.bytes as f64 / 1048576.0
                ),
                Err(e) => {
                    failed += 1;
                    println!("[失败] {e}");
                }
            }
        }
        return if failed == 0 { ExitCode::SUCCESS } else { ExitCode::from(1) };
    }

    let Some(target) = flag_value(args, "--to") else {
        eprintln!("[错误] 需要 --to <IP[:端口]>，或 --to-all");
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
            let Some(local) = local_ipv4() else {
                eprintln!("[错误] 找不到可用的局域网地址");
                return ExitCode::from(1);
            };
            let found = match scan(local, 8, true) {
                Ok(peers) => peers.into_iter().find(|p| p.host == target),
                Err(e) => {
                    eprintln!("[错误] {e}");
                    return ExitCode::from(1);
                }
            };
            match found {
                Some(peer) if peer.port > 0 => {
                    println!("对端端口: {}", peer.port);
                    (target.to_string(), peer.port)
                }
                _ => {
                    eprintln!("[错误] 8 秒内没扫到 {target}，请确认对端已打开分享面板");
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
        "待发送 {} 个文件，共 {:.1} MB → {ip}:{port}",
        files.len(),
        total as f64 / 1048576.0
    );

    match hwshare::outbound::transmit(&ip, port, &files, display_name, &log) {
        Ok(report) => {
            println!(
                "\n[完成] 已发送 {} 个文件，{:.1} MB",
                report.files.len(),
                report.bytes as f64 / 1048576.0
            );
            for name in &report.files {
                println!("  {name}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("\n[失败] {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_listen(args: &[String]) -> ExitCode {
    let port: u16 = flag_value(args, "--port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let dest = flag_value(args, "--dest")
        .map(PathBuf::from)
        .unwrap_or_else(default_dest);
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
    println!("监听 {}:{}，等待连接（一次）...", local, listener.port);

    let mut channel = match listener.accept(Duration::from_secs(300)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[错误] {e}");
            return ExitCode::from(1);
        }
    };
    println!("来自 {} 的连接", channel.peer());
    let Ok(private) = transmit::load_or_create_identity(None) else {
        eprintln!("[错误] 身份密钥加载失败");
        return ExitCode::from(1);
    };
    serve_one(&mut channel, &private, &dest, &default_device_name(), true)
}

struct ServeConfig {
    local: Ipv4Addr,
    name: String,
    port: u16,
    no_discovery: bool,
    explicit_dest: Option<PathBuf>,
}

impl ServeConfig {
    fn dest(&self) -> PathBuf {
        self.explicit_dest.clone().unwrap_or_else(default_dest)
    }
}

struct ActivePermit(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl ActivePermit {
    fn acquire(counter: &std::sync::Arc<std::sync::atomic::AtomicUsize>) -> Self {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self(counter.clone())
    }
}

impl Drop for ActivePermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

fn serve_config(args: &[String]) -> std::result::Result<ServeConfig, String> {
    let local = local_ipv4().ok_or_else(|| "找不到可用的局域网地址".to_string())?;
    Ok(ServeConfig {
        local,
        name: flag_value(args, "--name")
            .map(str::to_string)
            .unwrap_or_else(default_device_name),
        port: flag_value(args, "--port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(5684),
        no_discovery: args.iter().any(|a| a == "--no-discovery"),
        explicit_dest: flag_value(args, "--dest").map(PathBuf::from),
    })
}

fn run_service(cfg: ServeConfig, verbose: bool) -> std::result::Result<(), String> {
    let initial_dest = cfg.dest();
    let private = transmit::load_or_create_identity(None)
        .map_err(|_| "身份密钥加载失败".to_string())?;
    let public_der = hwshare::crypto::public_der(&private).unwrap_or_default();
    let identity = hwshare::identity_v2(&public_der).unwrap_or_default();
    let listener = Listener::bind(&cfg.local.to_string(), cfg.port)
        .map_err(|e| format!("TCP 监听失败: {e}"))?;

    if let Err(e) = std::fs::create_dir_all(&initial_dest) {
        return Err(format!("创建保存目录失败: {e}"));
    }

    if !cfg.no_discovery {
        spawn_advertiser(cfg.local, identity, cfg.name.clone());
    }
    let _ = verbose;

    log_line(&format!(
        "[监听] {}:{} 就绪（每条连接独立处理）",
        cfg.local, listener.port
    ));

    let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    const MAX_CONCURRENT: usize = 16;

    loop {
        let mut channel = match listener.accept(Duration::from_secs(3600)) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let peer = channel.peer().to_string();

        if active.load(std::sync::atomic::Ordering::Relaxed) >= MAX_CONCURRENT {
            log_line(&format!("[忽略] {peer} 连接过多，本轮跳过"));
            continue;
        }

        let dest = cfg.dest();
        let name = cfg.name.clone();
        let key = private.clone();
        let permit = ActivePermit::acquire(&active);

        let spawned = std::thread::Builder::new()
            .name("hwshare-serve".to_string())
            .spawn(move || {
                let _permit = permit;
                if should_log(&peer, "conn", Duration::from_secs(30)) {
                    log_line(&format!("[连接] 来自 {peer}"));
                }
                let code = serve_one(&mut channel, &key, &dest, &name, true);
                if code != ExitCode::SUCCESS
                    && should_log(&peer, "fail", Duration::from_secs(30))
                {
                    log_line(&format!("[握手失败] {peer}"));
                }
            });
        if let Err(e) = spawned {
            log_line(&format!("[错误] 无法创建接收线程：{e}"));
        }
    }
}

fn should_log(peer: &str, kind: &str, window: Duration) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static MAP: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    let map = MAP.get_or_init(|| Mutex::new(HashMap::new()));
    let key = format!("{kind}|{peer}");
    let mut guard = match map.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    match guard.get(&key) {
        Some(at) if at.elapsed() < window => false,
        _ => {
            guard.insert(key, Instant::now());
            true
        }
    }
}

fn log_line(text: &str) {
    eprintln!("{text}");
    #[cfg(windows)]
    hwshare::tray::log_line(text);
}

#[cfg(windows)]
fn cmd_tray(args: &[String]) -> ExitCode {
    use windows_sys::Win32::System::Threading::CreateMutexW;

    let cfg = match serve_config(args) {
        Ok(c) => c,
        Err(e) => {
            hwshare::tray::alert("华为分享", &e);
            return ExitCode::from(1);
        }
    };

    let mutex_name: Vec<u16> = format!("Local\\HWShareTray.v3.{}\0", cfg.port)
        .encode_utf16()
        .collect();
    let guard = unsafe { CreateMutexW(std::ptr::null(), 1, mutex_name.as_ptr()) };
    let already_running =
        unsafe { windows_sys::Win32::Foundation::GetLastError() } == 183;
    if !guard.is_null() && already_running {
        hwshare::tray::alert(
            "华为分享",
            &format!(
                "端口 {} 上已经有一个华为分享在运行。\n\n\
                 图标在任务栏右下角，可能收在 ^ 折叠区里；\n\
                 投递面板在屏幕右下角（托盘菜单「显示投递窗口」可以叫回来）。",
                cfg.port
            ),
        );
        return ExitCode::from(0);
    }

    hwshare::tray::enable_dpi_awareness();
    let dest_text = cfg.dest().display().to_string();
    hwshare::tray::set_context(&cfg.name, &dest_text, &cfg.local.to_string());

    let verbose = std::env::var("HWSHARE_DEBUG").is_ok();
    std::thread::spawn(move || {
        if let Err(e) = run_service(cfg, verbose) {
            hwshare::tray::log_line(&format!("服务启动失败: {e}"));
            hwshare::tray::alert("启动失败", &e);
            std::process::exit(1);
        }
    });

    ExitCode::from(hwshare::tray::run_loop() as u8)
}

#[cfg(not(windows))]
fn cmd_tray(_args: &[String]) -> ExitCode {
    eprintln!("[错误] 托盘只支持 Windows；请用 `serve` 子命令在终端里常驻");
    ExitCode::from(1)
}

fn cmd_serve(args: &[String]) -> ExitCode {
    let cfg = match serve_config(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[错误] {e}");
            return ExitCode::from(1);
        }
    };
    let dest = cfg.dest();
    println!("华为分享 接收服务");
    println!("  名称   : {}", cfg.name);
    println!("  保存到 : {}", dest.display());
    println!("  监听   : {}:{}", cfg.local, cfg.port);
    if let Some(p) = hwshare::trace::current_path() {
        println!("  采集   : {}", p.display());
    }
    println!("  按 Ctrl+C 退出\n");

    let verbose = std::env::var("HWSHARE_DEBUG").is_ok();
    match run_service(cfg, verbose) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[错误] {e}");
            ExitCode::from(1)
        }
    }
}

fn spawn_advertiser(local: Ipv4Addr, identity: String, name: String) {
    std::thread::spawn(move || {
        let Ok(socket) = discovery::DiscoverySocket::bind(local) else {
            eprintln!("[警告] UDP 端口被占用，本次不做广播（设备可能发现不了本机）");
            return;
        };
        let me = local.to_string();
        let beacon = discovery::discovery_beacon(&me, 5684, &identity, &name, true);
        let answer = discovery::discovery_beacon(&me, 5684, &identity, &name, false);
        let query = discovery::advertisement_query_harmony(&me, 5684, &identity, &name);

        let mut last_broadcast = Instant::now() - Duration::from_secs(10);
        let mut last_answer: Vec<(String, Instant)> = Vec::new();
        let mut seen_hosts: Vec<String> = Vec::new();

        let mut last_query = Instant::now() - Duration::from_secs(60);

        loop {
            if let Some((host, data)) = socket.recv() {
                if host != me && discovery::is_discovery_packet(&data) {
                    if let Ok((peer, _, _)) =
                        discovery::parse_discovery_beacon(&data, &host, local, 24)
                    {
                        hwshare::peers::upsert(&peer.name, &peer.host, peer.port, &peer.kind);
                        if !seen_hosts.iter().any(|h| *h == peer.host) {
                            if seen_hosts.len() >= 32 {
                                seen_hosts.remove(0);
                            }
                            seen_hosts.push(peer.host.clone());
                            log_line(&format!(
                                "[发现] {} ({}) @ {}:{}",
                                peer.name, peer.kind, peer.host, peer.port
                            ));
                        }
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
                        let _ = socket.transmit(&host, &answer);
                    }
                }
            }
            let force = discovery::take_scan_request();
            if force || last_broadcast.elapsed() >= Duration::from_millis(900) {
                let _ = socket.transmit("broadcast", &beacon);
                let _ = socket.transmit("multicast", &beacon);
                let _ = socket.transmit("broadcast", &answer);
                let _ = socket.transmit("multicast", &answer);
                let query_every = if seen_hosts.is_empty() {
                    Duration::from_millis(1500)
                } else {
                    Duration::from_secs(10)
                };
                if force || last_query.elapsed() >= query_every {
                    let _ = socket.transmit("broadcast", &query);
                    let _ = socket.transmit("multicast", &query);
                    last_query = Instant::now();
                }
                last_broadcast = Instant::now();
            }
        }
    });
}

fn serve_one(
    channel: &mut Channel,
    private: &rsa::RsaPrivateKey,
    dest: &std::path::Path,
    name: &str,
    verbose: bool,
) -> ExitCode {
    let mut session = match hwshare::receive::accept_connection(
        channel,
        private,
        true,
        Duration::from_secs(30),
    ) {
        Ok(s) => s,
        Err(e) => {
            if verbose {
                eprintln!("[拒绝] 握手失败: {e}");
            }
            return ExitCode::from(1);
        }
    };
    println!(
        "[请求] {} 个文件，{:.1} MB（对端 {}）",
        session.file_count,
        session.total_bytes as f64 / 1048576.0,
        session.peer
    );

    let answer = hwshare::confirm::ask(
        &session.peer,
        session.file_count,
        session.total_bytes,
        channel.try_clone_stream().ok(),
    );
    session.accepted = answer.accepted;
    hwshare::receive::record_drained(channel, &session, answer.drained);

    match hwshare::receive::run_session(
        &session,
        channel,
        dest,
        name,
        Duration::from_secs(600),
    ) {
        Ok(_result) if !session.accepted => {
            println!("[拒绝] 已拒绝本次分享，未接收任何文件");
            ExitCode::SUCCESS
        }
        Ok(result) => {
            println!(
                "[完成] 收到 {} 个文件，{:.1} MB",
                result.saved.len(),
                result.bytes as f64 / 1048576.0
            );
            for path in &result.saved {
                println!("  {}", path.display());
            }
            let _ = std::io::stdout().flush();
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("[中断] {e}");
            ExitCode::from(1)
        }
    }
}
