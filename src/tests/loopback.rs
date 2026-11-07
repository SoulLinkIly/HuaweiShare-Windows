use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use hwshare::channel::Listener;
use hwshare::outbound;
use hwshare::receive;
use hwshare::trace;
use hwshare::transmit;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cleanup(path: &Path) -> Cleanup {
    Cleanup(path.to_path_buf())
}

fn temp(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("hwshare-loop-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn spawn_receiver(
    dest: PathBuf,
) -> (u16, thread::JoinHandle<std::result::Result<receive::ReceiveResult, String>>) {
    let listener = Listener::bind("127.0.0.1", 0).expect("bind");
    let port = listener.port;
    let handle = thread::spawn(move || -> std::result::Result<_, String> {
        let mut channel = listener
            .accept(Duration::from_secs(15))
            .map_err(|e| format!("accept: {e}"))?;
        let private = transmit::load_or_create_identity(None).map_err(|e| format!("身份: {e}"))?;
        let mut session = receive::accept_connection(
            &mut channel,
            &private,
            true,
            Duration::from_secs(30),
        )
        .map_err(|e| format!("握手: {e}"))?;
        session.accepted = true;
        receive::run_session(
            &session,
            &mut channel,
            &dest,
            "loopback",
            Duration::from_secs(90),
        )
        .map_err(|e| format!("接收: {e}"))
    });
    (port, handle)
}

fn write(path: &Path, len: usize, seed: u8) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    let data: Vec<u8> = (0..len).map(|i| seed.wrapping_add((i % 251) as u8)).collect();
    std::fs::write(path, data).unwrap();
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_dir() {
            collect_files(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn frames_of(path: &Path) -> Vec<(String, String, String, u64)> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.contains("\"ev\":\"frame\"") && !line.contains("\"ev\": \"frame\"") {
            continue;
        }
        let field = |name: &str| -> String {
            let key = format!("\"{name}\":");
            let Some(i) = line.find(&key) else { return String::new() };
            let rest = &line[i + key.len()..];
            let rest = rest.trim_start();
            if let Some(stripped) = rest.strip_prefix('"') {
                let end = stripped.find('"').unwrap_or(0);
                stripped[..end].to_string()
            } else {
                let end = rest.find([',', '}']).unwrap_or(rest.len());
                rest[..end].trim().to_string()
            }
        };
        let len: u64 = field("len").parse().unwrap_or(0);
        out.push((field("dir"), field("ch"), field("kind_name"), len));
    }
    out
}

#[test]
fn three_files_roundtrip_keeps_bytes() {
    let _guard = serial();

    let src = temp("src");
    let dest = temp("dst");
    let _clean = (cleanup(&src), cleanup(&dest));

    write(&src.join("empty.txt"), 0, 1);
    write(&src.join("small.txt"), 1024, 7);
    write(&src.join("nested/big.bin"), 300 * 1024, 33);

    let inputs = vec![
        src.join("empty.txt"),
        src.join("small.txt"),
        src.join("nested/big.bin"),
    ];

    let (port, receiver) = spawn_receiver(dest.clone());

    let result = outbound::transmit(
        "127.0.0.1",
        port,
        &inputs,
        "loopback",
        &|line| eprintln!("[send] {line}"),
    );
    let report = result.unwrap_or_else(|e| panic!("发送失败: {e}"));

    let received = receiver.join().expect("接收线程 panic").expect("接收失败");

    println!("发送 {} 个文件 / {} 字节", report.files.len(), report.bytes);
    println!("接收 {} 个文件 / {} 字节", received.saved.len(), received.bytes);

    for path in &inputs {
        let name = path.file_name().unwrap();
        let got = dest.join(name);
        let want = std::fs::read(path).unwrap();
        let have = std::fs::read(&got).unwrap_or_else(|e| panic!("{}: {e}", got.display()));
        assert_eq!(want, have, "{} 内容不一致", name.to_string_lossy());
    }

    let mut all = Vec::new();
    collect_files(&dest, &mut all);
    assert_eq!(all.len(), 3, "接收目录文件数不对: {all:?}");
}

#[test]
fn frame_order_and_done_ack() {
    let _guard = serial();

    let src = temp("src2");
    let dest = temp("dst2");
    let _clean = (cleanup(&src), cleanup(&dest));
    write(&src.join("a.bin"), 200 * 1024, 11);
    let inputs = vec![src.join("a.bin")];

    let capture = temp("cap").join("loop.jsonl");
    let _clean_cap = cleanup(capture.parent().unwrap());
    trace::start(trace::Config {
        path: capture.clone(),
        peer: None,
        local: None,
        scope: trace::Scope::Frames,
        session_id: "loopback".to_string(),
        source: "test".to_string(),
        max_bytes: 64 * 1024 * 1024,
    })
    .expect("trace start");

    let (port, receiver) = spawn_receiver(dest.clone());
    let result = outbound::transmit("127.0.0.1", port, &inputs, "loopback", &|_| {});
    let received = receiver.join().expect("接收线程 panic");
    trace::finish("test");

    result.unwrap_or_else(|e| panic!("发送失败: {e}"));
    received.expect("接收失败");

    let frames = frames_of(&capture);
    let mut seq: Vec<String> = Vec::new();
    for (dir, _ch, kind, len) in &frames {
        if kind.is_empty() {
            continue;
        }
        seq.push(format!("{dir}:{kind}({len})"));
    }
    println!("帧序列（{} 条）:", seq.len());
    for s in &seq {
        println!("  {s}");
    }

    let kinds: Vec<&str> = frames
        .iter()
        .filter(|(_, _, k, _)| !k.is_empty())
        .map(|(_, _, k, _)| k.as_str())
        .collect();

    let pos = |kind: &str| -> Vec<usize> {
        kinds
            .iter()
            .enumerate()
            .filter(|(_, k)| **k == kind)
            .map(|(i, _)| i)
            .collect()
    };

    let settings = pos("SETTINGS");
    let list = pos("LIST");
    let data = pos("DATA");
    let done = pos("DONE");
    let done_ack = pos("DONE_ACK");

    assert_eq!(settings.len(), 4, "SETTINGS 应双方各两帧: {kinds:?}");
    assert!(!list.is_empty(), "没有 LIST: {kinds:?}");
    assert!(!data.is_empty(), "没有 DATA: {kinds:?}");
    assert!(!done.is_empty(), "没有 DONE: {kinds:?}");
    assert!(!done_ack.is_empty(), "没有 DONE_ACK: {kinds:?}");

    assert!(
        settings[0] < list[0] && list[0] < data[0],
        "帧序应为 SETTINGS → LIST → DATA: {kinds:?}"
    );
    assert!(
        *data.last().unwrap() < done[0],
        "DONE 必须在最后一个 DATA 之后: {kinds:?}"
    );
    assert!(
        done[0] < done_ack[0],
        "DONE_ACK 必须在 DONE 之后: {kinds:?}"
    );

    const DFS: u64 = 65535;
    for (dir, _, kind, len) in &frames {
        if kind != "DATA" {
            continue;
        }
        assert!(
            len + 8 <= DFS,
            "{dir} 的 DATA 帧 {len}+8 超过声明的 dfs {DFS}"
        );
    }

    let big = frames
        .iter()
        .filter(|(_, _, k, _)| k == "DATA")
        .map(|(_, _, _, l)| *l)
        .max()
        .unwrap();
    assert_eq!(big + 8, DFS, "满帧应正好等于 dfs");
}

#[test]
fn folder_keeps_layout() {
    let _guard = serial();

    let src = temp("src3");
    let dest = temp("dst3");
    let _clean = (cleanup(&src), cleanup(&dest));

    write(&src.join("tree/a.txt"), 128, 3);
    write(&src.join("tree/sub/b.bin"), 5 * 1024, 9);
    write(&src.join("tree/sub/deep/c.bin"), 64 * 1024, 21);

    let inputs = vec![src.join("tree")];
    let (port, receiver) = spawn_receiver(dest.clone());

    let report = outbound::transmit("127.0.0.1", port, &inputs, "loopback", &|_| {})
        .unwrap_or_else(|e| panic!("发送失败: {e}"));
    let received = receiver.join().expect("接收线程 panic").expect("接收失败");

    println!("发送 {} 个文件 / {} 字节", report.files.len(), report.bytes);
    println!("接收 {} 个文件 / {} 字节", received.saved.len(), received.bytes);

    let root = dest.join("tree");
    let base = if root.exists() { root } else { dest.clone() };

    for rel in ["a.txt", "sub/b.bin", "sub/deep/c.bin"] {
        let want = std::fs::read(src.join("tree").join(rel)).unwrap();
        let got_path = base.join(rel);
        let have = std::fs::read(&got_path)
            .unwrap_or_else(|e| panic!("{}（根 {}）: {e}", got_path.display(), base.display()));
        assert_eq!(want, have, "{rel} 内容不一致");
    }
}

fn recv_root(dest: &Path, top: &str) -> PathBuf {
    let root = dest.join(top);
    if root.exists() {
        root
    } else {
        dest.to_path_buf()
    }
}

#[test]
fn folder_with_empty_dirs_and_zero_byte_files() {
    let _guard = serial();

    let src = temp("src4");
    let dest = temp("dst4");
    let _clean = (cleanup(&src), cleanup(&dest));

    write(&src.join("tree/keep.bin"), 8 * 1024, 5);
    write(&src.join("tree/zero.txt"), 0, 0);
    write(&src.join("tree/sub/keep2.txt"), 300, 7);
    write(&src.join("tree/sub/zero2.bin"), 0, 0);
    std::fs::create_dir_all(src.join("tree/hollow")).unwrap();
    std::fs::create_dir_all(src.join("tree/sub/hollow2")).unwrap();

    let (port, receiver) = spawn_receiver(dest.clone());
    let report = outbound::transmit("127.0.0.1", port, &[src.join("tree")], "loopback", &|_| {})
        .unwrap_or_else(|e| panic!("发送失败: {e}"));
    let received = receiver.join().expect("接收线程 panic").expect("接收失败");

    println!("发送 {} 个文件 / {} 字节", report.files.len(), report.bytes);
    println!("接收 {} 个文件 / {} 字节", received.saved.len(), received.bytes);

    let base = recv_root(&dest, "tree");
    for rel in ["keep.bin", "zero.txt", "sub/keep2.txt", "sub/zero2.bin"] {
        let got = base.join(rel);
        assert!(got.is_file(), "缺文件 {}（根 {}）", got.display(), base.display());
        let want = std::fs::read(src.join("tree").join(rel)).unwrap();
        let have = std::fs::read(&got).unwrap();
        assert_eq!(want, have, "{rel} 内容不一致");
    }
    for dir in ["hollow", "sub/hollow2"] {
        assert!(
            !base.join(dir).exists(),
            "空目录 {dir} 不该被传过去（协议清单只有文件，sender 只报数不发送）"
        );
    }
    assert_eq!(received.saved.len(), 4, "接收条目数不对");
}

#[test]
fn folder_with_only_zero_byte_files() {
    let _guard = serial();

    let src = temp("src5");
    let dest = temp("dst5");
    let _clean = (cleanup(&src), cleanup(&dest));

    write(&src.join("empty/zero1.txt"), 0, 0);
    write(&src.join("empty/sub/zero2.txt"), 0, 0);
    std::fs::create_dir_all(src.join("empty/blank")).unwrap();

    let (port, receiver) = spawn_receiver(dest.clone());
    let report = outbound::transmit("127.0.0.1", port, &[src.join("empty")], "loopback", &|_| {})
        .unwrap_or_else(|e| panic!("发送失败: {e}"));
    let received = receiver.join().expect("接收线程 panic").expect("接收失败");

    println!("发送 {} 个文件 / {} 字节", report.files.len(), report.bytes);
    println!("接收 {} 个文件 / {} 字节", received.saved.len(), received.bytes);

    let base = recv_root(&dest, "empty");
    for rel in ["zero1.txt", "sub/zero2.txt"] {
        let got = base.join(rel);
        assert!(got.is_file(), "缺空文件 {}（根 {}）", got.display(), base.display());
        assert_eq!(std::fs::metadata(&got).unwrap().len(), 0, "{rel} 应为 0 字节");
    }
    assert!(
        !base.join("blank").exists(),
        "空目录 blank 不该被传过去（协议清单只有文件）"
    );
    assert_eq!(received.saved.len(), 2, "接收条目数不对");
}

#[test]
fn two_sends_run_concurrently() {
    let _guard = serial();

    let src = temp("src6");
    let d1 = temp("dst6a");
    let d2 = temp("dst6b");
    let _clean = (cleanup(&src), cleanup(&d1), cleanup(&d2));

    write(&src.join("big.bin"), 6 * 1024 * 1024, 13);
    let inputs = vec![src.join("big.bin")];

    let (p1, r1) = spawn_receiver(d1.clone());
    let (p2, r2) = spawn_receiver(d2.clone());

    let a = {
        let inputs = inputs.clone();
        thread::spawn(move || outbound::transmit("127.0.0.1", p1, &inputs, "dev-a", &|_| {}))
    };
    let b = {
        let inputs = inputs.clone();
        thread::spawn(move || outbound::transmit("127.0.0.1", p2, &inputs, "dev-b", &|_| {}))
    };

    let mut peak = 0usize;
    for _ in 0..400 {
        let now = hwshare::progress::active();
        if now > peak {
            peak = now;
        }
        if peak >= 2 {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }

    let ra = a.join().expect("发送线程 a panic");
    let rb = b.join().expect("发送线程 b panic");
    let ha = r1.join().expect("接收线程 a panic");
    let hb = r2.join().expect("接收线程 b panic");

    ra.unwrap_or_else(|e| panic!("第一路发送失败: {e}"));
    rb.unwrap_or_else(|e| panic!("第二路发送失败: {e}"));
    ha.expect("第一路接收失败");
    hb.expect("第二路接收失败");

    println!("并发峰值 {peak}");

    let want = std::fs::read(src.join("big.bin")).unwrap();
    for dest in [&d1, &d2] {
        let got = std::fs::read(dest.join("big.bin"))
            .unwrap_or_else(|e| panic!("{}: {e}", dest.display()));
        assert_eq!(want.len(), got.len(), "{} 长度不一致", dest.display());
        assert!(want == got, "{} 内容不一致", dest.display());
    }

    assert!(peak >= 2, "两路没有同时在跑，并发峰值只有 {peak}");
    assert_eq!(hwshare::progress::active(), 0, "结束后活跃任务应清零");
}
