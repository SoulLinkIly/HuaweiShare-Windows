//! 构建脚本：把图标与版本信息分别编进两个 exe（hwshare / hwshare-cli）。
//!
//! Rust 的 windows-gnu 目标不会自动带 `.rsrc`，所以 exe 在资源管理器里是白板图标、
//! 右键属性也没有版本号。这里用 windres 把 `assets/hwshare.rc` 编成 COFF 资源对象，
//! 再通过 `rustc-link-arg-bins` 塞进链接。
//!
//! windres 来自 w64devkit（或任意 mingw-w64 发行版）。找不到就跳过并在构建日志里
//! 提醒，不让整个构建失败。

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/hwshare.rc");
    println!("cargo:rerun-if-changed=assets/hwshare-cli.rc");
    println!("cargo:rerun-if-changed=assets/hwshare.ico");
    println!("cargo:rerun-if-env-changed=HWSHARE_WINDRES");

    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    if out_dir.is_empty() {
        return;
    }

    // 两个 exe 各带一份资源：版本信息里的 OriginalFilename / FileDescription
    // 要跟自己的文件名对得上，不能再拿一份 .res.o 喂给所有 bin。
    let jobs: [(&str, &str, &str); 2] = [
        ("hwshare", "assets/hwshare.rc", "hwshare.res.o"),
        ("hwshare-cli", "assets/hwshare-cli.rc", "hwshare-cli.res.o"),
    ];

    // build.ps1 找到 windres 后会把它写进 HWSHARE_WINDRES；没设就退回 PATH 查找。
    let windres = std::env::var("HWSHARE_WINDRES")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "windres".to_string());

    for (bin, rc, obj_name) in jobs {
        let rc_path = Path::new(rc);
        if !rc_path.exists() {
            println!("cargo:warning=缺少 {rc}，{bin}.exe 不带图标/版本资源");
            continue;
        }
        let obj = Path::new(&out_dir).join(obj_name);
        let result = Command::new(&windres)
            .args(["--codepage=65001", "-i"])
            .arg(rc_path)
            .arg("-o")
            .arg(&obj)
            .arg("--output-format=coff")
            .status();

        match result {
            Ok(status) if status.success() => {
                println!("cargo:rustc-link-arg-bin={bin}={}", obj.display());
            }
            Ok(status) => println!(
                "cargo:warning=windres 处理 {rc} 退出码 {status}，{bin}.exe 不带图标/版本资源"
            ),
            Err(e) => println!(
                "cargo:warning=找不到 windres（{e}），{bin}.exe 不带图标/版本资源"
            ),
        }
    }
}
