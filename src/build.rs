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

    let jobs: [(&str, &str, &str); 2] = [
        ("hwshare", "assets/hwshare.rc", "hwshare.res.o"),
        ("hwshare-cli", "assets/hwshare-cli.rc", "hwshare-cli.res.o"),
    ];

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
