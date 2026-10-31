use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/hwshare.rc");
    println!("cargo:rerun-if-changed=assets/hwshare.ico");

    let rc = Path::new("assets/hwshare.rc");
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    if !rc.exists() || out_dir.is_empty() {
        return;
    }

    let obj = Path::new(&out_dir).join("hwshare.res.o");
    let result = Command::new("windres")
        .args(["--codepage=65001", "-i"])
        .arg(rc)
        .arg("-o")
        .arg(&obj)
        .arg("--output-format=coff")
        .status();

    match result {
        Ok(status) if status.success() => {
            println!("cargo:rustc-link-arg-bins={}", obj.display());
        }
        Ok(status) => println!(
            "cargo:warning=windres 退出码 {status}，本次构建的 exe 不带图标/版本资源"
        ),
        Err(e) => println!(
            "cargo:warning=找不到 windres（{e}），本次构建的 exe 不带图标/版本资源"
        ),
    }
}
