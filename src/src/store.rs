//! 数据目录（`%LOCALAPPDATA%\HWShareWin`）：home() 与 path()。

use std::path::PathBuf;
use std::sync::OnceLock;

const APP_DIR: &str = "HWShareWin";

fn local_appdata() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|b| PathBuf::from(b).join(APP_DIR))
}

fn exe_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    exe.parent().map(|p| p.to_path_buf())
}

pub fn home() -> PathBuf {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = local_appdata()
            .or_else(exe_dir)
            .unwrap_or_else(|| PathBuf::from("."));
        let _ = std::fs::create_dir_all(&dir);
        dir
    })
    .clone()
}

pub fn path(name: &str) -> PathBuf {
    home().join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_is_absolute_and_reused() {
        let a = home();
        let b = home();
        assert_eq!(a, b, "同一次运行必须固定");
        assert!(a.is_absolute(), "{}", a.display());
        assert!(a.exists(), "{}", a.display());
    }

    #[test]
    fn path_joins_under_home() {
        assert_eq!(path("a.log"), home().join("a.log"));
    }

    #[test]
    fn home_prefers_local_appdata() {
        let Some(expected) = local_appdata() else {
            return;
        };
        assert_eq!(home(), expected);
    }
}
