use std::path::{Path, PathBuf};

use rsa::RsaPrivateKey;

use crate::crypto;
use crate::{tlv_encode, Error, Result};

pub fn collect(paths: &[PathBuf]) -> Result<(Vec<(String, u64)>, u64)> {
    if paths.is_empty() {
        return Err(Error::Argument);
    }
    let mut entries = Vec::with_capacity(paths.len());
    let mut total = 0u64;
    for path in paths {
        let meta = std::fs::metadata(path).map_err(|e| Error::Io(format!("{}: {e}", path.display())))?;
        if !meta.is_file() {
            return Err(Error::Argument);
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(Error::Argument)?
            .to_string();
        total += meta.len();
        entries.push((name, meta.len()));
    }
    Ok((entries, total))
}

const GALLERY_EXTENSIONS: &[&str] = &[

    "jpg", "jpeg", "png", "gif", "webp", "bmp", "heic", "heif", "dng", "tif", "tiff", "avif",

    "mp4", "mov", "mkv", "avi", "3gp", "m4v", "webm", "flv", "wmv", "mpg", "mpeg", "ts",
];

fn is_gallery_file(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .map(|e| GALLERY_EXTENSIONS.contains(&e.as_str()))
        .unwrap_or(false)
}

fn offer_category(names: &[String]) -> String {
    if let Ok(value) = std::env::var("HWSHARE_SEND_TYPE") {
        if value.parse::<u8>().is_ok() {
            return value;
        }
    }
    let gallery_batch = !names.is_empty() && names.iter().all(|name| is_gallery_file(name));
    if gallery_batch { "0".to_string() } else { "3".to_string() }
}

fn extension_summary(names: &[String]) -> String {
    let mut map: std::collections::BTreeMap<String, u32> = Default::default();
    for name in names {
        let ext = Path::new(name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        *map.entry(ext).or_insert(0) += 1;
    }
    let items: Vec<String> = map
        .into_iter()
        .map(|(ext, count)| format!(r#""{ext}":{count}"#))
        .collect();
    format!("{{{}}}", items.join(","))
}

pub fn build_offer(names: &[String], total: u64, display_name: &str) -> Result<Vec<u8>> {
    if names.is_empty() {
        return Err(Error::Argument);
    }
    let count = names.len();
    let mut fields = Vec::new();
    let send_type = offer_category(names);
    let summary = extension_summary(names);
    for (tag, value) in [
        (1u64, send_type.to_string()),
        (2, display_name.to_string()),
        (3, count.to_string()),
        (4, total.to_string()),
        (5, "0".to_string()),
        (6, count.to_string()),
        (7, summary),
        (16, "0".to_string()),
    ] {
        fields.extend(tlv_encode(tag, value.as_bytes())?);
    }
    tlv_encode(7, &fields)
}

pub fn load_or_create_identity(path: Option<&Path>) -> Result<RsaPrivateKey> {
    let target = match path {
        Some(p) => p.to_path_buf(),
        None => default_identity_path(),
    };
    if let Ok(text) = std::fs::read_to_string(&target) {
        match crypto::from_pem(&text) {
            Ok(key) => return Ok(key),
            Err(e) => {
                let bad = target.with_extension("pem.bad");
                let _ = std::fs::rename(&target, &bad);
                eprintln!(
                    "[警告] 身份密钥解析失败（{e}），已备份为 {} 并重新生成",
                    bad.display()
                );
            }
        }
    }
    let key = crypto::generate().map_err(Error::Crypto)?;
    if let Some(parent) = target.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match crypto::to_pem(&key) {
        Ok(pem) => {
            let tmp = target.with_extension("pem.tmp");
            if std::fs::write(&tmp, &pem)
                .and_then(|_| std::fs::rename(&tmp, &target))
                .is_err()
            {
                let _ = std::fs::remove_file(&tmp);
                eprintln!(
                    "[警告] 身份密钥无法写入 {}，本次运行有效、下次会重新生成",
                    target.display()
                );
            }
        }
        Err(e) => eprintln!("[警告] 身份密钥编码失败：{e}"),
    }
    Ok(key)
}

pub fn default_identity_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
    PathBuf::from(base).join("HWShareWin").join("Huawei").join("identity.pem")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_is_tlv7() {
        let names = vec!["a.jpg".to_string()];
        let offer = build_offer(&names, 100, "PC").unwrap();
        let mut off = 0;
        assert_eq!(crate::varint_decode(&offer, &mut off).unwrap(), 7);
    }

    #[test]
    fn send_type_by_batch() {
        std::env::remove_var("HWSHARE_SEND_TYPE");

        let photos = vec!["a.jpg".to_string(), "b.PNG".to_string()];
        assert_eq!(offer_category(&photos), "0", "纯图片批次应走图库");

        let video = vec!["clip.mp4".to_string()];
        assert_eq!(offer_category(&video), "0", "纯视频批次应走图库");

        let mixed_gallery = vec!["a.heic".to_string(), "b.mov".to_string()];
        assert_eq!(offer_category(&mixed_gallery), "0", "图片+视频混批仍属图库");

        let docs = vec!["a.pdf".to_string(), "b.zip".to_string()];
        assert_eq!(offer_category(&docs), "3", "文档批次走文件管理");

        let mixed = vec!["a.jpg".to_string(), "b.pdf".to_string()];
        assert_eq!(offer_category(&mixed), "3", "图文混批按文件提交");

        let no_ext = vec!["README".to_string()];
        assert_eq!(offer_category(&no_ext), "3", "无扩展名按文件提交");

        std::env::set_var("HWSHARE_SEND_TYPE", "0");
        assert_eq!(offer_category(&docs), "0", "环境变量应能强制图库");
        std::env::set_var("HWSHARE_SEND_TYPE", "1");
        assert_eq!(offer_category(&photos), "1", "环境变量应能复现黑图库");
        std::env::set_var("HWSHARE_SEND_TYPE", "abc");
        assert_eq!(offer_category(&photos), "0", "非法值应退回按批次判断");
        std::env::remove_var("HWSHARE_SEND_TYPE");
    }

    #[test]
    fn extension_summary_counts() {
        let names = vec!["a.jpg".to_string(), "b.jpg".to_string(), "c.pdf".to_string()];
        let s = extension_summary(&names);
        assert!(s.contains(r#""jpg":2"#));
        assert!(s.contains(r#""pdf":1"#));
    }
}
