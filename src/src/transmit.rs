//! 发送侧共用件：身份加载、offer 构建、批次分类与扩展名直方图。
//!
//! 文件收集（展开目录、算总字节）只有一份，在 `outbound::collect`。

use std::path::{Path, PathBuf};

use rsa::RsaPrivateKey;

use crate::crypto;
use crate::{tlv_encode, Error, Result};

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

pub fn is_gallery_batch(names: &[String]) -> bool {
    !names.is_empty() && names.iter().all(|name| is_gallery_file(name))
}

fn share_batch_category(names: &[String], folders: usize) -> String {

    if folders > 0 {
        return "4".to_string();
    }
    if is_gallery_batch(names) { "0".to_string() } else { "3".to_string() }
}

fn file_type_histogram(names: &[String], tablet: bool) -> String {
    let mut map: std::collections::BTreeMap<String, u32> = Default::default();
    for name in names {
        let ext = Path::new(name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        *map.entry(ext).or_insert(0) += 1;
    }

    if !tablet {
        let items: Vec<String> = map
            .into_iter()
            .map(|(ext, count)| format!(r#""{ext}":{count}"#))
            .collect();
        return format!("{{{}}}", items.join(","));
    }

    let items: Vec<String> = map
        .into_iter()
        .map(|(ext, count)| {
            if ext.is_empty() {
                format!(r#""": {count}"#)
            } else {
                format!(r#"".{ext}" : {count}"#)
            }
        })
        .collect();
    format!("{{  {}}}", items.join(", "))
}

pub fn build_offer(
    names: &[String],
    total: u64,
    display_name: &str,
    target_len: Option<usize>,
    tablet: bool,
    folders: usize,
) -> Result<Vec<u8>> {
    if names.is_empty() {
        return Err(Error::Argument);
    }
    let count = names.len();
    let mut fields = Vec::new();
    let send_type = share_batch_category(names, folders);

    let summary = file_type_histogram(names, tablet);
    for (tag, value) in [
        (1u64, send_type.to_string()),
        (2, display_name.to_string()),
        (3, count.to_string()),
        (4, total.to_string()),

        (5, folders.to_string()),
        (6, count.to_string()),
        (7, summary),

        (16, if tablet { "1" } else { "0" }.to_string()),
    ] {
        fields.extend(tlv_encode(tag, value.as_bytes())?);
    }
    let mut payload = tlv_encode(7, &fields)?;

    if let Some(target) = target_len {
        while payload.len() + 2 <= target {
            let need = target - payload.len();
            let n = (need - 2).min(120);
            fields.extend(tlv_encode(0x7E, &vec![0u8; n])?);
            payload = tlv_encode(7, &fields)?;
        }
    }
    Ok(payload)
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
            let mut wrote_tmp = false;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
            {
                use std::io::Write;
                wrote_tmp = f.write_all(pem.as_bytes()).and_then(|_| f.sync_all()).is_ok();
                drop(f);
            }

            let mut saved = false;
            if wrote_tmp {
                match std::fs::rename(&tmp, &target) {
                    Ok(()) => saved = true,
                    Err(_) => {
                        let _ = std::fs::remove_file(&tmp);
                    }
                }
            }

            if !saved && std::fs::write(&target, &pem).is_ok() {
                saved = true;
            }
            if !saved {
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
    crate::store::home().join("Huawei").join("identity.pem")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_is_tlv7() {
        let names = vec!["a.jpg".to_string()];
        let offer = build_offer(&names, 100, "PC", None, false, 0).unwrap();
        let mut off = 0;
        assert_eq!(crate::varint_decode(&offer, &mut off).unwrap(), 7);
    }

    #[test]
    fn offer_len_follows_total_digits() {

        for (total, want) in [(1000u64, 56usize), (10000, 57), (100000, 58)] {
            let names: Vec<String> = vec!["a.jpg".to_string()];
            let offer = build_offer(&names, total, "PC", Some(want), false, 0).unwrap();
            assert_eq!(offer.len(), want, "总字节 {total} 应补到 {want}");
        }

        let names = vec!["a.jpg".to_string()];
        assert!(build_offer(&names, 100, "PC", None, false, 0).unwrap().len() < 111);
    }

    #[test]
    fn send_type_by_batch() {
        let photos = vec!["a.jpg".to_string(), "b.PNG".to_string()];
        assert_eq!(share_batch_category(&photos, 0), "0", "纯图片批次应走图库");

        let video = vec!["clip.mp4".to_string()];
        assert_eq!(share_batch_category(&video, 0), "0", "纯视频批次应走图库");

        let mixed_gallery = vec!["a.heic".to_string(), "b.mov".to_string()];
        assert_eq!(share_batch_category(&mixed_gallery, 0), "0", "图片+视频混批仍属图库");

        let docs = vec!["a.pdf".to_string(), "b.zip".to_string()];
        assert_eq!(share_batch_category(&docs, 0), "3", "文档批次走文件管理");

        let mixed = vec!["a.jpg".to_string(), "b.pdf".to_string()];
        assert_eq!(share_batch_category(&mixed, 0), "3", "图文混批按文件提交");

        let no_ext = vec!["README".to_string()];
        assert_eq!(share_batch_category(&no_ext, 0), "3", "无扩展名按文件提交");
    }

    #[test]
    fn extension_summary_counts() {
        let names = vec!["a.jpg".to_string(), "b.jpg".to_string(), "c.pdf".to_string()];
        let s = file_type_histogram(&names, true);

        assert_eq!(s, r#"{  ".jpg" : 2, ".pdf" : 1}"#);
    }

    #[test]
    fn extension_summary_harmony_is_compact() {
        let names = vec!["a.txt".to_string()];
        assert_eq!(file_type_histogram(&names, false), r#"{"txt":1}"#);
        let two = vec!["a.jpg".to_string(), "b.jpg".to_string(), "c.pdf".to_string()];
        assert_eq!(file_type_histogram(&two, false), r#"{"jpg":2,"pdf":1}"#);
    }

    #[test]
    fn extension_summary_matches_real_device_bytes() {

        let names = vec!["x.png".to_string()];
        assert_eq!(file_type_histogram(&names, true), r#"{  ".png" : 1}"#);
    }
}
