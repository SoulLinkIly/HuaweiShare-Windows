use std::path::{Path, PathBuf};
use std::sync::Mutex;

static DEST: Mutex<Option<PathBuf>> = Mutex::new(None);

const CHUNK_MIN: usize = 512;
const CHUNK_MAX: usize = 65535;

pub fn default_dest() -> PathBuf {
    let base = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
    PathBuf::from(base).join("Downloads").join("HWShare")
}

fn config_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(PathBuf::from(base).join("HWShareWin").join("config.json"))
}

fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

fn parse_dest(text: &str) -> Option<PathBuf> {
    let value: serde_json::Value = serde_json::from_str(strip_bom(text)).ok()?;
    let dest = value.get("dest")?.as_str()?.trim().to_string();
    if dest.is_empty() {
        None
    } else {
        Some(PathBuf::from(dest))
    }
}

fn load_from_disk() -> Option<PathBuf> {
    parse_dest(&std::fs::read_to_string(config_path()?).ok()?)
}

pub fn current() -> PathBuf {
    if let Ok(slot) = DEST.lock() {
        if let Some(path) = slot.as_ref() {
            return path.clone();
        }
    }
    let loaded = load_from_disk().unwrap_or_else(default_dest);
    if let Ok(mut slot) = DEST.lock() {
        *slot = Some(loaded.clone());
    }
    loaded
}

fn parse_chunk(text: &str) -> Option<usize> {
    let value: serde_json::Value = serde_json::from_str(strip_bom(text)).ok()?;
    let n = value.get("chunk")?.as_u64()? as usize;
    (CHUNK_MIN..=CHUNK_MAX).contains(&n).then_some(n)
}

pub fn chunk() -> Option<usize> {
    parse_chunk(&std::fs::read_to_string(config_path()?).ok()?)
}

fn write_config(dest: &str) -> std::io::Result<()> {
    let Some(cfg) = config_path() else {
        return Ok(());
    };
    if let Some(dir) = cfg.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut object = std::fs::read_to_string(&cfg)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(strip_bom(&text)).ok())
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    object.insert("dest".to_string(), serde_json::Value::String(dest.to_string()));

    let text = serde_json::Value::Object(object).to_string();
    let tmp = cfg.with_extension("json.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, &cfg).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

pub fn set_dest(path: &Path) -> std::io::Result<()> {
    if let Ok(mut slot) = DEST.lock() {
        *slot = Some(path.to_path_buf());
    }
    write_config(&path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dest_ends_with_hwshare() {
        let path = default_dest();
        assert!(path.ends_with("HWShare"), "{}", path.display());
    }

    #[test]
    fn parses_config_with_utf8_bom() {
        let text = "\u{feff}{\"dest\":\"F:\\\\Huawei Share\",\"chunk\":65499}";
        assert_eq!(parse_chunk(text), Some(65499));
        assert_eq!(parse_dest(text), Some(PathBuf::from("F:\\Huawei Share")));
    }

    #[test]
    fn parse_chunk_respects_range() {
        assert_eq!(parse_chunk(r#"{"chunk":32768}"#), Some(32768));
        assert_eq!(parse_chunk(r#"{"dest":"D:\\x","chunk":1422}"#), Some(1422));

        assert_eq!(parse_chunk(r#"{"chunk":511}"#), None);
        assert_eq!(parse_chunk(r#"{"chunk":65536}"#), None);
        assert_eq!(parse_chunk(r#"{"chunk":"32768"}"#), None);
        assert_eq!(parse_chunk(r#"{"dest":"D:\\x"}"#), None);
    }

    #[test]
    fn parse_dest_reads_json() {
        assert_eq!(
            parse_dest(r#"{"dest":"D:\\照片\\华为分享"}"#),
            Some(PathBuf::from(r"D:\照片\华为分享"))
        );
        assert_eq!(parse_dest(r#"{"dest":""}"#), None);
        assert_eq!(parse_dest("not json"), None);
    }
}
