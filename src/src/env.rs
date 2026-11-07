//! 环境变量读取（带缓存），用于调试开关与参数覆盖。

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};

fn cache() -> &'static Mutex<HashMap<&'static str, Option<String>>> {
    static CACHE: OnceLock<Mutex<HashMap<&'static str, Option<String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn text(name: &'static str) -> Option<String> {
    let mut guard = match cache().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard
        .entry(name)
        .or_insert_with(|| std::env::var(name).ok())
        .clone()
}

fn with_cached<R>(name: &'static str, f: impl FnOnce(Option<&str>) -> R) -> R {
    let mut guard = match cache().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let cached = guard.entry(name).or_insert_with(|| std::env::var(name).ok());
    f(cached.as_deref())
}

pub fn present(name: &'static str) -> bool {
    with_cached(name, |value| value.is_some())
}

pub fn flag(name: &'static str) -> bool {
    with_cached(name, |value| {
        value
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    })
}

pub fn unless_zero(name: &'static str) -> bool {
    with_cached(name, |value| value.map(|value| value.trim() != "0").unwrap_or(true))
}

pub fn num<T: FromStr>(name: &'static str, default: T) -> T {
    with_cached(name, |value| {
        value
            .and_then(|value| value.trim().parse::<T>().ok())
            .unwrap_or(default)
    })
}
