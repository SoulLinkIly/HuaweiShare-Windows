//! 收尾清理：空文件补建、未完成文件删除、浮窗守卫。
//!
//! 这些事的共同点是「成功失败都得做」，所以用 `Drop` 兜住，
//! 而不是在每个 `return Err` 前面手写一遍。

use super::*;

/// 把清单里声明为 0 字节的文件逐个「建出来」。
///
/// 协议里 0 字节文件不走数据通道，只能在收尾时按名字创建。
/// 单个失败只记 trace、不打断整批——一个空文件失败不该让其余文件作废。
pub(super) fn materialize_empty_files(
    destination: &Path,
    pending: &mut Vec<(u16, String)>,
    done_ids: &mut Vec<u16>,
    saved: &mut Vec<PathBuf>,
    done: &mut usize,
    clip_info: &mut Option<ClipInfo>,
) {
    for (empty_id, name) in pending.drain(..) {
        if name.trim().is_empty() {
            continue;
        }
        // 0 字节的剪贴板文本：不建文件，也不去覆盖用户的剪贴板（空内容没有
        // 价值），但这条必须计入完成数——否则会话会一直等这个「没收完」的条目。
        if clip::is_target(&name) {
            *clip_info = Some(clip::deliver(&[], false, 0));
            if !done_ids.contains(&empty_id) {
                done_ids.push(empty_id);
            }
            *done += 1;
            continue;
        }
        match create_part_atomic(destination, &name) {
            Ok((target, part, raw)) => {
                drop(raw);
                if let Err(e) = std::fs::rename(&part, &target) {
                    crate::trace::note("file#1", &format!("空文件改名失败 {name}: {e}"));
                    continue;
                }
                crate::trace::note("file#1", &format!("空文件已创建 {}", target.display()));
                if !done_ids.contains(&empty_id) {
                    done_ids.push(empty_id);
                }
                saved.push(target);
                *done += 1;
            }
            Err(e) => crate::trace::note("file#1", &format!("空文件创建失败 {name}: {e}")),
        }
    }
}

pub(super) struct PartGuard {
    path: Option<PathBuf>,
    keep: bool,
}

impl PartGuard {
    pub(super) fn new() -> Self {
        Self { path: None, keep: false }
    }
    pub(super) fn track(&mut self, p: PathBuf) {
        self.path = Some(p);
    }
    pub(super) fn clear(&mut self) {
        self.path = None;
    }
    pub(super) fn commit(&mut self) {
        self.keep = true;
    }
}

impl Drop for PartGuard {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        if let Some(p) = self.path.take() {
            match std::fs::remove_file(&p) {
                Ok(()) => crate::trace::note("file#1", &format!("已删除未完成文件 {}", p.display())),
                Err(e) => crate::trace::note(
                    "file#1",
                    &format!("删除未完成文件失败 {}：{e}", p.display()),
                ),
            }
        }
    }
}

pub(super) struct OverlayGuard {
    pub(super) done: bool,
}
impl Drop for OverlayGuard {
    fn drop(&mut self) {
        if self.done {
            return;
        }

        ov::abort();
    }
}
