//! 合并对端发来的清单（重传时会分片到达），并回 ack。

use crate::channel::Channel;
use crate::transfer::{self};
use crate::Result;

pub(super) const MAX_MANIFEST: usize = crate::transfer::MAX_MANIFEST_ENTRIES;

pub(super) fn merge_manifest(
    expected: &mut Vec<(u16, u64, String)>,
    empty: &mut Vec<(u16, String)>,
    data: &[u8],
) -> usize {
    if data.len() < 2 {
        return 0;
    }

    let mut seen: std::collections::HashSet<u16> = expected
        .iter()
        .map(|(id, _, _)| *id)
        .chain(empty.iter().map(|(id, _)| *id))
        .collect();
    let mut offset = 2usize;
    let mut added = 0usize;
    while offset + 12 <= data.len() {
        let id = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let size_bytes: [u8; 8] = match data[offset + 2..offset + 10].try_into() {
            Ok(v) => v,
            Err(_) => break,
        };
        let fsize = u64::from_be_bytes(size_bytes);
        let nlen = u16::from_be_bytes([data[offset + 10], data[offset + 11]]) as usize;
        offset += 12;
        if offset + nlen > data.len() {
            break;
        }
        let name = String::from_utf8_lossy(&data[offset..offset + nlen]).to_string();
        offset += nlen;

        if !seen.insert(id) {
            crate::trace::note("file#1", &format!("清单里 id={id} 重复，忽略后一条"));
            continue;
        }
        if fsize == 0 {

            crate::trace::note(
                "file#1",
                &format!("清单里 {name} 是 0 字节，按空文件接受（ACK 后收尾时创建）"),
            );
            empty.push((id, name));
            continue;
        }
        if name.trim().is_empty() {
            crate::trace::note("file#1", &format!("清单里 id={id} 没有文件名，忽略"));
            continue;
        }

        if expected.len() + empty.len() >= MAX_MANIFEST {
            crate::trace::note(
                "file#1",
                &format!("清单超过 {MAX_MANIFEST} 条，其余忽略"),
            );
            break;
        }
        expected.push((id, fsize, name));
        added += 1;
    }
    added
}

pub(super) fn ack_manifest(
    chan: &mut Channel,
    key: &[u8],
    trans: u16,
    expected: &[(u16, u64, String)],
    empty: &[(u16, String)],
) -> Result<()> {
    let mut ids: Vec<u8> = Vec::with_capacity((expected.len() + empty.len()) * 2);
    for (id, _, _) in expected {
        ids.extend_from_slice(&id.to_be_bytes());
    }

    for (id, _) in empty {
        ids.extend_from_slice(&id.to_be_bytes());
    }
    let ack = transfer::assemble_dfile_packet(2, 0, 0, trans, &ids)?;
    chan.transmit(&transfer::dfile_seal_control(key, &ack)?)
}
