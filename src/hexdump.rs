// src/hexdump.rs — memory segment hexdump export (legacy mode only).
//
// Consolidated mode skips this entirely (raw hex is low-value for AI analysis
// and the #1 token sink). Here for completeness / legacy parity. Streams to
// 1MB-sharded files; O(1) memory.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::Result;
use idalib::IDB;

const CHUNK: usize = 1024 * 1024; // 1MB
const BYTES_PER_LINE: usize = 16;

/// Export all segments as hexdump. Returns total bytes written.
pub fn export_memory(idb: &IDB, out_dir: &Path) -> Result<usize> {
    let mem_dir = out_dir.join("memory");
    std::fs::create_dir_all(&mem_dir)?;
    let mut total = 0usize;

    for (_id, seg) in idb.segments() {
        let seg_name = seg.name().unwrap_or_else(|| "?".to_string());
        let start = u64::from(seg.start_address());
        let end = u64::from(seg.end_address());
        let mut addr = start;
        while addr < end {
            let chunk_end = std::cmp::min(addr + CHUNK as u64, end);
            let fname = format!("{:08X}--{:08X}.txt", addr, chunk_end);
            let path = mem_dir.join(&fname);
            let size = write_chunk(idb, &path, addr, chunk_end, &seg_name)?;
            total += size;
            addr = chunk_end;
        }
    }
    eprintln!("[inp] memory: {} bytes hexdumped", total);
    Ok(total)
}

fn write_chunk(idb: &IDB, path: &Path, start: u64, end: u64, seg_name: &str) -> Result<usize> {
    let mut w = BufWriter::new(File::create(path)?);
    writeln!(w, "# Memory dump: {:#X} - {:#X}", start, end)?;
    writeln!(w, "# Segment: {}", seg_name)?;
    writeln!(w, "#{}", "=".repeat(76))?;

    let mut total = 0usize;
    let mut addr = start;
    while addr < end {
        let line_len = std::cmp::min(BYTES_PER_LINE as u64, end - addr) as usize;
        let bytes = idb.get_bytes(addr.into(), line_len);
        if bytes.is_empty() {
            addr += BYTES_PER_LINE as u64;
            continue;
        }
        let hex = bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = bytes
            .iter()
            .map(|&b| if (0x20..=0x7E).contains(&b) { b as char } else { '.' })
            .collect();
        writeln!(w, "{:016X} | {:48} | {}", addr, hex, ascii)?;
        total += line_len;
        addr += BYTES_PER_LINE as u64;
    }
    w.flush()?;
    Ok(total)
}
