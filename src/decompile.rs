// src/decompile.rs — batch decompile loop.
//
// Design (macOS-safe):
//   - All IDA API calls stay on the main thread (libidalib requires main-thread
//     affinity on macOS due to Cocoa/NSApplication).
//   - A single writer thread receives finished results over a channel and does
//     the file I/O (pure, no IDA calls). This keeps the main thread free to
//     drive Hex-Rays instead of blocking on disk.
//   - Memory stays flat: each function's pseudocode string is produced, handed
//     to the channel, and dropped after writing. Nothing accumulates.
//
// For consolidated mode, output is a single streaming `decompiled.c` (append).
// For legacy mode, the writer emits one `.c`/`.asm` per function.

use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use anyhow::Result;
use idalib::IDB;

use crate::config::{ExportMode, DECOMPILE_TIME_LIMIT_SECS, MAX_FUNC_SIZE_FOR_DECOMPILE};
use crate::func_discover::{DiscoveredFunc, FuncKind};
use crate::writers::Writer;

/// One unit of work produced on the main thread, consumed by the writer thread.
pub struct DecResult {
    pub start_ea: u64,
    pub name: String,
    pub body: String,
    pub export_type: ExportType,
    pub fallback_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportType {
    Decompile,
    DisassemblyFallback,
}

impl ExportType {
    pub fn as_str(self) -> &'static str {
        match self {
            ExportType::Decompile => "decompile",
            ExportType::DisassemblyFallback => "disassembly-fallback",
        }
    }
}

/// Aggregate counters returned when the loop finishes.
#[derive(Debug, Default)]
pub struct DecompStats {
    pub exported: usize,
    pub fallback: usize,
    pub skipped: usize,
    pub failed: usize,
}

/// Run the full decompile pass.
///
/// `writer` owns the output files and runs on its own thread; we feed it
/// results via a bounded-ish channel (mpsc is unbounded by default — fine
/// here since the producer is the bottleneck, not the consumer).
pub fn run_decompile_pass(
    idb: &IDB,
    funcs: &[DiscoveredFunc],
    mode: ExportMode,
    writer: Writer,
) -> Result<DecompStats> {
    let (tx, rx) = mpsc::channel::<DecResult>();
    let writer = writer;
    let writer_thread = thread::spawn(move || -> Result<DecompStats> {
        writer.run(rx, mode)
    });

    let mut stats = DecompStats::default();
    let total = funcs.len();
    let start = Instant::now();
    let decompiler_ok = idb.decompiler_available();

    for (i, func) in funcs.iter().enumerate() {
        // Lib/extern functions are skipped outright.
        if func.kind == FuncKind::SkipLib {
            stats.skipped += 1;
            continue;
        }

        let result = decompile_one(idb, func, decompiler_ok);
        match result {
            Some(r) => {
                if r.export_type == ExportType::DisassemblyFallback {
                    stats.fallback += 1;
                } else {
                    stats.exported += 1;
                }
                // send to writer; if the writer thread died, propagate.
                if tx.send(r).is_err() {
                    break;
                }
            }
            None => {
                stats.failed += 1;
            }
        }

        if (i + 1) % 500 == 0 {
            let el = start.elapsed().as_secs_f64();
            let rate = (i + 1) as f64 / el;
            eprintln!(
                "[inp] decompile {}/{} ({:.0}/s, ok={} fb={} skip={} fail={})",
                i + 1,
                total,
                rate,
                stats.exported,
                stats.fallback,
                stats.skipped,
                stats.failed
            );
        }
    }

    // Drop tx so the writer thread sees channel-close and flushes + returns.
    drop(tx);
    let wstats = writer_thread.join().expect("writer thread panicked")?;
    // Writer owns the authoritative exported count (it sees what actually landed on disk).
    stats.exported = wstats.exported;
    stats.fallback = wstats.fallback;
    stats.failed += wstats.failed;
    Ok(stats)
}

/// Decompile (or fall back) a single function on the main thread.
fn decompile_one(idb: &IDB, func: &DiscoveredFunc, decompiler_ok: bool) -> Option<DecResult> {
    let start_ea = func.start_ea;
    let name = func.name.clone();

    // Pre-classified too-large / too-many-insn → go straight to disassembly.
    if !func.needs_disasm_fallback && decompiler_ok {
        if let Some(f) = idb.function_at(start_ea.into()) {
            let t0 = Instant::now();
            match idb.decompile(&f) {
                Ok(cfunc) => {
                    let body = cfunc.pseudocode();
                    let elapsed = t0.elapsed().as_secs();
                    if elapsed > DECOMPILE_TIME_LIMIT_SECS {
                        eprintln!(
                            "[inp] slow decompile: {} @ {:#X} ({}s)",
                            name, start_ea, elapsed
                        );
                    }
                    if body.trim().is_empty() {
                        return disassembly_fallback(idb, func, "empty decompilation result");
                    }
                    return Some(DecResult {
                        start_ea,
                        name,
                        body,
                        export_type: ExportType::Decompile,
                        fallback_reason: None,
                    });
                }
                Err(e) => {
                    let reason = format!("decompilation failure: {}", e);
                    return disassembly_fallback(idb, func, &reason);
                }
            }
        }
        return disassembly_fallback(idb, func, "function_at returned None");
    }
    let reason = if func.needs_disasm_fallback {
        format!(
            "function too large ({} bytes, limit {})",
            func.size(),
            MAX_FUNC_SIZE_FOR_DECOMPILE
        )
    } else {
        "decompiler unavailable".to_string()
    };
    disassembly_fallback(idb, func, &reason)
}

/// Build a minimal disassembly view when Hex-Rays fails / is skipped.
///
/// idalib does not expose `generate_disasm_line` (a known coverage gap — it
/// focuses on the decompiler). So for the fallback we render each instruction
/// as `addr: <bytes>` using `get_bytes` per item, capped at 5000 lines. This is
/// lower-fidelity than the Python version's real mnemonics, but keeps the
/// fallback working and is clearly labelled.
fn disassembly_fallback(idb: &IDB, func: &DiscoveredFunc, reason: &str) -> Option<DecResult> {
    let mut ea = func.start_ea;
    let end = func.end_ea;
    let mut lines = Vec::new();
    while ea < end {
        // Read a small chunk starting at ea; item size is unknown without full
        // disasm rendering, so emit 16 bytes per line as a hex window.
        let chunk_len = std::cmp::min(16, end - ea);
        let bytes = idb.get_bytes(ea.into(), chunk_len as usize);
        let hex: String = bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
        lines.push(format!("{:X}: {}", ea, hex));
        match idb.next_head_with(ea.into(), end.into()) {
            Some(next) if u64::from(next) > ea => ea = u64::from(next),
            _ => {
                // No next head — advance by chunk_len to avoid an infinite loop.
                ea += chunk_len.max(1);
            }
        }
        if lines.len() > 5000 {
            break; // hard cap; rare giant functions
        }
    }
    if lines.is_empty() {
        return None; // genuine failure — no bytes either
    }
    // Note the lower fidelity in the body so downstream consumers are aware.
    lines.insert(0, "// (raw bytes — idalib has no disasm text renderer; decompiler failed)".to_string());
    Some(DecResult {
        start_ea: func.start_ea,
        name: func.name.clone(),
        body: lines.join("\n"),
        export_type: ExportType::DisassemblyFallback,
        fallback_reason: Some(reason.to_string()),
    })
}
