// src/func_discover.rs — enumerate functions to export + classify each one.
//
// Two sources combine so the Rust port behaves like the Python one even when
// the IDB was opened with auto-analysis disabled (the big-binary path):
//   1. `idb.functions()` — the canonical function table IDA already knows about.
//   2. `idb.entries()`   — entry/export points (covers freshly-opened, un-analysed IDBs).
// We dedupe by start address. Each discovered function is classified:
//   - Lib        → skip (matches Python FUNC_LIB behaviour)
//   - Too large  → disassembly fallback candidate
//   - Otherwise  → decompile candidate
//
// NOTE: idalib's `functions()` iterator already reflects whatever analysis ran,
// so for a normally-analysed IDB this just returns the full table. For a skip-
// analysis open, callers must trigger analysis per-range before decompiling
// (see decompile.rs); this module only enumerates *what* to export.

use idalib::IDB;

use crate::config::{MAX_FUNC_INSN_COUNT, MAX_FUNC_SIZE_FOR_DECOMPILE};

/// Classification of a single discovered function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuncKind {
    /// Normal function — try Hex-Rays decompile.
    Decompile,
    /// Library function — skip entirely.
    SkipLib,
}

/// A function discovered for export.
#[derive(Debug, Clone)]
pub struct DiscoveredFunc {
    pub start_ea: u64,
    pub end_ea: u64,
    pub name: String,
    pub kind: FuncKind,
    /// True if the function exceeds the decompile size/instruction guards.
    pub needs_disasm_fallback: bool,
}

impl DiscoveredFunc {
    pub fn size(&self) -> u64 {
        self.end_ea.saturating_sub(self.start_ea)
    }
}

/// Walk the IDB's function table and return all exportable functions, sorted by address.
///
/// `insn_count_hint` caps the per-function instruction scan so a single giant
/// function can't make discovery O(huge) — matches the Python `MAX_FUNC_INSN_COUNT` guard.
pub fn discover_all(idb: &IDB) -> Vec<DiscoveredFunc> {
    let mut out: Vec<DiscoveredFunc> = Vec::new();
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();

    for (_id, func) in idb.functions() {
        let start = u64::from(func.start_address());
        if !seen.insert(start) {
            continue;
        }
        let end = u64::from(func.end_address());
        let name = func
            .name()
            .unwrap_or_else(|| format!("sub_{:X}", start));
        let flags = func.flags();

        // Skip library functions (FUNC_LIB) — matches the Python `func.flags & FUNC_LIB`.
        //
        // NOTE: we deliberately do NOT skip FUNC_THUNK. Real-world thunks often
        // carry meaningful pseudocode (Go syscall wrappers like Syscall/Syscall6,
        // AES _expand_key_256a, etc.). The Python version only skips FUNC_LIB, and
        // skipping thunks too dropped 4 valid functions in the okrd_server test.
        let is_lib = flags.contains(idalib::func::FunctionFlags::LIB);
        let kind = if is_lib {
            FuncKind::SkipLib
        } else {
            FuncKind::Decompile
        };

        let size = end.saturating_sub(start);
        let too_big = size > MAX_FUNC_SIZE_FOR_DECOMPILE;
        // Instruction-count guard only matters for decompile candidates.
        let needs_disasm_fallback = too_big
            || (kind == FuncKind::Decompile && insn_count_exceeds(idb, start, end));

        out.push(DiscoveredFunc {
            start_ea: start,
            end_ea: end,
            name,
            kind,
            needs_disasm_fallback,
        });
    }

    out.sort_by_key(|f| f.start_ea);
    out
}

/// Count instructions up to `MAX_FUNC_INSN_COUNT + 1` via `next_head`.
/// Stops early so a pathological function can't dominate discovery time.
fn insn_count_exceeds(idb: &IDB, start: u64, end: u64) -> bool {
    let mut ea = start;
    let mut count = 0usize;
    while ea < end {
        count += 1;
        if count > MAX_FUNC_INSN_COUNT {
            return true;
        }
        match idb.next_head_with(ea.into(), end.into()) {
            Some(next) if u64::from(next) > ea => ea = u64::from(next),
            _ => break,
        }
    }
    count > MAX_FUNC_INSN_COUNT
}

/// How many discovered functions are decompile candidates (not lib/extern).
pub fn count_decompile_candidates(funcs: &[DiscoveredFunc]) -> usize {
    funcs.iter().filter(|f| f.kind == FuncKind::Decompile).count()
}
