// src/config.rs — configuration constants, ExportMode enum, and CLI options.
//
// Mirrors the Python INP.py thresholds (LARGE_BINARY_FUNC_THRESHOLD etc.) so the
// Rust port stays behaviour-compatible. All knobs live here so they're easy to tune.

use std::path::PathBuf;

use clap::Parser;

/// Export mode: how to lay out decompiled output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportMode {
    /// Auto-pick based on function count.
    Auto,
    /// One .c per function + function_index.txt (small files).
    Legacy,
    /// Single decompiled.c + function_list.txt + callgraph.txt (large files).
    Consolidated,
}

impl ExportMode {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "legacy" => ExportMode::Legacy,
            "consolidated" => ExportMode::Consolidated,
            _ => ExportMode::Auto,
        }
    }

    /// Resolve `Auto` against a concrete function count.
    pub fn resolve(self, func_count: usize) -> Self {
        match self {
            ExportMode::Auto => {
                if func_count > LARGE_BINARY_FUNC_THRESHOLD {
                    ExportMode::Consolidated
                } else {
                    ExportMode::Legacy
                }
            }
            other => other,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ExportMode::Auto => "auto",
            ExportMode::Legacy => "legacy",
            ExportMode::Consolidated => "consolidated",
        }
    }
}

// ---- Tunable thresholds (kept as module-level pub for easy adjustment) ----

/// Functions above this count ⇒ treat as a large binary (auto → consolidated).
pub const LARGE_BINARY_FUNC_THRESHOLD: usize = 20_000;

/// Decompile size guard: skip Hex-Rays for functions larger than this (bytes),
/// fall back to disassembly. Matches the Python default (16 KiB).
pub const MAX_FUNC_SIZE_FOR_DECOMPILE: u64 = 16 * 1024;

/// Skip decompile for functions with more than this many instructions.
pub const MAX_FUNC_INSN_COUNT: usize = 3000;

/// Per-function decompile timeout is handled by Hex-Rays itself; we only log slow ones above this.
pub const DECOMPILE_TIME_LIMIT_SECS: u64 = 15;

/// Consolidated callgraph sampling: BFS hops from entry/exports.
pub const LARGE_CALLGRAPH_BFS_HOPS: usize = 3;
/// Consolidated callgraph sampling: max nodes kept.
pub const LARGE_CALLGRAPH_MAX_NODES: usize = 5000;
/// Consolidated strings: drop strings shorter than this.
pub const LARGE_STRING_MIN_LEN: usize = 4;

/// Functions processed per outer batch between progress checkpoints.
#[allow(dead_code)] // reserved for future checkpoint/resume cadence tuning
pub const PROGRESS_CHECKPOINT_EVERY: usize = 50;
/// Memory pressure: call clear_cached_cfuncs this often (consolidated = aggressive).
/// Reserved: idalib manages its own decompiler cache lifecycle; these tune a
/// future explicit flush if a memory-pressure mode is added.
#[allow(dead_code)]
pub const DECOMPILE_CACHE_CLEAR_CONSOLIDATED: usize = 100;
#[allow(dead_code)]
pub const DECOMPILE_CACHE_CLEAR_LEGACY: usize = 500;

/// CLI options.
#[derive(Parser, Debug)]
#[command(name = "inp", version, about = "IDA export for AI analysis (Rust, idalib)")]
pub struct Cli {
    /// Path to the input binary OR an existing .i64 IDB.
    pub input: PathBuf,

    /// Output directory. Defaults to `<input>_export_for_ai` next to the input.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Export mode: auto | legacy | consolidated.
    #[arg(short, long, default_value = "auto")]
    pub mode: String,

    /// Skip IDA auto-analysis on open (useful for huge binaries that never finish analysis).
    /// Functions are still discovered and decompiled on demand.
    #[arg(short = 'a', long = "skip-analysis")]
    pub skip_analysis: bool,

    /// Force re-export even if output dir has prior progress.
    #[arg(long)]
    pub force: bool,
}
