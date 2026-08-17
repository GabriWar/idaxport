// src/main.rs — CLI entry point and orchestration.
//
// Thin top-level: CLI parse → open IDB → metadata → discover funcs → decompile
// pass → callgraph → AGENTS.md. Heavy lifting lives in submodules.

mod agents_md;
mod callgraph;
mod config;
mod decompile;
mod func_discover;
mod hexdump;
mod metadata;
mod paths;
mod writers;

use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use config::{Cli, ExportMode};
use idalib::IDBOpenOptions;
use writers::Writer;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mode = ExportMode::parse(&cli.mode);

    eprintln!("[inp] input  : {}", cli.input.display());
    let out_dir = match &cli.output {
        Some(p) => p.clone(),
        None => paths::default_export_dir(&cli.input),
    };
    eprintln!("[inp] output : {}", out_dir.display());
    paths::ensure_dir(&out_dir)?;

    // Open the IDB. skip_analysis ⇒ disable auto-analysis (huge binaries);
    // functions are still enumerated and decompiled on demand.
    let mut opts = IDBOpenOptions::new();
    opts.auto_analyse(!cli.skip_analysis);
    let idb = opts
        .open(&cli.input)
        .with_context(|| format!("failed to open {}", cli.input.display()))?;

    let t0 = Instant::now();

    eprintln!("[inp] discovering functions...");
    let funcs = func_discover::discover_all(&idb);
    let total = funcs.len();
    let candidates = func_discover::count_decompile_candidates(&funcs);
    let resolved = mode.resolve(total);
    eprintln!(
        "[inp] functions: {} (decompile candidates: {}) | decompiler: {} | mode: {}",
        total,
        candidates,
        idb.decompiler_available(),
        resolved.as_str()
    );

    let consolidated = matches!(resolved, ExportMode::Consolidated);

    // Phase 1: metadata (strings/imports/exports).
    metadata::run_all(&idb, &out_dir, consolidated)?;

    // Phase 2: decompile pass (main thread drives IDA, writer thread does I/O).
    let writer = Writer::new(out_dir.clone());
    let stats = decompile::run_decompile_pass(&idb, &funcs, resolved, writer)?;

    // Phase 3: callgraph (sampled from entries/exports).
    if let Err(e) = callgraph::export_callgraph(&idb, &out_dir) {
        eprintln!("[inp] callgraph export failed: {}", e);
    }

    // Phase 4: memory hexdump (legacy only — consolidated skips for token savings).
    if !consolidated {
        if let Err(e) = hexdump::export_memory(&idb, &out_dir) {
            eprintln!("[inp] memory export failed: {}", e);
        }
    }

    // Phase 5: AGENTS.md (AI auto-start context).
    agents_md::write_agents_md(&out_dir, resolved, total)?;

    let el = t0.elapsed().as_secs_f64();
    eprintln!(
        "[inp] done in {:.1}s — exported={} fallback={} skipped={} failed={}",
        el, stats.exported, stats.fallback, stats.skipped, stats.failed
    );
    eprintln!("[inp] output: {}", out_dir.display());

    Ok(())
}
