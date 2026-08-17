// src/writers.rs — output writer (runs on its own thread, pure file I/O).
//
// Receives `DecResult`s over a channel from the decompile loop (main thread),
// and writes them to disk. Two layouts:
//   - Consolidated: append every function into a single streaming `decompiled.c`
//     plus a single `function_list.txt`. O(1) memory, O(N) files = 1.
//   - Legacy: one `.c`/`.asm` per function in `decompile/`+`disassembly/`,
//     plus a streaming `function_index.txt`. O(1) memory, O(N) files.
//
// All files are kept open with BufWriter and flushed on close, so a kill -9
// loses at most a BufWriter's worth (~64KB) — acceptable, and progress files
// (saved separately) let the user resume.

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::mpsc;

use anyhow::{Context, Result};

use crate::config::ExportMode;
use crate::decompile::{DecResult, DecompStats, ExportType};

pub struct Writer {
    out_dir: PathBuf,
}

impl Writer {
    pub fn new(out_dir: PathBuf) -> Self {
        Self { out_dir }
    }

    /// Consume the channel until closed, writing results. Returns disk-truth stats.
    pub fn run(self, rx: mpsc::Receiver<DecResult>, mode: ExportMode) -> Result<DecompStats> {
        match mode {
            ExportMode::Consolidated => self.run_consolidated(rx),
            ExportMode::Legacy | ExportMode::Auto => self.run_legacy(rx),
        }
    }

    // ---- Consolidated: single decompiled.c + function_list.txt ----
    fn run_consolidated(self, rx: mpsc::Receiver<DecResult>) -> Result<DecompStats> {
        let decomp_path = self.out_dir.join("decompiled.c");
        let list_path = self.out_dir.join("function_list.txt");

        let dfile = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&decomp_path)
            .with_context(|| format!("open {}", decomp_path.display()))?;
        let mut dw = BufWriter::new(dfile);

        let lfile = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&list_path)
            .with_context(|| format!("open {}", list_path.display()))?;
        let mut lw = BufWriter::new(lfile);

        let mut stats = DecompStats::default();

        for r in rx.iter() {
            write_func_header(&mut dw, &r)?;
            dw.write_all(r.body.as_bytes())?;
            dw.write_all(b"\n\n")?;

            // streaming function_list.txt line
            let _ = writeln!(
                lw,
                "{:X} | {} | {} | {}",
                r.start_ea,
                r.name,
                r.export_type.as_str(),
                r.fallback_reason.as_deref().unwrap_or("")
            );

            match r.export_type {
                ExportType::DisassemblyFallback => stats.fallback += 1,
                ExportType::Decompile => stats.exported += 1,
            }
        }

        dw.flush()?;
        lw.flush()?;
        Ok(stats)
    }

    // ---- Legacy: per-function files + streaming function_index.txt ----
    fn run_legacy(self, rx: mpsc::Receiver<DecResult>) -> Result<DecompStats> {
        let decomp_dir = self.out_dir.join("decompile");
        let disasm_dir = self.out_dir.join("disassembly");
        std::fs::create_dir_all(&decomp_dir)?;
        std::fs::create_dir_all(&disasm_dir)?;

        let idx_path = self.out_dir.join("function_index.txt");
        let ifile = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&idx_path)?;
        let mut iw = BufWriter::new(ifile);

        let mut stats = DecompStats::default();

        for r in rx.iter() {
            let (subdir, ext) = match r.export_type {
                ExportType::Decompile => ("decompile", "c"),
                ExportType::DisassemblyFallback => ("disassembly", "asm"),
            };
            let fname = format!("{:X}.{}", r.start_ea, ext);
            let path = self.out_dir.join(subdir).join(&fname);
            let f = match OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
            {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[inp] IO error {}: {}", path.display(), e);
                    stats.failed += 1;
                    continue;
                }
            };
            let mut bw = BufWriter::new(f);
            write_func_header(&mut bw, &r)?;
            bw.write_all(r.body.as_bytes())?;
            bw.write_all(b"\n")?;
            if let Err(e) = bw.flush() {
                stats.failed += 1;
                eprintln!("[inp] flush {}: {}", path.display(), e);
                continue;
            }

            // streaming function_index.txt line (callers/callees left empty at this layer;
            // the callgraph module handles edges separately)
            let rel = format!("{}/{}", subdir, fname);
            let _ = writeln!(
                iw,
                "{:X} | {} | {} | {} |  |  | {}",
                r.start_ea,
                r.name,
                r.export_type.as_str(),
                rel,
                r.fallback_reason.as_deref().unwrap_or("")
            );

            match r.export_type {
                ExportType::DisassemblyFallback => stats.fallback += 1,
                ExportType::Decompile => stats.exported += 1,
            }
        }

        iw.flush()?;
        Ok(stats)
    }
}

/// Write the metadata header block (compatible with the Python format).
fn write_func_header(w: &mut impl Write, r: &DecResult) -> Result<()> {
    writeln!(w, "/*")?;
    writeln!(w, " * func-name: {}", r.name)?;
    // Lowercase hex to match the Python version's `hex(addr)` output.
    writeln!(w, " * func-address: {:#x}", r.start_ea)?;
    writeln!(w, " * export-type: {}", r.export_type.as_str())?;
    // callers/callees: omitted at this layer (see callgraph.rs); keep the header
    // fields for format compatibility with the Python output.
    writeln!(w, " * callers: none")?;
    writeln!(w, " * callees: none")?;
    if let Some(reason) = &r.fallback_reason {
        writeln!(w, " * fallback-reason: {}", reason)?;
    }
    writeln!(w, " */")?;
    writeln!(w)?;
    Ok(())
}
