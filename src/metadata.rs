// src/metadata.rs — strings / imports / exports / pointers export.
//
// These are the non-decompile metadata files. Each runs to completion in one
// pass and streams to a BufWriter (O(1) memory). Mirrors the Python
// export_strings/imports/exports/pointers but consolidated into one module.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::Result;
use idalib::IDB;

use crate::config::LARGE_STRING_MIN_LEN;

/// Export the strings table. `min_len > 0` filters short strings (consolidated mode).
pub fn export_strings(idb: &IDB, out_dir: &Path, min_len: usize) -> Result<usize> {
    let path = out_dir.join("strings.txt");
    let mut w = BufWriter::new(File::create(&path)?);
    writeln!(w, "# Strings exported from IDA")?;
    writeln!(w, "# Format: address | length | string")?;
    if min_len > 0 {
        writeln!(w, "# (min_len filter={} applied)", min_len)?;
    }
    writeln!(w, "#{}", "=".repeat(80))?;

    let mut count = 0usize;
    for (addr, s) in idb.strings().iter() {
        if min_len > 0 && s.chars().count() < min_len {
            continue;
        }
        let escaped = s.replace('\n', "\\n").replace('\r', "\\r");
        writeln!(w, "{:X} | {} | {}", u64::from(addr), s.chars().count(), escaped)?;
        count += 1;
    }
    w.flush()?;
    Ok(count)
}

/// Export the entry/export points table.
///
/// NOTE: we deliberately avoid `idb.entries()` — its iterator has an off-by-one
/// that never advances `index` on the success path, causing an infinite loop
/// (confirmed against idalib 0.9). Instead we walk `names()` and emit public
/// names as exports (public == exported in IDA's name list).
pub fn export_exports(idb: &IDB, out_dir: &Path) -> Result<usize> {
    let path = out_dir.join("exports.txt");
    let mut w = BufWriter::new(File::create(&path)?);
    writeln!(w, "# Exports (public names)")?;
    writeln!(w, "# Format: addr:name")?;
    writeln!(w, "#{}", "=".repeat(60))?;

    let mut count = 0usize;
    for nm in idb.names().iter() {
        if nm.is_public() {
            writeln!(w, "{:X}:{}", u64::from(nm.address()), nm.name())?;
            count += 1;
        }
    }
    w.flush()?;
    Ok(count)
}

/// Export a best-effort imports table: names located in extern/got-style segments.
///
/// idalib does not expose `enum_import_names`. We classify by segment: any named
/// address inside an `extern`/`.got`/`__got` segment is treated as an import.
pub fn export_imports(idb: &IDB, out_dir: &Path) -> Result<usize> {
    let path = out_dir.join("imports.txt");
    let mut w = BufWriter::new(File::create(&path)?);
    writeln!(w, "# Imports (names in extern/got segments)")?;
    writeln!(w, "# Format: addr:name")?;
    writeln!(w, "#{}", "=".repeat(60))?;

    // Collect import-segment address ranges once.
    let mut import_ranges: Vec<(u64, u64)> = Vec::new();
    for (_id, seg) in idb.segments() {
        let name = seg.name().unwrap_or_default().to_lowercase();
        if name.contains("extern")
            || name.contains(".got")
            || name.contains("__got")
            || name.contains(".idata")
        {
            import_ranges.push((u64::from(seg.start_address()), u64::from(seg.end_address())));
        }
    }

    let mut count = 0usize;
    for nm in idb.names().iter() {
        let a = u64::from(nm.address());
        if import_ranges.iter().any(|(s, e)| a >= *s && a < *e) {
            writeln!(w, "{:X}:{}", a, nm.name())?;
            count += 1;
        }
    }
    w.flush()?;
    Ok(count)
}

/// Run all metadata exports, applying consolidated string filtering.
pub fn run_all(
    idb: &IDB,
    out_dir: &Path,
    consolidated: bool,
) -> Result<(usize, usize, usize)> {
    let min_len = if consolidated { LARGE_STRING_MIN_LEN } else { 0 };
    let s = export_strings(idb, out_dir, min_len)?;
    let e = export_exports(idb, out_dir)?;
    let i = export_imports(idb, out_dir)?;
    eprintln!(
        "[inp] metadata: strings={} exports={} imports={} (string min_len={})",
        s, e, i, min_len
    );
    Ok((s, e, i))
}
