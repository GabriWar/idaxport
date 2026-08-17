// src/callgraph.rs — sampled call-graph (consolidated/large-binary mode).
//
// Full caller/callee walks are an O(F·degree) CPU sink on large binaries. Instead
// we BFS from entry/export points up to `LARGE_CALLGRAPH_BFS_HOPS` hops, capped
// at `LARGE_CALLGRAPH_MAX_NODES` nodes, and stream edges to callgraph.txt.
// This gives the AI a navigable skeleton (entry → reachable callees) without
// the full-graph cost.

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::Result;
use idalib::IDB;

use crate::config::{LARGE_CALLGRAPH_BFS_HOPS, LARGE_CALLGRAPH_MAX_NODES};

/// Callees of a function, via code xrefs from its instruction range.
///
/// We use `first_xref_from` walking the function's heads to collect call targets.
/// This is the same logic as the Python `get_callees`, ported to idalib's API.
fn callees_of(idb: &IDB, start: u64, end: u64) -> Vec<u64> {
    let mut out = HashSet::new();
    let mut ea = start;
    while ea < end {
        // Walk every xref originating at this head; code refs (calls) are what we want.
        let mut opt = idb.first_xref_from(ea.into(), idalib::xref::XRefQuery::ALL);
        while let Some(xr) = opt {
            if xr.is_code() {
                let to = u64::from(xr.to());
                // Resolve to the containing function start (if any).
                if let Some(f) = idb.function_at(to.into()) {
                    out.insert(u64::from(f.start_address()));
                }
            }
            opt = xr.next_from();
        }
        match idb.next_head_with(ea.into(), end.into()) {
            Some(next) if u64::from(next) > ea => ea = u64::from(next),
            _ => break,
        }
        if out.len() > 4096 {
            break; // pathological function guard
        }
    }
    out.into_iter().collect()
}

/// Write the sampled call graph. Returns (nodes, edges).
pub fn export_callgraph(idb: &IDB, out_dir: &Path) -> Result<(usize, usize)> {
    let path = out_dir.join("callgraph.txt");
    let mut w = BufWriter::new(File::create(&path)?);
    writeln!(w, "# Callgraph (sampled from entry/export functions)")?;

    // Roots = public-named addresses that resolve to a real function.
    // (Avoids idb.entries() whose iterator has an off-by-one infinite loop in
    // idalib 0.9; using public names is a reliable entry/export proxy.)
    let mut roots: Vec<u64> = Vec::new();
    for nm in idb.names().iter() {
        if !nm.is_public() {
            continue;
        }
        let ea = u64::from(nm.address());
        if idb.function_at(ea.into()).is_some() {
            roots.push(ea);
        }
    }
    if roots.is_empty() {
        writeln!(w, "# (no entry points found)")?;
        w.flush()?;
        return Ok((0, 0));
    }

    let mut visited: HashSet<u64> = HashSet::new();
    let mut edges: Vec<(u64, u64)> = Vec::new();
    let mut frontier: VecDeque<u64> = roots.iter().copied().collect();

    for _hop in 0..LARGE_CALLGRAPH_BFS_HOPS {
        if frontier.is_empty() || visited.len() >= LARGE_CALLGRAPH_MAX_NODES {
            break;
        }
        let mut next_frontier: VecDeque<u64> = VecDeque::new();
        while let Some(ea) = frontier.pop_front() {
            if visited.contains(&ea) || visited.len() >= LARGE_CALLGRAPH_MAX_NODES {
                continue;
            }
            visited.insert(ea);
            let end = match idb.function_at(ea.into()) {
                Some(f) => u64::from(f.end_address()),
                None => ea + 4, // unknown; bail
            };
            for callee in callees_of(idb, ea, end) {
                edges.push((ea, callee));
                if !visited.contains(&callee) {
                    next_frontier.push_back(callee);
                }
            }
        }
        frontier = next_frontier;
    }

    writeln!(
        w,
        "# Roots: {} | Hops: {} | Nodes: {} | Edges: {}",
        roots.len(),
        LARGE_CALLGRAPH_BFS_HOPS,
        visited.len(),
        edges.len()
    )?;
    writeln!(w, "# Format: caller_addr -> callee_addr")?;
    writeln!(w, "#{}", "=".repeat(80))?;
    for (caller, callee) in &edges {
        let cname = func_name(idb, *caller);
        let ename = func_name(idb, *callee);
        writeln!(w, "{:X} | {} -> {:X} | {}", caller, cname, callee, ename)?;
    }
    w.flush()?;
    Ok((visited.len(), edges.len()))
}

fn func_name(idb: &IDB, ea: u64) -> String {
    if let Some(f) = idb.function_at(ea.into()) {
        if let Some(n) = f.name() {
            return n;
        }
    }
    format!("sub_{:X}", ea)
}
