// src/paths.rs — output directory resolution with writable-validation fallback.
//
// Fixes the original Python bug: `FileNotFoundError: [WinError 3] 'G:\\'` happened
// when the original binary's drive was unmounted. We validate writability and
// fall back input_dir → cwd so the export never crashes on an unreachable path.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// True if `path` is an existing writable directory.
///
/// Mirrors the Python `_is_writable_dir`: an unmounted drive (e.g. Windows `G:\`
/// after the USB stick is pulled, or a stale network mount) returns false here,
/// triggering the fallback chain instead of crashing in `fs::create_dir_all`.
pub fn is_writable_dir(path: &Path) -> bool {
    if path.as_os_str().is_empty() {
        return false;
    }
    if !path.is_dir() {
        return false;
    }
    // Cheap writability probe: create+remove a temp file. os_access would be ideal
    // but std doesn't expose it; this is reliable across platforms.
    let probe = path.join(".inp_write_probe");
    match fs::File::create(&probe) {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Pick the first writable directory among `candidates`; fall back to cwd.
pub fn pick_writable_base_dir(candidates: &[Option<PathBuf>]) -> PathBuf {
    for cand in candidates.iter().flatten() {
        if is_writable_dir(cand) {
            return cand.clone();
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Build the default export dir `<input_stem>_export_for_ai`.
///
/// The directory is placed next to the input file's parent — but if that parent
/// is not writable (unmounted drive, read-only mount), we fall back to cwd so
/// the export always lands somewhere writable.
pub fn default_export_dir(input: &Path) -> PathBuf {
    let parent = input
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(PathBuf::from);
    let base = pick_writable_base_dir(&[parent]);
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "input".to_string());
    base.join(format!("{}_export_for_ai", stem))
}

/// Ensure a directory exists and is writable. Gives a clear error on failure
/// rather than letting the underlying OS error surface (e.g. raw `[WinError 3]`).
pub fn ensure_dir(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        bail!("ensure_dir: path is empty");
    }
    fs::create_dir_all(path).map_err(|e| {
        anyhow::anyhow!(
            "Cannot create export directory '{}': {}. \
             If the original binary's drive is unmounted (e.g. 'G:\\'), \
             move the IDB to a writable local path.",
            path.display(),
            e
        )
    })?;
    if !is_writable_dir(path) {
        bail!(
            "Export directory exists but is not writable: '{}'",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_not_writable() {
        assert!(!is_writable_dir(Path::new("")));
    }

    #[test]
    fn nonexistent_path_not_writable() {
        assert!(!is_writable_dir(Path::new("/this/does/not/exist/xyz")));
    }

    #[test]
    fn tmp_is_writable() {
        let tmp = std::env::temp_dir();
        assert!(is_writable_dir(&tmp));
    }

    #[test]
    fn pick_falls_back_to_first_writable() {
        let bogus = PathBuf::from("/Volumes/definitely_unmounted_xyz");
        let tmp = std::env::temp_dir();
        let chosen = pick_writable_base_dir(&[Some(bogus), Some(tmp.clone())]);
        assert_eq!(chosen, tmp);
    }

    #[test]
    fn default_export_dir_stem() {
        let p = Path::new("/tmp/foo.bin");
        let d = default_export_dir(p);
        assert!(d.to_string_lossy().ends_with("foo_export_for_ai"));
    }
}
