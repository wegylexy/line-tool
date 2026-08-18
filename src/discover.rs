use anyhow::{anyhow, Result};
use std::path::PathBuf;

/// Finds LINE's main chat database without the user having to know the
/// install path. LINE names its per-account `.edb` after an opaque id
/// (`qw<hex>.edb`) with several smaller sibling files alongside it
/// (`album_qw....edb`, `chatStats_qw....edb`, `keep_qw....edb`) and a
/// separate `AutoSuggest` subfolder - rather than parse those naming
/// conventions (which could change), this picks the LARGEST `.edb` directly
/// under `Data\db` (non-recursive), since the main chat database dwarfs the
/// others by two to three orders of magnitude (hundreds of MB vs tens of KB).
pub fn discover_edb() -> Result<PathBuf> {
    let local_appdata = std::env::var("LOCALAPPDATA")
        .map_err(|_| anyhow!("LOCALAPPDATA is not set; pass --edb explicitly"))?;
    let db_dir = PathBuf::from(local_appdata)
        .join("LINE")
        .join("Data")
        .join("db");

    let entries = std::fs::read_dir(&db_dir).map_err(|e| {
        anyhow!(
            "can't read {}: {e} (pass --edb explicitly)",
            db_dir.display()
        )
    })?;

    let mut candidates: Vec<(u64, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("edb") {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            candidates.push((meta.len(), path));
        }
    }

    candidates.sort_by_key(|(size, _)| std::cmp::Reverse(*size));
    candidates
        .into_iter()
        .next()
        .map(|(_, path)| path)
        .ok_or_else(|| {
            anyhow!(
                "no .edb file found under {}; pass --edb explicitly",
                db_dir.display()
            )
        })
}
