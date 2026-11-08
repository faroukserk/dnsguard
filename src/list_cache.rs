use std::fs;
use std::path::{Path, PathBuf};

pub fn cache_path_for(cache_dir: &Path, url: &url::Url) -> PathBuf {
    // simple stable filename: hash url string
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    url.as_str().hash(&mut h);
    cache_dir.join(format!("{:x}.bin", h.finish()))
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() { return Err("empty".into()); }
    if bytes.len() > 20 * 1024 * 1024 { return Err("too large".into()); }
    if let Some(parent) = path.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn read_cached(path: &Path) -> Option<Vec<u8>> {
    fs::read(path).ok()
}
