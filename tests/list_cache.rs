use dnsguard::list_cache;
use tempfile::tempdir;

#[test]
fn write_atomic_replaces() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("f.bin");
    list_cache::write_atomic(&p, b"hello").unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), b"hello");
    list_cache::write_atomic(&p, b"world").unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), b"world");
}

#[test]
fn write_atomic_rejects_empty() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("f.bin");
    list_cache::write_atomic(&p, b"x").unwrap();
    assert!(list_cache::write_atomic(&p, b"").is_err());
    assert_eq!(std::fs::read(&p).unwrap(), b"x");
}

#[test]
fn write_atomic_rejects_large() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("f.bin");
    list_cache::write_atomic(&p, b"x").unwrap();
    let big = vec![0u8; 21 * 1024 * 1024];
    assert!(list_cache::write_atomic(&p, &big).is_err());
    assert_eq!(std::fs::read(&p).unwrap(), b"x");
}
