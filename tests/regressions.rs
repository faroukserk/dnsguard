use std::fs;
use std::path::PathBuf;

#[test]
fn corpus_inputs_do_not_panic() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/parse");
    if !dir.exists() { return; }
    let mut failures = Vec::new();
    let mut count = 0usize;
    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.file_name().unwrap() == ".gitkeep" { continue; }
        count += 1;
        let data = fs::read(&path).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let state = dnsguard::testing::test_state();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(async { let _ = dnsguard::handle_query(&data, &state).await; });
        }));
        if result.is_err() { failures.push(path.display().to_string()); }
    }
    println!("loaded {} corpus files", count);
    assert!(count >= 1900, "expected >=1900, got {}", count);
    assert!(failures.is_empty(), "panics on: {:?}", failures);
}

// Named regressions go below
#[test]
fn regression_placeholder_compiles() {
    let data = [0u8; 12];
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let state = dnsguard::testing::test_state();
    rt.block_on(async { let _ = dnsguard::handle_query(&data, &state).await; });
}
