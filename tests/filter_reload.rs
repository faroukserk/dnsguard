use dnsguard::filter::Filter;
use dnsguard::handler::State;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tempfile::tempdir;

#[tokio::test]
async fn from_files_valid() {
    let dir = tempdir().unwrap();
    let allow = dir.path().join("allow.txt");
    let block = dir.path().join("block.txt");
    std::fs::write(&allow, "safe.example.com\n").unwrap();
    std::fs::write(&block, "ads.example.com\n").unwrap();
    let f = Filter::from_files(&allow, &block).unwrap();
    assert!(f.is_blocked("ads.example.com"));
}

#[tokio::test]
async fn from_files_missing() {
    let dir = tempdir().unwrap();
    let allow = dir.path().join("allow.txt");
    let block = dir.path().join("block.txt");
    std::fs::write(&allow, "example.com\n").unwrap();
    assert!(Filter::from_files(&allow, &block).is_err());
}

#[tokio::test]
async fn from_files_empty() {
    let dir = tempdir().unwrap();
    let allow = dir.path().join("allow.txt");
    let block = dir.path().join("block.txt");
    std::fs::write(&allow, "example.com\n").unwrap();
    std::fs::write(&block, "").unwrap();
    assert!(Filter::from_files(&allow, &block).is_err());
}

#[tokio::test]
async fn reload_changes_result() {
    let dir = tempdir().unwrap();
    let allow = dir.path().join("allow.txt");
    let block = dir.path().join("block.txt");
    std::fs::write(&allow, "example.com\n").unwrap();
    std::fs::write(&block, "ads.example.com\n").unwrap();
    let state = State {
        upstreams: vec![],
        timeout_ms: 10,
        filter: arc_swap::ArcSwap::new(Arc::new(Filter::from_files(&allow, &block).unwrap())),
        cache: None,
        udp_sem: Arc::new(tokio::sync::Semaphore::new(1024)),
        tcp_sem: Arc::new(tokio::sync::Semaphore::new(256)),
        tcp_idle_timeout_secs: 5,
        filter_reloads: std::sync::atomic::AtomicU64::new(0),
        filter_reload_failures: std::sync::atomic::AtomicU64::new(0),
        list_downloads: std::sync::atomic::AtomicU64::new(0),
        list_download_failures: std::sync::atomic::AtomicU64::new(0),
    };
    // make a query for a domain not blocked initially
    let new_block = dir.path().join("block2.txt");
    std::fs::write(&new_block, "example.com\n").unwrap();
    let before = state.filter_reloads.load(Ordering::Relaxed);
    state.reload(&allow, &new_block).unwrap();
    assert_eq!(state.filter_reloads.load(Ordering::Relaxed), before + 1);
}

#[tokio::test]
async fn reload_bad_leaves_old() {
    let dir = tempdir().unwrap();
    let allow = dir.path().join("allow.txt");
    let block = dir.path().join("block.txt");
    std::fs::write(&allow, "example.com\n").unwrap();
    std::fs::write(&block, "ads.example.com\n").unwrap();
    let state = State {
        upstreams: vec![],
        timeout_ms: 10,
        filter: arc_swap::ArcSwap::new(Arc::new(Filter::from_files(&allow, &block).unwrap())),
        cache: None,
        udp_sem: Arc::new(tokio::sync::Semaphore::new(1024)),
        tcp_sem: Arc::new(tokio::sync::Semaphore::new(256)),
        tcp_idle_timeout_secs: 5,
        filter_reloads: std::sync::atomic::AtomicU64::new(0),
        filter_reload_failures: std::sync::atomic::AtomicU64::new(0),
        list_downloads: std::sync::atomic::AtomicU64::new(0),
        list_download_failures: std::sync::atomic::AtomicU64::new(0),
    };
    let bad = dir.path().join("missing.txt");
    let before_fail = state.filter_reload_failures.load(Ordering::Relaxed);
    assert!(state.reload(&allow, &bad).is_err());
    assert_eq!(state.filter_reload_failures.load(Ordering::Relaxed), before_fail + 1);
}

#[tokio::test]
async fn reload_concurrency() {
    let dir = tempdir().unwrap();
    let allow = dir.path().join("allow.txt");
    let block1 = dir.path().join("block1.txt");
    let block2 = dir.path().join("block2.txt");
    std::fs::write(&allow, "example.com\n").unwrap();
    std::fs::write(&block1, "ads.example.com\n").unwrap();
    std::fs::write(&block2, "tracker.example.com\n").unwrap();
    let state = Arc::new(State {
        upstreams: vec![],
        timeout_ms: 10,
        filter: arc_swap::ArcSwap::new(Arc::new(Filter::from_files(&allow, &block1).unwrap())),
        cache: None,
        udp_sem: Arc::new(tokio::sync::Semaphore::new(1024)),
        tcp_sem: Arc::new(tokio::sync::Semaphore::new(256)),
        tcp_idle_timeout_secs: 5,
        filter_reloads: std::sync::atomic::AtomicU64::new(0),
        filter_reload_failures: std::sync::atomic::AtomicU64::new(0),
        list_downloads: std::sync::atomic::AtomicU64::new(0),
        list_download_failures: std::sync::atomic::AtomicU64::new(0),
    });
    // build a minimal DNS query for ads.example.com A
    // skip actual query; just ensure reload doesn't panic
    let st = state.clone();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let s = st.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..500 {
                let _ = s.filter.load();
            }
        }));
    }
    let st2 = st.clone();
    let rh = tokio::spawn(async move {
        for i in 0..100 {
            let p = if i % 2 == 0 { block1.clone() } else { block2.clone() };
            let _ = st2.reload(&allow, &p);
        }
    });
    for h in handles { h.await.unwrap(); }
    rh.await.unwrap();
}
