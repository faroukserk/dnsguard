pub mod cache;
pub mod config;
pub mod downloader;
pub mod filter;
pub mod handler;
pub mod list_cache;
pub mod upstream;

pub use handler::{handle_query, State, udp_limit, fit_for_udp};

pub mod testing {
    use crate::filter::Filter;
    use crate::handler::State;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use tokio::sync::Semaphore;

    pub fn test_state() -> State {
        State {
            upstreams: vec![],
            timeout_ms: 10,
            filter: arc_swap::ArcSwap::new(Arc::new(Filter::default())),
            cache: None,
            udp_sem: Arc::new(Semaphore::new(1024)),
            tcp_sem: Arc::new(Semaphore::new(256)),
            tcp_idle_timeout_secs: 5,
            filter_reloads: AtomicU64::new(0),
            filter_reload_failures: AtomicU64::new(0),
            list_downloads: AtomicU64::new(0),
            list_download_failures: AtomicU64::new(0),
        }
    }
}
