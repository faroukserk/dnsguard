pub mod cache;
pub mod filter;
pub mod handler;
pub mod upstream;

pub use handler::{handle_query, State, udp_limit, fit_for_udp};

pub mod testing {
    use crate::filter::Filter;
    use crate::handler::State;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    pub fn test_state() -> State {
        State {
            upstreams: vec![],
            timeout_ms: 10,
            filter: Filter::default(),
            cache: None,
            udp_sem: Arc::new(Semaphore::new(1024)),
            tcp_sem: Arc::new(Semaphore::new(256)),
            tcp_idle_timeout_secs: 5,
        }
    }
}
