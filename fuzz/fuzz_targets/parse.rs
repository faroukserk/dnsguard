#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RT: OnceLock<Runtime> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let rt = RT.get_or_init(|| tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap());
    let state = dnsguard::testing::test_state();
    rt.block_on(async {
        let _ = dnsguard::handle_query(data, &state).await;
    });
});
