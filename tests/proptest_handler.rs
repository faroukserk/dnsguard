use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn handle_query_does_not_panic(data in prop::collection::vec(any::<u8>(), 0..=4096)) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let state = dnsguard::testing::test_state();
        rt.block_on(async { let _ = dnsguard::handle_query(&data, &state).await; });
    }
}
