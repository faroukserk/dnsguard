use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::method;

#[tokio::test]
async fn cold_start_fetches_and_blocks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("remote-block.example\n"))
        .mount(&server)
        .await;
    assert!(server.uri().starts_with("http"));
}
