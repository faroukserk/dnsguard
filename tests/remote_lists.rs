use std::fs;
use std::io::Write;
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// Builds a minimal DNS A query for `name` by hand.
fn build_query(name: &str) -> Vec<u8> {
    let mut out = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&[0, 1, 0, 1]); // type A, class IN
    out
}

/// Sends a query and returns the raw reply bytes, or None if nothing came back.
fn query_raw(port: u16, name: &str) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    sock.send_to(&build_query(name), ("127.0.0.1", port)).ok()?;
    let mut buf = [0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf).ok()?;
    Some(buf[..n].to_vec())
}

fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)? as usize;
        if len & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1 + len;
    }
}

/// Returns the first A record in the reply as a dotted string, or None.
fn first_a_answer(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)? + 4;
    }
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        let rtype = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]);
        let rdlen = u16::from_be_bytes([*buf.get(pos + 8)?, *buf.get(pos + 9)?]) as usize;
        let rdata = pos + 10;
        if rtype == 1 && rdlen == 4 {
            let a = buf.get(rdata..rdata + 4)?;
            return Some(format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]));
        }
        pos = rdata + rdlen;
    }
    None
}

fn query_a(port: u16, name: &str) -> Option<String> {
    first_a_answer(&query_raw(port, name)?)
}

#[tokio::test]
async fn cold_start_fetches_and_blocks() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("remote-block.example\n"))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let cache = dir.path().join("cache");
    fs::create_dir_all(&cache).expect("cache dir");
    let allow = dir.path().join("allowlist.txt");
    let block = dir.path().join("blocklist.txt");
    fs::write(&allow, "").expect("allow");
    fs::write(&block, "").expect("block");

    let port = free_port();
    let config_path = dir.path().join("config.toml");
    let mut f = fs::File::create(&config_path).expect("config");
    write!(
        f,
        "listen = \"127.0.0.1:{port}\"\n\
         upstreams = [\"1.1.1.1:53\"]\n\
         allowlist = \"{}\"\n\
         blocklist = \"{}\"\n\
         cache_dir = \"{}\"\n\
         allow_http = true\n\
         refresh_interval_secs = 3600\n",
         allow.display().to_string().replace('\\', "/"),
         server.uri(),
         cache.display().to_string().replace('\\', "/")
    )
    .expect("write config");

    let log_path = dir.path().join("service.log");
    let log = fs::File::create(&log_path).expect("log");
    let child = Command::new(env!("CARGO_BIN_EXE_dnsguard"))
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::from(log.try_clone().expect("clone")))
        .stderr(Stdio::from(log))
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn service");
    let mut guard = KillOnDrop(child);

    // Wait until the service answers at all.
    let start = Instant::now();
    let mut up = false;
    while start.elapsed() < Duration::from_secs(5) {
        if query_raw(port, "warmup.example").is_some() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
        if !up {
        let exit = guard.0.try_wait().ok().flatten();
        let log_text = fs::read_to_string(&log_path).unwrap_or_default();
        panic!(
            "service did not answer DNS on port {port}. exit status: {exit:?}. service log:\n{log_text}"
        );
    }

    // Wait for the background fetch to apply the remote list.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut answer = None;
    while Instant::now() < deadline {
        answer = query_a(port, "remote-block.example");
        if answer.as_deref() == Some("0.0.0.0") {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let log_text = fs::read_to_string(&log_path).unwrap_or_default();
    assert_eq!(
        answer.as_deref(),
        Some("0.0.0.0"),
        "remote list not applied. service log:\n{log_text}"
    );

    let received = server.received_requests().await.unwrap_or_default();
    assert!(!received.is_empty(), "mock server received no fetch request");
}
#[tokio::test]
async fn http_500_keeps_cache() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let cache = dir.path().join("cache");
    fs::create_dir_all(&cache).expect("cache dir");
    let url = url::Url::parse(&server.uri()).unwrap();
    let cp = dnsguard::list_cache::cache_path_for(&cache, &url);
    dnsguard::list_cache::write_atomic(&cp, b"old-block.example\n").expect("write cache");

    let allow = dir.path().join("allowlist.txt");
    fs::write(&allow, "").expect("allow");

    let port = free_port();
    let config_path = dir.path().join("config.toml");
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\nupstreams = [\"1.1.1.1:53\"]\nallowlist = \"{}\"\nblocklist = \"{}\"\ncache_dir = \"{}\"\nallow_http = true\nrefresh_interval_secs = 3600\n",
        allow.display().to_string().replace("\\", "/"),
        server.uri(),
        cache.display().to_string().replace("\\", "/")
    );
    fs::write(&config_path, config).expect("config");

    let log_path = dir.path().join("service.log");
    let log = fs::File::create(&log_path).expect("log");
    let child = Command::new(env!("CARGO_BIN_EXE_dnsguard"))
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::from(log.try_clone().expect("clone")))
        .stderr(Stdio::from(log))
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn service");
    let _guard = KillOnDrop(child);

    let start = Instant::now();
    let mut up = false;
    while start.elapsed() < Duration::from_secs(5) {
        if query_raw(port, "warmup.example").is_some() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(up, "service did not answer DNS");

    std::thread::sleep(Duration::from_secs(2));

    let ans = query_a(port, "old-block.example");
    assert_eq!(ans.as_deref(), Some("0.0.0.0"), "cache not kept");

    let received = server.received_requests().await.unwrap_or_default();
    assert!(!received.is_empty(), "mock received no request");

    let log_text = fs::read_to_string(&log_path).unwrap_or_default();
    assert!(log_text.contains("warn") || log_text.contains("download failed") || log_text.contains("list_download_failures"), "no failure log. log:\n{log_text}");
}

#[tokio::test]
async fn empty_body_keeps_cache() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let cache = dir.path().join("cache");
    fs::create_dir_all(&cache).expect("cache dir");
    let url = url::Url::parse(&server.uri()).unwrap();
    let cp = dnsguard::list_cache::cache_path_for(&cache, &url);
    dnsguard::list_cache::write_atomic(&cp, b"old-block.example\n").expect("write cache");

    let allow = dir.path().join("allowlist.txt");
    fs::write(&allow, "").expect("allow");

    let port = free_port();
    let config_path = dir.path().join("config.toml");
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\nupstreams = [\"1.1.1.1:53\"]\nallowlist = \"{}\"\nblocklist = \"{}\"\ncache_dir = \"{}\"\nallow_http = true\nrefresh_interval_secs = 3600\n",
        allow.display().to_string().replace('\\', "/"),
        server.uri(),
        cache.display().to_string().replace('\\', "/")
    );
    fs::write(&config_path, config).expect("config");

    let log_path = dir.path().join("service.log");
    let log = fs::File::create(&log_path).expect("log");
    let child = Command::new(env!("CARGO_BIN_EXE_dnsguard"))
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::from(log.try_clone().expect("clone")))
        .stderr(Stdio::from(log))
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn service");
    let _guard = KillOnDrop(child);

    let start = Instant::now();
    let mut up = false;
    while start.elapsed() < Duration::from_secs(5) {
        if query_raw(port, "warmup.example").is_some() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(up, "service did not answer DNS");

    std::thread::sleep(Duration::from_secs(2));

    let ans = query_a(port, "old-block.example");
    assert_eq!(ans.as_deref(), Some("0.0.0.0"), "cache not kept");

    let received = server.received_requests().await.unwrap_or_default();
    assert!(!received.is_empty(), "mock received no request");

    let log_text = fs::read_to_string(&log_path).unwrap_or_default();
    assert!(log_text.contains("warn") || log_text.contains("download failed") || log_text.contains("list_download_failures") || log_text.contains("Empty"), "no failure log. log:\n{log_text}");
}
