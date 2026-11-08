use std::fs;
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

fn encode_name(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for label in name.split('.') {
        v.push(label.len() as u8);
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0);
    v
}

fn build_query(name: &str) -> Vec<u8> {
    let mut out = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(&encode_name(name));
    out.extend_from_slice(&[0, 1, 0, 1]);
    out
}

fn cname_reply(query: &[u8], target: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&query[0..2]);
    out.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    out.extend_from_slice(&query[12..]);
    out.extend_from_slice(&[0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60]);
    let rdata = encode_name(target);
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    out
}

fn query_raw(port: u16, name: &str) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
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

fn toml_path(p: &std::path::Path) -> String {
    p.display().to_string().replace('\\', "/")
}

#[test]
fn cname_to_blocked_name_returns_zero_address() {
    let upstream = UdpSocket::bind("127.0.0.1:0").expect("bind upstream");
    let up_port = upstream.local_addr().expect("upstream addr").port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = upstream.recv_from(&mut buf) {
            if n >= 12 {
                let reply = cname_reply(&buf[..n], "tracker.example");
                let _ = upstream.send_to(&reply, peer);
            }
        }
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let allow = dir.path().join("allowlist.txt");
    let block = dir.path().join("blocklist.txt");
    fs::write(&allow, "").expect("allow");
    fs::write(&block, "tracker.example\n").expect("block");

    let port = free_port();
    let config_path = dir.path().join("config.toml");
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\nupstreams = [\"127.0.0.1:{up_port}\"]\nallowlist = \"{}\"\nblocklist = \"{}\"\n",
        toml_path(&allow),
        toml_path(&block),
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
    let mut guard = KillOnDrop(child);

    let start = Instant::now();
    let mut up = false;
    let mut ready_ms = 0u128;
    while start.elapsed() < Duration::from_secs(5) {
        let log_text = fs::read_to_string(&log_path).unwrap_or_default();
        if log_text.contains("DNSGuard UDP listener started") && log_text.contains("DNSGuard TCP listener started")
            && query_raw(port, "warmup.example").is_some() {
            up = true;
            ready_ms = start.elapsed().as_millis();
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !up {
        let exit = guard.0.try_wait().ok().flatten();
        let log_text = fs::read_to_string(&log_path).unwrap_or_default();
        panic!(
            "service did not answer DNS on port {port}. exit status: {exit:?}. service log:\\n{log_text}"
        );
    }
    eprintln!("readiness time: {} ms", ready_ms);
    assert!(ready_ms > 0, "readiness was instantaneous");

    let first = query_a(port, "innocent.example");
    let second = query_a(port, "innocent.example");
    let log_text = fs::read_to_string(&log_path).unwrap_or_default();

    assert_eq!(
        first.as_deref(),
        Some("0.0.0.0"),
        "first query not blocked via CNAME. service log:\n{log_text}"
    );
    assert_eq!(
        second.as_deref(),
        Some("0.0.0.0"),
        "second query not blocked (upstream answer may have been cached). service log:\n{log_text}"
    );
}