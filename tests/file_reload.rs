use std::fs::{self, OpenOptions};
use std::io::Write;
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

fn build_query(name: &str) -> Vec<u8> {
    let mut out = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&[0, 1, 0, 1]);
    out
}

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
fn blocklist_edit_takes_effect_without_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let allow = dir.path().join("allowlist.txt");
    let block = dir.path().join("blocklist.txt");
    fs::write(&allow, "").expect("allow");
    fs::write(&block, "unrelated.example\n").expect("block");

    let port = free_port();
    let config_path = dir.path().join("config.toml");
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\nupstreams = [\"1.1.1.1:53\"]\nallowlist = \"{}\"\nblocklist = \"{}\"\n",
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
    assert!(up, "service did not answer DNS on port {port}");

    let before = query_a(port, "poll-check.example");
    assert_ne!(
        before.as_deref(),
        Some("0.0.0.0"),
        "domain blocked before it was added to the blocklist"
    );

    let mut f = OpenOptions::new()
        .append(true)
        .open(&block)
        .expect("open blocklist");
    f.write_all(b"poll-check.example\n").expect("append");
    f.flush().expect("flush");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut after = None;
    while Instant::now() < deadline {
        after = query_a(port, "poll-check.example");
        if after.as_deref() == Some("0.0.0.0") {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    let log_text = fs::read_to_string(&log_path).unwrap_or_default();
    assert_eq!(
        after.as_deref(),
        Some("0.0.0.0"),
        "blocklist edit not applied within 15s. service log:\n{log_text}"
    );
}
