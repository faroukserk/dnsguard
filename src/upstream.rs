use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

pub async fn forward(upstreams: &[SocketAddr], timeout_ms: u64, request: &[u8]) -> Result<Vec<u8>> {
    let id = if request.len() >= 2 { u16::from_be_bytes([request[0], request[1]]) } else { 0 };
    for upstream in upstreams {
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => continue,
        };
        if socket.send_to(request, upstream).await.is_err() { continue; }
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        let mut buf = [0u8; 4096];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() { break; }
            match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id => {
                    return Ok(buf[..n].to_vec());
                }
                Ok(Ok(_)) => continue,
                _ => break,
            }
        }
    }
    Ok(servfail(request))
}

fn servfail(request: &[u8]) -> Vec<u8> {
    let mut out = request.to_vec();
    if out.len() < 12 { out.resize(12, 0); }
    // flags bytes 2,3: set QR=1, RCODE=2 (SERVFAIL), keep opcode
    let flags = u16::from_be_bytes([out[2], out[3]]);
    let opcode = flags & 0x7800;
    let new_flags = opcode | 0x8000 | 0x0002;
    out[2] = (new_flags >> 8) as u8;
    out[3] = (new_flags & 0xff) as u8;
    // zero answer/authority/additional counts
    out[6..8].copy_from_slice(&[0,0]);
    out[8..10].copy_from_slice(&[0,0]);
    out[10..12].copy_from_slice(&[0,0]);
    out
}
