use dnsguard::filter::Filter;
use dnsguard::handler::{handle_query, State};

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};

#[derive(Debug, Clone, Deserialize)]
struct Config {
    #[serde(default = "default_listen")]
    listen: SocketAddr,
    #[serde(default = "default_upstreams")]
    upstreams: Vec<SocketAddr>,
    #[serde(default)]
    blocklist: Option<PathBuf>,
    #[serde(default)]
    allowlist: Option<PathBuf>,
    #[serde(default = "default_timeout")]
    upstream_timeout_ms: u64,
    #[serde(default = "default_max_in_flight")]
    max_in_flight: usize,
    #[serde(default = "default_max_tcp")]
    max_tcp_connections: usize,
    #[serde(default = "default_tcp_idle")]
    tcp_idle_timeout_secs: u64,
}

fn default_listen() -> SocketAddr { "127.0.0.1:5353".parse().expect("valid default") }
fn default_upstreams() -> Vec<SocketAddr> { vec!["1.1.1.1:53".parse().expect("valid default")] }
fn default_timeout() -> u64 { 2000 }
fn default_max_in_flight() -> usize { 1024 }
fn default_max_tcp() -> usize { 256 }
fn default_tcp_idle() -> u64 { 5 }

impl Default for Config {
    fn default() -> Self { Self { listen: default_listen(), upstreams: default_upstreams(), blocklist: None, allowlist: None, upstream_timeout_ms: default_timeout(), max_in_flight: default_max_in_flight(), max_tcp_connections: default_max_tcp(), tcp_idle_timeout_secs: default_tcp_idle() } }
}

impl Config {
    fn load(path: Option<&PathBuf>) -> Result<Self> {
        let Some(path) = path else { return Ok(Self::default()) };
        let text = std::fs::read_to_string(path).with_context(|| format!("reading config {}", path.display()))?;
        let config: Self = toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        anyhow::ensure!(!config.upstreams.is_empty(), "at least one upstream is required");
        anyhow::ensure!(config.max_in_flight > 0, "max_in_flight must be > 0");
        anyhow::ensure!(config.max_tcp_connections > 0, "max_tcp_connections must be > 0");
        anyhow::ensure!(config.tcp_idle_timeout_secs > 0, "tcp_idle_timeout_secs must be > 0");
        Ok(config)
    }
}

#[derive(Debug, Parser)]
#[command(name = "dnsguard", about = "DNSGuard network filter")]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("dnsguard=info").init();
    let args = Args::parse();
    let config = Config::load(args.config.as_ref())?;
    let filter = Filter::load(config.blocklist.as_deref(), config.allowlist.as_deref());
    let state = Arc::new(State {
        upstreams: config.upstreams.clone(),
        timeout_ms: config.upstream_timeout_ms,
        filter,
        cache: None,
        udp_sem: Arc::new(tokio::sync::Semaphore::new(config.max_in_flight)),
        tcp_sem: Arc::new(tokio::sync::Semaphore::new(config.max_tcp_connections)),
        tcp_idle_timeout_secs: config.tcp_idle_timeout_secs,
    });
    let socket = std::sync::Arc::new(UdpSocket::bind(config.listen).await.context("binding UDP listener")?);
    info!(address = %socket.local_addr()?, "DNSGuard UDP listener started");

    let tcp_listener = TcpListener::bind(config.listen).await.context("binding TCP listener")?;
    info!(address = %tcp_listener.local_addr()?, "DNSGuard TCP listener started");

    let mut packet = [0_u8; 4096];
    loop {
        tokio::select! {
            result = socket.recv_from(&mut packet) => {
                let (length, client) = result.context("receiving UDP packet")?;
                if length < 12 {
                    warn!(%client, length, "dropping malformed DNS packet");
                    continue;
                }
                let request = packet[..length].to_vec();
                let permit = match state.udp_sem.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => { /* dropped_overload */ continue; }
                };
                let state = state.clone();
                let socket = socket.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    // parse for limit ...
                    let limit = if let Ok(m) = hickory_proto::op::Message::from_vec(&request) { dnsguard::handler::udp_limit(&m) } else { 512 };
                    if let Some(resp_bytes) = handle_query(&request, &state).await {
                        let out = if let Ok(m) = hickory_proto::op::Message::from_vec(&resp_bytes) {
                            dnsguard::handler::fit_for_udp(m, limit).unwrap_or(resp_bytes)
                        } else { resp_bytes };
                        let _ = socket.send_to(&out, client).await;
                    }
                });
            }
            result = tcp_listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        let permit = match state.tcp_sem.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => { let _ = stream; continue; }
                        };
                        info!(%peer, "TCP connection accepted");
                        let state = state.clone();
                        let idle = state.tcp_idle_timeout_secs;
                        tokio::spawn(async move {
                            let _permit = permit;
                            let mut stream = stream;
                            loop {
                                let mut len_buf = [0u8; 2];
                                match tokio::time::timeout(std::time::Duration::from_secs(idle), stream.read_exact(&mut len_buf)).await {
                                    Ok(Ok(_)) => {}
                                    _ => break,
                                }
                                let len = u16::from_be_bytes(len_buf) as usize;
                                if len == 0 { break; }
                                let mut buf = vec![0u8; len];
                                if tokio::time::timeout(std::time::Duration::from_secs(idle), stream.read_exact(&mut buf)).await.is_err() { break; }
                                if let Some(resp) = handle_query(&buf, &state).await {
                                    let mut out = Vec::with_capacity(resp.len() + 2);
                                    out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
                                    out.extend_from_slice(&resp);
                                    if stream.write_all(&out).await.is_err() { break; }
                                }
                            }
                            tracing::debug!(%peer, "TCP connection closed");
                        });
                    }
                    Err(e) => warn!(error = %e, "TCP accept failed"),
                }
            }
            _ = tokio::signal::ctrl_c() => { info!("shutting down"); break; }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_config_has_local_listener_and_upstream() {
        let config = Config::default();
        assert_eq!(config.listen, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(config.upstreams.len(), 1);
    }

    #[test]
    fn config_rejects_empty_upstreams() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "upstreams = []").unwrap();
        let error = Config::load(Some(&file.path().to_path_buf())).unwrap_err();
        assert!(error.to_string().contains("at least one upstream"));
    }
}
