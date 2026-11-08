use dnsguard::filter::Filter;
use dnsguard::handler::{handle_query, State};

use anyhow::{Context, Result};
use clap::Parser;
use std::{path::{Path, PathBuf}};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};

use dnsguard::config::Config;
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
    let config_path = args.config.clone();
    let config = Config::load(args.config.as_ref())?;
    let filter = arc_swap::ArcSwap::new(Arc::new(Filter::load(config.blocklist.as_deref(), config.allowlist.as_deref())));
    // cache-first startup for remote sources
    let (allow_src, block_src) = config.sources();
    let mut allow_bytes = Vec::new();
    let mut block_bytes = Vec::new();
    let mut any_cached = false;
    if let Some(dnsguard::config::ListSource::Remote(url)) = allow_src {
        let cp = dnsguard::list_cache::cache_path_for(&PathBuf::from(&config.cache_dir), &url);
        if let Some(b) = dnsguard::list_cache::read_cached(&cp) { allow_bytes = b; any_cached = true; }
        else { info!(url = %url, "remote source has no cache yet"); }
    }
    if let Some(dnsguard::config::ListSource::Remote(url)) = block_src {
        let cp = dnsguard::list_cache::cache_path_for(&PathBuf::from(&config.cache_dir), &url);
        if let Some(b) = dnsguard::list_cache::read_cached(&cp) { block_bytes = b; any_cached = true; info!(url = %url, "loaded remote list from cache"); }
        else { info!(url = %url, "remote source has no cache yet"); }
    }
    if any_cached && !block_bytes.is_empty() && let Ok(f) = Filter::from_bytes(&allow_bytes, &block_bytes) {
        info!(allow_bytes = allow_bytes.len(), block_bytes = block_bytes.len(), "loaded remote lists from cache");
        filter.store(Arc::new(f));
    }
    let state = Arc::new(State {
        upstreams: config.upstreams.clone(),
        timeout_ms: config.upstream_timeout_ms,
        filter,
        cache: None,
        udp_sem: Arc::new(tokio::sync::Semaphore::new(config.max_in_flight)),
        tcp_sem: Arc::new(tokio::sync::Semaphore::new(config.max_tcp_connections)),
        tcp_idle_timeout_secs: config.tcp_idle_timeout_secs,
        filter_reloads: std::sync::atomic::AtomicU64::new(0),
        filter_reload_failures: std::sync::atomic::AtomicU64::new(0),
        list_downloads: std::sync::atomic::AtomicU64::new(0),
        list_download_failures: std::sync::atomic::AtomicU64::new(0),
    });
    let config_dir = config_path.map(|p| p.parent().unwrap_or(Path::new(".")).to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
    let allow_path = config.allowlist.as_ref().map(|p| if p.is_absolute() { p.clone() } else { config_dir.join(p) });
    let block_path = config.blocklist.as_ref().map(|p| if p.is_absolute() { p.clone() } else { config_dir.join(p) });
    if let (Some(allow), Some(block)) = (allow_path.clone(), block_path.clone()) {
        let poll_ms = config.poll_interval_ms;
        let state_watch = state.clone();
        let allow_w = allow.clone();
        let block_w = block.clone();
        tokio::spawn(async move {
            let mut last_allow = std::fs::metadata(&allow_w).and_then(|m| m.modified()).ok();
            let mut last_block = std::fs::metadata(&block_w).and_then(|m| m.modified()).ok();
            let mut last_allow_len = std::fs::metadata(&allow_w).map(|m| m.len()).ok();
            let mut last_block_len = std::fs::metadata(&block_w).map(|m| m.len()).ok();
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(poll_ms));
            loop {
                interval.tick().await;
                tracing::debug!("file watch tick");
                let cur_allow = std::fs::metadata(&allow_w).and_then(|m| m.modified()).ok();
                let cur_block = std::fs::metadata(&block_w).and_then(|m| m.modified()).ok();
                let cur_allow_len = std::fs::metadata(&allow_w).map(|m| m.len()).ok();
                let cur_block_len = std::fs::metadata(&block_w).map(|m| m.len()).ok();
                if cur_allow != last_allow || cur_block != last_block || cur_allow_len != last_allow_len || cur_block_len != last_block_len {
                    tracing::info!("file change detected, reloading");
                    if state_watch.reload(&allow_w, &block_w).is_ok() {
                        tracing::info!("filter reloaded (file change)");
                    }
                    last_allow = cur_allow;
                    last_block = cur_block;
                    last_allow_len = cur_allow_len;
                    last_block_len = cur_block_len;
                }
            }
        });
        // keep signal handler too
        let state_sig = state.clone();
        let allow_s = allow.clone();
        let block_s = block.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                if let Ok(mut sig) = signal(SignalKind::hangup()) {
                    loop {
                        sig.recv().await;
                        if state_sig.reload(&allow_s, &block_s).is_ok() {
                            tracing::info!("filter reloaded");
                        }
                    }
                }
            }
            #[cfg(windows)]
            {
                if let Ok(mut ctrl) = tokio::signal::windows::ctrl_break() {
                    loop {
                        ctrl.recv().await;
                        if state_sig.reload(&allow_s, &block_s).is_ok() {
                            tracing::info!("filter reloaded");
                        }
                    }
                }
            }
        });
    } else {
        warn!("reload disabled: allowlist/blocklist not configured");
    }
    // background fetch for remote block source
    if let Some(dnsguard::config::ListSource::Remote(url)) = config.sources().1 {
        tracing::info!(url = %url, "starting remote list fetch");
        let state_bg = state.clone();
        let cache_dir = PathBuf::from(&config.cache_dir);
        let cp = dnsguard::list_cache::cache_path_for(&cache_dir, &url);
        let client = reqwest::Client::new();
        let url_c = url.clone();
        tokio::spawn(async move {
            match dnsguard::downloader::fetch_list(&client, &url_c, 20 * 1024 * 1024).await {
                Ok(bytes) => {
                    if dnsguard::list_cache::write_atomic(&cp, &bytes).is_ok() {
                        let allow_bytes = dnsguard::list_cache::read_cached(&dnsguard::list_cache::cache_path_for(&cache_dir, &url_c)).unwrap_or_default();
                        // allow empty ok
                        let _ = allow_bytes;
                        let allow = Vec::new();
                        if state_bg.reload_from_bytes(&allow, &bytes).is_ok() {
                            tracing::info!(url = %url_c, "remote list downloaded");
                        }
                    }
                }
                Err(e) => {
                    state_bg.list_download_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(url = %url_c, error = ?e, "remote list download failed");
                }
            }
        });
    }
    // scheduled refresh task for every remote source
    for src in [config.sources().0, config.sources().1].into_iter().flatten() {
        if let dnsguard::config::ListSource::Remote(url) = src {
            let state_r = state.clone();
            let cache_dir = PathBuf::from(&config.cache_dir);
            let cp = dnsguard::list_cache::cache_path_for(&cache_dir, &url);
            let client = reqwest::Client::new();
            let url_r = url.clone();
            let interval_secs = config.refresh_interval_secs.max(1);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                ticker.tick().await; // skip immediate
                loop {
                    ticker.tick().await;
                    match dnsguard::downloader::fetch_list(&client, &url_r, 20 * 1024 * 1024).await {
                        Ok(bytes) => {
                            if dnsguard::list_cache::write_atomic(&cp, &bytes).is_ok() {
                                let allow = Vec::new();
                                let _ = state_r.reload_from_bytes(&allow, &bytes);
                            }
                        }
                        Err(e) => {
                            state_r.list_download_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tracing::warn!(url = %url_r, error = ?e, "remote list refresh failed");
                        }
                    }
                }
            });
        }
    }
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
