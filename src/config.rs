use serde::Deserialize;
use std::path::PathBuf;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: std::net::SocketAddr,
    #[serde(default = "default_upstreams")]
    pub upstreams: Vec<std::net::SocketAddr>,
    #[serde(default)]
    pub blocklist: Option<PathBuf>,
    #[serde(default)]
    pub allowlist: Option<PathBuf>,
    #[serde(default = "default_timeout")]
    pub upstream_timeout_ms: u64,
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: usize,
    #[serde(default = "default_max_tcp")]
    pub max_tcp_connections: usize,
    #[serde(default = "default_tcp_idle")]
    pub tcp_idle_timeout_secs: u64,
    #[serde(default = "default_cache_dir")]
    pub cache_dir: PathBuf,
    #[serde(default = "default_refresh")]
    pub refresh_interval_secs: u64,
    #[serde(default)]
    pub allow_http: bool,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config error: {0}")]
    Msg(String),
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
            if self.upstreams.is_empty() { return Err(ConfigError::Msg("at least one upstream".into())); }
            if self.max_in_flight == 0 { return Err(ConfigError::Msg("max_in_flight must be > 0".into())); }
        if self.max_tcp_connections == 0 { return Err(ConfigError::Msg("max_tcp_connections must be > 0".into())); }
        if self.tcp_idle_timeout_secs == 0 { return Err(ConfigError::Msg("tcp_idle_timeout_secs must be > 0".into())); }
        if self.refresh_interval_secs == 0 { return Err(ConfigError::Msg("refresh_interval_secs must be > 0".into())); }
        Ok(())
    }

    pub fn sources(&self) -> (Option<ListSource>, Option<ListSource>) {
        let allow = self.allowlist.as_ref().map(|p| ListSource::parse(&p.to_string_lossy(), self.allow_http).unwrap_or_else(|_| ListSource::Local(p.clone())));
        let block = self.blocklist.as_ref().map(|p| ListSource::parse(&p.to_string_lossy(), self.allow_http).unwrap_or_else(|_| ListSource::Local(p.clone())));
        (allow, block)
    }

    pub fn load(path: Option<&PathBuf>) -> Result<Self, anyhow::Error> {
        let path = path.cloned().unwrap_or_else(|| PathBuf::from("config.toml"));
        if !path.exists() { anyhow::bail!("config file not found"); }
        let text = std::fs::read_to_string(&path)?;
        let config: Self = toml::from_str(&text)?;
        config.validate().map_err(|e| anyhow::anyhow!("{}", e))?;
        Ok(config)
    }
}

pub enum ListSource {
    Local(PathBuf),
    Remote(Url),
}

impl ListSource {
    pub fn parse(s: &str, allow_http: bool) -> Result<Self, ConfigError> {
        if s.starts_with("http://") || s.starts_with("https://") {
            let url = Url::parse(s).map_err(|e| ConfigError::Msg(e.to_string()))?;
            if url.scheme() == "http" && !allow_http {
                return Err(ConfigError::Msg("http not allowed".into()));
            }
            Ok(ListSource::Remote(url))
        } else {
            Ok(ListSource::Local(PathBuf::from(s)))
        }
    }
}

fn default_listen() -> std::net::SocketAddr { "127.0.0.1:5353".parse().unwrap() }
fn default_upstreams() -> Vec<std::net::SocketAddr> { vec!["1.1.1.1:53".parse().unwrap()] }
fn default_timeout() -> u64 { 2000 }
fn default_max_in_flight() -> usize { 1024 }
fn default_max_tcp() -> usize { 256 }
fn default_tcp_idle() -> u64 { 5 }
fn default_cache_dir() -> PathBuf { PathBuf::from("./list-cache") }
fn default_refresh() -> u64 { 86400 }
fn default_poll_interval() -> u64 { 5000 }

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            upstreams: default_upstreams(),
            blocklist: None,
            allowlist: None,
            upstream_timeout_ms: default_timeout(),
            max_in_flight: default_max_in_flight(),
            max_tcp_connections: default_max_tcp(),
            tcp_idle_timeout_secs: default_tcp_idle(),
            cache_dir: default_cache_dir(),
            refresh_interval_secs: default_refresh(),
            allow_http: false,
            poll_interval_ms: default_poll_interval(),
        }
    }
}