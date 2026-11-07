use hickory_proto::op::Message;
use moka::future::Cache;
use std::time::{Duration, Instant};

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct CacheKey {
    pub name: String,
    pub record_type: u16,
}

#[derive(Clone)]
pub struct CacheEntry {
    pub message: Message,
    pub expires_at: Instant,
}

pub struct DnsCache {
    cache: Cache<CacheKey, CacheEntry>,
}

impl DnsCache {
    pub fn new(max_entries: u64) -> Self {
        Self { cache: Cache::new(max_entries) }
    }

    pub async fn get(&self, key: &CacheKey) -> Option<Message> {
        if let Some(entry) = self.cache.get(key).await {
            if Instant::now() >= entry.expires_at { return None; }
            let mut msg = entry.message.clone();
            let remaining = entry.expires_at.duration_since(Instant::now()).as_secs().max(1) as u32;
            for rec in &mut msg.answers { rec.ttl = remaining.min(rec.ttl).max(1); }
            for rec in &mut msg.authorities { rec.ttl = remaining.min(rec.ttl).max(1); }
            return Some(msg);
        }
        None
    }

    pub async fn insert(&self, key: CacheKey, msg: Message) {
        if let Some(ttl) = cache_ttl(&msg) {
            let entry = CacheEntry { message: msg, expires_at: Instant::now() + ttl };
            self.cache.insert(key, entry).await;
        }
    }
}

pub fn cache_ttl(msg: &Message) -> Option<Duration> {
    if msg.metadata.truncation { return None; }
    if msg.metadata.response_code != hickory_proto::op::ResponseCode::NoError {
        return None;
    }
    // SERVFAIL etc already handled by response_code? NoError only
    let answers = &msg.answers;
    if !answers.is_empty() {
        let min = answers.iter().map(|r| r.ttl).min().unwrap_or(0);
        if min == 0 { return None; }
        return Some(Duration::from_secs(min as u64).min(Duration::from_secs(86400)));
    }
    // NXDOMAIN/NODATA: SOA in authority
    for rec in &msg.authorities {
        let ttl = rec.ttl;
        if ttl > 0 { return Some(Duration::from_secs((ttl as u64).min(60))); }
    }
    Some(Duration::from_secs(60))
}
