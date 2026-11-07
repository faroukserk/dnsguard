use crate::cache::{CacheKey, DnsCache};
use crate::filter::Filter;
use crate::upstream::forward;
use hickory_proto::op::Message;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Semaphore;

pub struct State {
    pub upstreams: Vec<SocketAddr>,
    pub timeout_ms: u64,
    pub filter: Filter,
    pub cache: Option<Arc<DnsCache>>,
    pub udp_sem: Arc<Semaphore>,
    pub tcp_sem: Arc<Semaphore>,
    pub tcp_idle_timeout_secs: u64,
}

pub async fn handle_query(bytes: &[u8], state: &State) -> Option<Vec<u8>> {
    if bytes.len() < 12 { return None; }
    if bytes.len() > 4096 { return None; }
    // parse
    let msg = match Message::from_vec(bytes) {
        Ok(m) => m,
        Err(_) => {
            let mut out = bytes.to_vec();
            let flags = u16::from_be_bytes([out[2], out[3]]);
            let rd = flags & 0x0100;
            let new_flags = 0x8000 | rd | 0x0001;
            out[2] = (new_flags >> 8) as u8;
            out[3] = (new_flags & 0xff) as u8;
            out[6..8].copy_from_slice(&[0,0]);
            out[8..10].copy_from_slice(&[0,0]);
            out[10..12].copy_from_slice(&[0,0]);
            return Some(out);
        }
    };
    let question = msg.queries.first()?;
    let name = question.name().to_string().trim_end_matches('.').to_lowercase();
    let qtype = u16::from(question.query_type());

    // filter
    if let Some(resp) = state.filter.blocked_response(bytes) { return Some(resp); }

    // cache
    let key = CacheKey { name: name.clone(), record_type: qtype };
    if let Some(cache) = &state.cache && let Some(cached) = cache.get(&key).await {
        let mut m = cached;
        m.metadata.id = msg.metadata.id;
        if let Ok(v) = m.to_vec() { return Some(v); }
    }

    // forward
    let resp_bytes = forward(&state.upstreams, state.timeout_ms, bytes).await.ok()?;
    if let Some(cache) = &state.cache && let Ok(rmsg) = Message::from_vec(&resp_bytes) {
        cache.insert(key, rmsg).await;
    }
    Some(resp_bytes)
}

pub fn udp_limit(request: &Message) -> usize {
    let size = request.edns.as_ref().map(|e| e.max_payload() as usize).unwrap_or(512);
    size.clamp(512, 4096)
}

#[allow(clippy::result_unit_err)]
pub fn fit_for_udp(response: Message, limit: usize) -> Result<Vec<u8>, ()> {
    if let Ok(v) = response.to_vec() && v.len() <= limit { return Ok(v); }
    let mut r = response;
    r.answers.clear();
    r.authorities.clear();
    r.additionals.clear();
    r.metadata.truncation = true;
    r.to_vec().map_err(|_| ())
}
