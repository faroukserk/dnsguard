use std::collections::HashSet;
use std::fs;
use std::path::Path;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum FilterError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("file has no valid rules: {0}")]
    Empty(String),
}

impl Filter {
    pub fn from_files(allow: &std::path::Path, block: &std::path::Path) -> Result<Self, FilterError> {
        let allow_bytes = std::fs::read(allow)?;
        let block_bytes = std::fs::read(block)?;
        Self::from_bytes(&allow_bytes, &block_bytes)
    }

    pub fn from_bytes(allow: &[u8], block: &[u8]) -> Result<Self, FilterError> {
        let allow_text = std::str::from_utf8(allow).map_err(|e| FilterError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())))?;
        let block_text = std::str::from_utf8(block).map_err(|e| FilterError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())))?;
        let allowed = parse_list_text(allow_text);
        let blocked = parse_list_text(block_text);
        if blocked.is_empty() { return Err(FilterError::Empty("block".into())); }
        Ok(Self::new(blocked, allowed))
    }
}
use hickory_proto::op::Message;
use hickory_proto::rr::Name;

pub fn names_in_chain(msg: &Message) -> Vec<Name> {
    let mut out = Vec::new();
    if let Some(q) = msg.queries.first() {
        out.push(q.name().clone());
    }
    let mut seen = std::collections::HashSet::new();
    let mut current = out.first().cloned();
    // walk CNAMEs
    let mut hops = 0;
    while hops < 8 {
        // find cname for current
        let mut next = None;
        for rr in &msg.answers {
            if let hickory_proto::rr::RData::CNAME(cname) = &rr.data
                && Some(rr.name.clone()) == current {
                next = Some(cname.0.clone());
                break;
            }
        }
        match next {
            Some(n) => {
                if seen.contains(&n) { break; } // loop
                seen.insert(n.clone());
                out.push(n.clone());
                current = Some(n);
                hops += 1;
            }
            None => break,
        }
    }
    out.truncate(9); // query + up to 8
    out
}
#[derive(Default, Clone)]
pub struct Filter {
    blocked: HashSet<String>,
    allowed: HashSet<String>,
}

impl Filter {
    pub fn new(blocked: HashSet<String>, allowed: HashSet<String>) -> Self {
        Self { blocked: normalize_set(blocked), allowed: normalize_set(allowed) }
    }

    pub fn load(blocklist: Option<&Path>, allowlist: Option<&Path>) -> Self {
        let blocked = blocklist.map(load_list).unwrap_or_default();
        let allowed = allowlist.map(load_list).unwrap_or_default();
        Self::new(blocked, allowed)
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        let d = normalize(domain);
        // allowlist precedence
        if suffix_match(&self.allowed, &d) { return false; }
        suffix_match(&self.blocked, &d)
    }

    pub fn blocked_response(&self, request: &[u8]) -> Option<Vec<u8>> {
        let (domain, qtype) = parse_question(request)?;
        if !self.is_blocked(&domain) { return None; }
        Some(build_blocked(request, qtype))
    }
    pub fn forced_blocked_response(&self, request: &[u8]) -> Option<Vec<u8>> {
        let (_, qtype) = parse_question(request)?;
        Some(build_blocked(request, qtype))
    }
}

fn normalize(s: &str) -> String {
    s.trim().trim_end_matches('.').to_lowercase()
}

fn normalize_set(set: HashSet<String>) -> HashSet<String> {
    set.into_iter().map(|s| normalize(&s)).filter(|s| !s.is_empty()).collect()
}

fn suffix_match(set: &HashSet<String>, domain: &str) -> bool {
    let mut current = domain.to_string();
    loop {
        if set.contains(&current) { return true; }
        match current.find('.') {
            Some(i) => current = current[i+1..].to_string(),
            None => break,
        }
    }
    false
}

fn parse_list_text(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() { continue; }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let domain = if parts.len() >= 2 { parts[parts.len()-1] } else { parts[0] };
        if !domain.is_empty() { out.insert(domain.to_string()); }
    }
    out
}

fn load_list(path: &Path) -> HashSet<String> {
    fs::read_to_string(path).map(|t| parse_list_text(&t)).unwrap_or_default()
}

fn parse_question(request: &[u8]) -> Option<(String, u16)> {
    if request.len() < 12 { return None; }
    let mut pos = 12;
    let mut labels = Vec::new();
    while pos < request.len() {
        let len = request[pos] as usize;
        if len == 0 { pos += 1; break; }
        if pos + 1 + len > request.len() { return None; }
        labels.push(String::from_utf8_lossy(&request[pos+1..pos+1+len]).to_string());
        pos += 1 + len;
    }
    if pos + 4 > request.len() { return None; }
    let qtype = u16::from_be_bytes([request[pos], request[pos+1]]);
    let domain = labels.join(".");
    Some((domain, qtype))
}

fn build_blocked(request: &[u8], qtype: u16) -> Vec<u8> {
    // A/AAAA -> zero IP; else NXDOMAIN
    let is_a = qtype == 1;
    let is_aaaa = qtype == 28;
    if !is_a && !is_aaaa {
        // NXDOMAIN: copy request, set QR+RCODE 3
        let mut out = request.to_vec();
        if out.len() < 12 { out.resize(12, 0); }
        let flags = u16::from_be_bytes([out[2], out[3]]);
        let opcode = flags & 0x7800;
        let new_flags = opcode | 0x8000 | 0x0003;
        out[2] = (new_flags >> 8) as u8;
        out[3] = (new_flags & 0xff) as u8;
        out[6..8].copy_from_slice(&[0,0]);
        out[8..10].copy_from_slice(&[0,0]);
        out[10..12].copy_from_slice(&[0,0]);
        return out;
    }
    // find end of question section
    let mut pos = 12;
    while pos < request.len() && request[pos] != 0 { pos += 1 + request[pos] as usize; }
    if pos >= request.len() { return request.to_vec(); }
    pos += 1; // null
    let question_end = pos + 4; // qtype+qclass
    let mut out = Vec::with_capacity(request.len() + 16);
    // header
    out.extend_from_slice(&request[..2]); // id
    let flags = u16::from_be_bytes([request[2], request[3]]);
    let opcode = flags & 0x7800;
    let new_flags = opcode | 0x8000; // QR, NOERROR
    out.extend_from_slice(&new_flags.to_be_bytes());
    out.extend_from_slice(&[0,1]); // qdcount
    out.extend_from_slice(&[0,1]); // ancount
    out.extend_from_slice(&[0,0]); // nscount
    out.extend_from_slice(&[0,0]); // arcount
    // question
    out.extend_from_slice(&request[12..question_end]);
    // answer name pointer to question name (offset 12)
    out.extend_from_slice(&[0xC0, 0x0C]);
    // type
    out.extend_from_slice(&qtype.to_be_bytes());
    // class IN
    out.extend_from_slice(&[0,1]);
    // TTL (60)
    out.extend_from_slice(&60u32.to_be_bytes());
    if is_a {
        out.extend_from_slice(&[0,4]); // rdlength
        out.extend_from_slice(&[0,0,0,0]);
    } else {
        out.extend_from_slice(&[0,16]);
        out.extend_from_slice(&[0u8;16]);
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn suffix_matching_blocks_subdomain() {
        let f = Filter::new(["ads.example.com".to_string()].into(), HashSet::new());
        assert!(f.is_blocked("a.b.ads.example.com"));
        assert!(f.is_blocked("ads.example.com"));
        assert!(!f.is_blocked("example.com"));
    }

    #[test]
    fn allowlist_precedence() {
        let f = Filter::new(
            ["example.com".to_string()].into(),
            ["safe.example.com".to_string()].into(),
        );
        assert!(f.is_blocked("ads.example.com"));
        assert!(!f.is_blocked("safe.example.com"));
    }

    #[test]
    fn load_hosts_style_list() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "0.0.0.0 ads.example.com").unwrap();
        writeln!(file, "# comment").unwrap();
        writeln!(file, "tracker.example.com").unwrap();
        let set = load_list(file.path());
        assert!(set.contains("ads.example.com"));
        assert!(set.contains("tracker.example.com"));
    }
}
