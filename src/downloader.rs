use reqwest::Client;
use url::Url;

#[derive(Debug)]
pub enum DownloadError {
    Status(u16),
    Empty,
    TooLarge,
    Other(String),
}

pub async fn fetch_list(client: &Client, url: &Url, max_bytes: usize) -> Result<Vec<u8>, DownloadError> {
    let resp = client.get(url.as_str()).timeout(std::time::Duration::from_secs(10)).send().await.map_err(|e| DownloadError::Other(e.to_string()))?;
    if !resp.status().is_success() { return Err(DownloadError::Status(resp.status().as_u16())); }
    let bytes = resp.bytes().await.map_err(|e| DownloadError::Other(e.to_string()))?;
    if bytes.is_empty() { return Err(DownloadError::Empty); }
    if bytes.len() > max_bytes { return Err(DownloadError::TooLarge); }
    Ok(bytes.to_vec())
}
