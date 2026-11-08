use dnsguard::config::Config;

#[test]
fn zero_refresh_interval_rejected() {
    let toml = "refresh_interval_secs = 0\n";
    let c: Config = toml::from_str(toml).unwrap();
    let err = c.validate().unwrap_err();
    assert!(err.to_string().contains("refresh_interval_secs"));
}

#[test]
fn http_rejected_by_default() {
    let src = "http://example.com/list.txt";
    let ls = dnsguard::config::ListSource::parse(src, false);
    assert!(ls.is_err());
}

#[test]
fn http_allowed_with_flag() {
    let src = "http://example.com/list.txt";
    let ls = dnsguard::config::ListSource::parse(src, true);
    assert!(ls.is_ok());
}

#[test]
fn https_accepted_by_default() {
    let src = "https://example.com/list.txt";
    let ls = dnsguard::config::ListSource::parse(src, false);
    assert!(ls.is_ok());
}
