//! Which address a request really came from, for rate limiting.
//!
//! Behind a reverse proxy (Traefik, Pangolin) every request arrives from the
//! proxy's own address -- rate limiting on that would let one misbehaving
//! client lock *everyone* out. So for connections from a configured
//! **trusted proxy**, the client address is taken from `X-Forwarded-For`
//! instead: the right-most entry that is not itself a trusted proxy (entries
//! further left are client-supplied and can't be trusted). For any other
//! connection the header is ignored entirely -- a client can't pick its own
//! rate-limit bucket by sending one.

use std::net::IpAddr;

use axum::http::HeaderMap;

/// A list of trusted proxy networks (`"172.18.0.0/16"`, or a single
/// address such as `"10.0.0.5"`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<(IpAddr, u8)>);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid trusted proxy '{0}': expected an IP address or CIDR network")]
pub struct InvalidTrustedProxy(pub String);

impl TrustedProxies {
    pub fn parse(entries: &[String]) -> Result<Self, InvalidTrustedProxy> {
        entries
            .iter()
            .map(|entry| parse_cidr(entry).ok_or_else(|| InvalidTrustedProxy(entry.clone())))
            .collect::<Result<_, _>>()
            .map(Self)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        self.0
            .iter()
            .any(|(network, prefix)| in_network(ip, *network, *prefix))
    }

    /// The address to attribute a request to -- see the module docs.
    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        if !self.contains(peer) {
            return peer;
        }
        let forwarded: Vec<IpAddr> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .filter_map(|entry| entry.trim().parse().ok())
            .collect();
        forwarded
            .into_iter()
            .rev()
            .find(|ip| !self.contains(*ip))
            .unwrap_or(peer)
    }
}

fn parse_cidr(entry: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = match entry.trim().split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (entry.trim(), None),
    };
    let ip = canonical(address.parse().ok()?);
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix.parse().ok().filter(|p| *p <= max)?,
        None => max,
    };
    Some((ip, prefix))
}

/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`, how a dual-stack socket reports an
/// IPv4 peer) compares as plain IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn in_network(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(ip) & mask == u32::from(net) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(ip) & mask == u128::from(net) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxies(entries: &[&str]) -> TrustedProxies {
        TrustedProxies::parse(&entries.iter().map(|e| e.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn xff(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", value.parse().unwrap());
        headers
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_networks_and_single_addresses() {
        let trusted = proxies(&["172.18.0.0/16", "10.0.0.5", "fd00::/8"]);
        assert!(trusted.contains(ip("172.18.3.4")));
        assert!(!trusted.contains(ip("172.19.0.1")));
        assert!(trusted.contains(ip("10.0.0.5")));
        assert!(!trusted.contains(ip("10.0.0.6")));
        assert!(trusted.contains(ip("fd12::1")));
        assert!(trusted.contains(ip("::ffff:172.18.0.9")), "IPv4-mapped peers match");
        assert!(proxies(&["0.0.0.0/0"]).contains(ip("8.8.8.8")));
    }

    #[test]
    fn rejects_malformed_entries() {
        for bad in ["not-an-ip", "10.0.0.0/33", "fd00::/129", "10.0.0.0/x"] {
            assert_eq!(
                TrustedProxies::parse(&[bad.to_string()]),
                Err(InvalidTrustedProxy(bad.to_string()))
            );
        }
    }

    /// The core anti-spoofing property: a client that isn't a trusted proxy
    /// can't choose its rate-limit bucket by sending the header.
    #[test]
    fn ignores_forwarded_for_from_an_untrusted_peer() {
        let trusted = proxies(&["172.18.0.0/16"]);
        assert_eq!(trusted.client_ip(ip("203.0.113.9"), &xff("1.2.3.4")), ip("203.0.113.9"));
        assert_eq!(
            TrustedProxies::default().client_ip(ip("172.18.0.2"), &xff("1.2.3.4")),
            ip("172.18.0.2"),
            "no trusted proxies configured means the header is never read"
        );
    }

    /// From a trusted proxy, the right-most untrusted entry is the client;
    /// entries to its left were supplied by the client and are ignored.
    #[test]
    fn takes_the_rightmost_untrusted_forwarded_address_from_a_trusted_proxy() {
        let trusted = proxies(&["172.18.0.0/16", "10.9.9.9"]);
        let peer = ip("172.18.0.2");
        assert_eq!(trusted.client_ip(peer, &xff("198.51.100.7")), ip("198.51.100.7"));
        assert_eq!(
            trusted.client_ip(peer, &xff("6.6.6.6, 198.51.100.7, 10.9.9.9")),
            ip("198.51.100.7"),
            "a spoofed left-most entry is skipped, a trusted hop is skipped"
        );
        assert_eq!(trusted.client_ip(peer, &HeaderMap::new()), peer, "no header: the proxy itself");
        assert_eq!(trusted.client_ip(peer, &xff("garbage")), peer);
    }
}
