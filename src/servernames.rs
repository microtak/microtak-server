//! The names (IP addresses and DNS names) the server certificate is issued
//! for, and keeping them current.
//!
//! A deployed MicroTAK box often has several addresses at once -- a LAN
//! port, Starlink, Wi-Fi, a second LAN -- and they change as links come and
//! go (DHCP leases, a Starlink dish reconnecting). Clients reach the server
//! by whichever address is reachable from where they are, so the server
//! certificate should name all of them. With `server_names_from_interfaces`
//! (on by default) the server lists its own interface addresses at startup
//! and re-checks them periodically; when the set changes it issues a fresh
//! server certificate from its own CA and swaps it into every listener live
//! -- no restart, and no effect on enrolled devices (they pin the CA, not a
//! particular server certificate).
//!
//! Inside a container on a bridge network the server only sees the
//! container's own address, not the host's -- there, list the host's
//! addresses in `server_names` (or use host networking).

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::PrivateKeyDer;
use tracing::{info, warn};

use crate::certsource::{self, SwappableCert};
use crate::pki::{self, CertificateAuthority, PkiError};

/// This host's interface addresses clients could plausibly reach it by:
/// loopback, link-local, and unspecified addresses are left out.
pub fn interface_addresses() -> Vec<String> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let set: BTreeSet<IpAddr> = interfaces
        .iter()
        .map(|interface| interface.ip())
        .filter(|ip| is_reachable_address(*ip))
        .collect();
    set.into_iter().map(|ip| ip.to_string()).collect()
}

fn is_reachable_address(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_link_local(),
        // fe80::/10
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

/// The full, de-duplicated SAN list: the common name first, then the
/// configured names, then (optionally) the detected interface addresses.
pub fn collect(common_name: &str, configured: &[String], interfaces: &[String]) -> Vec<String> {
    let mut names = vec![common_name.to_string()];
    for name in configured.iter().chain(interfaces) {
        if !names.contains(name) {
            names.push(name.clone());
        }
    }
    names
}

/// Issue a server certificate for `names` from `ca`, ready to serve.
pub fn issue_server_cert(
    ca: &CertificateAuthority,
    common_name: &str,
    names: &[String],
    validity: time::Duration,
) -> Result<(rustls::sign::CertifiedKey, rustls::pki_types::CertificateDer<'static>, PrivateKeyDer<'static>), ServerCertError> {
    let (csr, key) = pki::build_csr(common_name)?;
    let signed = ca.sign_server_csr(&csr, names, validity)?;
    let cert_der = pki::cert_pem_to_der(&signed.cert_pem)?;
    let key_der = PrivateKeyDer::from(key);
    let certified = certsource::certified_key(vec![cert_der.clone()], key_der.clone_key())?;
    Ok((certified, cert_der, key_der))
}

#[derive(Debug, thiserror::Error)]
pub enum ServerCertError {
    #[error(transparent)]
    Pki(#[from] PkiError),
    #[error(transparent)]
    Cert(#[from] certsource::CertLoadError),
}

/// Re-check the interface addresses every `interval`; when they change,
/// re-issue the server certificate and swap it into `target`.
pub async fn watch_interfaces(
    ca: CertificateAuthority,
    target: Arc<SwappableCert>,
    common_name: String,
    configured: Vec<String>,
    validity: time::Duration,
    interval: Duration,
    mut current: Vec<String>,
) {
    loop {
        tokio::time::sleep(interval).await;
        let names = collect(&common_name, &configured, &interface_addresses());
        if names == current {
            continue;
        }
        match issue_server_cert(&ca, &common_name, &names, validity) {
            Ok((certified, _, _)) => {
                target.replace(certified);
                info!(names = ?names, "network addresses changed -- re-issued the server certificate");
                current = names;
            }
            Err(error) => warn!(%error, "failed to re-issue the server certificate for changed addresses"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_addresses_no_client_can_reach_us_by() {
        for unreachable in ["127.0.0.1", "::1", "0.0.0.0", "169.254.10.20", "fe80::1", "224.0.0.1"] {
            assert!(!is_reachable_address(unreachable.parse().unwrap()), "{unreachable}");
        }
        for reachable in ["192.168.1.10", "10.5.0.2", "100.64.0.7", "2001:db8::5", "fd00::1"] {
            assert!(is_reachable_address(reachable.parse().unwrap()), "{reachable}");
        }
    }

    #[test]
    fn collect_puts_the_common_name_first_and_dedups() {
        let names = collect(
            "microtak-server",
            &["tak.example.com".into(), "192.168.1.10".into()],
            &["192.168.1.10".into(), "100.64.0.7".into()],
        );
        assert_eq!(
            names,
            vec!["microtak-server", "tak.example.com", "192.168.1.10", "100.64.0.7"]
        );
    }

    #[test]
    fn interface_addresses_never_include_loopback() {
        let addresses = interface_addresses();
        assert!(!addresses.iter().any(|a| a == "127.0.0.1" || a == "::1"));
    }
}
