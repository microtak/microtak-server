//! Connection admission for every listener: how many connections may be
//! open at once (in total and per client address), and how long a client
//! gets to finish the TLS handshake.
//!
//! Without these, anyone who can reach a port -- no certificate needed --
//! can open connections and never complete the handshake, holding a socket
//! and a task each until the server runs out of file descriptors.
//!
//! One [`Admission`] is shared by all listeners, so the total cap covers the
//! whole server. A [`Permit`] is held for the lifetime of a connection and
//! releases its slot on drop.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionLimits {
    /// How long a client gets to complete the TLS handshake.
    pub handshake_timeout: Duration,
    /// How long an HTTP listener waits for a request's headers to arrive
    /// (Slowloris: a connection kept open by an endless request).
    pub http_header_timeout: Duration,
    /// Open connections across all listeners.
    pub max_connections: usize,
    /// Open connections from one client address. Only meaningful when the
    /// server sees real client addresses (directly, or via PROXY protocol
    /// from a trusted proxy) -- behind a proxy that hides them, every client
    /// shares the proxy's address.
    pub max_connections_per_ip: usize,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            http_header_timeout: Duration::from_secs(10),
            max_connections: 1024,
            max_connections_per_ip: 64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Admission {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    limits: AdmissionLimits,
    open: Mutex<Open>,
}

#[derive(Debug, Default)]
struct Open {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

impl Default for Admission {
    fn default() -> Self {
        Self::new(AdmissionLimits::default())
    }
}

impl Admission {
    pub fn new(limits: AdmissionLimits) -> Self {
        Self {
            inner: Arc::new(Inner {
                limits,
                open: Mutex::new(Open::default()),
            }),
        }
    }

    pub fn handshake_timeout(&self) -> Duration {
        self.inner.limits.handshake_timeout
    }

    pub fn http_header_timeout(&self) -> Duration {
        self.inner.limits.http_header_timeout
    }

    /// A slot for one connection from `ip`, or `None` if the total or the
    /// per-address limit is reached (the caller drops the connection).
    pub fn admit(&self, ip: IpAddr) -> Option<Permit> {
        let limits = self.inner.limits;
        let mut open = self.inner.open.lock().unwrap();
        let from_ip = open.per_ip.get(&ip).copied().unwrap_or(0);
        if open.total >= limits.max_connections || from_ip >= limits.max_connections_per_ip {
            return None;
        }
        open.total += 1;
        open.per_ip.insert(ip, from_ip + 1);
        Some(Permit {
            inner: Arc::clone(&self.inner),
            ip,
        })
    }

    /// Currently open (admitted) connections.
    pub fn open_connections(&self) -> usize {
        self.inner.open.lock().unwrap().total
    }
}

/// One admitted connection; frees its slot when dropped.
#[derive(Debug)]
pub struct Permit {
    inner: Arc<Inner>,
    ip: IpAddr,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut open = self.inner.open.lock().unwrap();
        open.total -= 1;
        if let Some(count) = open.per_ip.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                open.per_ip.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(total: usize, per_ip: usize) -> AdmissionLimits {
        AdmissionLimits {
            max_connections: total,
            max_connections_per_ip: per_ip,
            ..AdmissionLimits::default()
        }
    }

    const A: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
    const B: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2));

    #[test]
    fn per_ip_limit_applies_per_address() {
        let admission = Admission::new(limits(10, 2));
        let _a1 = admission.admit(A).unwrap();
        let _a2 = admission.admit(A).unwrap();
        assert!(admission.admit(A).is_none(), "third from A is over the per-IP limit");
        assert!(admission.admit(B).is_some(), "B has its own allowance");
    }

    #[test]
    fn total_limit_applies_across_addresses() {
        let admission = Admission::new(limits(2, 10));
        let _a = admission.admit(A).unwrap();
        let _b = admission.admit(B).unwrap();
        assert!(admission.admit(B).is_none());
    }

    #[test]
    fn dropping_a_permit_frees_its_slot() {
        let admission = Admission::new(limits(1, 1));
        let permit = admission.admit(A).unwrap();
        assert!(admission.admit(A).is_none());
        drop(permit);
        assert_eq!(admission.open_connections(), 0);
        assert!(admission.admit(A).is_some());
    }
}
