//! PROXY protocol (v1 text and v2 binary, as sent by HAProxy, Traefik and
//! cloud load balancers): a TCP proxy in front of MicroTAK prepends the real
//! client address to the connection, so connection limits, rate limiting,
//! logs and `clientEndPoints` see the client instead of the proxy.
//!
//! Only honoured from configured proxies (`proxy_protocol_from`): a header
//! from anyone else is not parsed (the bytes then reach the TLS handshake,
//! which fails), so clients can't spoof their address. From a configured
//! proxy the header is optional -- a connection without one keeps the
//! proxy's own address (e.g. a health check).
//!
//! Spec: <https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt>.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
const V1_PREFIX: &[u8] = b"PROXY ";
/// Longest valid v1 header, CRLF included.
const V1_MAX: usize = 107;

#[derive(Debug, thiserror::Error)]
pub enum ProxyHeaderError {
    #[error("malformed PROXY protocol header: {0}")]
    Malformed(&'static str),
    #[error("timed out waiting for the PROXY protocol header")]
    Timeout,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// If `stream` starts with a PROXY header, consume exactly that header and
/// return the client address it names (`None` for a `LOCAL`/`UNKNOWN`
/// header, i.e. "use the connection's own address"). Without a header,
/// nothing is consumed and `None` is returned.
pub async fn read_header(stream: &mut TcpStream, wait: Duration) -> Result<Option<SocketAddr>, ProxyHeaderError> {
    tokio::time::timeout(wait, read_header_inner(stream))
        .await
        .map_err(|_| ProxyHeaderError::Timeout)?
}

async fn read_header_inner(stream: &mut TcpStream) -> Result<Option<SocketAddr>, ProxyHeaderError> {
    // Peek until we can tell whether a header is there at all. A TLS
    // ClientHello starts with 0x16, so one differing byte decides.
    let mut peeked = [0u8; 16];
    let n = loop {
        let n = stream.peek(&mut peeked).await?;
        if n == 0 {
            return Ok(None); // closed before sending anything
        }
        let looks_v2 = V2_SIGNATURE.starts_with(&peeked[..n.min(12)]);
        let looks_v1 = V1_PREFIX.starts_with(&peeked[..n.min(V1_PREFIX.len())]);
        if !(looks_v2 || looks_v1) {
            return Ok(None);
        }
        if n >= 16 || (looks_v1 && n >= V1_PREFIX.len()) {
            break n;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    };

    if n >= 16 && peeked[..12] == V2_SIGNATURE {
        let mut header = [0u8; 16];
        stream.read_exact(&mut header).await?;
        let len = u16::from_be_bytes([header[14], header[15]]) as usize;
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await?;
        return parse_v2(&header, &payload);
    }

    // v1: read up to and including CRLF, byte by byte so nothing past the
    // header is consumed.
    let mut line = Vec::with_capacity(V1_MAX);
    loop {
        let byte = stream.read_u8().await?;
        line.push(byte);
        if line.ends_with(b"\r\n") {
            break;
        }
        if line.len() >= V1_MAX {
            return Err(ProxyHeaderError::Malformed("v1 header too long"));
        }
    }
    parse_v1(&line)
}

fn parse_v1(line: &[u8]) -> Result<Option<SocketAddr>, ProxyHeaderError> {
    let text = std::str::from_utf8(line).map_err(|_| ProxyHeaderError::Malformed("v1 header not ASCII"))?;
    let text = text.strip_suffix("\r\n").ok_or(ProxyHeaderError::Malformed("v1 header without CRLF"))?;
    let mut parts = text.split(' ');
    if parts.next() != Some("PROXY") {
        return Err(ProxyHeaderError::Malformed("v1 header without PROXY"));
    }
    match parts.next() {
        Some("UNKNOWN") => Ok(None),
        Some("TCP4") | Some("TCP6") => {
            let source: IpAddr = parts
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or(ProxyHeaderError::Malformed("v1 source address"))?;
            let _destination = parts.next();
            let port: u16 = parts
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or(ProxyHeaderError::Malformed("v1 source port"))?;
            Ok(Some(SocketAddr::new(source, port)))
        }
        _ => Err(ProxyHeaderError::Malformed("v1 protocol")),
    }
}

fn parse_v2(header: &[u8; 16], payload: &[u8]) -> Result<Option<SocketAddr>, ProxyHeaderError> {
    let version_command = header[12];
    if version_command >> 4 != 2 {
        return Err(ProxyHeaderError::Malformed("v2 version"));
    }
    match version_command & 0x0f {
        0 => return Ok(None), // LOCAL: e.g. the proxy's own health check
        1 => {}
        _ => return Err(ProxyHeaderError::Malformed("v2 command")),
    }
    match header[13] >> 4 {
        0x1 if payload.len() >= 12 => {
            let ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let port = u16::from_be_bytes([payload[8], payload[9]]);
            Ok(Some(SocketAddr::new(IpAddr::V4(ip), port)))
        }
        0x2 if payload.len() >= 36 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&payload[..16]);
            let port = u16::from_be_bytes([payload[32], payload[33]]);
            Ok(Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)))
        }
        0x0 => Ok(None), // AF_UNSPEC
        _ => Err(ProxyHeaderError::Malformed("v2 address family or length")),
    }
}

/// A v2 header for `client` -> `server`, as a proxy would send it (used by
/// tests here and elsewhere).
pub fn encode_v2(client: SocketAddr, server: SocketAddr) -> Vec<u8> {
    let mut out = V2_SIGNATURE.to_vec();
    out.push(0x21); // version 2, PROXY
    match (client, server) {
        (SocketAddr::V4(c), SocketAddr::V4(s)) => {
            out.push(0x11); // AF_INET, STREAM
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&c.ip().octets());
            out.extend_from_slice(&s.ip().octets());
            out.extend_from_slice(&c.port().to_be_bytes());
            out.extend_from_slice(&s.port().to_be_bytes());
        }
        (c, s) => {
            let v6 = |a: SocketAddr| match a.ip() {
                IpAddr::V4(ip) => ip.to_ipv6_mapped(),
                IpAddr::V6(ip) => ip,
            };
            out.push(0x21); // AF_INET6, STREAM
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&v6(c).octets());
            out.extend_from_slice(&v6(s).octets());
            out.extend_from_slice(&c.port().to_be_bytes());
            out.extend_from_slice(&s.port().to_be_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// Send `bytes` over a real socket and run [`read_header`] on the server
    /// side; returns the parsed address and whatever followed the header.
    async fn roundtrip(bytes: Vec<u8>) -> (Result<Option<SocketAddr>, ProxyHeaderError>, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let (mut server, _) = listener.accept().await.unwrap();
        let parsed = read_header(&mut server, Duration::from_secs(2)).await;
        let mut rest = Vec::new();
        let _ = server.read_to_end(&mut rest).await;
        client.await.unwrap();
        (parsed, rest)
    }

    #[tokio::test]
    async fn v2_ipv4_header_is_parsed_and_consumed_exactly() {
        let client: SocketAddr = "203.0.113.7:51234".parse().unwrap();
        let mut bytes = encode_v2(client, "10.0.0.1:8089".parse().unwrap());
        bytes.extend_from_slice(b"\x16\x03\x01TLS");
        let (parsed, rest) = roundtrip(bytes).await;
        assert_eq!(parsed.unwrap(), Some(client));
        assert_eq!(rest, b"\x16\x03\x01TLS");
    }

    #[tokio::test]
    async fn v2_ipv6_header_is_parsed() {
        let client: SocketAddr = "[2001:db8::7]:4000".parse().unwrap();
        let bytes = encode_v2(client, "[2001:db8::1]:8443".parse().unwrap());
        assert_eq!(roundtrip(bytes).await.0.unwrap(), Some(client));
    }

    #[tokio::test]
    async fn v1_header_is_parsed_and_consumed_exactly() {
        let mut bytes = b"PROXY TCP4 198.51.100.9 10.0.0.1 40000 8089\r\n".to_vec();
        bytes.extend_from_slice(b"\x16rest");
        let (parsed, rest) = roundtrip(bytes).await;
        assert_eq!(parsed.unwrap(), Some("198.51.100.9:40000".parse().unwrap()));
        assert_eq!(rest, b"\x16rest");
    }

    #[tokio::test]
    async fn without_a_header_nothing_is_consumed() {
        let (parsed, rest) = roundtrip(b"\x16\x03\x01hello".to_vec()).await;
        assert_eq!(parsed.unwrap(), None);
        assert_eq!(rest, b"\x16\x03\x01hello");
    }

    #[tokio::test]
    async fn local_and_unknown_headers_mean_use_the_connection_address() {
        let mut local = V2_SIGNATURE.to_vec();
        local.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
        assert_eq!(roundtrip(local).await.0.unwrap(), None);
        assert_eq!(roundtrip(b"PROXY UNKNOWN\r\n".to_vec()).await.0.unwrap(), None);
    }

    #[tokio::test]
    async fn malformed_headers_are_errors() {
        assert!(roundtrip(b"PROXY TCP4 not-an-ip 10.0.0.1 1 2\r\n".to_vec()).await.0.is_err());
        let mut bad_version = V2_SIGNATURE.to_vec();
        bad_version.extend_from_slice(&[0x31, 0x11, 0x00, 0x00]);
        assert!(roundtrip(bad_version).await.0.is_err());
        let endless = [b"PROXY TCP4 ".to_vec(), vec![b'1'; 200]].concat();
        assert!(roundtrip(endless).await.0.is_err());
    }
}
