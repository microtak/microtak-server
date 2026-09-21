//! mTLS-authenticated CoT relay listener.
//!
//! Same framing/relay behavior as [`super::tcp`] (built on the same
//! [`super::codec::StreamDecoder`] and broadcast-based relay), but requires
//! a valid client certificate signed by the configured CA before any CoT is
//! accepted (`docs/TEST-PLAN.md` §3, TC-TLS-01/02/03).
//!
//! **Not yet implemented**: binding the authenticated cert's Common Name to
//! the CoT event's own `uid` (TC-TLS-04) — that depends on a device
//! registry (the planned `users` module, not yet built; see `src/lib.rs`).
//! This module only extracts and logs the peer CN today.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use super::codec::{DecodedItem, StreamDecoder};

const BROADCAST_CAPACITY: usize = 1024;

#[derive(Clone)]
struct Outbound {
    sender: SocketAddr,
    xml: Arc<str>,
}

/// Build a server TLS config that requires a client certificate signed by
/// `ca_cert_der`, presenting `server_cert_chain`/`server_key` as this
/// server's own identity. `client_cert_verifier` is intentionally
/// `WebPkiClientVerifier`'s default (client auth required, no
/// `allow_unauthenticated`) — satisfies TC-TLS-03's "reject a client with
/// no cert at all" half; the "or accept anonymously" half is not offered by
/// this constructor.
pub fn server_config(
    ca_cert_der: CertificateDer<'static>,
    server_cert_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, TlsSetupError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(ca_cert_der)
        .map_err(TlsSetupError::InvalidCaCert)?;

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(TlsSetupError::VerifierBuild)?;

    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_cert_chain, server_key)
        .map_err(TlsSetupError::InvalidServerCert)
}

#[derive(Debug, thiserror::Error)]
pub enum TlsSetupError {
    #[error("invalid CA certificate: {0}")]
    InvalidCaCert(rustls::Error),
    #[error("failed to build client certificate verifier: {0}")]
    VerifierBuild(rustls::server::VerifierBuilderError),
    #[error("invalid server certificate/key: {0}")]
    InvalidServerCert(rustls::Error),
}

pub struct TlsRelay {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    tx: broadcast::Sender<Outbound>,
}

impl TlsRelay {
    pub async fn bind(addr: SocketAddr, config: Arc<ServerConfig>) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let (tx, _rx) = broadcast::channel(BROADCAST_CAPACITY);
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(config),
            tx,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept connections forever, spawning a task per client. Only returns
    /// on a fatal `accept()` error (the listener socket itself is broken).
    /// A failed TLS handshake (untrusted client cert, no cert presented,
    /// etc.) disconnects that one client and does not affect the listener.
    pub async fn run(self) -> std::io::Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let acceptor = self.acceptor.clone();
            let tx = self.tx.clone();
            let rx = self.tx.subscribe();
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let cn = peer_common_name(&tls_stream);
                        info!(%peer, cn = cn.as_deref().unwrap_or("<none>"), "mTLS client connected");
                        handle_client(tls_stream, peer, tx, rx).await;
                    }
                    Err(error) => {
                        warn!(%peer, %error, "TLS handshake failed, rejecting client");
                    }
                }
            });
        }
    }
}

fn peer_common_name(stream: &TlsStream<TcpStream>) -> Option<String> {
    let (_, connection) = stream.get_ref();
    let certs = connection.peer_certificates()?;
    let leaf = certs.first()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string);
    cn
}

async fn handle_client(
    stream: TlsStream<TcpStream>,
    peer: SocketAddr,
    tx: broadcast::Sender<Outbound>,
    mut rx: broadcast::Receiver<Outbound>,
) {
    let mut decoder = StreamDecoder::new();
    let mut read_buf = [0u8; 4096];
    let (mut reader, mut writer) = split(stream);

    loop {
        tokio::select! {
            read_result = reader.read(&mut read_buf) => {
                let n = match read_result {
                    Ok(0) => {
                        info!(%peer, "mTLS client disconnected");
                        return;
                    }
                    Ok(n) => n,
                    Err(error) => {
                        warn!(%peer, %error, "read error, disconnecting client");
                        return;
                    }
                };

                match decoder.feed(&read_buf[..n]) {
                    Ok(items) => {
                        for item in items {
                            match item {
                                DecodedItem::Event(event) => match event.to_xml() {
                                    Ok(xml) => {
                                        let _ = tx.send(Outbound { sender: peer, xml: xml.into() });
                                    }
                                    Err(error) => {
                                        warn!(%peer, %error, "failed to re-serialize decoded event, dropping");
                                    }
                                },
                                DecodedItem::Skipped { error, .. } => {
                                    debug!(%peer, %error, "skipped semantically-invalid CoT event");
                                }
                            }
                        }
                    }
                    Err(error) => {
                        warn!(%peer, %error, "stream error, disconnecting client");
                        return;
                    }
                }
            }
            broadcast_result = rx.recv() => {
                match broadcast_result {
                    Ok(msg) if msg.sender == peer => {}
                    Ok(msg) => {
                        if let Err(error) = writer.write_all(msg.xml.as_bytes()).await {
                            warn!(%peer, %error, "write error, disconnecting client");
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(%peer, skipped, "client fell behind, some broadcast events were dropped for it");
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::{build_csr, CertificateAuthority};
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use std::time::Duration as StdDuration;
    use time::Duration;
    use tokio::time::timeout;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    fn event_xml(uid: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><event version="2.0" uid="{uid}" type="a-f-G-U-C" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/></event>"#
        )
    }

    /// Self-sign a leaf cert directly (not CA-issued) -- used to build an
    /// "untrusted" client cert for the rejection test.
    fn self_signed_leaf(common_name: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).unwrap();
        (cert.der().clone(), PrivateKeyDer::from(key))
    }

    /// Shared test fixture: a CA, a server cert issued by it, and the
    /// rustls server config built from both.
    struct Fixture {
        ca: CertificateAuthority,
        server_config: Arc<ServerConfig>,
    }

    /// Unlike a device client CSR (CN only -- client-cert verification
    /// doesn't check hostname), a *server* cert must carry a DNS SAN
    /// matching the name the client connects with, since rustls's webpki
    /// verifier checks SAN, not CN, for server identity (RFC 6125).
    fn build_server_csr(common_name: &str, dns_name: &str) -> (String, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        let mut params = CertificateParams::new(vec![dns_name.to_string()]).unwrap();
        params.distinguished_name = dn;
        let csr = params.serialize_request(&key).unwrap();
        (csr.pem().unwrap(), key)
    }

    fn build_fixture() -> Fixture {
        let ca = CertificateAuthority::generate("EdgeTAK Test CA").unwrap();
        let (server_csr, server_key) = build_server_csr("edgetak-server", "edgetak-server");
        let signed = ca.sign_csr(&server_csr, Duration::days(365)).unwrap();
        let server_cert_der = pem_to_der(&signed.cert_pem);
        let ca_cert_der = pem_to_der(&ca.ca_cert_pem());

        let config = server_config(
            ca_cert_der,
            vec![server_cert_der],
            PrivateKeyDer::from(server_key),
        )
        .unwrap();

        Fixture {
            ca,
            server_config: Arc::new(config),
        }
    }

    fn pem_to_der(pem_str: &str) -> CertificateDer<'static> {
        let parsed = pem::parse(pem_str).unwrap();
        CertificateDer::from(parsed.contents().to_vec())
    }

    fn client_tls_connector(ca: &CertificateAuthority, client_cn: &str) -> TlsConnector {
        let (csr, key) = build_csr(client_cn).unwrap();
        let signed = ca.sign_csr(&csr, Duration::days(365)).unwrap();
        let cert_der = pem_to_der(&signed.cert_pem);
        let ca_der = pem_to_der(&ca.ca_cert_pem());

        let mut roots = RootCertStore::empty();
        roots.add(ca_der).unwrap();

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![cert_der], PrivateKeyDer::from(key))
            .unwrap();

        TlsConnector::from(Arc::new(client_config))
    }

    fn untrusted_client_tls_connector(ca: &CertificateAuthority) -> TlsConnector {
        let (leaf_der, leaf_key) = self_signed_leaf("untrusted-device");
        let ca_der = pem_to_der(&ca.ca_cert_pem());

        let mut roots = RootCertStore::empty();
        roots.add(ca_der).unwrap();

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![leaf_der], leaf_key)
            .unwrap();

        TlsConnector::from(Arc::new(client_config))
    }

    /// TC-TLS-01: a client presenting a cert signed by the configured CA
    /// completes the mTLS handshake and its CoT is relayed -- exercised
    /// end-to-end against a real TCP socket and a real TLS handshake, not
    /// mocked.
    #[tokio::test]
    async fn tc_tls_01_accepts_valid_ca_signed_client_cert_and_relays() {
        let fixture = build_fixture();
        let relay = TlsRelay::bind("127.0.0.1:0".parse().unwrap(), fixture.server_config)
            .await
            .unwrap();
        let addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let connector_a = client_tls_connector(&fixture.ca, "device-a");
        let connector_b = client_tls_connector(&fixture.ca, "device-b");

        let tcp_a = TcpStream::connect(addr).await.unwrap();
        let mut tls_a = connector_a
            .connect(ServerName::try_from("edgetak-server").unwrap(), tcp_a)
            .await
            .expect("client A handshake should succeed against the trusted CA");

        let tcp_b = TcpStream::connect(addr).await.unwrap();
        let mut tls_b = connector_b
            .connect(ServerName::try_from("edgetak-server").unwrap(), tcp_b)
            .await
            .expect("client B handshake should succeed against the trusted CA");

        tokio::time::sleep(StdDuration::from_millis(50)).await;

        tls_a
            .write_all(event_xml("FROM-A-MTLS").as_bytes())
            .await
            .unwrap();

        let mut recv_buf = vec![0u8; 4096];
        let n = timeout(StdDuration::from_secs(2), tls_b.read(&mut recv_buf))
            .await
            .expect("timed out waiting for relayed event over mTLS")
            .unwrap();
        let received = String::from_utf8_lossy(&recv_buf[..n]);
        assert!(received.contains("FROM-A-MTLS"), "got: {received}");
    }

    /// TC-TLS-02: a client presenting a cert NOT signed by the configured
    /// CA is rejected -- either the handshake itself fails, or (TLS 1.3
    /// allows a client to consider its handshake "done" locally once it
    /// has sent its own Finished message, before the server's rejection
    /// alert arrives) the very next read/write on the "connected" stream
    /// fails once the server's rejection lands.
    #[tokio::test]
    async fn tc_tls_02_rejects_client_cert_not_signed_by_ca() {
        let fixture = build_fixture();
        let relay = TlsRelay::bind("127.0.0.1:0".parse().unwrap(), fixture.server_config)
            .await
            .unwrap();
        let addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let connector = untrusted_client_tls_connector(&fixture.ca);
        let tcp = TcpStream::connect(addr).await.unwrap();
        let connect_result = connector
            .connect(ServerName::try_from("edgetak-server").unwrap(), tcp)
            .await;

        let mut stream = match connect_result {
            Err(_) => return, // rejected during the handshake itself -- acceptable.
            Ok(stream) => stream,
        };

        let write_result = stream.write_all(event_xml("SHOULD-BE-REJECTED").as_bytes()).await;
        let mut buf = [0u8; 16];
        let read_result = timeout(StdDuration::from_secs(2), stream.read(&mut buf)).await;

        let rejected = write_result.is_err()
            || matches!(read_result, Ok(Ok(0)) | Ok(Err(_)));
        assert!(
            rejected,
            "server must reject an untrusted client cert (write error, read error, or EOF expected); got write={write_result:?} read={read_result:?}"
        );
    }
}
