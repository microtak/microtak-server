//! mTLS-authenticated CoT relay listener.
//!
//! Same framing/relay behavior as [`super::tcp`] (built on the same
//! [`super::codec::StreamDecoder`] and broadcast-based relay), but requires
//! a valid client certificate signed by the configured CA before any CoT is
//! accepted (`docs/TEST-PLAN.md` §3, TC-TLS-01/02/03), and enforces
//! [`DeviceRegistry`] identity binding (TC-TLS-04) plus revocation
//! (TC-TLS-05, connect-time only — no continuous re-check of an
//! already-open session, matching the interim policy documented in
//! `docs/TEST-PLAN.md`).
//!
//! A connection whose cert has no extractable Common Name, or whose CN is
//! revoked, is disconnected immediately after the handshake. A connection
//! whose CoT claims a `uid` already bound to a *different* device is
//! disconnected as soon as that event is decoded — see
//! [`DeviceRegistry::bind_uid`] for the exact binding policy.
//!
//! Shares a [`RelayHub`] with [`super::tcp::TcpRelay`] — a CoT event
//! ingested here is relayed to plain-TCP clients too, and vice versa.

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
use super::hub::{Outbound, RelayHub};
use crate::registry::DeviceRegistry;

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
    hub: RelayHub,
    registry: Arc<DeviceRegistry>,
}

impl TlsRelay {
    pub async fn bind(
        addr: SocketAddr,
        config: Arc<ServerConfig>,
        hub: RelayHub,
        registry: Arc<DeviceRegistry>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(config),
            hub,
            registry,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept connections forever, spawning a task per client. Only returns
    /// on a fatal `accept()` error (the listener socket itself is broken).
    /// A failed TLS handshake, a cert with no extractable CN, or a revoked
    /// CN disconnects that one client and does not affect the listener.
    pub async fn run(self) -> std::io::Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let acceptor = self.acceptor.clone();
            let tx = self.hub.sender();
            let rx = self.hub.subscribe();
            let registry = Arc::clone(&self.registry);
            tokio::spawn(async move {
                let mut tls_stream = match acceptor.accept(stream).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        warn!(%peer, %error, "TLS handshake failed, rejecting client");
                        return;
                    }
                };

                let Some(cn) = peer_common_name(&tls_stream) else {
                    warn!(%peer, "client cert has no extractable Common Name, disconnecting");
                    // Send a proper TLS close_notify rather than an abrupt
                    // drop, so the client observes a prompt, unambiguous
                    // rejection instead of waiting on a read that may never
                    // resolve.
                    let _ = tls_stream.shutdown().await;
                    return;
                };

                if registry.is_revoked(&cn) {
                    warn!(%peer, cn, "rejecting connection from revoked device");
                    let _ = tls_stream.shutdown().await;
                    return;
                }

                info!(%peer, cn, "mTLS client connected");
                handle_client(tls_stream, peer, cn, tx, rx, registry).await;
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
    cn: String,
    tx: broadcast::Sender<Outbound>,
    mut rx: broadcast::Receiver<Outbound>,
    registry: Arc<DeviceRegistry>,
) {
    let mut decoder = StreamDecoder::new();
    let mut read_buf = [0u8; 4096];
    let (mut reader, mut writer) = split(stream);

    loop {
        tokio::select! {
            read_result = reader.read(&mut read_buf) => {
                let n = match read_result {
                    Ok(0) => {
                        info!(%peer, cn, "mTLS client disconnected");
                        return;
                    }
                    Ok(n) => n,
                    Err(error) => {
                        warn!(%peer, cn, %error, "read error, disconnecting client");
                        return;
                    }
                };

                match decoder.feed(&read_buf[..n]) {
                    Ok(items) => {
                        for item in items {
                            match item {
                                DecodedItem::Event(event) => {
                                    // TC-TLS-04: this connection's authenticated
                                    // identity (cn) must own the uid it's
                                    // asserting.
                                    if let Err(error) = registry.bind_uid(&cn, &event.uid) {
                                        warn!(%peer, cn, uid = %event.uid, %error, "uid binding violation, disconnecting client");
                                        let _ = writer.shutdown().await;
                                        return;
                                    }
                                    match event.to_xml() {
                                        Ok(xml) => {
                                            let _ = tx.send(Outbound { sender: peer, xml: xml.into() });
                                        }
                                        Err(error) => {
                                            warn!(%peer, cn, %error, "failed to re-serialize decoded event, dropping");
                                        }
                                    }
                                },
                                DecodedItem::Skipped { error, .. } => {
                                    debug!(%peer, cn, %error, "skipped semantically-invalid CoT event");
                                }
                            }
                        }
                    }
                    Err(error) => {
                        warn!(%peer, cn, %error, "stream error, disconnecting client");
                        let _ = writer.shutdown().await;
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

    /// Shared test fixture: a CA, a server cert issued by it, the rustls
    /// server config built from both, and the device registry every client
    /// cert gets enrolled into (mirroring what the real enrollment HTTP
    /// endpoint would have done before a device ever connects).
    struct Fixture {
        ca: CertificateAuthority,
        server_config: Arc<ServerConfig>,
        registry: Arc<DeviceRegistry>,
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
            registry: Arc::new(DeviceRegistry::in_memory()),
        }
    }

    fn pem_to_der(pem_str: &str) -> CertificateDer<'static> {
        let parsed = pem::parse(pem_str).unwrap();
        CertificateDer::from(parsed.contents().to_vec())
    }

    /// Sign a client cert for `client_cn` and enroll it in the fixture's
    /// registry -- mirroring the real enrollment flow (HTTP endpoint signs
    /// + records) that a raw `ca.sign_csr` call alone wouldn't do.
    fn client_tls_connector(fixture: &Fixture, client_cn: &str) -> TlsConnector {
        let (csr, key) = build_csr(client_cn).unwrap();
        let signed = fixture.ca.sign_csr(&csr, Duration::days(365)).unwrap();
        fixture
            .registry
            .enroll(client_cn, &signed.cert_pem, 0)
            .unwrap();

        let cert_der = pem_to_der(&signed.cert_pem);
        let ca_der = pem_to_der(&fixture.ca.ca_cert_pem());

        let mut roots = RootCertStore::empty();
        roots.add(ca_der).unwrap();

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![cert_der], PrivateKeyDer::from(key))
            .unwrap();

        TlsConnector::from(Arc::new(client_config))
    }

    async fn connect_client(
        addr: SocketAddr,
        fixture: &Fixture,
        cn: &str,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let connector = client_tls_connector(fixture, cn);
        let tcp = TcpStream::connect(addr).await.unwrap();
        connector
            .connect(ServerName::try_from("edgetak-server").unwrap(), tcp)
            .await
            .unwrap_or_else(|e| panic!("handshake for {cn} should succeed against the trusted CA: {e}"))
    }

    fn untrusted_client_tls_connector(fixture: &Fixture) -> TlsConnector {
        let (leaf_der, leaf_key) = self_signed_leaf("untrusted-device");
        let ca_der = pem_to_der(&fixture.ca.ca_cert_pem());

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
        let relay = TlsRelay::bind(
            "127.0.0.1:0".parse().unwrap(),
            fixture.server_config.clone(),
            RelayHub::new(),
            fixture.registry.clone(),
        )
        .await
        .unwrap();
        let addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let mut tls_a = connect_client(addr, &fixture, "device-a").await;
        let mut tls_b = connect_client(addr, &fixture, "device-b").await;

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
        let relay = TlsRelay::bind(
            "127.0.0.1:0".parse().unwrap(),
            fixture.server_config.clone(),
            RelayHub::new(),
            fixture.registry.clone(),
        )
        .await
        .unwrap();
        let addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let connector = untrusted_client_tls_connector(&fixture);
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

    /// TC-TLS-05 (connect-time revocation check): a device revoked in the
    /// registry is disconnected immediately after a handshake that would
    /// otherwise succeed (its cert is still validly signed by the CA --
    /// revocation is enforced by EdgeTAK's own registry, not the TLS layer).
    #[tokio::test]
    async fn tc_tls_05_disconnects_revoked_device_at_connect_time() {
        let fixture = build_fixture();
        let relay = TlsRelay::bind(
            "127.0.0.1:0".parse().unwrap(),
            fixture.server_config.clone(),
            RelayHub::new(),
            fixture.registry.clone(),
        )
        .await
        .unwrap();
        let addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let stream = connect_client(addr, &fixture, "device-revoked").await;
        fixture.registry.revoke("device-revoked").unwrap();

        // The already-open connection isn't force-closed mid-session (see
        // module docs: revocation is connect-time only), but a *new*
        // connection attempt for the same CN must be rejected.
        drop(stream);

        let connector = client_tls_connector(&fixture, "device-revoked");
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut new_stream = connector
            .connect(ServerName::try_from("edgetak-server").unwrap(), tcp)
            .await
            .expect("TLS handshake itself still succeeds -- the cert is validly signed");

        let write_result = new_stream
            .write_all(event_xml("SHOULD-BE-REJECTED").as_bytes())
            .await;
        let mut buf = [0u8; 16];
        let read_result = timeout(StdDuration::from_secs(2), new_stream.read(&mut buf)).await;
        let rejected = write_result.is_err() || matches!(read_result, Ok(Ok(0)) | Ok(Err(_)));
        assert!(
            rejected,
            "a revoked device's new connection must be rejected post-handshake; write={write_result:?} read={read_result:?}"
        );
    }

    /// TC-TLS-04: a second device (different cert, different authenticated
    /// CN) trying to assert a uid already bound to a first device is
    /// disconnected -- the cross-device spoofing case this binding exists
    /// to prevent.
    #[tokio::test]
    async fn tc_tls_04_disconnects_on_cross_device_uid_spoofing() {
        let fixture = build_fixture();
        let relay = TlsRelay::bind(
            "127.0.0.1:0".parse().unwrap(),
            fixture.server_config.clone(),
            RelayHub::new(),
            fixture.registry.clone(),
        )
        .await
        .unwrap();
        let addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let mut tls_a = connect_client(addr, &fixture, "device-a").await;
        let mut tls_spoofer = connect_client(addr, &fixture, "device-spoofer").await;
        tokio::time::sleep(StdDuration::from_millis(50)).await;

        // device-a legitimately claims SHARED-UID first.
        tls_a
            .write_all(event_xml("SHARED-UID").as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(StdDuration::from_millis(50)).await;
        assert_eq!(
            fixture.registry.find("device-a").unwrap().uid.as_deref(),
            Some("SHARED-UID")
        );

        // device-spoofer, as a legitimate *other* connected client, is
        // entitled to receive device-a's just-broadcast event -- drain that
        // expected traffic before looking for a rejection signal, so it
        // isn't mistaken for one.
        let mut drain_buf = vec![0u8; 4096];
        let drained = timeout(StdDuration::from_secs(2), tls_spoofer.read(&mut drain_buf))
            .await
            .expect("timed out waiting for device-a's relayed event")
            .unwrap();
        assert!(
            String::from_utf8_lossy(&drain_buf[..drained]).contains("SHARED-UID"),
            "expected to first drain device-a's legitimately relayed event"
        );

        // device-spoofer, a different authenticated identity, then tries to
        // claim the same uid -- must be disconnected.
        let write_result = tls_spoofer
            .write_all(event_xml("SHARED-UID").as_bytes())
            .await;
        let mut buf = [0u8; 16];
        let read_result = timeout(StdDuration::from_secs(2), tls_spoofer.read(&mut buf)).await;
        let rejected = write_result.is_err() || matches!(read_result, Ok(Ok(0)) | Ok(Err(_)));
        assert!(
            rejected,
            "a device asserting another device's uid must be disconnected; write={write_result:?} read={read_result:?}"
        );

        // The uid must still belong to device-a, not have been overwritten.
        assert_eq!(
            fixture.registry.find("device-a").unwrap().uid.as_deref(),
            Some("SHARED-UID")
        );
        assert_eq!(fixture.registry.find("device-spoofer").unwrap().uid, None);
    }
}
