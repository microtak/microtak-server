//! Marti-compatible REST API surface.
//!
//! - [`enrollment`]: certificate enrollment (`/Marti/api/tls/*`), served
//!   over HTTPS without client-cert auth (a client has no cert yet) by
//!   [`TlsHttpServer`] -- never plain HTTP.
//! - [`missions`]: mission metadata CRUD, change log, and subscriptions
//!   (`/Marti/api/missions/*`), served mTLS-authenticated via
//!   [`MtlsHttpServer`] — TC-MARTI-10.
//! - [`client_endpoints`]: `GET /Marti/api/clientEndPoints` (TC-MARTI-09),
//!   backed by the live [`crate::transport::connections::ConnectedClients`]
//!   registry rather than a static list.
//! - [`content`]: DataSync file content upload/download by hash
//!   (`/Marti/api/sync/*`, TC-MARTI-07/08), on top of
//!   [`crate::content_store::ContentStore`].
//! - [`admin`]: mint/list/revoke enrollment invite tokens and user
//!   accounts, plus certificate-admin lookups (`/Marti/api/admin/*`,
//!   `/Marti/api/certadmin/*`), gated by a configured admin cert Common
//!   Name on top of the usual mTLS auth -- see its own doc comment for the
//!   bootstrap order this implies.
//! - [`oauth`]: `POST /oauth/token`, real TAK-Server/CloudTAK-compatible
//!   password-grant login (HTTPS, same listener as [`enrollment`]).
//! - [`discovery`]: small version/config probe endpoints
//!   (`/Marti/api/version`, `/Marti/api/version/config`,
//!   `/files/api/config`) real clients use to confirm a working connection.
//! - [`contacts`]: `GET /Marti/api/contacts/all`, mapped from the same live
//!   connection registry [`client_endpoints`] uses.
//! - [`groups`]: `GET /Marti/api/groups/all`, a real, honestly-empty stub.
//!
//! Not yet implemented: real groups/channels, device profiles.
//!
//! [`MtlsHttpServer`] injects the connecting cert's Common Name into every
//! request as a [`PeerIdentity`] extension — [`missions`] uses this to
//! reject a request whose claimed `creatorUid`/`actorUid` doesn't match the
//! authenticated connection's own identity (MicroTAK's policy: an HTTP API
//! caller's identity *is* its cert's CN, the same identity enrollment
//! issued it — this doesn't require any prior CoT-relay interaction, so it
//! works for HTTP-only callers like a web frontend that never streams raw
//! CoT through the relay).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::response::IntoResponse;
use axum::{Extension, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::registry::{Access, DeviceRegistry};
use crate::transport::admission::Admission;
use tracing::warn;

pub mod admin;
pub mod client_endpoints;
pub mod contacts;
pub mod content;
pub mod discovery;
pub mod enrollment;
pub mod groups;
pub mod missions;
pub mod oauth;

/// The authenticated identity of an mTLS-connected caller — the connecting
/// client certificate's Common Name. Injected as a request extension by
/// [`MtlsHttpServer`]; extract it in a handler with
/// `Extension(PeerIdentity(cn)): Extension<PeerIdentity>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity(pub String);

/// The client's IP address, for rate limiting: the TCP peer, or -- when
/// the peer is a configured trusted reverse proxy (an
/// `Extension<Arc<TrustedProxies>>` on the router) -- the client address it
/// forwarded (see [`crate::clientip`]). Never rejects: a request without
/// connection info (e.g. a router driven directly in a unit test) just
/// yields `None`.
#[derive(Debug, Clone, Copy)]
pub struct PeerIp(pub Option<std::net::IpAddr>);

#[axum::async_trait]
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip());
        let trusted = parts
            .extensions
            .get::<Arc<crate::clientip::TrustedProxies>>();
        Ok(PeerIp(match (peer, trusted) {
            (Some(peer), Some(trusted)) => Some(trusted.client_ip(peer, &parts.headers)),
            (peer, _) => peer,
        }))
    }
}

impl PeerIp {
    /// Rate-limit key for this client -- see [`crate::ratelimit`].
    pub fn limit_key(&self) -> String {
        match self.0 {
            Some(ip) => crate::ratelimit::ip_key(ip),
            None => "ip:unknown".to_string(),
        }
    }
}

/// The enrollment/OAuth listener: HTTPS **without** a client certificate
/// (a device has none yet -- the same `clientAuth="false"` shape as the
/// official TAK Server's `:8446`). **TLS only**: there is no plain-HTTP
/// fallback and no redirect (a redirect would itself be plain HTTP) -- a
/// client speaking plain HTTP just fails the handshake. Built with
/// [`crate::transport::tls::server_auth_only_config`], so its certificate
/// comes from a [`crate::certsource::SwappableCert`] (MicroTAK's own CA by
/// default, or hot-reloaded files such as a Let's Encrypt certificate).
///
/// Same bind/`local_addr`/`run` shape as [`MtlsHttpServer`]. Each request
/// carries the peer address as axum `ConnectInfo`, so [`PeerIp`] (and the
/// rate limiter behind it) works exactly as it would under `axum::serve`.
pub struct TlsHttpServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    router: Router,
    admission: Admission,
}

impl TlsHttpServer {
    pub async fn bind(
        addr: SocketAddr,
        tls_config: Arc<ServerConfig>,
        router: Router,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(tls_config),
            router,
            admission: Admission::default(),
        })
    }

    /// Connection limits, handshake and request-header timeouts (default:
    /// [`AdmissionLimits::default`](crate::transport::admission::AdmissionLimits)).
    pub fn with_admission(mut self, admission: Admission) -> Self {
        self.admission = admission;
        self
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept connections forever, spawning a task per client. Only returns
    /// on a fatal `accept()` error.
    pub async fn run(self) -> std::io::Result<()> {
        loop {
            let (mut stream, peer) = self.listener.accept().await?;
            let admission = self.admission.clone();
            let acceptor = self.acceptor.clone();
            let router = self.router.clone();
            tokio::spawn(async move {
                let Some((peer, _permit)) = admission.admit_stream(&mut stream, peer).await else {
                    return;
                };
                let tls_stream =
                    match tokio::time::timeout(admission.handshake_timeout(), acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(error)) => {
                            if is_plaintext_http(&error) {
                                warn!(%peer, "client spoke plain HTTP to the enrollment port -- it is HTTPS only");
                            } else {
                                warn!(%peer, %error, "TLS handshake failed on the enrollment port");
                            }
                            return;
                        }
                        Err(_) => {
                            warn!(%peer, "TLS handshake timed out on the enrollment port");
                            return;
                        }
                    };

                let router = router.layer(Extension(axum::extract::ConnectInfo(peer)));
                let io = TokioIo::new(tls_stream);
                let service = TowerToHyperService::new(router);
                if let Err(error) = http_builder(&admission)
                    .serve_connection(io, service)
                    .await
                {
                    warn!(%peer, %error, "error serving enrollment connection");
                }
            });
        }
    }
}

/// The HTTP connection builder both listeners use: request headers must
/// arrive within the admission's header timeout (Slowloris).
fn http_builder(admission: &Admission) -> ConnBuilder<TokioExecutor> {
    let mut builder = ConnBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(admission.http_header_timeout());
    builder
}

/// rustls reports a plaintext HTTP request as a record with an invalid
/// content type -- worth a clearer log line, since it's the most likely
/// misconfiguration (an `http://` URL typed into a client).
fn is_plaintext_http(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .is_some_and(|tls| {
            matches!(
                tls,
                rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType)
            )
        })
}

/// An mTLS-authenticated HTTP listener serving a pre-built [`Router`] —
/// same bind/`local_addr`/`run` shape as [`TlsHttpServer`] and
/// [`crate::transport::tls::TlsRelay`], but every request requires a valid
/// client certificate signed by the configured CA (build the `ServerConfig`
/// with [`crate::transport::tls::server_config`], the same function the CoT
/// mTLS relay uses — one cert-verification policy, reused, not
/// reimplemented per listener).
///
/// Hand-rolled on `hyper-util` + `tokio-rustls` rather than via `axum::serve`
/// (which only binds a plain [`TcpListener`]) — this is the standard
/// low-level pattern for TLS-terminated axum services.
pub struct MtlsHttpServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    router: Router,
    admission: Admission,
    registry: Option<Arc<DeviceRegistry>>,
}

impl MtlsHttpServer {
    pub async fn bind(
        addr: SocketAddr,
        tls_config: Arc<ServerConfig>,
        router: Router,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(tls_config),
            router,
            admission: Admission::default(),
            registry: None,
        })
    }

    /// Connection limits, handshake and request-header timeouts (default:
    /// [`AdmissionLimits::default`](crate::transport::admission::AdmissionLimits)).
    pub fn with_admission(mut self, admission: Admission) -> Self {
        self.admission = admission;
        self
    }

    /// Refuse revoked certificates and blocked identities -- at connect and
    /// on every request, since a keep-alive connection can outlive a
    /// revocation. See [`DeviceRegistry::access`].
    pub fn with_registry(mut self, registry: Arc<DeviceRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept connections forever, spawning a task per client. Only returns
    /// on a fatal `accept()` error (the listener socket itself is broken).
    /// A failed TLS handshake, or a cert with no extractable Common Name,
    /// disconnects that one client and does not affect the listener.
    pub async fn run(self) -> std::io::Result<()> {
        loop {
            let (mut stream, peer) = self.listener.accept().await?;
            let admission = self.admission.clone();
            let acceptor = self.acceptor.clone();
            let router = self.router.clone();
            let registry = self.registry.clone();
            tokio::spawn(async move {
                let Some((peer, _permit)) = admission.admit_stream(&mut stream, peer).await else {
                    return;
                };
                let mut tls_stream =
                    match tokio::time::timeout(admission.handshake_timeout(), acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(error)) => {
                            warn!(%peer, %error, "TLS handshake failed for Marti API request, rejecting client");
                            return;
                        }
                        Err(_) => {
                            warn!(%peer, "TLS handshake timed out on the Marti API port");
                            return;
                        }
                    };

                let peer_cert: Option<Vec<u8>> = {
                    let (_, connection) = tls_stream.get_ref();
                    connection
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .map(|cert| cert.as_ref().to_vec())
                };
                let Some((cn, peer_cert)) = peer_cert.and_then(|der| {
                    crate::pki::common_name_from_cert_der(&der).map(|cn| (cn, der))
                }) else {
                    warn!(%peer, "client cert has no extractable Common Name, disconnecting");
                    return;
                };

                let mut router = router.layer(Extension(PeerIdentity(cn.clone())));
                if let Some(registry) = registry {
                    let access = registry.access(&cn, &peer_cert);
                    if access != Access::Allowed {
                        warn!(%peer, cn, ?access, "refusing Marti API connection: certificate revoked or identity blocked");
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls_stream).await;
                        return;
                    }
                    router = router.layer(axum::middleware::from_fn(move |request, next: axum::middleware::Next| {
                        let registry = Arc::clone(&registry);
                        let cn = cn.clone();
                        let peer_cert = peer_cert.clone();
                        async move {
                            if registry.access(&cn, &peer_cert) != Access::Allowed {
                                return (
                                    axum::http::StatusCode::FORBIDDEN,
                                    axum::Json(serde_json::json!({
                                        "error": "certificate revoked or identity blocked"
                                    })),
                                )
                                    .into_response();
                            }
                            next.run(request).await
                        }
                    }));
                }
                let io = TokioIo::new(tls_stream);
                let service = TowerToHyperService::new(router);
                if let Err(error) = http_builder(&admission)
                    .serve_connection(io, service)
                    .await
                {
                    warn!(%peer, %error, "error serving Marti API connection");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::{build_csr, CertificateAuthority};
    use crate::transport::admission::{Admission, AdmissionLimits};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn short_limits() -> Admission {
        Admission::new(AdmissionLimits {
            handshake_timeout: Duration::from_millis(200),
            http_header_timeout: Duration::from_millis(200),
            ..AdmissionLimits::default()
        })
    }

    fn server_cert(ca: &CertificateAuthority) -> (Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>) {
        let (csr, key) = build_csr("microtak-server").unwrap();
        let signed = ca
            .sign_server_csr(&csr, &["microtak-server".to_string()], time::Duration::days(1))
            .unwrap();
        (
            vec![crate::pki::cert_pem_to_der(&signed.cert_pem).unwrap()],
            rustls::pki_types::PrivateKeyDer::from(key),
        )
    }

    async fn assert_closed_within(stream: &mut (impl AsyncReadExt + Unpin), limit: Duration) {
        let mut buf = [0u8; 64];
        loop {
            let read = tokio::time::timeout(limit, stream.read(&mut buf))
                .await
                .expect("the server must close the connection, not wait forever");
            match read {
                Ok(0) | Err(_) => return,
                Ok(_) => continue, // e.g. a 408 response before the close
            }
        }
    }

    /// The mTLS API listener drops a connection that never starts the TLS
    /// handshake (no certificate is needed to hold a socket otherwise).
    #[tokio::test]
    async fn mtls_api_drops_a_stalled_handshake() {
        let ca = CertificateAuthority::generate("Listener Test CA").unwrap();
        let (chain, key) = server_cert(&ca);
        let ca_der = crate::pki::cert_pem_to_der(&ca.ca_cert_pem()).unwrap();
        let tls = crate::transport::tls::server_config(ca_der, chain, key).unwrap();
        let server = MtlsHttpServer::bind("127.0.0.1:0".parse().unwrap(), Arc::new(tls), Router::new())
            .await
            .unwrap()
            .with_admission(short_limits());
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.run());

        let mut stalled = TcpStream::connect(addr).await.unwrap();
        assert_closed_within(&mut stalled, Duration::from_secs(2)).await;
    }

    /// The enrollment listener (no client cert, reachable by anyone) drops a
    /// connection whose HTTP request headers never complete.
    #[tokio::test]
    async fn enrollment_listener_drops_a_never_finished_request() {
        let ca = CertificateAuthority::generate("Listener Test CA").unwrap();
        let (chain, key) = server_cert(&ca);
        let cert = crate::certsource::certified_key(chain, key).unwrap();
        let tls = crate::transport::tls::server_auth_only_config(Arc::new(
            crate::certsource::SwappableCert::new(cert),
        ));
        let server = TlsHttpServer::bind("127.0.0.1:0".parse().unwrap(), Arc::new(tls), Router::new())
            .await
            .unwrap()
            .with_admission(short_limits());
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.run());

        let mut roots = rustls::RootCertStore::empty();
        roots.add(crate::pki::cert_pem_to_der(&ca.ca_cert_pem()).unwrap()).unwrap();
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connector
            .connect(rustls::pki_types::ServerName::try_from("microtak-server").unwrap(), tcp)
            .await
            .unwrap();
        tls.write_all(b"GET /Marti/api/tls/config HTTP/1.1\r\nHost: microtak-server\r\n")
            .await
            .unwrap();
        assert_closed_within(&mut tls, Duration::from_secs(2)).await;
    }
}
