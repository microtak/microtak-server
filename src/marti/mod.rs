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

use axum::{Extension, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
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
}

/// How long a client gets to complete the TLS handshake before the
/// connection is dropped -- stops idle half-open connections from piling up.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept connections forever, spawning a task per client. Only returns
    /// on a fatal `accept()` error.
    pub async fn run(self) -> std::io::Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let acceptor = self.acceptor.clone();
            let router = self.router.clone();
            tokio::spawn(async move {
                let tls_stream =
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
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
                if let Err(error) = ConnBuilder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
                {
                    warn!(%peer, %error, "error serving enrollment connection");
                }
            });
        }
    }
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
        })
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
            let (stream, peer) = self.listener.accept().await?;
            let acceptor = self.acceptor.clone();
            let router = self.router.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        warn!(%peer, %error, "TLS handshake failed for Marti API request, rejecting client");
                        return;
                    }
                };

                let cn = {
                    let (_, connection) = tls_stream.get_ref();
                    connection
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .and_then(|cert| crate::pki::common_name_from_cert_der(cert.as_ref()))
                };
                let Some(cn) = cn else {
                    warn!(%peer, "client cert has no extractable Common Name, disconnecting");
                    return;
                };

                let router = router.layer(Extension(PeerIdentity(cn)));
                let io = TokioIo::new(tls_stream);
                let service = TowerToHyperService::new(router);
                if let Err(error) = ConnBuilder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
                {
                    warn!(%peer, %error, "error serving Marti API connection");
                }
            });
        }
    }
}
