//! Marti-compatible REST API surface.
//!
//! - [`enrollment`]: certificate enrollment (`/Marti/api/tls/*`), served
//!   unauthenticated (by design — a client has no cert yet).
//! - [`missions`]: mission metadata CRUD, change log, and subscriptions
//!   (`/Marti/api/missions/*`), served mTLS-authenticated via
//!   [`MtlsHttpServer`] — TC-MARTI-10.
//!
//! Not yet implemented: `clientEndPoints` reflecting live connections
//! (TC-MARTI-09), groups, device profiles.
//!
//! [`MtlsHttpServer`] injects the connecting cert's Common Name into every
//! request as a [`PeerIdentity`] extension — [`missions`] uses this to
//! reject a request whose claimed `creatorUid`/`actorUid` doesn't match the
//! authenticated connection's own identity (EdgeTAK's policy: an HTTP API
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

pub mod enrollment;
pub mod missions;

/// The authenticated identity of an mTLS-connected caller — the connecting
/// client certificate's Common Name. Injected as a request extension by
/// [`MtlsHttpServer`]; extract it in a handler with
/// `Extension(PeerIdentity(cn)): Extension<PeerIdentity>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity(pub String);

/// A plain-HTTP listener serving a pre-built [`Router`], following the same
/// bind-then-`local_addr`-then-`run` shape as
/// [`crate::transport::tcp::TcpRelay`] and [`crate::transport::tls::TlsRelay`]
/// — lets a caller (or a test) learn the actual bound port before starting
/// to serve, which matters when binding an ephemeral port (`:0`).
///
/// **Only for endpoints meant to be unauthenticated** (currently just
/// `marti::enrollment`) — see [`MtlsHttpServer`] for everything else.
pub struct PlainHttpServer {
    listener: TcpListener,
    router: Router,
}

impl PlainHttpServer {
    pub async fn bind(addr: SocketAddr, router: Router) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener, router })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serve until the process exits or the listener errors.
    pub async fn run(self) -> std::io::Result<()> {
        axum::serve(self.listener, self.router).await
    }
}

/// An mTLS-authenticated HTTP listener serving a pre-built [`Router`] —
/// same bind/`local_addr`/`run` shape as [`PlainHttpServer`] and
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
