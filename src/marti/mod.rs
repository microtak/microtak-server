//! Marti-compatible REST API surface.
//!
//! - [`enrollment`]: certificate enrollment (`/Marti/api/tls/*`), served
//!   unauthenticated (by design — a client has no cert yet).
//! - [`missions`]: mission metadata CRUD, change log, and subscriptions
//!   (`/Marti/api/missions/*`), served mTLS-authenticated via
//!   [`MtlsHttpServer`] — TC-MARTI-10.
//!
//! Not yet implemented: DataSync file content storage (hash-addressed
//! upload/download, TC-MARTI-07/08), `clientEndPoints` reflecting live
//! connections (TC-MARTI-09), groups, device profiles. Authenticating the
//! *connection* (a valid cert signed by the CA is required) is as far as
//! this goes — request handlers don't yet cross-check a claimed
//! `creatorUid`/`actorUid` against the connecting cert's identity, the same
//! incremental order the CoT transport followed (mTLS first, then identity
//! binding as its own pass — see `transport::tls`'s history).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::warn;

pub mod enrollment;
pub mod missions;

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
    /// A failed TLS handshake (untrusted/missing client cert) disconnects
    /// that one client and does not affect the listener.
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
