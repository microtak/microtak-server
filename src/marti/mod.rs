//! Marti-compatible REST API surface.
//!
//! - [`enrollment`]: certificate enrollment (`/Marti/api/tls/*`), served
//!   unauthenticated.
//! - [`missions`]: mission metadata CRUD, change log, and subscriptions
//!   (`/Marti/api/missions/*`), served — for now — unauthenticated too; see
//!   [`missions`]'s own doc comment for why that's a known, temporary gap
//!   (TC-MARTI-10).
//!
//! Not yet implemented: DataSync file content storage (hash-addressed
//! upload/download, TC-MARTI-07/08), `clientEndPoints` reflecting live
//! connections (TC-MARTI-09), groups, device profiles.

use std::net::SocketAddr;

use axum::Router;
use tokio::net::TcpListener;

pub mod enrollment;
pub mod missions;

/// A plain-HTTP listener serving a pre-built [`Router`], following the same
/// bind-then-`local_addr`-then-`run` shape as
/// [`crate::transport::tcp::TcpRelay`] and [`crate::transport::tls::TlsRelay`]
/// — lets a caller (or a test) learn the actual bound port before starting
/// to serve, which matters when binding an ephemeral port (`:0`).
///
/// **Known simplification, applies to every router served through this**:
/// plain HTTP, no TLS. See `marti::enrollment`'s and `marti::missions`'s own
/// doc comments for the per-endpoint reasoning and what's at risk.
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
