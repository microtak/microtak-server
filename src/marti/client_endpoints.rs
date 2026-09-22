//! `GET /Marti/api/clientEndPoints` (TC-MARTI-09) — reflects who is actually
//! connected right now, backed by [`crate::transport::connections::ConnectedClients`].
//!
//! A real reference implementation was found to return a static/hardcoded
//! empty list for this endpoint regardless of who was actually connected —
//! this handler exists specifically so EdgeTAK's answer is never that.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use crate::transport::connections::{ClientEndpoint, ConnectedClients};

pub fn router(clients: ConnectedClients) -> Router {
    Router::new()
        .route("/Marti/api/clientEndPoints", get(list_client_endpoints))
        .with_state(clients)
}

async fn list_client_endpoints(State(clients): State<ConnectedClients>) -> Json<Vec<ClientEndpoint>> {
    Json(clients.list())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::connections::Transport;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// TC-MARTI-09: the endpoint reflects real, live registrations — not a
    /// static empty list — and stops listing a connection once it's
    /// unregistered.
    #[tokio::test]
    async fn reflects_live_registrations_not_a_static_list() {
        let clients = ConnectedClients::new();
        let app = router(clients.clone());

        let empty: Vec<ClientEndpoint> = serde_json::from_slice(
            &axum::body::to_bytes(
                app.clone()
                    .oneshot(
                        Request::builder()
                            .uri("/Marti/api/clientEndPoints")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap()
                    .into_body(),
                usize::MAX,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        assert!(empty.is_empty());

        clients.register(ClientEndpoint {
            remote_addr: "127.0.0.1:1".parse().unwrap(),
            transport: Transport::Tls,
            common_name: Some("device-a".to_string()),
            uid: Some("UID-A".to_string()),
            connected_at_unix: 1_000,
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/Marti/api/clientEndPoints")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Vec<ClientEndpoint> = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body.len(), 1);
        assert_eq!(body[0].common_name.as_deref(), Some("device-a"));

        clients.unregister("127.0.0.1:1".parse().unwrap());
        let after: Vec<ClientEndpoint> = serde_json::from_slice(
            &axum::body::to_bytes(
                app.oneshot(
                    Request::builder()
                        .uri("/Marti/api/clientEndPoints")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .into_body(),
                usize::MAX,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        assert!(after.is_empty());
    }
}
