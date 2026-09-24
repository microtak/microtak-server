//! `GET /Marti/api/contacts/all` -- mapped from the same live
//! [`ConnectedClients`] registry that already backs
//! [`super::client_endpoints`], not a static empty stub.
//!
//! Confirmed from real client source (`dfpc-coe/node-tak`'s
//! `lib/api/contacts.ts`): a `Contact` carries `callsign`/`team`/`role`/
//! `takv`/`notes`/`filterGroups`, none of which MicroTAK actually tracks
//! per-connection today (only the cert Common Name and bound CoT `uid` --
//! see `transport::connections`). Rather than fabricate plausible-looking
//! values for fields with no real data behind them, only `uid` (from a
//! real bound connection) and `callsign` (using the cert Common Name, the
//! closest real identity MicroTAK has -- not a claim that it's the same
//! thing a client's own `<contact callsign="...">` would say) are
//! populated; everything else is an honest empty default. A connection
//! that hasn't bound a `uid` yet is skipped entirely -- a contact with no
//! identity isn't a useful contact.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::transport::connections::ConnectedClients;

#[derive(Debug, Clone, Serialize)]
struct Contact {
    uid: String,
    callsign: String,
    team: String,
    role: String,
    takv: String,
    notes: String,
    #[serde(rename = "filterGroups")]
    filter_groups: Vec<String>,
}

pub fn router(clients: ConnectedClients) -> Router {
    Router::new()
        .route("/Marti/api/contacts/all", get(list_contacts))
        .with_state(clients)
}

async fn list_contacts(State(clients): State<ConnectedClients>) -> Json<Vec<Contact>> {
    let contacts = clients
        .list()
        .into_iter()
        .filter_map(|endpoint| {
            let uid = endpoint.uid?;
            Some(Contact {
                uid,
                callsign: endpoint.common_name.unwrap_or_default(),
                team: String::new(),
                role: String::new(),
                takv: String::new(),
                notes: String::new(),
                filter_groups: Vec::new(),
            })
        })
        .collect();
    Json(contacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::connections::{ClientEndpoint, Transport};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn reflects_live_bound_connections_not_a_static_list() {
        let clients = ConnectedClients::new();
        let app = router(clients.clone());

        let empty: Vec<serde_json::Value> = serde_json::from_slice(
            &axum::body::to_bytes(
                app.clone()
                    .oneshot(Request::builder().uri("/Marti/api/contacts/all").body(Body::empty()).unwrap())
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
            .oneshot(Request::builder().uri("/Marti/api/contacts/all").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Vec<serde_json::Value> =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body.len(), 1);
        assert_eq!(body[0]["uid"], "UID-A");
        assert_eq!(body[0]["callsign"], "device-a");
    }

    /// A connection with no bound `uid` yet has no real identity -- must
    /// not appear as a contact with an empty/fabricated one.
    #[tokio::test]
    async fn connections_without_a_bound_uid_are_omitted() {
        let clients = ConnectedClients::new();
        clients.register(ClientEndpoint {
            remote_addr: "127.0.0.1:1".parse().unwrap(),
            transport: Transport::Tls,
            common_name: Some("device-a".to_string()),
            uid: None,
            connected_at_unix: 1_000,
        });
        let app = router(clients);

        let body: Vec<serde_json::Value> = serde_json::from_slice(
            &axum::body::to_bytes(
                app.oneshot(Request::builder().uri("/Marti/api/contacts/all").body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .into_body(),
                usize::MAX,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        assert!(body.is_empty());
    }
}
