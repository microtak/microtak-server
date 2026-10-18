//! The official `SecurityAuthenticationApi` parts MicroTAK has an answer
//! for: `GET /Marti/api/security/isSecure`.
//!
//! `getNonSecurePorts` lists the CoT inputs without TLS and the web
//! connectors without TLS. MicroTAK's counterparts: the plain-TCP relay (an
//! input) and the plain-HTTP metrics listener (a connector), when enabled.
//! `security/config`, `authentication/config` and `/Marti/api/config`
//! describe the official server's own configuration (JKS stores, LDAP,
//! CoreConfig), which MicroTAK doesn't have; they stay unanswered.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::Value;

#[derive(Clone)]
pub struct SecurityState {
    /// Listening ports without TLS.
    pub non_secure_ports: Vec<u16>,
}

pub fn router(state: SecurityState) -> Router {
    Router::new()
        .route("/Marti/api/security/isSecure", get(is_secure))
        .with_state(state)
}

/// `HashSet<Integer>.toString()`: bucket order of a 16-slot table
/// (`(h ^ h >>> 16) & 15`), then insertion order within a bucket.
fn java_set_string(ports: &[u16]) -> String {
    let mut unique: Vec<u16> = Vec::new();
    for p in ports {
        if !unique.contains(p) {
            unique.push(*p);
        }
    }
    let mut indexed: Vec<(usize, u16)> = unique.into_iter().enumerate().collect();
    indexed.sort_by_key(|(i, p)| {
        let h = u32::from(*p);
        ((h ^ (h >> 16)) & 15, *i)
    });
    format!(
        "[{}]",
        indexed
            .iter()
            .map(|(_, p)| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

async fn is_secure(State(state): State<SecurityState>) -> Json<Value> {
    let data = if state.non_secure_ports.is_empty() {
        "true".to_string()
    } else {
        java_set_string(&state.non_secure_ports)
    };
    super::envelope::api_response("isSecure?", data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn data(ports: Vec<u16>) -> Value {
        let response = router(SecurityState {
            non_secure_ports: ports,
        })
        .oneshot(
            Request::builder()
                .uri("/Marti/api/security/isSecure")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["type"], "isSecure?");
        body["data"].clone()
    }

    #[tokio::test]
    async fn is_secure_lists_the_ports_without_tls() {
        assert_eq!(data(vec![]).await, "true");
        assert_eq!(data(vec![8087]).await, "[8087]");
        // 8087 & 15 = 7, 9090 & 15 = 2: HashSet order, not insertion order.
        assert_eq!(data(vec![8087, 9090]).await, "[9090, 8087]");
    }
}
