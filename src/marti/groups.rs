//! `GET /Marti/api/groups/all` -- a real, honestly-empty stub.
//!
//! Confirmed from real client source (`dfpc-coe/node-tak`'s
//! `lib/api/groups.ts`): a real TAK Server's "groups" are channel/team
//! memberships, unrelated to anything MicroTAK currently models (missions
//! have subscribers and roles, but no separate group/channel concept).
//! Real client code only needs a well-shaped, empty response to avoid
//! erroring during login/discovery -- implementing actual groups is future
//! scope, not attempted here.

use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

pub fn router() -> Router {
    Router::new().route("/Marti/api/groups/all", get(list_groups))
}

async fn list_groups() -> impl IntoResponse {
    Json(json!({
        "version": "3",
        "type": "com.bbn.marti.remote.groups.Group",
        "data": [],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn returns_a_well_shaped_empty_list() {
        let response = router()
            .oneshot(Request::builder().uri("/Marti/api/groups/all").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        )
        .unwrap();
        assert_eq!(body["data"].as_array().unwrap().len(), 0);
    }
}
