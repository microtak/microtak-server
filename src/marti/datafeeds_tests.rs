use super::*;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

use crate::groups::Membership;

fn app(admin_only: bool) -> (Router, Arc<DataFeedStore>) {
    let store = Arc::new(DataFeedStore::in_memory());
    let groups = Arc::new(GroupStore::in_memory());
    groups.create("Red", None, 0).unwrap();
    groups
        .set_member("Red", "red-device", Some(Membership::Both))
        .unwrap();
    let router = router(DataFeedsState {
        store: Arc::clone(&store),
        groups,
        admin_common_name: Some("admin".into()),
        admin_only,
    });
    (router, store)
}

async fn call(
    app: &Router,
    identity: &str,
    method: &str,
    uri: &str,
    body: &str,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .extension(PeerIdentity(identity.to_string()))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

const APRS: &str = r#"{"name":"aprs bridge","type":"Streaming","protocol":"stcp","port":18088,"auth":"ANONYMOUS","tag":["aprs"],"filtergroup":["Red"],"unknownProperty":1}"#;

#[tokio::test]
async fn admins_create_feeds_in_the_official_shape() {
    let (app, store) = app(true);
    let (status, body) = call(&app, "admin", "POST", "/Marti/api/datafeeds", APRS).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["type"], "tak.server.feeds.DataFeed");
    let data = &body["data"];
    assert_eq!(data["name"], "aprs bridge");
    assert_eq!(data["tags"], json!(["aprs"]));
    assert_eq!(data["filterGroups"], json!(["Red"]));
    assert_eq!(data["port"], 18088);
    assert_eq!(data["archive"], true);
    assert_eq!(data["federated"], true);
    assert_eq!(data["coreVersion"], 2);
    assert_eq!(data["coreVersion2TlsVersions"], "TLSv1.2,TLSv1.3");
    assert_eq!(data["sSyncCacheRetentionSeconds"], 3600);
    assert!(data.get("uuid").is_none(), "the posted feed had none");
    let feed = store.by_name("aprs bridge").unwrap();
    assert_eq!(feed.uuid.len(), 36, "assigned");
    assert_eq!(feed.visible_to, BTreeSet::from(["Red".to_string()]));

    let (status, body) = call(&app, "red-device", "GET", "/Marti/api/datafeeds", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"][0]["uuid"], feed.uuid);
    let (_, body) = call(&app, "someone-else", "GET", "/Marti/api/datafeeds", "").await;
    assert_eq!(body["data"], json!([]), "not in Red");
    let (status, _) = call(
        &app,
        "red-device",
        "GET",
        "/Marti/api/datafeeds/aprs%20bridge",
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        "someone-else",
        "GET",
        "/Marti/api/datafeeds/aprs%20bridge",
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn validation_is_the_official_one() {
    let (app, _) = app(true);
    let post = |body: &'static str| {
        let app = app.clone();
        async move { call(&app, "admin", "POST", "/Marti/api/datafeeds", body).await }
    };
    let (status, body) =
        post(r#"{"name":"bad-name!","type":"Streaming","protocol":"stcp","port":1}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["messages"], json!(["Invalid input name."]));
    let (_, body) = post(r#"{"name":"x","protocol":"stcp","port":1}"#).await;
    assert_eq!(body["messages"], json!(["Null data feed type provided"]));
    let (_, body) =
        post(r#"{"name":"x","type":"Streaming","protocol":"udp","port":1,"auth":"FILE"}"#).await;
    assert_eq!(
        body["messages"][0],
        "If Authentication Type is set to File or LDAP, then Protocol should be be Streaming TCP or Secure Streaming TCP."
    );
    let (_, body) = post(r#"{"name":"x","type":"Streaming","protocol":"mcast","port":1}"#).await;
    assert_eq!(
        body["messages"][0],
        "If Protocol is set to Multicast, then the Multicast Group must be provided."
    );
    let (status, _) = post(r#"{"name":"x","type":"streaming","protocol":"stcp","port":1}"#).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "DataFeedType.valueOf is case-sensitive"
    );
    let (status, _) =
        post(r#"{"name":"x","type":"Streaming","protocol":"stcp","port":1,"auth":"x509"}"#).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Jackson binds the JAXB constant names"
    );
}

#[tokio::test]
async fn update_and_delete_follow_the_official_rules() {
    let (app, store) = app(true);
    // Officially an update only finds feeds within the caller's groups.
    let (status, _) = call(
        &app,
        "admin",
        "PUT",
        "/Marti/api/datafeeds/aprs%20bridge",
        APRS,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let anon = r#"{"name":"aprs bridge","type":"Streaming","protocol":"stcp","port":18088,"auth":"ANONYMOUS","tag":["aprs"]}"#;
    call(&app, "admin", "POST", "/Marti/api/datafeeds", anon).await;
    let changed =
        r#"{"name":"aprs bridge","type":"Streaming","protocol":"tls","port":18089,"auth":"X_509"}"#;
    let (status, body) = call(
        &app,
        "admin",
        "PUT",
        "/Marti/api/datafeeds/aprs%20bridge",
        changed,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("data").is_none());
    let feed = store.by_name("aprs bridge").unwrap();
    assert_eq!((feed.protocol.as_str(), feed.port), ("tls", Some(18089)));
    assert_eq!(feed.tags, ["aprs"], "kept when none are posted");
    assert_eq!(
        feed.visible_to,
        BTreeSet::from(["__ANON__".to_string()]),
        "now the updater's groups"
    );
    let (status, _) = call(&app, "admin", "PUT", "/Marti/api/datafeeds/nope", changed).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &app,
        "admin",
        "DELETE",
        "/Marti/api/datafeeds/aprs%20bridge",
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(store.all().is_empty());
    let (status, _) = call(
        &app,
        "admin",
        "DELETE",
        "/Marti/api/datafeeds/aprs%20bridge",
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn only_the_admin_manages_feeds_unless_switched_off() {
    let (app, _) = app(true);
    for (method, uri) in [
        ("POST", "/Marti/api/datafeeds"),
        ("PUT", "/Marti/api/datafeeds/x"),
        ("DELETE", "/Marti/api/datafeeds/x"),
    ] {
        let (status, _) = call(&app, "red-device", method, uri, APRS).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
    }
    let (open, _) = app_open();
    let (status, _) = call(&open, "red-device", "POST", "/Marti/api/datafeeds", APRS).await;
    assert_eq!(status, StatusCode::OK, "as officially");
}

fn app_open() -> (Router, Arc<DataFeedStore>) {
    app(false)
}
