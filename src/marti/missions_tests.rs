//! The official Mission API's behaviour, endpoint by endpoint. Each test
//! names the official code it follows (`TAK-Product-Center/Server`
//! `MissionApi`, `MissionServiceDefaultImpl`, the role filter, the
//! repositories); see the wiki page `Official-Mission-API`.

use super::*;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

struct Harness {
    state: MissionsState,
    app: Router,
}

fn harness() -> Harness {
    let mut state = MissionsState::in_memory();
    state.admin_common_name = Some("admin".into());
    let app = router_with(state.clone());
    Harness { state, app }
}

struct Reply {
    status: StatusCode,
    body: Vec<u8>,
    content_type: Option<String>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", String::from_utf8_lossy(&self.body)))
    }
    fn data(&self) -> Value {
        self.json()["data"].clone()
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

impl Harness {
    async fn call(&self, method: &str, uri: &str, cn: &str, headers: &[(&str, &str)], body: &str) -> Reply {
        let mut builder = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let mut request = builder.body(Body::from(body.to_string())).unwrap();
        request.extensions_mut().insert(PeerIdentity(cn.to_string()));
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let content_type = response.headers().get("content-type").map(|v| v.to_str().unwrap().to_string());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap().to_vec();
        Reply { status, body, content_type }
    }

    async fn get(&self, uri: &str, cn: &str) -> Reply {
        self.call("GET", uri, cn, &[], "").await
    }

    /// Creates a mission and returns (its JSON, the owner token).
    async fn create(&self, name: &str, cn: &str, query: &str) -> (Value, String) {
        let reply = self.call("PUT", &format!("/Marti/api/missions/{name}?creatorUid=ANDROID-{cn}{query}"), cn, &[], "").await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.text());
        let mission = reply.data()[0].clone();
        let token = mission["token"].as_str().unwrap().to_string();
        (mission, token)
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn is_pad_millis(s: &Value) -> bool {
    let s = s.as_str().unwrap_or("");
    s.len() == 24 && s.ends_with('Z') && s.as_bytes()[19] == b'.' && s[20..23].chars().all(|c| c.is_ascii_digit())
}

// --- create / get ------------------------------------------------------------------

/// `createMission` → `doInternalCreateMission`: 201, the official
/// envelope, the creator subscribed as owner with that token returned.
#[tokio::test]
async fn create_returns_the_mission_with_an_owner_token() {
    let h = harness();
    let reply = h
        .call("PUT", "/Marti/api/missions/Ops?creatorUid=ANDROID-1&description=Night%20op&chatRoom=ops-chat", "jz", &[], "")
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let envelope = reply.json();
    assert_eq!(envelope["version"], "3");
    assert_eq!(envelope["type"], "Mission");
    let m = &envelope["data"][0];
    assert_eq!(m["name"], "Ops");
    assert_eq!(m["description"], "Night op");
    assert_eq!(m["chatRoom"], "ops-chat");
    assert_eq!(m["tool"], "public");
    assert_eq!(m["creatorUid"], "ANDROID-1");
    assert_eq!(m["expiration"], -1);
    assert_eq!(m["passwordProtected"], false);
    assert_eq!(m["groups"], json!(["__ANON__"]));
    assert_eq!(m["keywords"], json!([]));
    assert_eq!(m["uids"], json!([]));
    assert_eq!(m["contents"], json!([]));
    assert!(m.get("defaultRole").is_none(), "NON_NULL: no default role set");
    assert_eq!(m["ownerRole"]["type"], "MISSION_OWNER");
    assert_eq!(m["ownerRole"]["permissions"].as_array().unwrap().len(), 8);
    assert!(is_pad_millis(&m["createTime"]), "{}", m["createTime"]);
    assert_eq!(m["guid"].as_str().unwrap().len(), 36);

    let claims = h.state.tokens.decode(m["token"].as_str().unwrap()).unwrap();
    assert_eq!(claims.token_type, TokenType::Subscription);
    let sub = h.state.store.subscription_by_id(m["guid"].as_str().unwrap(), &claims.id).unwrap();
    assert_eq!((sub.role, sub.client_uid.as_str(), sub.username.as_str()), (Role::Owner, "ANDROID-1", "jz"));
}

/// A JSON `Mission` body wins over query parameters.
#[tokio::test]
async fn a_json_body_overrides_the_query() {
    let h = harness();
    let reply = h
        .call(
            "PUT",
            "/Marti/api/missions/Ops?creatorUid=A&description=query",
            "jz",
            &[("content-type", "application/json")],
            r#"{"description":"body","defaultRole":{"type":"MISSION_READONLY_SUBSCRIBER"}}"#,
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let m = &reply.data()[0];
    assert_eq!(m["description"], "body");
    assert_eq!(m["defaultRole"]["type"], "MISSION_READONLY_SUBSCRIBER");
    assert_eq!(m["defaultRole"]["permissions"], json!(["MISSION_READ"]));
}

/// PUT on an existing name updates it (200), with `MISSION_WRITE`.
#[tokio::test]
async fn put_on_an_existing_mission_updates_it() {
    let h = harness();
    let (_, token) = h.create("Ops", "jz", "").await;
    let reply = h.call("PUT", "/Marti/api/missions/Ops?description=changed", "jz", &[("MissionAuthorization", &bearer(&token))], "").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.data()[0]["description"], "changed");
    assert_eq!(h.state.store.list().len(), 1);

    // A read-only default role can't write.
    let (_, _) = h.create("Read", "jz", "&defaultRole=MISSION_READONLY_SUBSCRIBER").await;
    let reply = h.call("PUT", "/Marti/api/missions/Read?description=x", "other", &[], "").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.json()["code"], 10);
}

/// `POST` with `allowDupe=true` creates a second mission of the same name.
#[tokio::test]
async fn post_with_allow_dupe_creates_a_duplicate() {
    let h = harness();
    h.create("Ops", "jz", "").await;
    let reply = h.call("POST", "/Marti/api/missions/Ops?creatorUid=B&allowDupe=true", "jz", &[], "").await;
    assert_eq!(reply.status, StatusCode::CREATED);
    assert_eq!(h.state.store.list().len(), 2);
}

/// The role filter: unknown → empty 404, deleted → empty 410.
#[tokio::test]
async fn unknown_and_deleted_missions_are_bodyless_404_and_410() {
    let h = harness();
    let reply = h.get("/Marti/api/missions/Nope/changes", "jz").await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert!(reply.body.is_empty());

    let (_, token) = h.create("Ops", "jz", "").await;
    let deleted = h.call("DELETE", "/Marti/api/missions/Ops?creatorUid=A", "jz", &[("Authorization", &bearer(&token))], "").await;
    assert_eq!(deleted.status, StatusCode::OK);
    assert_eq!(deleted.data()[0]["name"], "Ops");
    let reply = h.get("/Marti/api/missions/Ops", "jz").await;
    assert_eq!(reply.status, StatusCode::GONE);
    assert!(reply.body.is_empty());
    assert_eq!(h.get("/Marti/api/missions/guid/not-a-uuid", "jz").await.status, StatusCode::BAD_REQUEST);
}

/// `getMission`: password-protected without a token → 403 at API version
/// 2 (the default), the mission without content at version 3; the
/// password yields an ACCESS token.
#[tokio::test]
async fn password_protected_missions_follow_the_api_version() {
    let h = harness();
    let (_, owner) = h.create("Secret", "jz", "&password=pw").await;
    h.call("PUT", "/Marti/api/missions/Secret/contents?creatorUid=A", "jz", &[("MissionAuthorization", &bearer(&owner))], r#"{"uids":["u-1"]}"#)
        .await;

    let reply = h.get("/Marti/api/missions/Secret", "other").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    let reply = h.call("GET", "/Marti/api/missions/Secret", "other", &[("API_VERSION", "3")], "").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.data()[0]["uids"], json!([]), "cleared");
    assert_eq!(reply.data()[0]["passwordProtected"], true);

    let reply = h.get("/Marti/api/missions/Secret?password=wrong", "other").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let reply = h.get("/Marti/api/missions/Secret?password=pw", "other").await;
    assert_eq!(reply.status, StatusCode::OK);
    let access = reply.data()[0]["token"].as_str().unwrap().to_string();
    assert_eq!(h.state.tokens.decode(&access).unwrap().token_type, TokenType::Access);
    assert_eq!(reply.data()[0]["uids"][0]["data"], "u-1");

    // The ACCESS token gives the default role from now on.
    let reply = h.call("GET", "/Marti/api/missions/Secret/changes", "other", &[("MissionAuthorization", &bearer(&access))], "").await;
    assert_eq!(reply.status, StatusCode::OK);
    // A token for another mission doesn't count.
    let (_, other_owner) = h.create("Other", "jz", "").await;
    let reply = h.call("GET", "/Marti/api/missions/Secret/changes", "other", &[("MissionAuthorization", &bearer(&other_owner))], "").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    // The admin is owner everywhere.
    assert_eq!(h.get("/Marti/api/missions/Secret/changes", "admin").await.status, StatusCode::OK);
}

/// `getAllMissions` → `getAllMissionsByToolNoGroupCheck`: no invite-only,
/// password-protected only on request (and then cleared), tool `public`,
/// a set ordered by lowercase name.
#[tokio::test]
async fn the_list_follows_the_official_query() {
    let h = harness();
    h.create("bravo", "jz", "").await;
    h.create("Alpha", "jz", "").await;
    h.create("Locked", "jz", "&password=pw").await;
    h.create("Invite", "jz", "&inviteOnly=true").await;
    h.create("Tooled", "jz", "&tool=other").await;
    h.create("Viewer", "jz", "&defaultRole=MISSION_READONLY_SUBSCRIBER").await;

    let names = |reply: &Reply| -> Vec<String> {
        reply.data().as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap().to_string()).collect()
    };
    assert_eq!(names(&h.get("/Marti/api/missions", "jz").await), ["Alpha", "bravo"]);
    assert_eq!(names(&h.get("/Marti/api/missions?passwordProtected=true", "jz").await), ["Alpha", "bravo", "Locked"]);
    assert_eq!(names(&h.get("/Marti/api/missions?defaultRole=true", "jz").await), ["Alpha", "bravo", "Viewer"]);
    assert_eq!(names(&h.get("/Marti/api/missions?tool=other", "jz").await), ["Tooled"]);
}

/// Groups: a mission is invisible outside its groups.
#[tokio::test]
async fn missions_are_invisible_outside_their_groups() {
    let h = harness();
    h.state.groups.create("Red", None, 0).unwrap();
    h.state.groups.set_member("Red", "red-1", Some(crate::groups::Membership::Both)).unwrap();
    let reply = h.call("PUT", "/Marti/api/missions/RedOps?creatorUid=R&group=Red", "red-1", &[], "").await;
    assert_eq!(reply.status, StatusCode::CREATED);
    assert_eq!(reply.data()[0]["groups"], json!(["Red"]));
    assert_eq!(h.get("/Marti/api/missions/RedOps", "outsider").await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.get("/Marti/api/missions", "outsider").await.data(), json!([]));
    // A non-member can't put a mission into Red.
    let reply = h.call("PUT", "/Marti/api/missions/Sneaky?creatorUid=X&group=Red", "outsider", &[], "").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

// --- contents and changes -----------------------------------------------------------------

/// `addMissionContent`: hashes that are Enterprise Sync resources and
/// uids; unknown hashes skipped; changes squashed, newest first.
#[tokio::test]
async fn contents_and_changes() {
    let h = harness();
    let hash = "b".repeat(64);
    h.state
        .resources
        .insert(
            crate::sync::NewResource { uid: "r-1".into(), name: Some("map.png".into()), submission_user: "jz".into(), ..Default::default() },
            &hash,
            10,
            1,
        )
        .unwrap();
    let (_, token) = h.create("Ops", "jz", "").await;
    let auth = [("MissionAuthorization", bearer(&token))];
    let auth: Vec<(&str, &str)> = auth.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let body = format!(r#"{{"hashes":["{hash}","{}"],"uids":["marker-1"]}}"#, "c".repeat(64));
    let reply = h.call("PUT", "/Marti/api/missions/Ops/contents?creatorUid=ANDROID-1", "jz", &auth, &body).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let m = &reply.data()[0];
    assert_eq!(m["groups"], json!([]), "the official response clears groups");
    assert_eq!(m["contents"].as_array().unwrap().len(), 1, "unknown hash skipped");
    assert_eq!(m["contents"][0]["data"]["hash"], hash);
    assert_eq!(m["contents"][0]["creatorUid"], "ANDROID-1");
    assert_eq!(m["uids"][0]["data"], "marker-1");

    let reply = h.call("PUT", "/Marti/api/missions/Ops/contents", "jz", &auth, r#"{"hashes":[],"uids":[]}"#).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["message"], "Invalid Request: at least one hash or uid must be provided in request");

    let reply = h.call("DELETE", "/Marti/api/missions/Ops/contents?uid=marker-1&creatorUid=ANDROID-2", "jz", &auth, "").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.data()[0]["uids"], json!([]));

    let changes = h.call("GET", "/Marti/api/missions/Ops/changes", "jz", &auth, "").await;
    assert_eq!(changes.json()["type"], "MissionChange");
    let types: Vec<(String, Option<String>)> = changes
        .data()
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["type"].as_str().unwrap().to_string(), c["contentUid"].as_str().map(String::from)))
        .collect();
    assert_eq!(
        types,
        [
            ("REMOVE_CONTENT".to_string(), Some("marker-1".to_string())),
            ("ADD_CONTENT".to_string(), None),
            ("CREATE_MISSION".to_string(), None),
        ]
    );
    let add = &changes.data()[1];
    assert_eq!(add["contentResource"]["hash"], hash);
    assert!(add.get("contentHash").is_none(), "@JsonIgnore");
    assert!(is_pad_millis(&add["serverTime"]));
    let full = h.call("GET", "/Marti/api/missions/Ops/changes?squashed=false", "jz", &auth, "").await;
    assert_eq!(full.data().as_array().unwrap().len(), 4);
}

/// A read-only subscriber (`MISSION_READ` only) can read but not write.
#[tokio::test]
async fn read_only_subscribers_cannot_write() {
    let h = harness();
    h.create("Ops", "jz", "&defaultRole=MISSION_READONLY_SUBSCRIBER").await;
    let reply = h.call("PUT", "/Marti/api/missions/Ops/contents", "viewer", &[], r#"{"uids":["x"]}"#).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(h.get("/Marti/api/missions/Ops/changes", "viewer").await.status, StatusCode::OK);
}

// --- keywords ----------------------------------------------------------------------------------

#[tokio::test]
async fn keywords() {
    let h = harness();
    h.create("Ops", "jz", "").await;
    let reply = h.call("PUT", "/Marti/api/missions/Ops/keywords", "jz", &[("content-type", "application/json")], r#"["b","a","b"]"#).await;
    assert_eq!(reply.data()[0]["keywords"], json!(["a", "b"]), "a sorted set");
    let reply = h.call("DELETE", "/Marti/api/missions/Ops/keywords/zzz", "jz", &[], "").await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let reply = h.call("DELETE", "/Marti/api/missions/Ops/keywords/a", "jz", &[], "").await;
    assert_eq!(reply.data()[0]["keywords"], json!(["b"]));

    h.call("PUT", "/Marti/api/missions/Ops/contents", "jz", &[], r#"{"uids":["u-1"]}"#).await;
    assert_eq!(h.call("PUT", "/Marti/api/missions/Ops/uid/u-1/keywords", "jz", &[], r#"[]"#).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.call("PUT", "/Marti/api/missions/Ops/uid/u-1/keywords", "jz", &[], r#"["k1"]"#).await.status, StatusCode::OK);
    let m = h.get("/Marti/api/missions/Ops", "jz").await.data()[0].clone();
    assert_eq!(m["uids"][0]["keywords"], json!(["k1"]));
    h.call("DELETE", "/Marti/api/missions/Ops/uid/u-1/keywords", "jz", &[], "").await;
    let m = h.get("/Marti/api/missions/Ops", "jz").await.data()[0].clone();
    assert!(m["uids"][0].get("keywords").is_none(), "null keywords are omitted");
}

// --- subscriptions and roles -------------------------------------------------------------------

/// `createMissionSubscription` / `missionSubscribe` / `deleteMissionSubscription`.
#[tokio::test]
async fn subscribing_and_unsubscribing() {
    let h = harness();
    h.create("Ops", "jz", "").await;
    let reply = h.call("PUT", "/Marti/api/missions/Ops/subscription", "alpha", &[], "").await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "uid or topic required");

    let reply = h.call("PUT", "/Marti/api/missions/Ops/subscription?uid=ANDROID-A", "alpha", &[], "").await;
    assert_eq!(reply.status, StatusCode::CREATED);
    assert_eq!(reply.json()["type"], "com.bbn.marti.sync.model.MissionSubscription");
    let sub = reply.data();
    assert_eq!(sub["clientUid"], "ANDROID-A");
    assert_eq!(sub["username"], "alpha");
    assert_eq!(sub["role"]["type"], "MISSION_SUBSCRIBER");
    assert!(sub.get("mission").is_none(), "API version 2: no mission");
    let token = sub["token"].as_str().unwrap().to_string();

    let again = h.call("PUT", "/Marti/api/missions/Ops/subscription?uid=ANDROID-A", "alpha", &[("API_VERSION", "3")], "").await;
    assert_eq!(again.data()["token"], token.as_str(), "the same subscription");
    assert_eq!(again.data()["mission"]["name"], "Ops");

    let mine = h.get("/Marti/api/missions/Ops/subscription?uid=ANDROID-A", "alpha").await;
    assert_eq!(mine.data()["token"], token.as_str());
    assert_eq!(h.get("/Marti/api/missions/Ops/subscription?uid=ANDROID-A", "someone-else").await.status, StatusCode::NOT_FOUND);

    let list = h.get("/Marti/api/missions/Ops/subscriptions", "alpha").await;
    assert_eq!(list.json()["type"], "MissionSubscription");
    assert_eq!(list.data(), json!(["ANDROID-jz", "ANDROID-A"]));
    let roles = h.get("/Marti/api/missions/Ops/subscriptions/roles", "alpha").await;
    assert!(roles.data().as_array().unwrap().iter().all(|s| s.get("token").is_none()), "no tokens");

    // disconnectOnly defaults to true: the stored subscription stays.
    assert_eq!(h.call("DELETE", "/Marti/api/missions/Ops/subscription?uid=ANDROID-A", "alpha", &[], "").await.status, StatusCode::OK);
    assert_eq!(h.get("/Marti/api/missions/Ops/subscriptions", "alpha").await.data().as_array().unwrap().len(), 2);
    h.call("DELETE", "/Marti/api/missions/Ops/subscription?uid=ANDROID-A&disconnectOnly=false", "alpha", &[], "").await;
    assert_eq!(h.get("/Marti/api/missions/Ops/subscriptions", "alpha").await.data(), json!(["ANDROID-jz"]));

    // the subscription token decides the role
    let role = h.call("GET", "/Marti/api/missions/Ops/role", "jz", &[], "").await;
    assert_eq!(role.json()["type"], "com.bbn.marti.sync.model.MissionRole");
    assert_eq!(role.data()["type"], "MISSION_SUBSCRIBER", "no token: the default role");
}

/// `subscribe` to password-protected and invite-only missions.
#[tokio::test]
async fn subscribing_needs_the_password_or_an_invitation() {
    let h = harness();
    h.create("Secret", "jz", "&password=pw").await;
    assert_eq!(h.call("PUT", "/Marti/api/missions/Secret/subscription?uid=X", "alpha", &[], "").await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.call("PUT", "/Marti/api/missions/Secret/subscription?uid=X&password=no", "alpha", &[], "").await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.call("PUT", "/Marti/api/missions/Secret/subscription?uid=X&password=pw", "alpha", &[], "").await.status, StatusCode::CREATED);
    let (_, _) = h.create("Open", "jz", "").await;
    assert_eq!(
        h.call("PUT", "/Marti/api/missions/Open/subscription?uid=X&password=pw", "alpha", &[], "").await.status,
        StatusCode::FORBIDDEN,
        "a password for a mission without one"
    );

    let (_, owner) = h.create("Invited", "jz", "&inviteOnly=true").await;
    assert_eq!(h.call("PUT", "/Marti/api/missions/Invited/subscription?uid=X", "alpha", &[], "").await.status, StatusCode::FORBIDDEN);
    let reply = h
        .call("PUT", "/Marti/api/missions/Invited/invite/userName/alpha?creatorUid=ANDROID-jz", "jz", &[("MissionAuthorization", &bearer(&owner))], "")
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let invitations = h.get("/Marti/api/missions/invitations?clientUid=X", "alpha").await;
    assert_eq!(invitations.json()["type"], "MissionInvitation");
    assert_eq!(invitations.data()[0]["missionName"], "Invited");
    assert_eq!(invitations.data()[0]["type"], "userName");
    assert_eq!(invitations.data()[0]["role"]["type"], "MISSION_SUBSCRIBER");
    assert_eq!(h.call("PUT", "/Marti/api/missions/Invited/subscription?uid=X", "alpha", &[], "").await.status, StatusCode::CREATED);
}

#[tokio::test]
async fn invitations() {
    let h = harness();
    let (_, owner) = h.create("Ops", "jz", "").await;
    let auth = bearer(&owner);
    let reply = h.call("PUT", "/Marti/api/missions/Ops/invite/clientUid/ANDROID-B", "jz", &[("MissionAuthorization", &auth)], "").await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "creatorUid is required");
    let reply = h
        .call("PUT", "/Marti/api/missions/Ops/invite/clientUid/ANDROID-B?creatorUid=C&role=MISSION_OWNER", "jz", &[("MissionAuthorization", &auth)], "")
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    // Without a token the caller only has the default (subscriber) role,
    // which can't hand out owner.
    let reply = h.call("PUT", "/Marti/api/missions/Ops/invite/clientUid/ANDROID-C?creatorUid=C&role=MISSION_OWNER", "jz", &[], "").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    // Nor anything below the default role.
    let reply = h
        .call("PUT", "/Marti/api/missions/Ops/invite/clientUid/ANDROID-C?creatorUid=C&role=MISSION_READONLY_SUBSCRIBER", "jz", &[("MissionAuthorization", &auth)], "")
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    let names = h.get("/Marti/api/missions/all/invitations?clientUid=ANDROID-B", "anyone").await;
    assert_eq!(names.data(), json!(["Ops"]));
    let listed = h.get("/Marti/api/missions/Ops/invitations", "jz").await;
    assert_eq!(listed.data()[0]["invitee"], "ANDROID-B");
    assert_eq!(listed.data()[0]["role"]["type"], "MISSION_OWNER");

    // Subscribing consumes the clientUid invitation and uses its role.
    let token = listed.data()[0]["token"].as_str().unwrap().to_string();
    let sub = h.call("PUT", "/Marti/api/missions/Ops/subscription?uid=ANDROID-B", "bee", &[("MissionAuthorization", &bearer(&token))], "").await;
    assert_eq!(sub.data()["role"]["type"], "MISSION_OWNER");
    assert_eq!(h.get("/Marti/api/missions/Ops/invitations", "jz").await.data(), json!([]));

    h.call("PUT", "/Marti/api/missions/Ops/invite/callsign/Zulu?creatorUid=C", "jz", &[("MissionAuthorization", &auth)], "").await;
    let reply = h.call("DELETE", "/Marti/api/missions/Ops/invite/callsign/zulu?creatorUid=C", "jz", &[], "").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(h.get("/Marti/api/missions/Ops/invitations", "jz").await.data(), json!([]));
}

/// `setMissionRole`: `MISSION_SET_ROLE`, and only on missions with a
/// default role.
#[tokio::test]
async fn setting_a_role() {
    let h = harness();
    let (_, owner) = h.create("Ops", "jz", "").await;
    let auth = bearer(&owner);
    h.call("PUT", "/Marti/api/missions/Ops/subscription?uid=ANDROID-A", "alpha", &[], "").await;
    let reply = h.call("PUT", "/Marti/api/missions/Ops/role?clientUid=ANDROID-A&role=MISSION_OWNER", "jz", &[("MissionAuthorization", &auth)], "").await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "no default role on this mission");

    let (_, owner) = h.create("Roles", "jz", "&defaultRole=MISSION_SUBSCRIBER").await;
    let auth = bearer(&owner);
    let sub = h.call("PUT", "/Marti/api/missions/Roles/subscription?uid=ANDROID-A", "alpha", &[], "").await.data();
    let reply = h.call("PUT", "/Marti/api/missions/Roles/role?clientUid=ANDROID-A&role=MISSION_OWNER", "alpha", &[], "").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "a subscriber lacks MISSION_SET_ROLE");
    let reply = h.call("PUT", "/Marti/api/missions/Roles/role?clientUid=ANDROID-A&role=MISSION_OWNER", "jz", &[("MissionAuthorization", &auth)], "").await;
    assert_eq!(reply.status, StatusCode::OK);
    let role = h.call("GET", "/Marti/api/missions/Roles/role", "alpha", &[("MissionAuthorization", &bearer(sub["token"].as_str().unwrap()))], "").await;
    assert_eq!(role.data()["type"], "MISSION_OWNER");
}

// --- tokens, passwords, logs, CoT, errors -------------------------------------------------------

#[tokio::test]
async fn access_tokens_and_passwords() {
    let h = harness();
    let (_, owner) = h.create("Ops", "jz", "").await;
    let reply = h.get("/Marti/api/missions/Ops/token", "alpha").await;
    assert_eq!(reply.status, StatusCode::CREATED);
    assert_eq!(reply.json()["type"], "java.lang.String");
    assert_eq!(h.state.tokens.decode(reply.data().as_str().unwrap()).unwrap().token_type, TokenType::Access);

    assert_eq!(h.call("PUT", "/Marti/api/missions/Ops/password?password=pw", "alpha", &[], "").await.status, StatusCode::FORBIDDEN);
    let auth = bearer(&owner);
    assert_eq!(h.call("PUT", "/Marti/api/missions/Ops/password?password=pw", "jz", &[("MissionAuthorization", &auth)], "").await.status, StatusCode::OK);
    assert_eq!(h.get("/Marti/api/missions/Ops/changes", "alpha").await.status, StatusCode::FORBIDDEN, "now password-protected");
    assert_eq!(h.get("/Marti/api/missions/Ops/changes", "jz").await.status, StatusCode::FORBIDDEN, "no token, no role");
    assert_eq!(h.call("GET", "/Marti/api/missions/Ops/changes", "jz", &[("MissionAuthorization", &auth)], "").await.status, StatusCode::OK);
    assert_eq!(h.call("DELETE", "/Marti/api/missions/Ops/password", "jz", &[("MissionAuthorization", &auth)], "").await.status, StatusCode::OK);
    assert_eq!(h.get("/Marti/api/missions/Ops/changes", "alpha").await.status, StatusCode::OK);
}

#[tokio::test]
async fn log_entries() {
    let h = harness();
    h.create("Ops", "jz", "").await;
    let reply = h.call("POST", "/Marti/api/missions/logs/entries", "jz", &[], r#"{"id":"x","missionNames":["Ops"]}"#).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let reply = h
        .call(
            "POST",
            "/Marti/api/missions/logs/entries",
            "jz",
            &[],
            r#"{"content":"contact","creatorUid":"ANDROID-1","missionNames":["Ops"],"dtg":"2026-10-17T20:00:00.000Z"}"#,
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.json()["type"], "com.bbn.marti.sync.model.LogEntry");
    let entry = reply.data();
    let id = entry["id"].as_str().unwrap().to_string();
    assert_eq!(entry["dtg"], "2026-10-17T20:00:00.000Z");
    assert!(is_pad_millis(&entry["servertime"]));

    let one = h.get(&format!("/Marti/api/missions/logs/entries/{id}"), "jz").await;
    assert_eq!(one.data()[0]["content"], "contact");
    let put = h
        .call("PUT", "/Marti/api/missions/logs/entries", "jz", &[], &format!(r#"{{"id":"{id}","content":"changed","missionNames":["Ops"]}}"#))
        .await;
    assert_eq!(put.data()["content"], "changed");
    assert_eq!(h.get("/Marti/api/missions/Ops/log", "jz").await.data()[0]["content"], "changed");
    assert_eq!(h.get("/Marti/api/missions/all/logs", "jz").await.status, StatusCode::FORBIDDEN, "admin only");
    assert_eq!(h.get("/Marti/api/missions/all/logs", "admin").await.data().as_array().unwrap().len(), 1);
    assert_eq!(h.call("DELETE", &format!("/Marti/api/missions/logs/entries/{id}"), "jz", &[], "").await.status, StatusCode::OK);
    assert_eq!(h.get(&format!("/Marti/api/missions/logs/entries/{id}"), "jz").await.status, StatusCode::NOT_FOUND);
}

/// `getLatestMissionCotEvents`: XML, the latest event of each mission uid;
/// uid `details` come from it too.
#[tokio::test]
async fn mission_cot_and_uid_details() {
    let h = harness();
    h.create("Ops", "jz", "").await;
    h.call("PUT", "/Marti/api/missions/Ops/contents", "jz", &[], r#"{"uids":["m-1","never-seen"]}"#).await;
    let event = r#"<event version="2.0" uid="m-1" type="a-h-G" how="h-g-i-g-o" time="t" start="t" stale="t"><point lat="1.5" lon="2.5" hae="0" ce="0" le="0"/><detail><contact callsign="Hostile"/></detail></event>"#;
    h.state.latest_cot.record("m-1", &format!("<?xml version=\"1.0\"?>{event}"), 1);
    let reply = h.get("/Marti/api/missions/Ops/cot", "jz").await;
    assert_eq!(reply.content_type.as_deref(), Some("application/xml"));
    assert_eq!(reply.text(), format!("<?xml version='1.0' encoding='UTF-8' standalone='yes'?><events>{event}\n</events>"));
    let m = h.get("/Marti/api/missions/Ops", "jz").await.data()[0].clone();
    assert_eq!(m["uids"][0]["details"]["callsign"], "Hostile");
    assert_eq!(m["uids"][0]["details"]["location"], json!({ "lat": 1.5, "lon": 2.5 }));
    assert!(m["uids"][1].get("details").is_none());
}

/// `CustomExceptionHandler` bodies.
#[tokio::test]
async fn errors_have_the_official_body() {
    let h = harness();
    h.create("Ops", "jz", "").await;
    let reply = h.get("/Marti/api/missions/Ops/changes?secago=abc", "jz").await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["status"], "BAD_REQUEST");
    assert_eq!(reply.json()["code"], 2);
    assert!(reply.json()["message"].as_str().unwrap().starts_with("Invalid Request: "));
    let reply = h.get("/Marti/api/missions/Ops/changes?start=2026-10-18T00:00:00Z&end=2026-10-17T00:00:00Z", "jz").await;
    assert_eq!(reply.json()["message"], "Invalid Request: invalid time range");
}

/// `COT_DATE_FORMAT_PAD_MILLIS` always has three-digit milliseconds.
#[test]
fn mission_dates_pad_milliseconds() {
    assert_eq!(pad_millis(1_760_716_800_005), "2025-10-17T16:00:00.005Z");
    assert_eq!(pad_millis(1_760_716_800_040), "2025-10-17T16:00:00.040Z");
    assert_eq!(pad_millis(1_760_716_800_689), "2025-10-17T16:00:00.689Z");
}

/// A SUBSCRIPTION token carries that subscription's role -- here the
/// default subscriber role, which may not set a password.
#[tokio::test]
async fn a_subscription_token_carries_its_own_role() {
    let h = harness();
    h.create("Secret", "jz", "&password=pw").await;
    let sub = h.call("PUT", "/Marti/api/missions/Secret/subscription?uid=ANDROID-V&password=pw", "visitor", &[], "").await.data();
    let auth = bearer(sub["token"].as_str().unwrap());
    let role = h.call("GET", "/Marti/api/missions/Secret/role", "visitor", &[("MissionAuthorization", &auth)], "").await;
    assert_eq!(role.data()["type"], "MISSION_SUBSCRIBER");
    let reply = h.call("PUT", "/Marti/api/missions/Secret/password?password=x", "visitor", &[("MissionAuthorization", &auth)], "").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}
