use super::*;
use axum::body::Body;
use axum::http::Request;
use base64::Engine;
use tower::ServiceExt;

use crate::groups::Membership;
use crate::transport::hub::RelayHub;

struct Fixture {
    app: Router,
    enroll: Router,
    store: Arc<ProfileStore>,
    hub: RelayHub,
    tokens: Arc<EnrollmentTokenStore>,
    _dir: TempDir,
}

struct TempDir(std::path::PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn fixture() -> Fixture {
    let dir = std::env::temp_dir().join(format!(
        "microtak-profiles-api-{}-{}",
        std::process::id(),
        crate::marti::envelope::random_uuid()
    ));
    let store = Arc::new(
        ProfileStore::load_or_create(dir.join("profiles.log"), dir.join("content")).unwrap(),
    );
    let groups = Arc::new(GroupStore::in_memory());
    groups.create("Red", None, 0).unwrap();
    groups.create("Blue", None, 0).unwrap();
    groups
        .set_member("Red", "red-device", Some(Membership::Out))
        .unwrap();
    groups
        .set_member("Red", "red-user", Some(Membership::Both))
        .unwrap();
    let hub = RelayHub::new();
    let notifier = Arc::new(MissionNotifier::new(
        hub.sender(),
        Arc::new(crate::missions::MissionStore::in_memory()),
        Arc::new(crate::sync::ResourceStore::in_memory()),
        Arc::new(crate::latest_cot::LatestCot::in_memory()),
        Arc::clone(&groups),
    ));
    let users = Arc::new(UserStore::in_memory());
    users.mint("red-user", "s3cret", 0).unwrap();
    let tokens = Arc::new(EnrollmentTokenStore::in_memory());
    let app = router(ProfilesState {
        store: Arc::clone(&store),
        groups: Arc::clone(&groups),
        notifier,
        max_upload_bytes: 10 * 1024 * 1024,
    });
    let enroll = enrollment_router(EnrollmentProfilesState {
        store: Arc::clone(&store),
        groups,
        users,
        tokens: Arc::clone(&tokens),
        limiter: Arc::new(AuthLimiter::new(
            5,
            std::time::Duration::from_secs(60),
            100,
            1,
        )),
    });
    Fixture {
        app,
        enroll,
        store,
        hub,
        tokens,
        _dir: TempDir(dir),
    }
}

async fn call(
    app: &Router,
    identity: &str,
    method: &str,
    uri: &str,
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .extension(PeerIdentity(identity.to_string()))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, bytes)
}

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap()
}

/// Every zip entry (directories included) and the manifest.
fn entries(package: &[u8]) -> (Vec<String>, String) {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(package.to_vec())).unwrap();
    let names: Vec<String> = (0..archive.len())
        .map(|i| archive.by_index(i).unwrap().name().unwrap().to_string())
        .collect();
    let mut manifest = String::new();
    std::io::Read::read_to_string(
        &mut archive.by_name("MANIFEST/manifest.xml").unwrap(),
        &mut manifest,
    )
    .unwrap();
    (names, manifest)
}

/// An admin builds a "Red" profile with two files and makes it a
/// connection profile, as the official admin UI does.
async fn red_connection_profile(f: &Fixture) -> i64 {
    let (status, ..) = call(
        &f.app,
        "admin",
        "POST",
        "/Marti/api/device/profile/Red%20Team?group=Red&group=Nope",
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, ..) = call(
        &f.app,
        "admin",
        "POST",
        "/Marti/api/device/profile/Red%20Team",
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "exists already");
    for (name, body) in [("team.pref", "<preferences/>"), ("maps.zip", "zip-bytes")] {
        let (status, _, body) = call(
            &f.app,
            "admin",
            "PUT",
            &format!("/Marti/api/device/profile/Red%20Team/file?filename={name}"),
            body.as_bytes().to_vec(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json(&body)["data"]["name"], name);
    }
    let id = f.store.by_name("Red Team").unwrap().id;
    let posted = json!({ "id": id, "name": "Red Team", "active": true, "type": "Connection", "tool": null, "groups": ["Red"] });
    let (status, ..) = call(
        &f.app,
        "admin",
        "PUT",
        "/Marti/api/device/profile/Red%20Team",
        posted.to_string().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    id
}

#[tokio::test]
async fn the_admin_api_lists_profiles_as_the_official_server_does() {
    let f = fixture();
    let id = red_connection_profile(&f).await;

    let (status, _, body) = call(&f.app, "admin", "GET", "/Marti/api/device/profile", vec![]).await;
    assert_eq!(status, StatusCode::OK);
    let body = json(&body);
    assert_eq!(body["type"], "Profile");
    let p = &body["data"][0];
    assert_eq!(p["id"], id);
    assert_eq!(p["name"], "Red Team");
    assert_eq!(
        (
            p["active"].as_bool(),
            p["applyOnEnrollment"].as_bool(),
            p["applyOnConnect"].as_bool()
        ),
        (Some(true), Some(false), Some(true))
    );
    assert_eq!(p["type"], "Connection");
    assert_eq!(
        p["groups"],
        json!(["Red"]),
        "unknown group names are ignored"
    );
    assert!(p["updated"].is_i64(), "a java.util.Date: epoch millis");

    let (_, _, body) = call(
        &f.app,
        "admin",
        "GET",
        "/Marti/api/device/profile/Red%20Team",
        vec![],
    )
    .await;
    assert_eq!(json(&body)["data"]["name"], "Red Team");
    let (status, ..) = call(
        &f.app,
        "admin",
        "GET",
        "/Marti/api/device/profile/nope",
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (_, _, body) = call(
        &f.app,
        "admin",
        "GET",
        "/Marti/api/device/profile/Red%20Team/files",
        vec![],
    )
    .await;
    let files = json(&body);
    assert_eq!(files["type"], "ProfileFile");
    assert_eq!(
        files["data"][0]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["id", "name"]
    );
    let file_id = files["data"][0]["id"].as_i64().unwrap();
    let (status, headers, bytes) = call(
        &f.app,
        "admin",
        "GET",
        &format!("/Marti/api/device/profile/Red%20Team/file/{file_id}"),
        vec![],
    )
    .await;
    assert_eq!(
        (status, bytes.as_slice()),
        (StatusCode::OK, b"<preferences/>".as_slice())
    );
    assert_eq!(
        headers[header::CONTENT_DISPOSITION],
        "attachment; filename=team.pref"
    );

    let (status, ..) = call(
        &f.app,
        "admin",
        "DELETE",
        &format!("/Marti/api/device/profile/Red%20Team/file/{file_id}"),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(f.store.files(id).len(), 1);
    let (_, _, body) = call(
        &f.app,
        "admin",
        "GET",
        "/Marti/api/device/profile/directories",
        vec![],
    )
    .await;
    assert_eq!(json(&body)["data"], json!([]));

    let (status, ..) = call(
        &f.app,
        "admin",
        "DELETE",
        &format!("/Marti/api/device/profile/{id}"),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(f.store.all().is_empty());
}

#[tokio::test]
async fn updating_without_a_type_is_the_official_500() {
    let f = fixture();
    call(
        &f.app,
        "admin",
        "POST",
        "/Marti/api/device/profile/P",
        vec![],
    )
    .await;
    let id = f.store.by_name("P").unwrap().id;
    let posted = json!({ "id": id, "name": "P", "active": true, "groups": [] });
    let (status, ..) = call(
        &f.app,
        "admin",
        "PUT",
        "/Marti/api/device/profile/P",
        posted.to_string().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn devices_get_connection_profiles_of_their_groups_as_a_mission_package() {
    let f = fixture();
    red_connection_profile(&f).await;

    let uri = "/Marti/api/device/profile/connection?syncSecago=-1&clientUid=ANDROID-1";
    let (status, headers, package) = call(&f.app, "red-device", "GET", uri, vec![]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CONTENT_DISPOSITION],
        "attachment; filename=profile.zip"
    );
    let (names, manifest) = entries(&package);
    assert_eq!(
        names,
        [
            "file0/",
            "file0/team.pref",
            "file1/",
            "file1/maps.zip",
            "MANIFEST/",
            "MANIFEST/manifest.xml"
        ]
    );
    assert!(
        manifest.contains(r#"<Parameter name="name" value="Connection"/>"#),
        "{manifest}"
    );
    assert!(manifest.contains(r#"<Parameter name="onReceiveImport" value="true"/>"#));
    assert!(manifest.contains(r#"<Parameter name="onReceiveDelete" value="true"/>"#));
    assert!(
        manifest.contains(r#"<Content zipEntry="file1/maps.zip" ignore="false"/>"#),
        "{manifest}"
    );

    let (status, ..) = call(&f.app, "someone-else", "GET", uri, vec![]).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "not in Red");
    let (status, ..) = call(
        &f.app,
        "red-device",
        "GET",
        "/Marti/api/device/profile/connection?syncSecago=60&clientUid=A",
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "changed within the last minute");
    let (status, ..) = call(
        &f.app,
        "red-device",
        "GET",
        "/Marti/api/device/profile/connection?clientUid=A",
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "syncSecago is required");
    let (status, ..) = call(
        &f.app,
        "red-device",
        "GET",
        "/Marti/api/device/profile/connection?syncSecago=-1",
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "clientUid is required");
}

#[tokio::test]
async fn the_named_mission_package_is_stable_and_group_checked() {
    let f = fixture();
    let id = red_connection_profile(&f).await;
    let uri = "/Marti/api/device/profile/Red%20Team/missionpackage";
    let (status, _, first) = call(&f.app, "red-device", "GET", uri, vec![]).await;
    assert_eq!(status, StatusCode::OK);
    let (_, _, second) = call(&f.app, "red-device", "GET", uri, vec![]).await;
    assert_eq!(
        first, second,
        "the hash a file transfer announces must match"
    );
    let (_, manifest) = entries(&first);
    assert!(manifest.contains(&format!(
        r#"<Parameter name="uid" value="ProfileMissionPackage-{id}"/>"#
    )));
    assert!(manifest.contains(r#"<Parameter name="name" value="Red Team"/>"#));
    let (status, ..) = call(&f.app, "someone-else", "GET", uri, vec![]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, ..) = call(&f.app, "red-device", "HEAD", uri, vec![]).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn sending_a_profile_is_a_file_transfer_to_the_chosen_devices() {
    let f = fixture();
    red_connection_profile(&f).await;
    let mut rx = f.hub.subscribe();
    let (status, ..) = call(
        &f.app,
        "admin",
        "POST",
        "/Marti/api/device/profile/Red%20Team/send",
        br#"["ANDROID-1"]"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let sent = rx.try_recv().unwrap();
    assert_eq!(
        sent.dest_uids.as_deref(),
        Some(["ANDROID-1".to_string()].as_slice())
    );
    let (_, _, package) = call(
        &f.app,
        "red-device",
        "GET",
        "/Marti/api/device/profile/Red%20Team/missionpackage",
        vec![],
    )
    .await;
    let hash = crate::content_store::hex_sha256(&package);
    assert!(
        sent.xml.contains(&format!("uid='{hash}' type='b-f-t-r'")),
        "{}",
        sent.xml
    );
    assert!(sent.xml.contains("senderCallsign='TAK Server'"));
    assert!(
        sent.xml
            .contains(":8443/Marti/api/device/profile/Red+Team/missionpackage'"),
        "{}",
        sent.xml
    );
    let (status, ..) = call(
        &f.app,
        "admin",
        "POST",
        "/Marti/api/device/profile/Red%20Team/send",
        b"[]".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(rx.try_recv().is_err(), "nobody chosen, nothing sent");
}

#[tokio::test]
async fn tool_profiles_are_only_for_their_tool() {
    let f = fixture();
    let id = red_connection_profile(&f).await;
    let posted = json!({ "id": id, "name": "Red Team", "active": true, "type": "Tool", "tool": "radio", "groups": ["APPLY_TO_ALL_GROUPS"] });
    call(
        &f.app,
        "admin",
        "PUT",
        "/Marti/api/device/profile/Red%20Team",
        posted.to_string().into_bytes(),
    )
    .await;
    let (status, ..) = call(
        &f.app,
        "anyone",
        "GET",
        "/Marti/api/device/profile/tool/radio?clientUid=A",
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "all groups");
    let (status, ..) = call(
        &f.app,
        "anyone",
        "GET",
        "/Marti/api/device/profile/tool/other?clientUid=A",
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, ..) = call(
        &f.app,
        "anyone",
        "GET",
        "/Marti/api/device/profile/connection?syncSecago=-1&clientUid=A",
        vec![],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a tool's profile isn't a connection profile"
    );
}

async fn enroll_call(f: &Fixture, auth: Option<(&str, &str)>, query: &str) -> StatusCode {
    let mut request = Request::builder().uri(format!("/Marti/api/tls/profile/enrollment{query}"));
    if let Some((user, secret)) = auth {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{secret}"));
        request = request.header(header::AUTHORIZATION, format!("Basic {encoded}"));
    }
    f.enroll
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

/// ATAK's call right after enrolling, with the credentials it enrolled
/// with: a password account, or the invite token that enrolled the name.
#[tokio::test]
async fn enrollment_profiles_go_to_the_user_that_just_enrolled() {
    let f = fixture();
    call(
        &f.app,
        "admin",
        "POST",
        "/Marti/api/device/profile/Welcome?group=Red",
        vec![],
    )
    .await;
    let id = f.store.by_name("Welcome").unwrap().id;
    f.store.add_file(id, "welcome.pref", b"<p/>", 1).unwrap();

    assert_eq!(
        enroll_call(&f, None, "?clientUid=A").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        enroll_call(&f, Some(("red-user", "s3cret")), "?clientUid=A").await,
        StatusCode::OK
    );
    assert_eq!(
        enroll_call(&f, Some(("red-user", "wrong")), "?clientUid=A").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        enroll_call(&f, Some(("red-user", "s3cret")), "").await,
        StatusCode::BAD_REQUEST
    );

    let token = f.tokens.mint(None, None, 0).unwrap();
    assert_eq!(
        enroll_call(&f, Some(("red-device", &token)), "?clientUid=A").await,
        StatusCode::UNAUTHORIZED,
        "not used yet"
    );
    f.tokens
        .validate_and_consume(&token, "red-device", 0)
        .unwrap();
    assert_eq!(
        enroll_call(&f, Some(("red-device", &token)), "?clientUid=A").await,
        StatusCode::OK
    );
    assert_eq!(
        enroll_call(&f, Some(("other-device", &token)), "?clientUid=A").await,
        StatusCode::UNAUTHORIZED,
        "enrolled another name"
    );
    let other = f.tokens.mint(None, None, 0).unwrap();
    f.tokens
        .validate_and_consume(&other, "blue-device", 0)
        .unwrap();
    assert_eq!(
        enroll_call(&f, Some(("blue-device", &other)), "?clientUid=A").await,
        StatusCode::NO_CONTENT,
        "not in Red"
    );
}

/// Devices may fetch their profiles; everything else is the admin's
/// (the official `security-context.xml`).
#[test]
fn only_the_device_calls_are_open_to_non_admins() {
    use crate::marti::access::allowed;
    for (method, path) in [
        ("GET", "/Marti/api/device/profile/connection"),
        ("GET", "/Marti/api/device/profile/tool/radio"),
        ("GET", "/Marti/api/device/profile/Red/missionpackage"),
    ] {
        assert!(allowed(method, path, false), "{method} {path}");
    }
    for (method, path) in [
        ("GET", "/Marti/api/device/profile"),
        ("POST", "/Marti/api/device/profile/Red"),
        ("PUT", "/Marti/api/device/profile/Red/file"),
        ("POST", "/Marti/api/device/profile/Red/send"),
        ("DELETE", "/Marti/api/device/profile/1"),
    ] {
        assert!(!allowed(method, path, false), "{method} {path}");
        assert!(allowed(method, path, true), "{method} {path}");
    }
}
