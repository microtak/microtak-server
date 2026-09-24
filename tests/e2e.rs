//! End-to-end test suite: drives the fully-assembled [`microtak_server::app::App`]
//! (real CA, real registry, real enrollment HTTP endpoint, real plain-TCP
//! and mTLS relays, all wired together exactly as `microtakd` runs them) —
//! not any single module in isolation.
//!
//! Every test here enrolls devices through the real HTTP endpoint (not by
//! reaching into a registry directly, as the module-level tests do) and
//! then drives them through a real mTLS or plain-TCP connection against the
//! same running server. This is deliberately the *only* place that
//! exercises the full enroll-then-connect chain and cross-transport
//! relaying — everything else is covered at the module level (see
//! `docs/TEST-PLAN.md`), so these tests focus on integration behavior that
//! only exists once the pieces are assembled together. Building the first
//! version of this suite (alongside `src/app.rs`) is what surfaced a real
//! bug: `TcpRelay` and `TlsRelay` used to run on two independent broadcast
//! channels, so a plain-TCP client's CoT never reached an mTLS client and
//! vice versa — fixed in `src/transport/hub.rs`, and the cross-transport
//! tests below are what would have caught it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use microtak_server::app::{App, AppConfig};
use microtak_server::pki;
use reqwest::header::CONTENT_TYPE;
use rustls::pki_types::{PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

const SERVER_NAME: &str = "microtak-server";

static TEST_DIR_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A fresh, uniquely-named temp directory per call -- required because
/// `cargo test` runs test functions concurrently within one process, and
/// `App::bind` now persists state to `data_dir` (a shared fixed directory
/// would race: two tests' `App`s would read/write the same CA/registry/
/// mission files at once).
fn unique_temp_dir() -> std::path::PathBuf {
    let n = TEST_DIR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("microtak-e2e-{}-{n}", std::process::id()))
}

fn test_config() -> AppConfig {
    AppConfig {
        enrollment_addr: "127.0.0.1:0".parse().unwrap(),
        marti_api_addr: "127.0.0.1:0".parse().unwrap(),
        plain_tcp_addr: "127.0.0.1:0".parse().unwrap(),
        mtls_addr: "127.0.0.1:0".parse().unwrap(),
        data_dir: unique_temp_dir(),
        ..AppConfig::default()
    }
}

fn event_xml(uid: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><event version="2.0" uid="{uid}" type="a-f-G-U-C" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/></event>"#
    )
}

/// Enroll a device against the real, running enrollment HTTP endpoint --
/// the same request shape a real ATAK client would send.
async fn enroll(base_url: &str, common_name: &str) -> (String, rcgen::KeyPair) {
    let (csr_pem, key) = pki::build_csr(common_name).unwrap();
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(csr_pem)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "enrollment should succeed for a fresh common name"
    );
    let body: serde_json::Value = response.json().await.unwrap();
    let bare_cert = body["signedCert"]
        .as_str()
        .expect("enrollment response should carry signedCert")
        .to_string();
    // Real Marti wire format: bare base64, no PEM armor -- a real client
    // (`node-tak`'s `credentials.ts`) re-wraps this itself, so tests do the
    // same rather than assuming full-PEM.
    (wrap_pem(&bare_cert), key)
}

/// Re-armor a bare-base64 `signedCert`/`ca0` value into full PEM, the same
/// way a real client does before using it.
fn wrap_pem(bare_base64: &str) -> String {
    format!("-----BEGIN CERTIFICATE-----\n{bare_base64}\n-----END CERTIFICATE-----\n")
}

fn mtls_connector(ca_cert_pem: &str, cert_pem: &str, key: rcgen::KeyPair) -> TlsConnector {
    let ca_der = pki::cert_pem_to_der(ca_cert_pem).unwrap();
    let cert_der = pki::cert_pem_to_der(cert_pem).unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(ca_der).unwrap();

    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![cert_der], PrivateKeyDer::from(key))
        .unwrap();

    TlsConnector::from(Arc::new(client_config))
}

async fn connect_mtls(
    addr: SocketAddr,
    ca_cert_pem: &str,
    cert_pem: &str,
    key: rcgen::KeyPair,
) -> std::io::Result<TlsStream<TcpStream>> {
    let connector = mtls_connector(ca_cert_pem, cert_pem, key);
    let tcp = TcpStream::connect(addr).await?;
    connector
        .connect(ServerName::try_from(SERVER_NAME).unwrap(), tcp)
        .await
}

/// An mTLS-capable `reqwest` client for hitting the Marti missions API,
/// which (unlike enrollment) requires a client cert per request. Since the
/// server cert's SAN is the fixed name `SERVER_NAME`, not an IP,
/// `.resolve()` is used to point that hostname at the real loopback address
/// so hostname verification succeeds against `https://microtak-server:<port>/...`
/// URLs (the port in the URL is what's actually used to connect --
/// `resolve()`'s own port is ignored per its documented behavior).
fn mtls_reqwest_client(
    ca_cert_pem: &str,
    cert_pem: &str,
    key: rcgen::KeyPair,
    addr: SocketAddr,
) -> reqwest::Client {
    let mut identity_pem = cert_pem.as_bytes().to_vec();
    identity_pem.extend_from_slice(key.serialize_pem().as_bytes());
    let identity = reqwest::Identity::from_pem(&identity_pem).unwrap();
    let ca_cert = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes()).unwrap();

    reqwest::Client::builder()
        .identity(identity)
        .add_root_certificate(ca_cert)
        .resolve(SERVER_NAME, SocketAddr::new(addr.ip(), 0))
        // This is a loopback test server, not a real internet host -- the
        // sandbox's https_proxy env var would otherwise make reqwest try to
        // CONNECT through it to the fake SERVER_NAME hostname, which the
        // proxy can't resolve.
        .no_proxy()
        .build()
        .unwrap()
}

/// The core end-to-end chain nothing else tests: enroll via real HTTP,
/// then actually connect via mTLS using the cert that enrollment returned,
/// against the *same* running server -- proving the whole pipeline
/// produces a genuinely usable certificate, not just a well-formed one.
#[tokio::test]
async fn e2e_enroll_then_connect_via_mtls_and_relay_across_transports() {
    let app = App::bind(test_config()).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let plain_addr = app.plain_tcp_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    let base_url = format!("http://{enrollment_addr}");
    let (cert_a, key_a) = enroll(&base_url, "device-a").await;
    let (cert_b, key_b) = enroll(&base_url, "device-b").await;

    let mut tls_a = connect_mtls(mtls_addr, &ca_cert_pem, &cert_a, key_a)
        .await
        .expect("device-a's enrolled cert should be accepted for mTLS");
    let mut tls_b = connect_mtls(mtls_addr, &ca_cert_pem, &cert_b, key_b)
        .await
        .expect("device-b's enrolled cert should be accepted for mTLS");
    let mut plain_client = TcpStream::connect(plain_addr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // mTLS -> plain-TCP: an event from an mTLS client must reach a
    // plain-TCP client (the cross-transport relay this suite exists to
    // check).
    tls_a
        .write_all(event_xml("FROM-MTLS-A").as_bytes())
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(2), tls_b.read(&mut buf))
        .await
        .expect("device-b (mTLS) should receive device-a's event")
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("FROM-MTLS-A"));

    let n = timeout(Duration::from_secs(2), plain_client.read(&mut buf))
        .await
        .expect("plain-TCP client should receive an event relayed from an mTLS client")
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("FROM-MTLS-A"));

    // plain-TCP -> mTLS: the other direction across the same shared hub.
    plain_client
        .write_all(event_xml("FROM-PLAIN-TCP").as_bytes())
        .await
        .unwrap();

    let n = timeout(Duration::from_secs(2), tls_a.read(&mut buf))
        .await
        .expect("mTLS client should receive an event relayed from a plain-TCP client")
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("FROM-PLAIN-TCP"));
}

/// Periodic backup, end-to-end against the real assembled server: enroll a
/// device and upload real DataSync content, let a real (short-interval)
/// backup pass run, then confirm the backup directory actually contains
/// that data -- not just that `BackupRunner` works in isolation (its own
/// module tests already cover that), but that `App::bind` actually wires it
/// up and runs it against real, live-growing files.
#[tokio::test]
async fn e2e_backup_mirrors_live_server_state_to_disk() {
    use microtak_server::app::BackupConfig;

    let backup_dir = unique_temp_dir();
    let mut config = test_config();
    let data_dir = config.data_dir.clone();
    config.backup = BackupConfig {
        enabled: true,
        interval: Duration::from_millis(50),
        backup_dir: backup_dir.clone(),
        offsite_command: Vec::new(),
    };

    let app = App::bind(config).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    let base_url = format!("http://{enrollment_addr}");
    let (cert, key) = enroll(&base_url, "backup-client").await;
    let client = mtls_reqwest_client(&ca_cert_pem, &cert, key, marti_api_addr);
    let upload_url = format!(
        "https://{SERVER_NAME}:{}/Marti/api/sync/missionupload",
        marti_api_addr.port()
    );
    client
        .post(&upload_url)
        .body("backed up bytes")
        .send()
        .await
        .unwrap();

    // Give a couple of the 50ms backup ticks time to run.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let backed_up_devices_log = std::fs::read_to_string(backup_dir.join("devices.log")).unwrap();
    assert!(
        backed_up_devices_log.contains("backup-client"),
        "expected the enrolled device to appear in the backed-up devices.log: {backed_up_devices_log}"
    );
    let content_dir = backup_dir.join("content");
    let backed_up_hashes: Vec<_> = std::fs::read_dir(&content_dir)
        .unwrap_or_else(|e| panic!("expected {content_dir:?} to exist: {e}"))
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        backed_up_hashes.len(),
        1,
        "expected exactly the one uploaded content blob to be backed up"
    );
    let backed_up_bytes =
        std::fs::read(content_dir.join(&backed_up_hashes[0])).unwrap();
    assert_eq!(backed_up_bytes, b"backed up bytes");

    std::fs::remove_dir_all(&data_dir).ok();
    std::fs::remove_dir_all(&backup_dir).ok();
}

/// Missions API full lifecycle against the real, running, mTLS-authenticated
/// Marti HTTP endpoint (TC-MARTI-10): enroll a device via real HTTP first
/// (the same chain the core mTLS test exercises), then use its cert to
/// create (409 on a duplicate), subscribe, add content, patch, read back
/// the change log, and delete a mission.
#[tokio::test]
async fn e2e_missions_api_full_lifecycle() {
    let app = App::bind(test_config()).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    let enrollment_base_url = format!("http://{enrollment_addr}");
    let (cert, key) = enroll(&enrollment_base_url, "missions-client").await;
    let client = mtls_reqwest_client(&ca_cert_pem, &cert, key, marti_api_addr);

    let base_url = format!("https://{SERVER_NAME}:{}", marti_api_addr.port());

    // TC-MARTI-01/02: create, then reject a duplicate.
    let create_response = client
        .put(format!("{base_url}/Marti/api/missions/Recon%20Alpha"))
        .json(&serde_json::json!({"creatorUid": "missions-client", "description": "first pass"}))
        .send()
        .await
        .unwrap();
    assert_eq!(create_response.status(), 201);

    let duplicate_response = client
        .put(format!("{base_url}/Marti/api/missions/Recon%20Alpha"))
        .json(&serde_json::json!({"creatorUid": "missions-client"}))
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate_response.status(), 409);

    // TC-MARTI-04: subscribe.
    let subscribe_response = client
        .put(format!(
            "{base_url}/Marti/api/missions/Recon%20Alpha/subscription?uid=missions-client"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(subscribe_response.status(), 200);

    // Add content, then a partial update (TC-MARTI-12: only description
    // changes, keywords untouched).
    let content_response = client
        .put(format!(
            "{base_url}/Marti/api/missions/Recon%20Alpha/contents"
        ))
        .json(&serde_json::json!({"hash": "abc123", "filename": "map.kml", "creatorUid": "missions-client"}))
        .send()
        .await
        .unwrap();
    assert_eq!(content_response.status(), 200);

    let update_response = client
        .patch(format!("{base_url}/Marti/api/missions/Recon%20Alpha"))
        .json(&serde_json::json!({"description": "updated", "actorUid": "missions-client"}))
        .send()
        .await
        .unwrap();
    assert_eq!(update_response.status(), 200);
    let updated: serde_json::Value = update_response.json().await.unwrap();
    assert_eq!(updated["description"], "updated");
    assert_eq!(updated["contents"][0]["hash"], "abc123");

    // TC-MARTI-05: the change log reflects the full history in order.
    let changes_response = client
        .get(format!(
            "{base_url}/Marti/api/missions/Recon%20Alpha/changes"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(changes_response.status(), 200);
    let changes: serde_json::Value = changes_response.json().await.unwrap();
    let change_types: Vec<&str> = changes
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["change_type"].as_str().unwrap())
        .collect();
    assert_eq!(
        change_types,
        vec!["Create", "Subscribe", "AddContent", "Update"]
    );

    // Delete, then confirm it's gone.
    let delete_response = client
        .delete(format!("{base_url}/Marti/api/missions/Recon%20Alpha"))
        .send()
        .await
        .unwrap();
    assert_eq!(delete_response.status(), 204);

    let get_after_delete = client
        .get(format!("{base_url}/Marti/api/missions/Recon%20Alpha"))
        .send()
        .await
        .unwrap();
    assert_eq!(get_after_delete.status(), 404);
}

/// Mission roles, end-to-end with two real, separately-enrolled devices --
/// not the identity-claim check alone (already covered above), the actual
/// Owner/Subscriber authorization layered on top of it. Exercises the real
/// collaborative-Data-Sync shape: an outsider can't touch the mission at
/// all, a subscriber can contribute content but not manage it, and only the
/// owner can update/delete/manage roles -- with the last-owner protection
/// surfacing as a real 409 through the live server, not just at the store
/// level.
#[tokio::test]
async fn e2e_mission_roles_enforce_owner_and_subscriber_authorization() {
    let app = App::bind(test_config()).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    let enrollment_base_url = format!("http://{enrollment_addr}");
    let (owner_cert, owner_key) = enroll(&enrollment_base_url, "mission-owner").await;
    let (subscriber_cert, subscriber_key) = enroll(&enrollment_base_url, "mission-subscriber").await;
    let (outsider_cert, outsider_key) = enroll(&enrollment_base_url, "mission-outsider").await;

    let owner_client = mtls_reqwest_client(&ca_cert_pem, &owner_cert, owner_key, marti_api_addr);
    let subscriber_client =
        mtls_reqwest_client(&ca_cert_pem, &subscriber_cert, subscriber_key, marti_api_addr);
    let outsider_client =
        mtls_reqwest_client(&ca_cert_pem, &outsider_cert, outsider_key, marti_api_addr);
    let base_url = format!("https://{SERVER_NAME}:{}", marti_api_addr.port());

    // The creator gets Owner automatically.
    let create_response = owner_client
        .put(format!("{base_url}/Marti/api/missions/Roles%20Test"))
        .json(&serde_json::json!({"creatorUid": "mission-owner"}))
        .send()
        .await
        .unwrap();
    assert_eq!(create_response.status(), 201);
    let mission: serde_json::Value = create_response.json().await.unwrap();
    assert_eq!(mission["roles"]["mission-owner"], "owner");

    // An outsider (never subscribed) can't add content.
    let outsider_content = outsider_client
        .put(format!("{base_url}/Marti/api/missions/Roles%20Test/contents"))
        .json(&serde_json::json!({"hash": "aaa", "filename": "f.kml", "creatorUid": "mission-outsider"}))
        .send()
        .await
        .unwrap();
    assert_eq!(outsider_content.status(), 403);

    // Subscribing grants the Subscriber role, which does allow adding content...
    let subscribe_response = subscriber_client
        .put(format!(
            "{base_url}/Marti/api/missions/Roles%20Test/subscription?uid=mission-subscriber"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(subscribe_response.status(), 200);

    let subscriber_content = subscriber_client
        .put(format!("{base_url}/Marti/api/missions/Roles%20Test/contents"))
        .json(&serde_json::json!({"hash": "bbb", "filename": "g.kml", "creatorUid": "mission-subscriber"}))
        .send()
        .await
        .unwrap();
    assert_eq!(subscriber_content.status(), 200);

    // ...but not updating mission metadata or deleting it.
    let subscriber_update = subscriber_client
        .patch(format!("{base_url}/Marti/api/missions/Roles%20Test"))
        .json(&serde_json::json!({"description": "hijacked", "actorUid": "mission-subscriber"}))
        .send()
        .await
        .unwrap();
    assert_eq!(subscriber_update.status(), 403);

    let subscriber_delete = subscriber_client
        .delete(format!("{base_url}/Marti/api/missions/Roles%20Test"))
        .send()
        .await
        .unwrap();
    assert_eq!(subscriber_delete.status(), 403);

    // The owner promotes the subscriber to co-owner via the real role API...
    let promote_response = owner_client
        .put(format!("{base_url}/Marti/api/missions/Roles%20Test/role"))
        .json(&serde_json::json!({"uid": "mission-subscriber", "role": "owner"}))
        .send()
        .await
        .unwrap();
    assert_eq!(promote_response.status(), 200);

    // ...after which the former subscriber can update the mission.
    let now_owner_update = subscriber_client
        .patch(format!("{base_url}/Marti/api/missions/Roles%20Test"))
        .json(&serde_json::json!({"description": "co-owned now", "actorUid": "mission-subscriber"}))
        .send()
        .await
        .unwrap();
    assert_eq!(now_owner_update.status(), 200);

    // With two owners now, demoting one of them is allowed -- only the
    // *last* owner is protected.
    let demote_original_owner = owner_client
        .put(format!("{base_url}/Marti/api/missions/Roles%20Test/role"))
        .json(&serde_json::json!({"uid": "mission-owner", "role": "subscriber"}))
        .send()
        .await
        .unwrap();
    assert_eq!(demote_original_owner.status(), 200);

    // ...but now mission-subscriber is the *only* owner, so demoting/revoking
    // them is rejected with a real 409 through the live server.
    let demote_last_owner = subscriber_client
        .put(format!("{base_url}/Marti/api/missions/Roles%20Test/role"))
        .json(&serde_json::json!({"uid": "mission-subscriber", "role": "subscriber"}))
        .send()
        .await
        .unwrap();
    assert_eq!(demote_last_owner.status(), 409);

    // The now-demoted-to-Subscriber original owner can no longer delete the
    // mission; the remaining (last) owner still can.
    let former_owner_delete = owner_client
        .delete(format!("{base_url}/Marti/api/missions/Roles%20Test"))
        .send()
        .await
        .unwrap();
    assert_eq!(former_owner_delete.status(), 403);

    let last_owner_delete = subscriber_client
        .delete(format!("{base_url}/Marti/api/missions/Roles%20Test"))
        .send()
        .await
        .unwrap();
    assert_eq!(last_owner_delete.status(), 204);
}

/// TC-MARTI-07/08, end-to-end: upload real file bytes through the running
/// server, get back the server's own computed hash, reference that hash in
/// a mission's content list, then download it back and confirm the bytes
/// are byte-for-byte identical -- the full DataSync content round trip a
/// real ATAK client depends on, not just the content store in isolation.
#[tokio::test]
async fn e2e_datasync_content_upload_download_round_trip() {
    let app = App::bind(test_config()).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    let enrollment_base_url = format!("http://{enrollment_addr}");
    let (cert, key) = enroll(&enrollment_base_url, "content-client").await;
    let client = mtls_reqwest_client(&ca_cert_pem, &cert, key, marti_api_addr);
    let base_url = format!("https://{SERVER_NAME}:{}", marti_api_addr.port());

    let file_bytes = b"this is a real KML file's worth of bytes";
    let upload_response = client
        .post(format!("{base_url}/Marti/api/sync/missionupload"))
        .body(file_bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(upload_response.status(), 200);
    let upload_body: serde_json::Value = upload_response.json().await.unwrap();
    let hash = upload_body["hash"].as_str().unwrap().to_string();
    assert_eq!(hash.len(), 64, "expected a SHA-256 hex hash: {hash}");

    // TC-MARTI-07: re-uploading with a deliberately wrong claimed hash is
    // rejected, proving the server checks the real content, not the claim.
    let bad_upload = client
        .post(format!(
            "{base_url}/Marti/api/sync/missionupload?hash={}",
            "0".repeat(64)
        ))
        .body(file_bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(bad_upload.status(), 400);

    // Reference the real hash from a mission's content list.
    let create_response = client
        .put(format!("{base_url}/Marti/api/missions/Content%20Test"))
        .json(&serde_json::json!({"creatorUid": "content-client"}))
        .send()
        .await
        .unwrap();
    assert_eq!(create_response.status(), 201);

    let content_response = client
        .put(format!(
            "{base_url}/Marti/api/missions/Content%20Test/contents"
        ))
        .json(&serde_json::json!({"hash": hash, "filename": "recon.kml", "creatorUid": "content-client"}))
        .send()
        .await
        .unwrap();
    assert_eq!(content_response.status(), 200);

    let mission: serde_json::Value = client
        .get(format!("{base_url}/Marti/api/missions/Content%20Test"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(mission["contents"][0]["hash"], hash);

    // Download the exact bytes back by that same hash.
    let download_response = client
        .get(format!("{base_url}/Marti/api/sync/content?hash={hash}"))
        .send()
        .await
        .unwrap();
    assert_eq!(download_response.status(), 200);
    let downloaded = download_response.bytes().await.unwrap();
    assert_eq!(&downloaded[..], &file_bytes[..]);

    // A hash nothing was ever uploaded under is a clean 404.
    let missing_response = client
        .get(format!(
            "{base_url}/Marti/api/sync/content?hash={}",
            "f".repeat(64)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(missing_response.status(), 404);
}

/// TC-MARTI-10's residual gap, closed and verified end-to-end: a real,
/// validly mTLS-authenticated caller still gets rejected if the
/// `creatorUid` it claims doesn't match its own cert's CN.
#[tokio::test]
async fn e2e_missions_api_rejects_creatoruid_not_matching_authenticated_cert() {
    let app = App::bind(test_config()).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    let enrollment_base_url = format!("http://{enrollment_addr}");
    let (cert, key) = enroll(&enrollment_base_url, "real-identity").await;
    let client = mtls_reqwest_client(&ca_cert_pem, &cert, key, marti_api_addr);
    let base_url = format!("https://{SERVER_NAME}:{}", marti_api_addr.port());

    let response = client
        .put(format!("{base_url}/Marti/api/missions/Spoofed"))
        .json(&serde_json::json!({"creatorUid": "someone-else"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);

    // The rejected request must not have created anything.
    let get_response = client
        .get(format!("{base_url}/Marti/api/missions/Spoofed"))
        .send()
        .await
        .unwrap();
    assert_eq!(get_response.status(), 404);
}

/// TC-MARTI-10, the other half: a request presenting no client cert at all
/// must fail -- the missions API requires mTLS just like the CoT relay.
#[tokio::test]
async fn e2e_missions_api_rejects_requests_with_no_client_cert() {
    let app = App::bind(test_config()).await.unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    let ca_cert = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .resolve(SERVER_NAME, SocketAddr::new(marti_api_addr.ip(), 0))
        .no_proxy()
        .build()
        .unwrap();

    let result = client
        .get(format!(
            "https://{SERVER_NAME}:{}/Marti/api/missions",
            marti_api_addr.port()
        ))
        .send()
        .await;

    assert!(
        result.is_err(),
        "a request with no client cert must fail the mTLS handshake"
    );
}

/// Per this project's own testing philosophy (see `docs/TEST-PLAN.md` §7,
/// TC-CHAT-02's rationale): fan-out bugs can be *partial*, so verify
/// delivery to several recipients across mixed transports at once, not
/// just one.
#[tokio::test]
async fn e2e_fanout_to_multiple_clients_across_mixed_transports() {
    let app = App::bind(test_config()).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let plain_addr = app.plain_tcp_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    let base_url = format!("http://{enrollment_addr}");
    let (cert_b, key_b) = enroll(&base_url, "fanout-b").await;
    let (cert_c, key_c) = enroll(&base_url, "fanout-c").await;

    // The sender doesn't need to be enrolled/authenticated -- it connects
    // over the plain-TCP transport, like a trusted local bridge would.
    let mut sender = TcpStream::connect(plain_addr).await.unwrap();
    let mut tls_b = connect_mtls(mtls_addr, &ca_cert_pem, &cert_b, key_b)
        .await
        .unwrap();
    let mut tls_c = connect_mtls(mtls_addr, &ca_cert_pem, &cert_c, key_c)
        .await
        .unwrap();
    let mut plain_d = TcpStream::connect(plain_addr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    sender
        .write_all(event_xml("FANOUT-EVENT").as_bytes())
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    for (name, stream) in [
        ("mTLS client B", &mut tls_b as &mut (dyn tokio::io::AsyncRead + Unpin + Send)),
        ("mTLS client C", &mut tls_c),
        ("plain-TCP client D", &mut plain_d),
    ] {
        let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("{name} timed out waiting for the fanned-out event"))
            .unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).contains("FANOUT-EVENT"),
            "{name} did not receive the expected event"
        );
    }
}

/// TC-MARTI-09, end-to-end: `GET /Marti/api/clientEndPoints` reflects real
/// connections against the fully-assembled server -- a plain-TCP client (no
/// identity) and an mTLS client (real cert CN) both show up while connected,
/// and the mTLS one drops off the list once it disconnects. This is the
/// integration-level companion to `marti::client_endpoints`'s own unit test,
/// which only exercises the registry+router in isolation.
#[tokio::test]
async fn e2e_client_endpoints_reflects_real_connections() {
    let app = App::bind(test_config()).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let plain_addr = app.plain_tcp_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    let base_url = format!("http://{enrollment_addr}");
    let (cert, key) = enroll(&base_url, "endpoints-client").await;
    let (viewer_cert, viewer_key) = enroll(&base_url, "endpoints-viewer").await;

    let client = mtls_reqwest_client(&ca_cert_pem, &viewer_cert, viewer_key, marti_api_addr);
    let list_url = format!("https://{SERVER_NAME}:{}/Marti/api/clientEndPoints", marti_api_addr.port());

    let before: Vec<serde_json::Value> = client
        .get(&list_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(before.is_empty(), "no clients connected yet: {before:?}");

    let plain_client = TcpStream::connect(plain_addr).await.unwrap();
    let mtls_stream = connect_mtls(mtls_addr, &ca_cert_pem, &cert, key)
        .await
        .unwrap();
    // Bind the mTLS connection's uid so the endpoint's `uid` field is
    // populated too, not just `common_name`.
    let (mtls_reader, mut mtls_writer) = tokio::io::split(mtls_stream);
    mtls_writer
        .write_all(event_xml("ENDPOINTS-UID").as_bytes())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let during: Vec<serde_json::Value> = client
        .get(&list_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(during.len(), 2, "expected both live connections: {during:?}");
    assert!(
        during
            .iter()
            .any(|c| c["transport"] == "tcp" && c["common_name"].is_null()),
        "expected an unauthenticated plain-TCP entry: {during:?}"
    );
    assert!(
        during.iter().any(|c| c["transport"] == "tls"
            && c["common_name"] == "endpoints-client"
            && c["uid"] == "ENDPOINTS-UID"),
        "expected the mTLS entry with its bound cn and uid: {during:?}"
    );

    drop(plain_client);
    drop(mtls_reader);
    drop(mtls_writer);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let after: Vec<serde_json::Value> = client
        .get(&list_url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        after.is_empty(),
        "both connections disconnected, list should be empty again: {after:?}"
    );
}

/// Cross-device uid spoofing, exercised through the full enroll-then-connect
/// chain (unlike `transport::tls`'s own unit test, which enrolls directly
/// into a bespoke registry rather than via HTTP).
#[tokio::test]
async fn e2e_rejects_cross_device_uid_spoofing_after_http_enrollment() {
    let app = App::bind(test_config()).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    let base_url = format!("http://{enrollment_addr}");
    let (cert_a, key_a) = enroll(&base_url, "spoof-target").await;
    let (cert_spoofer, key_spoofer) = enroll(&base_url, "spoof-attacker").await;

    let mut tls_a = connect_mtls(mtls_addr, &ca_cert_pem, &cert_a, key_a)
        .await
        .unwrap();
    let mut tls_spoofer = connect_mtls(mtls_addr, &ca_cert_pem, &cert_spoofer, key_spoofer)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    tls_a
        .write_all(event_xml("CONTESTED-UID").as_bytes())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The spoofer, as a legitimate other connected client, is entitled to
    // receive spoof-target's just-broadcast event -- drain that expected
    // traffic before looking for a rejection signal.
    let mut drain_buf = vec![0u8; 4096];
    let drained = timeout(Duration::from_secs(2), tls_spoofer.read(&mut drain_buf))
        .await
        .expect("timed out waiting for spoof-target's relayed event")
        .unwrap();
    assert!(String::from_utf8_lossy(&drain_buf[..drained]).contains("CONTESTED-UID"));

    let write_result = tls_spoofer
        .write_all(event_xml("CONTESTED-UID").as_bytes())
        .await;
    let mut buf = [0u8; 16];
    let read_result = timeout(Duration::from_secs(2), tls_spoofer.read(&mut buf)).await;
    let rejected = write_result.is_err() || matches!(read_result, Ok(Ok(0)) | Ok(Err(_)));
    assert!(
        rejected,
        "a device claiming another enrolled device's uid must be disconnected; write={write_result:?} read={read_result:?}"
    );
}

/// Revocation, exercised through the full enroll-then-connect chain. There
/// is no HTTP admin endpoint for revocation yet, so the test reaches into
/// `App::registry` directly -- the same escape hatch an eventual admin API
/// would use internally.
#[tokio::test]
async fn e2e_revoked_device_rejected_on_new_connection() {
    let app = App::bind(test_config()).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    let registry = Arc::clone(&app.registry);
    tokio::spawn(app.run());

    let base_url = format!("http://{enrollment_addr}");
    let (cert, key) = enroll(&base_url, "revoke-me").await;

    registry.revoke("revoke-me").unwrap();

    let mut stream = connect_mtls(mtls_addr, &ca_cert_pem, &cert, key)
        .await
        .expect("TLS handshake itself still succeeds -- the cert is validly signed");

    let write_result = stream
        .write_all(event_xml("SHOULD-BE-REJECTED").as_bytes())
        .await;
    let mut buf = [0u8; 16];
    let read_result = timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    let rejected = write_result.is_err() || matches!(read_result, Ok(Ok(0)) | Ok(Err(_)));
    assert!(
        rejected,
        "a revoked device's new connection must be rejected; write={write_result:?} read={read_result:?}"
    );
}

/// A stream-level protocol violation on the plain-TCP transport disconnects
/// the client, even inside the fully assembled server (not just the
/// isolated `TcpRelay` unit test).
#[tokio::test]
async fn e2e_plain_tcp_client_disconnected_on_garbage_input() {
    let app = App::bind(test_config()).await.unwrap();
    let plain_addr = app.plain_tcp_addr().unwrap();
    tokio::spawn(app.run());

    let mut client = TcpStream::connect(plain_addr).await.unwrap();
    client
        .write_all(b"not a cot stream at all, garbage bytes")
        .await
        .unwrap();

    let mut buf = [0u8; 16];
    let n = timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("timed out waiting for disconnect")
        .unwrap();
    assert_eq!(n, 0, "expected EOF (server closed the connection)");
}

/// A client presenting a cert not signed by this server's CA is rejected,
/// exercised against the fully assembled server rather than a bespoke
/// fixture.
#[tokio::test]
async fn e2e_rejects_client_cert_not_signed_by_this_servers_ca() {
    let app = App::bind(test_config()).await.unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    // The client trusts the *real* server CA (so the server's own cert
    // verifies fine) but presents a client cert signed by an entirely
    // unrelated CA -- that's the untrusted half under test.
    let foreign_ca = pki::CertificateAuthority::generate("Foreign CA").unwrap();
    let (csr_pem, key) = pki::build_csr("outsider-device").unwrap();
    let signed = foreign_ca
        .sign_csr(&csr_pem, time::Duration::days(365))
        .unwrap();

    let connect_result = connect_mtls(mtls_addr, &ca_cert_pem, &signed.cert_pem, key).await;

    match connect_result {
        Err(_) => {} // rejected during the handshake itself -- acceptable.
        Ok(mut stream) => {
            let write_result = stream
                .write_all(event_xml("SHOULD-BE-REJECTED").as_bytes())
                .await;
            let mut buf = [0u8; 16];
            let read_result = timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
            let rejected = write_result.is_err() || matches!(read_result, Ok(Ok(0)) | Ok(Err(_)));
            assert!(
                rejected,
                "a cert from a foreign CA must be rejected by this server"
            );
        }
    }
}

/// The secure-by-default `Auto` enrollment mode's live transition (see
/// `docs/ARCHITECTURE.md` / `src/marti/admin.rs`): unlike the old
/// restart-based two-phase design this replaced, everything here happens
/// against *one* continuously-running server, no restart involved --
/// enrolling the configured admin device is itself what flips enrollment
/// from open to locked, live.
///
/// 1. Server starts with `admin_common_name` configured but no device
///    enrolled yet under that name -- enrollment is still open (an
///    unrelated device can enroll with no token at all).
/// 2. The admin device itself enrolls, also with no token (it has to be
///    able to bootstrap without one).
/// 3. From that moment on, with no restart, a new device with no token is
///    rejected.
/// 4. The admin mints a token via the real admin API (now reachable, since
///    the admin's own cert works over mTLS); a device enrolling with it
///    succeeds and the cert actually works over mTLS; the token can't be
///    reused by a second device.
#[tokio::test]
async fn e2e_enrollment_auto_mode_locks_down_the_moment_the_admin_enrolls() {
    let config = AppConfig {
        admin_common_name: Some("jz-admin".to_string()),
        // enrollment_mode defaults to Auto -- deliberately not set here,
        // to also prove the *default* is what locks down, not an opt-in
        // flag someone has to remember to flip.
        ..test_config()
    };
    let app = App::bind(config).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    let enrollment_base_url = format!("http://{enrollment_addr}");
    let base_url = format!("https://{SERVER_NAME}:{}", marti_api_addr.port());
    let plain_client = reqwest::Client::new();

    // Before the admin has enrolled, an unrelated device can enroll with
    // no token at all -- still open.
    let (before_cert, _before_key) = enroll(&enrollment_base_url, "device-before-admin").await;
    assert!(before_cert.contains("BEGIN CERTIFICATE"));

    // The admin device itself bootstraps the same way -- no token needed
    // for this specific enrollment either, or there'd be no way in at all.
    let (admin_cert, admin_key) = enroll(&enrollment_base_url, "jz-admin").await;

    // From this exact point on, with the same server still running, a new
    // device with no token is rejected -- the live transition.
    let (no_token_csr, _key) = pki::build_csr("device-no-token").unwrap();
    let rejected = plain_client
        .post(format!(
            "{enrollment_base_url}/Marti/api/tls/signClient/v2"
        ))
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(no_token_csr)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 403);

    let admin_client = mtls_reqwest_client(&ca_cert_pem, &admin_cert, admin_key, marti_api_addr);

    // The admin mints a real token through the real admin API.
    let mint_response = admin_client
        .post(format!("{base_url}/Marti/api/admin/enrollmentTokens"))
        .send()
        .await
        .unwrap();
    assert_eq!(mint_response.status(), 201);
    let mint_body: serde_json::Value = mint_response.json().await.unwrap();
    let token = mint_body["token"].as_str().unwrap();

    // A device enrolling with that token succeeds.
    let (with_token_csr, device_key) = pki::build_csr("device-with-token").unwrap();
    let signed = plain_client
        .post(format!(
            "{enrollment_base_url}/Marti/api/tls/signClient/v2?token={token}"
        ))
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(with_token_csr)
        .send()
        .await
        .unwrap();
    assert_eq!(signed.status(), 200);
    let signed_body: serde_json::Value = signed.json().await.unwrap();
    let device_cert = wrap_pem(signed_body["signedCert"].as_str().unwrap());

    // The new cert actually works over mTLS -- not just "the server said
    // 200." for the enrollment call.
    connect_mtls(mtls_addr, &ca_cert_pem, &device_cert, device_key)
        .await
        .expect("the token-enrolled device's cert should be accepted for mTLS");

    // The now-consumed token can't be reused by a second device.
    let (second_csr, _key2) = pki::build_csr("device-second").unwrap();
    let reused = plain_client
        .post(format!(
            "{enrollment_base_url}/Marti/api/tls/signClient/v2?token={token}"
        ))
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(second_csr)
        .send()
        .await
        .unwrap();
    assert_eq!(reused.status(), 403);
}
