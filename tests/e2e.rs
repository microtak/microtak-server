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

/// Most tests here exercise relaying, missions, etc. -- not enrollment
/// policy -- so they run in `Open` mode (any *new* identity may enroll)
/// with the plain-TCP relay enabled. The enrollment-policy tests at the
/// end of this file use the secure defaults explicitly.
fn test_config() -> AppConfig {
    AppConfig {
        enrollment_addr: "127.0.0.1:0".parse().unwrap(),
        marti_api_addr: "127.0.0.1:0".parse().unwrap(),
        plain_tcp_addr: "127.0.0.1:0".parse().unwrap(),
        plain_tcp_enabled: true,
        mtls_addr: "127.0.0.1:0".parse().unwrap(),
        data_dir: unique_temp_dir(),
        enrollment_mode: microtak_server::app::EnrollmentMode::Open,
        ..AppConfig::default()
    }
}

/// A device's own position report (SA): `<contact>` with a callsign *and*
/// an endpoint -- the kind of event that binds a device's uid.
fn event_xml(uid: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><event version="2.0" uid="{uid}" type="a-f-G-U-C" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/><detail><takv platform="ATAK-CIV" version="5.6.0" device="test" os="34"/><contact callsign="{uid}-CS" endpoint="*:-1:stcp"/><__group name="Cyan" role="Team Member"/></detail></event>"#
    )
}

/// A GeoChat message to "All Chat Rooms" from `sender_uid`, as ATAK sends it.
fn chat_xml(sender_uid: &str, message_id: &str) -> String {
    format!(
        r#"<event version="2.0" uid="GeoChat.{sender_uid}.All Chat Rooms.{message_id}" type="b-t-f" how="h-g-i-g-o" time="2026-09-29T12:01:00Z" start="2026-09-29T12:01:00Z" stale="2026-09-30T12:01:00Z"><point lat="53.25" lon="10.4" hae="12.0" ce="9.9" le="9999999.0"/><detail><__chat parent="RootContactGroup" groupOwner="false" messageId="{message_id}" chatroom="All Chat Rooms" id="All Chat Rooms" senderCallsign="{sender_uid}-CS"><chatgrp uid0="{sender_uid}" uid1="All Chat Rooms" id="All Chat Rooms"/></__chat><link uid="{sender_uid}" type="a-f-G-U-C" relation="p-p"/><remarks source="BAO.F.ATAK.{sender_uid}" to="All Chat Rooms" time="2026-09-29T12:01:00Z">hello from {sender_uid}</remarks></detail></event>"#
    )
}

/// A hostile-marker point dropped by `creator_uid`, as ATAK sends it --
/// with detail elements MicroTAK doesn't model (icon, colour).
fn marker_xml(marker_uid: &str, creator_uid: &str) -> String {
    format!(
        r#"<event version="2.0" uid="{marker_uid}" type="a-h-G" how="h-g-i-g-o" time="2026-09-29T12:02:00Z" start="2026-09-29T12:02:00Z" stale="2026-10-29T12:02:00Z"><point lat="53.26" lon="10.41" hae="0.0" ce="9999999.0" le="9999999.0"/><detail><status readiness="true"/><archive/><link uid="{creator_uid}" production_time="2026-09-29T12:02:00Z" type="a-f-G-U-C" parent_callsign="{creator_uid}-CS" relation="p-p"/><contact callsign="H.1"/><usericon iconsetpath="COT_MAPPING_2525B/a-h/a-h-G"/><color argb="-65536"/></detail></event>"#
    )
}

/// Read from `stream` until `needle` shows up (or time out), returning
/// everything read.
async fn read_until_contains(stream: &mut TlsStream<TcpStream>, needle: &str) -> String {
    let mut seen = String::new();
    let mut buf = vec![0u8; 8192];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !seen.contains(needle) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
            _ => break,
        }
    }
    seen
}

/// Whether anything containing `needle` arrives within a short window.
async fn receives_within(stream: &mut TlsStream<TcpStream>, needle: &str, wait: Duration) -> bool {
    let mut buf = vec![0u8; 8192];
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                if String::from_utf8_lossy(&buf[..n]).contains(needle) {
                    return true;
                }
            }
            _ => return false,
        }
    }
}

/// A client for the enrollment port the way a real device first meets it:
/// it has no CA to verify against yet, so it accepts the server's
/// certificate on first contact (OmniTAK's default, and the QR flow) and
/// pins the CA it receives in the enrollment response from then on. Strict
/// verification of the enrollment certificate itself is covered by
/// `e2e_enrollment_port_is_https_only_with_a_cert_from_the_servers_ca`.
fn enrollment_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .unwrap()
}

/// Enroll a device against the real, running enrollment HTTP endpoint --
/// the same request shape a real ATAK client would send.
async fn enroll(base_url: &str, common_name: &str) -> (String, rcgen::KeyPair) {
    let (csr_pem, key) = pki::build_csr(common_name).unwrap();
    let client = enrollment_client();
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

    let base_url = format!("https://{enrollment_addr}");
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

    let base_url = format!("https://{enrollment_addr}");
    let (cert, key) = enroll(&base_url, "backup-client").await;
    let client = mtls_reqwest_client(&ca_cert_pem, &cert, key, marti_api_addr);
    let upload_url = format!(
        "https://{SERVER_NAME}:{}/Marti/sync/upload?name=backup.txt",
        marti_api_addr.port()
    );
    let status = client
        .post(&upload_url)
        .header(CONTENT_TYPE, "text/plain")
        .body("backed up bytes")
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 200);

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

    let enrollment_base_url = format!("https://{enrollment_addr}");
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

    let enrollment_base_url = format!("https://{enrollment_addr}");
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

/// A running server with one ordinary enrolled device (Open mode), for the
/// Enterprise Sync tests.
async fn sync_client(cn: &str) -> (reqwest::Client, String, SocketAddr, String) {
    let app = App::bind(test_config()).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());
    let (cert, key) = enroll(&format!("https://{enrollment_addr}"), cn).await;
    let client = mtls_reqwest_client(&ca_cert_pem, &cert, key, marti_api_addr);
    let base_url = format!("https://{SERVER_NAME}:{}", marti_api_addr.port());
    (client, base_url, enrollment_addr, ca_cert_pem)
}

/// Official MissionPackageUploadServlet + ContentServlet: ATAK uploads a
/// data package as multipart part `assetfile`, gets back the content URL as
/// plain text, and downloads it with the stored type and name.
#[tokio::test]
async fn e2e_missionupload_and_content_like_the_official_server() {
    let (client, base_url, _, _) = sync_client("sync-alice").await;
    let package = b"PK\x03\x04 a data package".to_vec();
    let expected_hash = {
        use sha2::Digest;
        sha2::Sha256::digest(&package).iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let form = reqwest::multipart::Form::new().part(
        "assetfile",
        reqwest::multipart::Part::bytes(package.clone()).file_name("Recon.zip"),
    );
    let response = client
        .post(format!("{base_url}/Marti/sync/missionupload?hash=ignored&filename=Recon.zip&creatorUid=ANDROID-A"))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.headers()["content-type"].to_str().unwrap().starts_with("text/plain"));
    let url = response.text().await.unwrap();
    assert!(
        url.starts_with("https://") && url.ends_with(&format!("/Marti/sync/content?hash={expected_hash}")),
        "{url}"
    );

    let download = client.get(format!("{base_url}/Marti/sync/content?hash={expected_hash}")).send().await.unwrap();
    assert_eq!(download.status(), 200);
    assert_eq!(download.headers()["content-type"], "application/x-zip-compressed");
    assert_eq!(download.headers()["content-disposition"], "inline; filename=\"Recon.zip\"");
    assert_eq!(download.headers()["api-version"], "3");
    assert_eq!(download.bytes().await.unwrap().to_vec(), package);

    // Raw body: the official servlet insists on multipart.
    let raw = client
        .post(format!("{base_url}/Marti/sync/missionupload?filename=x.zip&creatorUid=A"))
        .body(b"raw".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), 400);
    // filename is required.
    let form = reqwest::multipart::Form::new().part("assetfile", reqwest::multipart::Part::bytes(b"x".to_vec()));
    let missing = client.post(format!("{base_url}/Marti/sync/missionupload?creatorUid=A")).multipart(form).send().await.unwrap();
    assert_eq!(missing.status(), 400);

    // missionquery: the content URL if the hash is known, 404 if not.
    let query = client.get(format!("{base_url}/Marti/sync/missionquery?hash={expected_hash}")).send().await.unwrap();
    assert_eq!(query.status(), 200);
    assert!(query.text().await.unwrap().ends_with(&format!("hash={expected_hash}")));
    let unknown = client.get(format!("{base_url}/Marti/sync/missionquery?hash={}", "f".repeat(64))).send().await.unwrap();
    assert_eq!(unknown.status(), 404);
    let none = client.get(format!("{base_url}/Marti/sync/content?hash={}", "f".repeat(64))).send().await.unwrap();
    assert_eq!(none.status(), 404);
}

/// Official UploadServlet: raw body, metadata as query parameters named like
/// Metadata fields (case-insensitive, arrays comma-separated); the answer is
/// the stored Metadata JSON. Unknown parameters are refused.
#[tokio::test]
async fn e2e_sync_upload_stores_metadata_like_the_official_server() {
    let (client, base_url, _, _) = sync_client("sync-bob").await;
    let response = client
        .post(format!(
            "{base_url}/Marti/sync/upload?name=photo.jpg&keywords=recon,photo&creatorUid=ANDROID-B&uid=MARKER-1&latitude=53.25&longitude=10.4"
        ))
        .header(CONTENT_TYPE, "image/jpeg")
        .body(b"\xff\xd8\xff jpeg".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let metadata: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(metadata["UID"], "MARKER-1");
    assert_eq!(metadata["Name"], "photo.jpg");
    assert_eq!(metadata["MIMEType"], "image/jpeg");
    assert_eq!(metadata["Keywords"], serde_json::json!(["recon", "photo"]));
    assert_eq!(metadata["CreatorUid"], "ANDROID-B");
    assert_eq!(metadata["SubmissionUser"], "sync-bob");
    assert_eq!(metadata["Latitude"], "53.25");
    assert_eq!(metadata["Size"], "8");
    assert!(metadata["PrimaryKey"].as_str().unwrap().parse::<i64>().is_ok());

    let by_uid = client.get(format!("{base_url}/Marti/sync/content?uid=MARKER-1")).send().await.unwrap();
    assert_eq!(by_uid.status(), 200);

    let unknown = client.post(format!("{base_url}/Marti/sync/upload?name=a&bogus=1")).body(b"x".to_vec()).send().await.unwrap();
    assert_eq!(unknown.status(), 400);
    let empty = client.post(format!("{base_url}/Marti/sync/upload?name=a")).body(Vec::<u8>::new()).send().await.unwrap();
    assert_eq!(empty.status(), 400);
}

/// Official SearchServlet ({resultCount, results} of Metadata) and the REST
/// /Marti/api/sync/search (envelope of Resource); keyword filter.
#[tokio::test]
async fn e2e_sync_search_both_flavours() {
    let (client, base_url, _, _) = sync_client("sync-carol").await;
    for (name, keywords) in [("a.zip", "missionpackage"), ("b.txt", "notes")] {
        let status = client
            .post(format!("{base_url}/Marti/sync/upload?name={name}&keywords={keywords}"))
            .body(name.as_bytes().to_vec())
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 200);
    }
    let servlet: serde_json::Value = client.get(format!("{base_url}/Marti/sync/search")).send().await.unwrap().json().await.unwrap();
    assert_eq!(servlet["resultCount"], 2, "{servlet}");
    assert_eq!(servlet["results"].as_array().unwrap().len(), 2);
    assert!(servlet["results"][0]["Hash"].is_string());

    let filtered: serde_json::Value = client
        .get(format!("{base_url}/Marti/sync/search?keywords=missionpackage"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(filtered["resultCount"], 1, "{filtered}");
    assert_eq!(filtered["results"][0]["Name"], "a.zip");

    let rest: serde_json::Value = client
        .get(format!("{base_url}/Marti/api/sync/search?keyword=notes"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rest["version"], "3");
    assert_eq!(rest["type"], "Resource");
    let data = rest["data"].as_array().unwrap();
    assert_eq!(data.len(), 1, "{rest}");
    assert_eq!(data[0]["name"], "b.txt");
    assert!(data[0]["submissionTime"].as_str().unwrap().ends_with('Z'));
}

/// Files are visible only within their groups; delete by hash (official
/// DeleteServlet) removes metadata and content.
#[tokio::test]
async fn e2e_sync_visibility_and_delete() {
    let config = AppConfig {
        admin_common_name: Some("admin".to_string()),
        ..test_config()
    };
    let app = App::bind(config).await.unwrap();
    let groups = app.groups.clone();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());
    groups.create("Red", None, 0).unwrap();
    groups.create("Blue", None, 0).unwrap();
    groups.set_member("Red", "red-user", Some(microtak_server::groups::Membership::Both)).unwrap();
    groups.set_member("Blue", "blue-user", Some(microtak_server::groups::Membership::Both)).unwrap();
    let url = format!("https://{enrollment_addr}");
    let (red_cert, red_key) = enroll(&url, "red-user").await;
    let (blue_cert, blue_key) = enroll(&url, "blue-user").await;
    let red = mtls_reqwest_client(&ca_cert_pem, &red_cert, red_key, marti_api_addr);
    let blue = mtls_reqwest_client(&ca_cert_pem, &blue_cert, blue_key, marti_api_addr);
    let base_url = format!("https://{SERVER_NAME}:{}", marti_api_addr.port());

    let body: serde_json::Value = serde_json::from_str(
        &red.post(format!("{base_url}/Marti/sync/upload?name=red.txt")).body(b"red secret".to_vec()).send().await.unwrap().text().await.unwrap(),
    )
    .unwrap();
    let hash = body["Hash"].as_str().unwrap().to_string();

    let blue_view = blue.get(format!("{base_url}/Marti/sync/content?hash={hash}")).send().await.unwrap();
    assert_eq!(blue_view.status(), 404, "Blue can't see Red's file");
    let blue_search: serde_json::Value = blue.get(format!("{base_url}/Marti/sync/search")).send().await.unwrap().json().await.unwrap();
    assert_eq!(blue_search["resultCount"], 0);
    assert_eq!(red.get(format!("{base_url}/Marti/sync/content?hash={hash}")).send().await.unwrap().status(), 200);

    let delete = red.delete(format!("{base_url}/Marti/sync/delete?Hash={hash}")).send().await.unwrap();
    assert_eq!(delete.status(), 200);
    assert!(delete.text().await.unwrap().contains("Deleted 1 resource(s)."));
    assert_eq!(red.get(format!("{base_url}/Marti/sync/content?hash={hash}")).send().await.unwrap().status(), 404);
}

/// Official MissionApi /resources/{hash} (admin only) and MetadataApi
/// keywords update.
#[tokio::test]
async fn e2e_resources_and_metadata_keywords() {
    let server = start_with_admin().await;
    let response = server
        .admin
        .post(format!("{}/Marti/sync/upload?name=k.txt&keywords=old", server.api_url))
        .body(b"keyword file".to_vec())
        .send()
        .await
        .unwrap();
    let metadata: serde_json::Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    let hash = metadata["Hash"].as_str().unwrap().to_string();

    let response = server
        .admin
        .put(format!("{}/Marti/api/sync/metadata/{hash}/keywords", server.api_url))
        .json(&serde_json::json!(["new", "two"]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let (status, resources) = server.admin_get(&format!("/Marti/api/resources/{hash}")).await;
    assert_eq!(status, 200);
    assert_envelope(&resources, "Resource");
    assert_eq!(resources["data"][0]["keywords"], serde_json::json!(["new", "two"]));
    assert_eq!(resources["data"][0]["hash"], hash.as_str());
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

    let enrollment_base_url = format!("https://{enrollment_addr}");
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

    let base_url = format!("https://{enrollment_addr}");
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

    let base_url = format!("https://{enrollment_addr}");
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

    let base_url = format!("https://{enrollment_addr}");
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

    let base_url = format!("https://{enrollment_addr}");
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

/// The secure default end to end (`Auto` mode, admin CN configured):
///
/// 1. From the very first start, a device with no token is rejected --
///    there is no open window.
/// 2. Nobody can claim the admin CN without the bootstrap token; the
///    admin enrolls with the token the server wrote to `data_dir`, after
///    which the file is gone and the token can't be used again.
/// 3. The admin mints an invite token via the real admin API; a device
///    enrolling with it succeeds and its cert works over mTLS; the token
///    can't be reused, and can't be used to take over an existing
///    identity.
#[tokio::test]
async fn e2e_auto_mode_is_locked_from_the_start_and_the_admin_bootstraps_with_a_token() {
    let config = AppConfig {
        admin_common_name: Some("admin".to_string()),
        // enrollment_mode defaults to Auto -- deliberately not overridden
        // from `AppConfig::default()`, to prove the *default* is locked.
        enrollment_mode: AppConfig::default().enrollment_mode,
        ..test_config()
    };
    let app = App::bind(config).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    let bootstrap_path = app
        .bootstrap_token_path()
        .expect("a fresh server with an admin CN has a bootstrap token outstanding");
    let bootstrap_token = std::fs::read_to_string(&bootstrap_path)
        .unwrap()
        .trim()
        .to_string();
    tokio::spawn(app.run());

    let enrollment_base_url = format!("https://{enrollment_addr}");
    let base_url = format!("https://{SERVER_NAME}:{}", marti_api_addr.port());
    let plain_client = enrollment_client();
    let post = |query: String, csr: String| {
        plain_client
            .post(format!("{enrollment_base_url}/Marti/api/tls/signClient/v2{query}"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr)
            .send()
    };

    // 1. Locked from the start: no token, no enrollment.
    let (csr, _key) = pki::build_csr("device-early-bird").unwrap();
    assert_eq!(post(String::new(), csr).await.unwrap().status(), 403);

    // 2. The admin CN can't be claimed without the bootstrap token...
    let (csr, _key) = pki::build_csr("admin").unwrap();
    assert_eq!(post(String::new(), csr).await.unwrap().status(), 403);
    // ...but can with it, exactly once.
    let (csr, admin_key) = pki::build_csr("admin").unwrap();
    let response = post(format!("?token={bootstrap_token}"), csr).await.unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let admin_cert = wrap_pem(body["signedCert"].as_str().unwrap());
    assert!(!bootstrap_path.exists(), "the used bootstrap token file is deleted");
    let (csr, _key) = pki::build_csr("admin").unwrap();
    assert_eq!(
        post(format!("?token={bootstrap_token}"), csr).await.unwrap().status(),
        403
    );

    // 3. The admin mints a real invite token through the real admin API.
    let admin_client = mtls_reqwest_client(&ca_cert_pem, &admin_cert, admin_key, marti_api_addr);
    let mint_response = admin_client
        .post(format!("{base_url}/Marti/api/admin/enrollmentTokens"))
        .send()
        .await
        .unwrap();
    assert_eq!(mint_response.status(), 201);
    let mint_body: serde_json::Value = mint_response.json().await.unwrap();
    let token = mint_body["token"].as_str().unwrap().to_string();

    // An invite token can't take over the admin identity.
    let (csr, _key) = pki::build_csr("admin").unwrap();
    assert_eq!(post(format!("?token={token}"), csr).await.unwrap().status(), 403);

    // A new device enrolling with it succeeds, and its cert works.
    let (csr, device_key) = pki::build_csr("device-with-token").unwrap();
    let signed = post(format!("?token={token}"), csr).await.unwrap();
    assert_eq!(signed.status(), 200);
    let signed_body: serde_json::Value = signed.json().await.unwrap();
    let device_cert = wrap_pem(signed_body["signedCert"].as_str().unwrap());
    connect_mtls(mtls_addr, &ca_cert_pem, &device_cert, device_key)
        .await
        .expect("the token-enrolled device's cert should be accepted for mTLS");

    // The consumed token can't be reused by a second device.
    let (csr, _key) = pki::build_csr("device-second").unwrap();
    assert_eq!(post(format!("?token={token}"), csr).await.unwrap().status(), 403);

    // A fresh token can't re-enroll the existing device either.
    let mint_body: serde_json::Value = admin_client
        .post(format!("{base_url}/Marti/api/admin/enrollmentTokens"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let second_token = mint_body["token"].as_str().unwrap();
    let (csr, _key) = pki::build_csr("device-with-token").unwrap();
    assert_eq!(
        post(format!("?token={second_token}"), csr).await.unwrap().status(),
        409
    );
}

/// TC-ENROLL-11, end to end -- the full exploit chain, not just the
/// issued cert's fields: a device enrolls with a CSR requesting CA
/// status, uses whatever it got back to sign a forged leaf for the admin
/// CN, and presents that chain to the admin API. It must not get in.
/// (Enrolled in `Open` mode, so this holds even for deployments that keep
/// enrollment open by choice.)
#[tokio::test]
async fn e2e_csr_requesting_ca_status_cannot_forge_the_admin_identity() {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };

    let config = AppConfig {
        admin_common_name: Some("admin".to_string()),
        enrollment_mode: microtak_server::app::EnrollmentMode::Open,
        ..test_config()
    };
    let app = App::bind(config).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    // 1. Enroll with a CSR asking to be a CA.
    let attacker_key = KeyPair::generate().unwrap();
    let mut csr_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    csr_params.distinguished_name = DistinguishedName::new();
    csr_params
        .distinguished_name
        .push(DnType::CommonName, "attacker");
    csr_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    csr_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let csr_pem = csr_params
        .serialize_request(&attacker_key)
        .unwrap()
        .pem()
        .unwrap();
    let response = enrollment_client()
        .post(format!("https://{enrollment_addr}/Marti/api/tls/signClient/v2"))
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(csr_pem)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let attacker_cert = wrap_pem(body["signedCert"].as_str().unwrap());

    // 2. Use the issued cert as an issuer for a forged admin leaf.
    let issuer = Issuer::from_ca_cert_pem(&attacker_cert, attacker_key).unwrap();
    let forged_key = KeyPair::generate().unwrap();
    let mut forged_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    forged_params.distinguished_name = DistinguishedName::new();
    forged_params
        .distinguished_name
        .push(DnType::CommonName, "admin");
    forged_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    forged_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let forged_cert = forged_params.signed_by(&forged_key, &issuer).unwrap().pem();

    // 3. Present forged leaf + attacker "intermediate" to the admin API.
    let chain_pem = format!("{forged_cert}{attacker_cert}");
    let client = mtls_reqwest_client(&ca_cert_pem, &chain_pem, forged_key, marti_api_addr);
    let result = client
        .get(format!(
            "https://{SERVER_NAME}:{}/Marti/api/admin/enrollmentTokens",
            marti_api_addr.port()
        ))
        .send()
        .await;

    match result {
        Err(_) => {} // TLS handshake refused the forged chain -- expected.
        Ok(response) => panic!(
            "forged admin chain was accepted by the TLS layer (status {})",
            response.status()
        ),
    }
}

/// TC-TLS-08/09, end to end: the enrollment port speaks TLS only -- a plain
/// HTTP request gets no HTTP response at all -- and its certificate chains
/// to the server's own CA and names the configured server names, so a
/// client that *does* verify (with the CA from `ca-cert.pem`, e.g. the
/// admin CLI during bootstrap) succeeds.
#[tokio::test]
async fn e2e_enrollment_port_is_https_only_with_a_cert_from_the_servers_ca() {
    let config = AppConfig {
        server_names: vec!["tak.example.com".to_string()],
        server_names_from_interfaces: false,
        ..test_config()
    };
    let app = App::bind(config).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    // Plain HTTP: the handshake fails, no HTTP response comes back.
    let plain = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{enrollment_addr}/Marti/api/tls/config"))
        .send()
        .await;
    assert!(plain.is_err(), "plain HTTP must not get an HTTP response: {plain:?}");

    // HTTPS, strictly verified against the server's CA, under both the
    // common name and a configured extra name.
    for name in [SERVER_NAME, "tak.example.com"] {
        let strict = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(ca_cert_pem.as_bytes()).unwrap())
            .tls_built_in_root_certs(false)
            .resolve(name, SocketAddr::new(enrollment_addr.ip(), 0))
            .no_proxy()
            .build()
            .unwrap();
        let response = strict
            .get(format!("https://{name}:{}/Marti/api/tls/config", enrollment_addr.port()))
            .send()
            .await
            .unwrap_or_else(|error| panic!("strict HTTPS to {name} failed: {error}"));
        assert_eq!(response.status(), 200);
    }

    // A name the certificate doesn't carry is refused by a verifying client.
    let wrong_name = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_cert_pem.as_bytes()).unwrap())
        .tls_built_in_root_certs(false)
        .resolve("not-this-server.example", SocketAddr::new(enrollment_addr.ip(), 0))
        .no_proxy()
        .build()
        .unwrap()
        .get(format!(
            "https://not-this-server.example:{}/Marti/api/tls/config",
            enrollment_addr.port()
        ))
        .send()
        .await;
    assert!(wrong_name.is_err());
}

/// The QR enrollment flow end to end, as OmniTAK/ATAK drive it from a
/// `tak://com.atakmap.app/enroll?host=…&username=…&token=…` code: the admin
/// mints a token bound to the device's name, the device enrolls over HTTPS
/// with `Basic(username, token)`, its cert works over mTLS, and the token
/// can't be used again.
#[tokio::test]
async fn e2e_qr_style_enrollment_with_a_bound_token_as_basic_auth_password() {
    let config = AppConfig {
        admin_common_name: Some("admin".to_string()),
        enrollment_mode: AppConfig::default().enrollment_mode,
        ..test_config()
    };
    let app = App::bind(config).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    let bootstrap = std::fs::read_to_string(app.bootstrap_token_path().unwrap()).unwrap();
    tokio::spawn(app.run());
    let enrollment_url = format!("https://{enrollment_addr}/Marti/api/tls/signClient/v2");

    let (csr, admin_key) = pki::build_csr("admin").unwrap();
    let body: serde_json::Value = enrollment_client()
        .post(format!("{enrollment_url}?token={}", bootstrap.trim()))
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(csr)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_cert = wrap_pem(body["signedCert"].as_str().unwrap());
    let admin = mtls_reqwest_client(&ca_cert_pem, &admin_cert, admin_key, marti_api_addr);

    let minted: serde_json::Value = admin
        .post(format!(
            "https://{SERVER_NAME}:{}/Marti/api/admin/enrollmentTokens",
            marti_api_addr.port()
        ))
        .json(&serde_json::json!({ "commonName": "phone-1" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = minted["token"].as_str().unwrap().to_string();

    let enroll_with = |cn: &'static str| {
        let token = token.clone();
        let enrollment_url = enrollment_url.clone();
        async move {
            let (csr, key) = pki::build_csr(cn).unwrap();
            let response = enrollment_client()
                .post(&enrollment_url)
                .basic_auth(cn, Some(&token))
                .header(CONTENT_TYPE, "text/plain")
                .body(csr)
                .send()
                .await
                .unwrap();
            (response, key)
        }
    };

    let (response, device_key) = enroll_with("phone-1").await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let device_cert = wrap_pem(body["signedCert"].as_str().unwrap());
    connect_mtls(mtls_addr, &ca_cert_pem, &device_cert, device_key)
        .await
        .expect("the QR-enrolled device's cert works over mTLS");

    let (again, _) = enroll_with("phone-1").await;
    assert_ne!(again.status(), 200, "the token is single-use");
}

/// TC-TLS-04 as revised: a device's own chat messages and markers -- each
/// with its own uid -- are relayed, **byte for byte** (detail elements
/// MicroTAK doesn't model, like `usericon`/`color`/`takv`, arrive intact),
/// and the sender stays connected.
#[tokio::test]
async fn e2e_a_devices_chat_and_markers_are_relayed_intact() {
    let app = App::bind(test_config()).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());
    let base_url = format!("https://{enrollment_addr}");
    let (cert_a, key_a) = enroll(&base_url, "chatty").await;
    let (cert_b, key_b) = enroll(&base_url, "listener").await;
    let mut a = connect_mtls(mtls_addr, &ca_cert_pem, &cert_a, key_a).await.unwrap();
    let mut b = connect_mtls(mtls_addr, &ca_cert_pem, &cert_b, key_b).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let sa = event_xml("ANDROID-chatty");
    a.write_all(sa.as_bytes()).await.unwrap();
    let got = read_until_contains(&mut b, "ANDROID-chatty-CS").await;
    assert!(got.contains(r#"<takv platform="ATAK-CIV""#), "SA detail relayed intact: {got}");

    let chat = chat_xml("ANDROID-chatty", "m1");
    a.write_all(chat.as_bytes()).await.unwrap();
    let got = read_until_contains(&mut b, "hello from ANDROID-chatty").await;
    assert!(got.contains(&chat), "the chat message arrives exactly as sent: {got}");

    let marker = marker_xml("marker-1", "ANDROID-chatty");
    a.write_all(marker.as_bytes()).await.unwrap();
    let got = read_until_contains(&mut b, "marker-1").await;
    assert!(got.contains(&marker), "the marker arrives exactly as sent: {got}");

    // Still connected: a later SA still flows.
    a.write_all(sa.as_bytes()).await.unwrap();
    assert!(read_until_contains(&mut b, "ANDROID-chatty-CS").await.contains("ANDROID-chatty-CS"));
}

/// Impersonation through authored content is dropped, not relayed: chat
/// "from" another device, a marker "created by" another device, and a
/// non-SA event reusing another device's uid. The impersonator stays
/// connected (its own traffic still flows).
#[tokio::test]
async fn e2e_content_impersonating_another_device_is_dropped() {
    let app = App::bind(test_config()).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());
    let base_url = format!("https://{enrollment_addr}");
    let (cert_v, key_v) = enroll(&base_url, "victim").await;
    let (cert_m, key_m) = enroll(&base_url, "mallory").await;
    let (cert_w, key_w) = enroll(&base_url, "watcher").await;
    let mut victim = connect_mtls(mtls_addr, &ca_cert_pem, &cert_v, key_v).await.unwrap();
    let mut mallory = connect_mtls(mtls_addr, &ca_cert_pem, &cert_m, key_m).await.unwrap();
    let mut watcher = connect_mtls(mtls_addr, &ca_cert_pem, &cert_w, key_w).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    victim.write_all(event_xml("ANDROID-victim").as_bytes()).await.unwrap();
    read_until_contains(&mut watcher, "ANDROID-victim-CS").await;
    mallory.write_all(event_xml("ANDROID-mallory").as_bytes()).await.unwrap();
    read_until_contains(&mut watcher, "ANDROID-mallory-CS").await;

    mallory.write_all(chat_xml("ANDROID-victim", "forged").as_bytes()).await.unwrap();
    mallory.write_all(marker_xml("forged-marker", "ANDROID-victim").as_bytes()).await.unwrap();
    let fake_position = r#"<event version="2.0" uid="ANDROID-victim" type="a-f-G-U-C" how="m-g" time="2026-09-29T12:00:00Z" start="2026-09-29T12:00:00Z" stale="2026-09-29T12:05:00Z"><point lat="0.0" lon="0.0" hae="0.0" ce="1.0" le="1.0"/><detail><contact callsign="FAKE"/></detail></event>"#;
    mallory.write_all(fake_position.as_bytes()).await.unwrap();
    // Then something legitimate, as a marker for "everything before this
    // has been processed".
    mallory.write_all(chat_xml("ANDROID-mallory", "legit").as_bytes()).await.unwrap();

    let got = read_until_contains(&mut watcher, "hello from ANDROID-mallory").await;
    assert!(got.contains("hello from ANDROID-mallory"), "mallory's own chat still flows: {got}");
    assert!(!got.contains("forged"), "forged chat/marker must not be relayed: {got}");
    assert!(!got.contains("FAKE"), "a fake position for the victim must not be relayed: {got}");
    assert!(
        !receives_within(&mut watcher, "forged", Duration::from_millis(300)).await,
        "nothing forged arrives late either"
    );
}

/// Groups end to end, with the official TAK Server's reachability rule: a
/// message reaches a device only when the sender's active IN groups meet
/// the device's active OUT groups. Devices without groups are anonymous
/// (`__ANON__` both ways). A device switching a channel off
/// (`PUT /Marti/api/groups/activebits`, what ATAK's channel selector calls)
/// stops receiving from it at once, without reconnecting.
#[tokio::test]
async fn e2e_groups_decide_who_receives_what() {
    use microtak_server::groups::Membership;

    let app = App::bind(test_config()).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    let groups = Arc::clone(&app.groups);
    tokio::spawn(app.run());

    groups.create("Red", None, 0).unwrap();
    groups.create("Blue", None, 0).unwrap();
    for (device, group, membership) in [
        ("red-1", "Red", Membership::Both),
        ("red-2", "Red", Membership::Both),
        ("red-2", "Blue", Membership::Both),
        ("blue-1", "Blue", Membership::Both),
        ("listener", "Red", Membership::Out),
    ] {
        groups.set_member(group, device, Some(membership)).unwrap();
    }

    let base_url = format!("https://{enrollment_addr}");
    let mut streams = std::collections::HashMap::new();
    let mut red2_identity = None;
    for device in ["red-1", "red-2", "blue-1", "anon-1", "listener"] {
        let (cert, key) = enroll(&base_url, device).await;
        if device == "red-2" {
            red2_identity = Some((cert.clone(), key.serialize_pem()));
        }
        streams.insert(device, connect_mtls(mtls_addr, &ca_cert_pem, &cert, key).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    async fn say(streams: &mut std::collections::HashMap<&str, TlsStream<TcpStream>>, from: &str) {
        let s = streams.get_mut(from).unwrap();
        s.write_all(event_xml(&format!("UID-{from}")).as_bytes()).await.unwrap();
    }
    async fn heard(
        streams: &mut std::collections::HashMap<&str, TlsStream<TcpStream>>,
        who: &str,
        from: &str,
    ) -> bool {
        receives_within(streams.get_mut(who).unwrap(), &format!("UID-{from}-CS"), Duration::from_millis(400)).await
    }

    say(&mut streams, "red-1").await;
    assert!(heard(&mut streams, "red-2", "red-1").await, "same group");
    assert!(heard(&mut streams, "listener", "red-1").await, "OUT member receives");
    assert!(!heard(&mut streams, "blue-1", "red-1").await, "other group");
    assert!(!heard(&mut streams, "anon-1", "red-1").await, "anonymous device");

    say(&mut streams, "listener").await;
    assert!(!heard(&mut streams, "red-1", "listener").await, "no IN membership: can't send into Red");

    say(&mut streams, "anon-1").await;
    assert!(!heard(&mut streams, "red-1", "anon-1").await, "anonymous traffic stays anonymous");

    say(&mut streams, "blue-1").await;
    assert!(heard(&mut streams, "red-2", "blue-1").await, "red-2 is in Blue too");

    // red-2 switches Blue off through the client API (bitpos: Red=1, Blue=2).
    let (red2_cert, red2_key_pem) = red2_identity.unwrap();
    let red2_key = rcgen::KeyPair::from_pem(&red2_key_pem).unwrap();
    let api = mtls_reqwest_client(&ca_cert_pem, &red2_cert, red2_key, marti_api_addr);
    let listed: serde_json::Value = api
        .get(format!("https://{SERVER_NAME}:{}/Marti/api/groups/all?useCache=true", marti_api_addr.port()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed["data"].as_array().unwrap().len(), 4, "Red and Blue, IN and OUT: {listed}");
    let status = api
        .put(format!("https://{SERVER_NAME}:{}/Marti/api/groups/activebits", marti_api_addr.port()))
        .json(&[1])
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 200);

    say(&mut streams, "blue-1").await;
    assert!(!heard(&mut streams, "red-2", "blue-1").await, "Blue switched off: nothing from it");
    say(&mut streams, "red-1").await;
    assert!(heard(&mut streams, "red-2", "red-1").await, "Red still on");
}

// ---------------------------------------------------------------------
// Revocation: certificates (lost devices) and identity blocks
// ---------------------------------------------------------------------

/// A running server with its admin enrolled via the bootstrap token.
struct Running {
    ca_cert_pem: String,
    enrollment_url: String,
    api_url: String,
    marti_api_addr: SocketAddr,
    mtls_addr: SocketAddr,
    admin: reqwest::Client,
}

async fn start_with_admin() -> Running {
    let config = AppConfig {
        admin_common_name: Some("admin".to_string()),
        enrollment_mode: AppConfig::default().enrollment_mode,
        ..test_config()
    };
    let app = App::bind(config).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let ca_cert_pem = app.ca_cert_pem.clone();
    let token = std::fs::read_to_string(app.bootstrap_token_path().unwrap())
        .unwrap()
        .trim()
        .to_string();
    tokio::spawn(app.run());

    let enrollment_url = format!("https://{enrollment_addr}");
    let (csr, admin_key) = pki::build_csr("admin").unwrap();
    let response = enrollment_client()
        .post(format!("{enrollment_url}/Marti/api/tls/signClient/v2?token={token}"))
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(csr)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let admin_cert = wrap_pem(body["signedCert"].as_str().unwrap());
    Running {
        admin: mtls_reqwest_client(&ca_cert_pem, &admin_cert, admin_key, marti_api_addr),
        ca_cert_pem,
        enrollment_url,
        api_url: format!("https://{SERVER_NAME}:{}", marti_api_addr.port()),
        marti_api_addr,
        mtls_addr,
    }
}

impl Running {
    /// Mint a password account `username` and return its password.
    async fn mint_user(&self, username: &str) -> String {
        let response = self
            .admin
            .post(format!("{}/Marti/api/admin/users", self.api_url))
            .json(&serde_json::json!({ "username": username }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
        let body: serde_json::Value = response.json().await.unwrap();
        body["password"].as_str().unwrap().to_string()
    }

    /// Enroll (or re-enroll) `cn` with its password account. Returns the
    /// status and, on success, the certificate + key.
    async fn enroll_with_password(&self, cn: &str, password: &str) -> (u16, Option<(String, rcgen::KeyPair)>) {
        let (csr, key) = pki::build_csr(cn).unwrap();
        let response = enrollment_client()
            .post(format!("{}/Marti/api/tls/signClient/v2", self.enrollment_url))
            .basic_auth(cn, Some(password))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        if status != 200 {
            return (status, None);
        }
        let body: serde_json::Value = response.json().await.unwrap();
        (status, Some((wrap_pem(body["signedCert"].as_str().unwrap()), key)))
    }

    fn client(&self, cert: &str, key: &rcgen::KeyPair) -> reqwest::Client {
        let key = rcgen::KeyPair::from_pem(&key.serialize_pem()).unwrap();
        mtls_reqwest_client(&self.ca_cert_pem, cert, key, self.marti_api_addr)
    }

    /// Whether `client` can still use the Marti API (a fresh connection).
    async fn api_works(&self, cert: &str, key: &rcgen::KeyPair) -> bool {
        match self
            .client(cert, key)
            .get(format!("{}/Marti/api/version", self.api_url))
            .send()
            .await
        {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }

    async fn stream(&self, cert: &str, key: &rcgen::KeyPair) -> TlsStream<TcpStream> {
        let key = rcgen::KeyPair::from_pem(&key.serialize_pem()).unwrap();
        connect_mtls(self.mtls_addr, &self.ca_cert_pem, cert, key).await.unwrap()
    }
}

/// The server closes `stream` (EOF or error) within `wait`.
async fn closed_within(stream: &mut TlsStream<TcpStream>, wait: Duration) -> bool {
    let mut buf = vec![0u8; 8192];
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            Ok(Ok(_)) => continue,
            Err(_) => return false,
        }
    }
}

/// A lost phone: the admin revokes its certificate. The live CoT session is
/// cut, the old certificate no longer works anywhere, and the owner
/// enrolls a new phone under the same identity with their account.
#[tokio::test]
async fn e2e_revoking_a_certificate_cuts_the_device_off_and_it_re_enrolls() {
    let server = start_with_admin().await;
    let password = server.mint_user("alice").await;
    let (status, enrolled) = server.enroll_with_password("alice", &password).await;
    assert_eq!(status, 200);
    let (old_cert, old_key) = enrolled.unwrap();
    assert!(server.api_works(&old_cert, &old_key).await);
    let mut live = server.stream(&old_cert, &old_key).await;
    live.write_all(event_xml("ALICE-UID").as_bytes()).await.unwrap();

    // The official certificate admin API: revoke by hash.
    let hash = pki::fingerprint_sha256_colon_hex(&old_cert).unwrap();
    let response = server
        .admin
        .delete(format!("{}/Marti/api/certadmin/cert/{hash}", server.api_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["type"], "TakCert");
    assert_eq!(body["data"]["hash"], hash.as_str());

    assert!(closed_within(&mut live, Duration::from_secs(2)).await, "the live CoT session is cut");
    assert!(!server.api_works(&old_cert, &old_key).await, "the revoked cert can't use the API");
    let mut again = server.stream(&old_cert, &old_key).await;
    assert!(closed_within(&mut again, Duration::from_secs(2)).await, "nor open a new CoT session");

    let (status, enrolled) = server.enroll_with_password("alice", &password).await;
    assert_eq!(status, 200, "the identity itself isn't blocked");
    let (new_cert, new_key) = enrolled.unwrap();
    assert!(server.api_works(&new_cert, &new_key).await, "the new certificate works");
    assert!(!server.api_works(&old_cert, &old_key).await, "the old one stays revoked");
}

/// Blocking an identity locks it out entirely -- current certificate,
/// live session, re-enrollment -- until the admin unblocks it.
#[tokio::test]
async fn e2e_blocking_an_identity_locks_it_out_until_unblocked() {
    let server = start_with_admin().await;
    let password = server.mint_user("bob").await;
    let (cert, key) = server.enroll_with_password("bob", &password).await.1.unwrap();
    let mut live = server.stream(&cert, &key).await;

    let block = server
        .admin
        .put(format!("{}/Marti/api/admin/devices/bob/block", server.api_url))
        .send()
        .await
        .unwrap();
    assert_eq!(block.status(), 204);
    assert!(closed_within(&mut live, Duration::from_secs(2)).await);
    assert!(!server.api_works(&cert, &key).await);
    let (status, _) = server.enroll_with_password("bob", &password).await;
    assert_eq!(status, 403, "a blocked identity can't get a new certificate");

    let unblock = server
        .admin
        .delete(format!("{}/Marti/api/admin/devices/bob/block", server.api_url))
        .send()
        .await
        .unwrap();
    assert_eq!(unblock.status(), 204);
    assert!(server.api_works(&cert, &key).await, "unblocked: the certificate works again");
}

/// Revoking a password account also revokes the certificate issued to it --
/// before, the account couldn't log in any more but its device kept full
/// access for the certificate's lifetime.
#[tokio::test]
async fn e2e_revoking_a_user_account_revokes_its_certificate() {
    let server = start_with_admin().await;
    let password = server.mint_user("erin").await;
    let (cert, key) = server.enroll_with_password("erin", &password).await.1.unwrap();

    let response = server
        .admin
        .delete(format!("{}/Marti/api/admin/users/erin", server.api_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    assert!(!server.api_works(&cert, &key).await);
}

// ---------------------------------------------------------------------
// Prometheus metrics
// ---------------------------------------------------------------------

/// The value of the sample `name` (exact series, labels included) in a
/// Prometheus text exposition.
fn sample(exposition: &str, series: &str) -> Option<f64> {
    exposition
        .lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' ')?.trim().parse().ok())
}

/// `/metrics` reports what the server actually holds and does: devices,
/// connections, events, missions, stored files (images counted apart).
#[tokio::test]
async fn e2e_metrics_report_what_the_server_holds() {
    let config = AppConfig {
        metrics_addr: Some("127.0.0.1:0".parse().unwrap()),
        ..test_config()
    };
    let app = App::bind(config).await.unwrap();
    let enrollment_addr = app.enrollment_addr().unwrap();
    let marti_api_addr = app.marti_api_addr().unwrap();
    let mtls_addr = app.mtls_addr().unwrap();
    let metrics_addr = app.metrics_addr().expect("metrics listener configured");
    let ca_cert_pem = app.ca_cert_pem.clone();
    tokio::spawn(app.run());

    let (cert, key) = enroll(&format!("https://{enrollment_addr}"), "metrics-device").await;
    let api_key = rcgen::KeyPair::from_pem(&key.serialize_pem()).unwrap();
    let mut stream = connect_mtls(mtls_addr, &ca_cert_pem, &cert, key).await.unwrap();
    stream.write_all(event_xml("METRICS-UID").as_bytes()).await.unwrap();

    let client = mtls_reqwest_client(&ca_cert_pem, &cert, api_key, marti_api_addr);
    let base_url = format!("https://{SERVER_NAME}:{}", marti_api_addr.port());
    let png = [b"\x89PNG\r\n\x1a\n".as_slice(), &[0u8; 64]].concat();
    for (name, body) in [("photo.png", png), ("notes.txt", b"plain text, not a picture".to_vec())] {
        let status = client
            .post(format!("{base_url}/Marti/sync/upload?name={name}"))
            .body(body)
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 200);
    }
    let status = client
        .put(format!("{base_url}/Marti/api/missions/Metrics%20Test"))
        .json(&serde_json::json!({"creatorUid": "metrics-device"}))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 201);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{metrics_addr}/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.headers()["content-type"].to_str().unwrap().starts_with("text/plain"));
    let text = response.text().await.unwrap();

    assert_eq!(sample(&text, "microtak_devices"), Some(1.0), "{text}");
    assert_eq!(sample(&text, "microtak_devices_blocked"), Some(0.0));
    assert_eq!(sample(&text, "microtak_connected_clients{transport=\"tls\"}"), Some(1.0));
    assert!(sample(&text, "microtak_cot_events_received_total{transport=\"tls\"}").unwrap() >= 1.0);
    assert_eq!(sample(&text, "microtak_missions"), Some(1.0));
    assert_eq!(sample(&text, "microtak_content_files{kind=\"image\"}"), Some(1.0));
    assert_eq!(sample(&text, "microtak_content_files{kind=\"other\"}"), Some(1.0));
    assert!(sample(&text, "microtak_content_bytes").unwrap() > 64.0);
    assert!(sample(&text, "microtak_enrollments_total").unwrap() >= 1.0);
    assert!(sample(&text, "microtak_data_dir_bytes").unwrap() > 0.0);
    assert!(text.contains("microtak_build_info{version=\""));
    for gauge in ["microtak_password_accounts", "microtak_groups", "microtak_enrollment_tokens_active", "microtak_certificates_revoked"] {
        assert!(sample(&text, gauge).is_some(), "{gauge} missing");
    }
}

// ---------------------------------------------------------------------
// Official certificate admin API (TAK Server CertManagerAdminApi.java)
// ---------------------------------------------------------------------

impl Running {
    /// Enroll `cn` with its password account, passing `clientUid` like ATAK.
    async fn enroll_with_client_uid(&self, cn: &str, password: &str, client_uid: &str) -> (String, rcgen::KeyPair) {
        let (csr, key) = pki::build_csr(cn).unwrap();
        let response = enrollment_client()
            .post(format!("{}/Marti/api/tls/signClient/v2?clientUid={client_uid}", self.enrollment_url))
            .basic_auth(cn, Some(password))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body: serde_json::Value = response.json().await.unwrap();
        (wrap_pem(body["signedCert"].as_str().unwrap()), key)
    }

    async fn admin_get(&self, path: &str) -> (u16, serde_json::Value) {
        let response = self.admin.get(format!("{}{path}", self.api_url)).send().await.unwrap();
        let status = response.status().as_u16();
        (status, response.json().await.unwrap_or(serde_json::Value::Null))
    }
}

/// The official response envelope: {version: "3", type, data, nodeId}.
fn assert_envelope(body: &serde_json::Value, kind: &str) {
    assert_eq!(body["version"], "3", "{body}");
    assert_eq!(body["type"], kind, "{body}");
    assert!(body["nodeId"].as_str().is_some_and(|id| !id.is_empty()), "{body}");
}

/// Official COT date format `yyyy-MM-dd'T'HH:mm:ss.S'Z'` (milliseconds
/// unpadded, as Java's SimpleDateFormat writes them).
fn is_cot_date(value: &serde_json::Value) -> bool {
    let Some(s) = value.as_str() else { return false };
    let Some((secs, millis)) = s.strip_suffix('Z').and_then(|v| v.split_once('.')) else { return false };
    secs.len() == 19 && !millis.is_empty() && millis.len() <= 3 && millis.chars().all(|c| c.is_ascii_digit())
}

#[tokio::test]
async fn e2e_certadmin_lists_certificates_in_the_official_shape() {
    let server = start_with_admin().await;
    let password = server.mint_user("alice").await;
    let (first, _) = server.enroll_with_client_uid("alice", &password, "ANDROID-A").await;
    let (second, _) = server.enroll_with_client_uid("alice", &password, "ANDROID-A").await;

    let (status, all) = server.admin_get("/Marti/api/certadmin/cert").await;
    assert_eq!(status, 200);
    assert_envelope(&all, "TakCert");
    let alice: Vec<&serde_json::Value> =
        all["data"].as_array().unwrap().iter().filter(|c| c["userDn"] == "alice").collect();
    assert_eq!(alice.len(), 2, "both issued certificates are listed: {all}");
    let cert = alice[0];
    assert!(cert["id"].is_i64());
    assert_eq!(cert["hash"], pki::fingerprint_sha256_colon_hex(&first).unwrap().as_str());
    assert_eq!(cert["clientUid"], "ANDROID-A");
    assert_eq!(cert["subjectDn"], "CN=alice");
    assert!(cert["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
    assert!(cert["serialNumber"].as_str().unwrap().chars().all(|c| c.is_ascii_hexdigit()));
    for field in ["issuanceDate", "expirationDate", "effectiveDate"] {
        assert!(is_cot_date(&cert[field]), "{field}: {}", cert[field]);
    }
    assert!(cert.get("revocationDate").is_none(), "null fields are omitted (NON_NULL)");

    let (_, by_user) = server.admin_get("/Marti/api/certadmin/cert?username=alice").await;
    assert_eq!(by_user["data"].as_array().unwrap().len(), 2);

    // Active = newest per clientUid + user; replaced = the older ones.
    let (_, active) = server.admin_get("/Marti/api/certadmin/cert/active").await;
    let second_hash = pki::fingerprint_sha256_colon_hex(&second).unwrap();
    let active_alice: Vec<_> = active["data"].as_array().unwrap().iter().filter(|c| c["userDn"] == "alice").collect();
    assert_eq!(active_alice.len(), 1);
    assert_eq!(active_alice[0]["hash"], second_hash.as_str());
    let (_, replaced) = server.admin_get("/Marti/api/certadmin/cert/replaced").await;
    assert!(replaced["data"].as_array().unwrap().iter().any(|c| c["hash"] == cert["hash"]));

    let (status, one) = server.admin_get(&format!("/Marti/api/certadmin/cert/{second_hash}")).await;
    assert_eq!(status, 200);
    assert_envelope(&one, "TakCert");
    assert_eq!(one["data"]["hash"], second_hash.as_str());

    // Unknown hash: the official server answers 500 (clients rely on it).
    let (status, _) = server.admin_get(&format!("/Marti/api/certadmin/cert/{}", "AB:".repeat(31) + "AB")).await;
    assert_eq!(status, 500);

    let pem = server
        .admin
        .get(format!("{}/Marti/api/certadmin/cert/{second_hash}/download", server.api_url))
        .send()
        .await
        .unwrap();
    assert_eq!(pem.status(), 200);
    assert!(pem.headers()["content-disposition"].to_str().unwrap().contains("alice_ClientCert.pem"));
    assert!(pem.text().await.unwrap().contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn e2e_certadmin_revokes_and_deletes_by_id() {
    let server = start_with_admin().await;
    let password = server.mint_user("bob").await;
    let (cert, key) = server.enroll_with_client_uid("bob", &password, "IOS-B").await;
    let hash = pki::fingerprint_sha256_colon_hex(&cert).unwrap();
    let (_, all) = server.admin_get("/Marti/api/certadmin/cert?username=bob").await;
    let id = all["data"][0]["id"].as_i64().unwrap();
    assert!(server.api_works(&cert, &key).await);

    let response = server
        .admin
        .delete(format!("{}/Marti/api/certadmin/cert/revoke/{id}", server.api_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!server.api_works(&cert, &key).await, "revoked by id");
    let (_, revoked) = server.admin_get("/Marti/api/certadmin/cert/revoked").await;
    let entry = revoked["data"].as_array().unwrap().iter().find(|c| c["hash"] == hash.as_str()).unwrap();
    assert!(is_cot_date(&entry["revocationDate"]), "{entry}");

    let zip = server
        .admin
        .get(format!("{}/Marti/api/certadmin/cert/download/{id}", server.api_url))
        .send()
        .await
        .unwrap();
    assert_eq!(zip.headers()["content-type"], "application/zip");
    assert!(zip.bytes().await.unwrap().starts_with(b"PK\x03\x04"));

    let response = server
        .admin
        .delete(format!("{}/Marti/api/certadmin/cert/delete/{id}", server.api_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let (_, after) = server.admin_get("/Marti/api/certadmin/cert?username=bob").await;
    assert!(after["data"].as_array().unwrap().is_empty(), "{after}");
}

#[tokio::test]
async fn e2e_certadmin_is_admin_only() {
    let server = start_with_admin().await;
    let password = server.mint_user("carol").await;
    let (cert, key) = server.enroll_with_password("carol", &password).await.1.unwrap();
    let carol = server.client(&cert, &key);
    for path in ["/Marti/api/certadmin/cert", "/Marti/api/certadmin/cert/active", "/Marti/api/certadmin/cert/revoked"] {
        let status = carol.get(format!("{}{path}", server.api_url)).send().await.unwrap().status();
        assert_eq!(status, 403, "{path}");
    }
}
