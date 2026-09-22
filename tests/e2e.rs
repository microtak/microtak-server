//! End-to-end test suite: drives the fully-assembled [`edgetak::app::App`]
//! (real CA, real registry, real enrollment HTTP endpoint, real plain-TCP
//! and mTLS relays, all wired together exactly as `edgetakd` runs them) —
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

use edgetak::app::{App, AppConfig};
use edgetak::pki;
use reqwest::header::CONTENT_TYPE;
use rustls::pki_types::{PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

const SERVER_NAME: &str = "edgetak-server";

static TEST_DIR_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A fresh, uniquely-named temp directory per call -- required because
/// `cargo test` runs test functions concurrently within one process, and
/// `App::bind` now persists state to `data_dir` (a shared fixed directory
/// would race: two tests' `App`s would read/write the same CA/registry/
/// mission files at once).
fn unique_temp_dir() -> std::path::PathBuf {
    let n = TEST_DIR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("edgetak-e2e-{}-{n}", std::process::id()))
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
    let cert_pem = body["signedCert"]
        .as_str()
        .expect("enrollment response should carry signedCert")
        .to_string();
    (cert_pem, key)
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
/// so hostname verification succeeds against `https://edgetak-server:<port>/...`
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
        .json(&serde_json::json!({"creatorUid": "user-1", "description": "first pass"}))
        .send()
        .await
        .unwrap();
    assert_eq!(create_response.status(), 201);

    let duplicate_response = client
        .put(format!("{base_url}/Marti/api/missions/Recon%20Alpha"))
        .json(&serde_json::json!({"creatorUid": "user-1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate_response.status(), 409);

    // TC-MARTI-04: subscribe.
    let subscribe_response = client
        .put(format!(
            "{base_url}/Marti/api/missions/Recon%20Alpha/subscription?uid=device-a"
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
        .json(&serde_json::json!({"hash": "abc123", "filename": "map.kml", "creatorUid": "device-a"}))
        .send()
        .await
        .unwrap();
    assert_eq!(content_response.status(), 200);

    let update_response = client
        .patch(format!("{base_url}/Marti/api/missions/Recon%20Alpha"))
        .json(&serde_json::json!({"description": "updated", "actorUid": "user-1"}))
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
