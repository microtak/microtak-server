//! Black-box suite: a real `microtakd` driven only over the network, the way
//! ATAK, iTAK and CloudTAK use a TAK server -- no microtak-server library
//! calls.
//!
//! Two modes:
//! - default (`cargo test --test blackbox`): starts the `microtakd` binary
//!   this crate builds, with a fresh data directory and its own config;
//! - against a running server (the Docker image in CI): set
//!   `MICROTAK_BLACKBOX_HOST`, `MICROTAK_BLACKBOX_ENROLLMENT_PORT`,
//!   `MICROTAK_BLACKBOX_API_PORT`, `MICROTAK_BLACKBOX_STREAM_PORT` and
//!   `MICROTAK_BLACKBOX_BOOTSTRAP_TOKEN` (the server's
//!   `data_dir/bootstrap-token`, admin common name `admin`). The server
//!   certificate must name `localhost`.
//!
//! The scenario: the admin bootstraps with the one-time token and mints two
//! password accounts; both enroll like ATAK (CSR, Basic auth, `clientUid`)
//! and get OAuth tokens like CloudTAK; on the CoT stream they exchange
//! position reports, pings, GeoChat, direct messages and markers; then a
//! mission is created, subscribed, filled with a file and a marker, fed a
//! streamed marker, logged, archived and deleted, with the official change
//! notifications arriving on the stream; finally the admin revokes a
//! certificate and the device is cut off.

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

const TIMEOUT: Duration = Duration::from_secs(5);

// --- the server under test ----------------------------------------------------

struct Server {
    host: String,
    enrollment_port: u16,
    api_port: u16,
    stream_port: u16,
    bootstrap_token: String,
    _process: Option<Process>,
}

struct Process(std::process::Child, std::path::PathBuf);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn free_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn server() -> Server {
    if let Ok(host) = std::env::var("MICROTAK_BLACKBOX_HOST") {
        let port = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} not set")).parse().unwrap();
        let server = Server {
            host,
            enrollment_port: port("MICROTAK_BLACKBOX_ENROLLMENT_PORT"),
            api_port: port("MICROTAK_BLACKBOX_API_PORT"),
            stream_port: port("MICROTAK_BLACKBOX_STREAM_PORT"),
            bootstrap_token: std::env::var("MICROTAK_BLACKBOX_BOOTSTRAP_TOKEN").expect("MICROTAK_BLACKBOX_BOOTSTRAP_TOKEN not set").trim().to_string(),
            _process: None,
        };
        wait_for_port(&server.host, server.enrollment_port).await;
        return server;
    }
    let dir = std::env::temp_dir().join(format!("microtak-blackbox-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (enrollment_port, api_port, stream_port, tcp_port) = (free_port(), free_port(), free_port(), free_port());
    let config = format!(
        r#"bind_host = "127.0.0.1"
enrollment_port = {enrollment_port}
marti_api_port = {api_port}
mtls_port = {stream_port}
plain_tcp_port = {tcp_port}
data_dir = "{data}"
admin_common_name = "admin"
server_names = ["localhost"]
server_names_from_interfaces = false
"#,
        data = dir.join("data").display()
    );
    let config_path = dir.join("microtak.toml");
    std::fs::write(&config_path, config).unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_microtakd"))
        .env("MICROTAK_CONFIG", &config_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("starting microtakd");
    let process = Process(child, dir.clone());
    wait_for_port("127.0.0.1", enrollment_port).await;
    let token_path = dir.join("data").join("bootstrap-token");
    let bootstrap_token = std::fs::read_to_string(&token_path).expect("a fresh server writes its bootstrap token").trim().to_string();
    Server { host: "127.0.0.1".into(), enrollment_port, api_port, stream_port, bootstrap_token, _process: Some(process) }
}

async fn wait_for_port(host: &str, port: u16) {
    for _ in 0..200 {
        if TcpStream::connect((host, port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("nothing listens on {host}:{port}");
}

// --- devices -------------------------------------------------------------------

/// An enrolled identity: its certificate, key and the server's CA.
struct Identity {
    cert_pem: String,
    key_pem: String,
    ca_pem: String,
}

fn pem(base64_der: &str) -> String {
    format!("-----BEGIN CERTIFICATE-----\n{base64_der}\n-----END CERTIFICATE-----\n")
}

impl Server {
    fn enrollment_url(&self, path: &str) -> String {
        format!("https://{}:{}{path}", self.host, self.enrollment_port)
    }

    /// First contact with the enrollment port, as a device has it: no CA
    /// to verify against yet (it arrives in the answer).
    fn enrollment_client() -> reqwest::Client {
        reqwest::Client::builder().danger_accept_invalid_certs(true).no_proxy().build().unwrap()
    }

    /// `POST /Marti/api/tls/signClient/v2` with a CSR, as ATAK sends it.
    async fn enroll(&self, cn: &str, query: &str, basic: Option<(&str, &str)>) -> Result<Identity, reqwest::StatusCode> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        let csr = params.serialize_request(&key).unwrap().pem().unwrap();
        let mut request = Self::enrollment_client()
            .post(self.enrollment_url(&format!("/Marti/api/tls/signClient/v2{query}")))
            .header("content-type", "application/octet-stream")
            .body(csr);
        if let Some((user, password)) = basic {
            request = request.basic_auth(user, Some(password));
        }
        let response = request.send().await.unwrap();
        if !response.status().is_success() {
            return Err(response.status());
        }
        let body: serde_json::Value = response.json().await.unwrap();
        Ok(Identity {
            cert_pem: pem(body["signedCert"].as_str().expect("signedCert")),
            key_pem: key.serialize_pem(),
            ca_pem: pem(body["ca0"].as_str().expect("ca0")),
        })
    }

    /// The API port's address (the host may be a name).
    fn api_addr(&self) -> SocketAddr {
        use std::net::ToSocketAddrs;
        (self.host.as_str(), self.api_port).to_socket_addrs().unwrap().next().expect("resolvable server host")
    }

    /// An mTLS client for the Marti API (`https://localhost:<port>`).
    fn api(&self, id: &Identity) -> Api {
        let identity = reqwest::Identity::from_pem(format!("{}{}", id.cert_pem, id.key_pem).as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .identity(identity)
            .add_root_certificate(reqwest::Certificate::from_pem(id.ca_pem.as_bytes()).unwrap())
            .resolve("localhost", self.api_addr())
            .no_proxy()
            .build()
            .unwrap();
        Api { client, base: format!("https://localhost:{}", self.api_port) }
    }

    /// The CoT stream (mTLS, 8089-style).
    async fn stream(&self, id: &Identity) -> Stream {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from_pem_slice(id.ca_pem.as_bytes()).unwrap()).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![CertificateDer::from_pem_slice(id.cert_pem.as_bytes()).unwrap()],
                PrivateKeyDer::from_pem_slice(id.key_pem.as_bytes()).unwrap(),
            )
            .unwrap();
        let tcp = TcpStream::connect((self.host.as_str(), self.stream_port)).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .expect("TLS to the CoT stream");
        Stream { tls, seen: String::new() }
    }
}

struct Api {
    client: reqwest::Client,
    base: String,
}

impl Api {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn json(&self, method: reqwest::Method, path: &str, body: Option<serde_json::Value>) -> (u16, serde_json::Value) {
        let mut request = self.client.request(method, self.url(path));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)))
    }
}

struct Stream {
    tls: TlsStream<TcpStream>,
    seen: String,
}

impl Stream {
    async fn send(&mut self, xml: &str) {
        self.tls.write_all(xml.as_bytes()).await.unwrap();
    }

    /// Reads until a complete `<event …>…</event>` containing `needle`
    /// arrived; returns that event. Panics after a timeout.
    async fn expect(&mut self, needle: &str) -> String {
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            if let Some(event) = self.take_event_with(needle) {
                return event;
            }
            let mut buf = [0u8; 16384];
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, self.tls.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => self.seen.push_str(&String::from_utf8_lossy(&buf[..n])),
                _ => panic!("no event containing {needle:?} arrived; got: {}", self.seen),
            }
        }
    }

    fn take_event_with(&mut self, needle: &str) -> Option<String> {
        let mut from = 0;
        while let Some(start) = self.seen[from..].find("<event").map(|i| i + from) {
            let end = self.seen[start..].find("</event>").map(|i| start + i + "</event>".len())?;
            let event = self.seen[start..end].to_string();
            if event.contains(needle) {
                self.seen.replace_range(start..end, "");
                return Some(event);
            }
            from = end;
        }
        None
    }

    /// Whether anything containing `needle` arrives within a short window.
    async fn receives(&mut self, needle: &str, wait: Duration) -> bool {
        if self.take_event_with(needle).is_some() {
            return true;
        }
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let mut buf = [0u8; 16384];
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, self.tls.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    self.seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if self.take_event_with(needle).is_some() {
                        return true;
                    }
                }
                _ => return false,
            }
        }
    }

    /// Whether the server closed the stream within `wait`.
    async fn closed(&mut self, wait: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let mut buf = [0u8; 16384];
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, self.tls.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => continue,
                Err(_) => return false,
            }
        }
    }
}

// --- CoT as ATAK sends it ------------------------------------------------------------

fn now() -> String {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let (days, secs) = (t / 86_400, t % 86_400);
    // civil-from-days (Howard Hinnant), enough for a CoT timestamp
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

fn sa(uid: &str, callsign: &str) -> String {
    let t = now();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><event version="2.0" uid="{uid}" type="a-f-G-U-C" how="h-e" time="{t}" start="{t}" stale="2099-01-01T00:00:00Z"><point lat="52.52" lon="13.405" hae="40" ce="9.9" le="9999999"/><detail><takv os="34" version="5.6.0" device="Blackbox" platform="ATAK-CIV"/><contact endpoint="*:-1:stcp" callsign="{callsign}"/><uid Droid="{callsign}"/><__group role="Team Member" name="Cyan"/><status battery="90"/><track course="0" speed="0"/></detail></event>"#
    )
}

fn ping(uid: &str) -> String {
    let t = now();
    format!(r#"<event version="2.0" uid="{uid}-ping" type="t-x-c-t" how="h-g-i-g-o" time="{t}" start="{t}" stale="2099-01-01T00:00:00Z"><point lat="0" lon="0" hae="0" ce="9999999" le="9999999"/><detail/></event>"#)
}

fn chat(sender: &str, callsign: &str, id: &str, to: Option<(&str, &str)>, text: &str) -> String {
    let t = now();
    let (room, room_id, marti) = match to {
        None => ("All Chat Rooms".to_string(), "All Chat Rooms".to_string(), String::new()),
        Some((uid, cs)) => (cs.to_string(), uid.to_string(), format!(r#"<marti><dest callsign="{cs}"/><dest uid="{uid}"/></marti>"#)),
    };
    format!(
        r#"<event version="2.0" uid="GeoChat.{sender}.{room_id}.{id}" type="b-t-f" how="h-g-i-g-o" time="{t}" start="{t}" stale="2099-01-01T00:00:00Z"><point lat="52.52" lon="13.405" hae="40" ce="9.9" le="9999999"/><detail><__chat parent="RootContactGroup" groupOwner="false" messageId="{id}" chatroom="{room}" id="{room_id}" senderCallsign="{callsign}"><chatgrp uid0="{sender}" uid1="{room_id}" id="{room_id}"/></__chat><link uid="{sender}" type="a-f-G-U-C" relation="p-p"/><remarks source="BAO.F.ATAK.{sender}" to="{room_id}" time="{t}">{text}</remarks>{marti}</detail></event>"#
    )
}

fn marker(uid: &str, creator: &str, extra_detail: &str) -> String {
    let t = now();
    format!(
        r#"<event version="2.0" uid="{uid}" type="a-h-G" how="h-g-i-g-o" time="{t}" start="{t}" stale="2099-01-01T00:00:00Z"><point lat="52.53" lon="13.41" hae="0" ce="9999999" le="9999999"/><detail><link uid="{creator}" type="a-f-G-U-C" relation="p-p"/><contact callsign="Hostile 1"/><usericon iconsetpath="COT_MAPPING_2525B/a-h/a-h-G"/>{extra_detail}</detail></event>"#
    )
}

// --- the scenario --------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn blackbox_suite() {
    let server = server().await;

    // 1. Locked by default: no token, no enrollment; the bootstrap token
    //    enrolls the admin exactly once.
    assert_eq!(server.enroll("early-bird", "", None).await.err(), Some(reqwest::StatusCode::FORBIDDEN));
    let admin = server.enroll("admin", &format!("?token={}", server.bootstrap_token), None).await.expect("admin bootstrap");
    assert!(server.enroll("admin", &format!("?token={}", server.bootstrap_token), None).await.is_err(), "the bootstrap token works once");
    let admin_api = server.api(&admin);

    // 2. The admin mints two password accounts.
    for user in ["alice", "bob"] {
        let (status, body) = admin_api
            .json(reqwest::Method::POST, "/Marti/api/admin/users", Some(serde_json::json!({ "username": user, "password": format!("{user}-secret-pw") })))
            .await;
        assert!(status == 200 || status == 201, "minting {user}: {status} {body}");
    }

    // 3. Devices enroll like ATAK: CSR + Basic auth + clientUid.
    let config = Server::enrollment_client().get(server.enrollment_url("/Marti/api/tls/config")).send().await.unwrap();
    assert_eq!(config.status(), 200);
    assert!(config.text().await.unwrap().contains("certificateConfig"));
    let alice = server.enroll("alice", "?clientUid=ANDROID-ALICE", Some(("alice", "alice-secret-pw"))).await.expect("alice enrolls");
    let bob = server.enroll("bob", "?clientUid=ANDROID-BOB", Some(("bob", "bob-secret-pw"))).await.expect("bob enrolls");
    assert_eq!(server.enroll("mallory", "", Some(("alice", "wrong"))).await.err(), Some(reqwest::StatusCode::UNAUTHORIZED));

    // 4. CloudTAK-style login: the official RS256 access token.
    let oauth = Server::enrollment_client()
        .post(server.enrollment_url("/oauth/token"))
        .form(&[("grant_type", "password"), ("username", "alice"), ("password", "alice-secret-pw")])
        .send()
        .await
        .unwrap();
    assert_eq!(oauth.status(), 200);
    let oauth: serde_json::Value = oauth.json().await.unwrap();
    assert_eq!(oauth["token_type"], "Bearer");
    let header = oauth["access_token"].as_str().unwrap().split('.').next().unwrap().to_string();
    let header = String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
    assert!(header.starts_with(r#"{"kid":""#) && header.ends_with(r#""alg":"RS256"}"#), "{header}");

    // 5. The CoT stream: position reports, ping/pong, relay.
    let mut a = server.stream(&alice).await;
    let mut b = server.stream(&bob).await;
    a.send(&sa("ANDROID-ALICE", "ALICE")).await;
    b.send(&sa("ANDROID-BOB", "BOB")).await;
    b.expect(r#"uid="ANDROID-ALICE""#).await;
    a.expect(r#"uid="ANDROID-BOB""#).await;
    a.send(&ping("ANDROID-ALICE")).await;
    let pong = a.expect("t-x-c-t-r").await;
    assert!(pong.contains(r#"uid="takPong""#), "{pong}");
    assert!(!b.receives("ANDROID-ALICE-ping", Duration::from_millis(300)).await, "pings are not relayed");

    // 6. GeoChat to all, a direct message, a marker.
    a.send(&chat("ANDROID-ALICE", "ALICE", "m1", None, "hello all")).await;
    assert!(b.expect("hello all").await.contains(r#"type="b-t-f""#));
    a.send(&chat("ANDROID-ALICE", "ALICE", "m2", Some(("ANDROID-BOB", "BOB")), "just for bob")).await;
    let direct = b.expect("just for bob").await;
    assert!(!direct.contains("<marti"), "forwarded without <marti>: {direct}");
    a.send(&marker("blackbox-marker-1", "ANDROID-ALICE", "")).await;
    b.expect(r#"uid="blackbox-marker-1""#).await;

    // 7. Contacts as the official ContactsApi lists them.
    let bob_api = server.api(&bob);
    let (status, contacts) = bob_api.json(reqwest::Method::GET, "/Marti/api/contacts/all", None).await;
    assert_eq!(status, 200);
    let alice_contact = contacts.as_array().unwrap().iter().find(|c| c["uid"] == "ANDROID-ALICE").expect("alice listed");
    assert_eq!((alice_contact["callsign"].as_str(), alice_contact["takv"].as_str()), (Some("ALICE"), Some("ATAK-CIV:5.6.0")));

    // 8. Missions through the official Mission API.
    let alice_api = server.api(&alice);
    let (status, created) = alice_api.json(reqwest::Method::PUT, "/Marti/api/missions/Blackbox%20Ops?creatorUid=ANDROID-ALICE&description=e2e", None).await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["type"], "Mission");
    let owner_token = created["data"][0]["token"].as_str().unwrap().to_string();
    let guid = created["data"][0]["guid"].as_str().unwrap().to_string();
    b.expect("t-x-m-n").await;

    let (status, sub) = bob_api.json(reqwest::Method::PUT, "/Marti/api/missions/Blackbox%20Ops/subscription?uid=ANDROID-BOB", None).await;
    assert_eq!(status, 201, "{sub}");
    assert_eq!(sub["data"]["role"]["type"], "MISSION_SUBSCRIBER");

    let upload = alice_api.client.post(alice_api.url("/Marti/sync/upload?name=notes.txt&creatorUid=ANDROID-ALICE")).body("mission notes").send().await.unwrap();
    assert_eq!(upload.status(), 200);
    let hash = serde_json::from_str::<serde_json::Value>(&upload.text().await.unwrap()).unwrap()["Hash"].as_str().unwrap().to_string();
    let (status, _) = alice_api
        .json(
            reqwest::Method::PUT,
            "/Marti/api/missions/Blackbox%20Ops/contents?creatorUid=ANDROID-ALICE",
            Some(serde_json::json!({ "hashes": [hash], "uids": ["blackbox-marker-1"] })),
        )
        .await;
    assert_eq!(status, 200);
    let change = b.expect("<contentUid>blackbox-marker-1</contentUid>").await;
    assert!(change.contains(r#"type="t-x-m-c""#), "{change}");
    b.expect(&format!("<hash>{hash}</hash>")).await;
    let download = bob_api.client.get(bob_api.url(&format!("/Marti/sync/content?hash={hash}"))).send().await.unwrap();
    assert_eq!(download.text().await.unwrap(), "mission notes");

    // A subscriber streams a marker into the mission.
    b.send(&marker("blackbox-marker-2", "ANDROID-BOB", r#"<marti><dest mission="Blackbox Ops"/></marti>"#)).await;
    let streamed = a.expect(r#"uid="blackbox-marker-2""#).await;
    assert!(!streamed.contains("<marti"), "{streamed}");
    let (_, mission) = alice_api.json(reqwest::Method::GET, "/Marti/api/missions/Blackbox%20Ops", None).await;
    let uids: Vec<&str> = mission["data"][0]["uids"].as_array().unwrap().iter().map(|u| u["data"].as_str().unwrap()).collect();
    assert_eq!(uids, ["blackbox-marker-1", "blackbox-marker-2"]);
    assert_eq!(mission["data"][0]["uids"][0]["details"]["callsign"], "Hostile 1");

    let (status, changes) = bob_api.json(reqwest::Method::GET, &format!("/Marti/api/missions/guid/{guid}/changes"), None).await;
    assert_eq!(status, 200);
    assert_eq!(changes["data"].as_array().unwrap().len(), 4, "create + file + two markers: {changes}");

    let (status, _) = alice_api
        .json(reqwest::Method::POST, "/Marti/api/missions/logs/entries", Some(serde_json::json!({ "content": "contact made", "creatorUid": "ANDROID-ALICE", "missionNames": ["Blackbox Ops"] })))
        .await;
    assert_eq!(status, 200);
    b.expect("t-x-m-c-l").await;

    let archive = bob_api.client.get(bob_api.url("/Marti/api/missions/Blackbox%20Ops/archive")).send().await.unwrap();
    assert_eq!(archive.status(), 200);
    let zip = archive.bytes().await.unwrap();
    assert_eq!(&zip[..2], b"PK", "a data package");

    // Bob (a subscriber) may not delete; the owner may.
    let (status, _) = bob_api.json(reqwest::Method::DELETE, "/Marti/api/missions/Blackbox%20Ops?creatorUid=ANDROID-BOB&deepDelete=true", None).await;
    assert_eq!(status, 403);
    let delete = alice_api
        .client
        .delete(alice_api.url("/Marti/api/missions/Blackbox%20Ops?creatorUid=ANDROID-ALICE"))
        .header("MissionAuthorization", format!("Bearer {owner_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), 200);
    b.expect("t-x-m-d").await;
    let gone = bob_api.client.get(bob_api.url("/Marti/api/missions/Blackbox%20Ops")).send().await.unwrap();
    assert_eq!(gone.status(), 410);

    // 9. The admin revokes bob's certificate: his stream is cut off.
    let (status, certs) = admin_api.json(reqwest::Method::GET, "/Marti/api/certadmin/cert?username=bob", None).await;
    assert_eq!(status, 200, "{certs}");
    let id = certs["data"][0]["id"].as_i64().expect("bob's certificate id");
    let (status, _) = admin_api.json(reqwest::Method::DELETE, &format!("/Marti/api/certadmin/cert/revoke/{id}"), None).await;
    assert_eq!(status, 200);
    assert!(b.closed(TIMEOUT).await, "a revoked device is disconnected");
    assert!(bob_api.client.get(bob_api.url("/Marti/api/contacts/all")).send().await.map(|r| !r.status().is_success()).unwrap_or(true));
}
