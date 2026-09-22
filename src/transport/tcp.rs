//! Plain-TCP CoT relay listener.
//!
//! No TLS/mTLS yet (see `docs/TEST-PLAN.md` §3 TC-TLS-*) — this is the
//! unauthenticated CoT streaming path only, satisfying TC-STREAM-01..05
//! (via [`super::codec::StreamDecoder`]) and TC-ROUTE-01 (baseline
//! broadcast-to-all-others relay). No persistence/late-join replay
//! (TC-ROUTE-05), no disconnect-notification CoT (TC-ROUTE-03), no
//! identity/uid binding (TC-TLS-04) yet.
//!
//! Shares a [`RelayHub`] with [`super::tls::TlsRelay`] — a CoT event
//! ingested here is relayed to mTLS clients too, and vice versa.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use super::codec::{DecodedItem, StreamDecoder};
use super::hub::{Outbound, RelayHub};

pub struct TcpRelay {
    listener: TcpListener,
    hub: RelayHub,
}

impl TcpRelay {
    pub async fn bind(addr: SocketAddr, hub: RelayHub) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener, hub })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept connections forever, spawning a task per client. Only returns
    /// on a fatal `accept()` error (the listener socket itself is broken).
    pub async fn run(self) -> std::io::Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let tx = self.hub.sender();
            let rx = self.hub.subscribe();
            tokio::spawn(async move {
                handle_client(stream, peer, tx, rx).await;
            });
        }
    }
}

async fn handle_client(
    mut stream: TcpStream,
    peer: SocketAddr,
    tx: broadcast::Sender<Outbound>,
    mut rx: broadcast::Receiver<Outbound>,
) {
    info!(%peer, "client connected");
    let mut decoder = StreamDecoder::new();
    let mut read_buf = [0u8; 4096];
    let (mut reader, mut writer) = stream.split();

    loop {
        tokio::select! {
            read_result = reader.read(&mut read_buf) => {
                let n = match read_result {
                    Ok(0) => {
                        info!(%peer, "client disconnected");
                        return;
                    }
                    Ok(n) => n,
                    Err(error) => {
                        warn!(%peer, %error, "read error, disconnecting client");
                        return;
                    }
                };

                match decoder.feed(&read_buf[..n]) {
                    Ok(items) => {
                        for item in items {
                            match item {
                                DecodedItem::Event(event) => {
                                    match event.to_xml() {
                                        Ok(xml) => {
                                            // A closed broadcast channel (no
                                            // subscribers at all) is not an
                                            // error for the sender.
                                            let _ = tx.send(Outbound { sender: peer, xml: xml.into() });
                                        }
                                        Err(error) => {
                                            warn!(%peer, %error, "failed to re-serialize decoded event, dropping");
                                        }
                                    }
                                }
                                DecodedItem::Skipped { error, .. } => {
                                    debug!(%peer, %error, "skipped semantically-invalid CoT event");
                                }
                            }
                        }
                    }
                    Err(error) => {
                        warn!(%peer, %error, "stream error, disconnecting client");
                        return;
                    }
                }
            }
            broadcast_result = rx.recv() => {
                match broadcast_result {
                    Ok(msg) if msg.sender == peer => {
                        // Echo suppression: don't relay a client's own event back to it.
                    }
                    Ok(msg) => {
                        if let Err(error) = writer.write_all(msg.xml.as_bytes()).await {
                            warn!(%peer, %error, "write error, disconnecting client");
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(%peer, skipped, "client fell behind, some broadcast events were dropped for it");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    fn event_xml(uid: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><event version="2.0" uid="{uid}" type="a-f-G-U-C" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/></event>"#
        )
    }

    /// TC-ROUTE-01: a real socket-level test — two actual TCP clients
    /// against a real listener on an ephemeral port, not a mocked
    /// transport.
    #[tokio::test]
    async fn tc_route_01_relays_event_to_other_client_but_not_back_to_sender() {
        let relay = TcpRelay::bind("127.0.0.1:0".parse().unwrap(), RelayHub::new())
            .await
            .unwrap();
        let addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let mut client_a = TcpStream::connect(addr).await.unwrap();
        let mut client_b = TcpStream::connect(addr).await.unwrap();
        // Let the server-side accept/subscribe loop register both
        // connections before anyone sends -- broadcast subscription happens
        // synchronously in the accept loop, but there's still a scheduling
        // gap between the client's connect() resolving and the server's
        // accept() iteration actually running.
        tokio::time::sleep(Duration::from_millis(50)).await;

        client_a
            .write_all(event_xml("FROM-A").as_bytes())
            .await
            .unwrap();

        let mut recv_buf = vec![0u8; 4096];
        let n = timeout(Duration::from_secs(2), client_b.read(&mut recv_buf))
            .await
            .expect("timed out waiting for relayed event")
            .unwrap();
        let received = String::from_utf8_lossy(&recv_buf[..n]);
        assert!(received.contains("FROM-A"), "got: {received}");

        // Sender must not receive its own event back.
        let echoed = timeout(Duration::from_millis(200), client_a.read(&mut recv_buf)).await;
        assert!(
            echoed.is_err(),
            "sender should not receive its own broadcast event back"
        );
    }

    /// TC-STREAM-04: a stream-level syntax error disconnects the client.
    #[tokio::test]
    async fn tc_stream_04_disconnects_client_on_garbage_input() {
        let relay = TcpRelay::bind("127.0.0.1:0".parse().unwrap(), RelayHub::new())
            .await
            .unwrap();
        let addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let mut client = TcpStream::connect(addr).await.unwrap();
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

    /// TC-STREAM-05: a semantically-invalid event doesn't kill the
    /// connection -- a later, valid event on the same socket still relays.
    #[tokio::test]
    async fn tc_stream_05_keeps_connection_open_after_skipped_event() {
        let relay = TcpRelay::bind("127.0.0.1:0".parse().unwrap(), RelayHub::new())
            .await
            .unwrap();
        let addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let mut client_a = TcpStream::connect(addr).await.unwrap();
        let mut client_b = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let bad_event = r#"<event version="2.0" type="a-f-G-U-C" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/></event>"#;
        let stream = format!("{bad_event}{}", event_xml("AFTER-BAD"));
        client_a.write_all(stream.as_bytes()).await.unwrap();

        let mut recv_buf = vec![0u8; 4096];
        let n = timeout(Duration::from_secs(2), client_b.read(&mut recv_buf))
            .await
            .expect("connection was dropped instead of skipping the bad event")
            .unwrap();
        let received = String::from_utf8_lossy(&recv_buf[..n]);
        assert!(received.contains("AFTER-BAD"), "got: {received}");
    }
}
