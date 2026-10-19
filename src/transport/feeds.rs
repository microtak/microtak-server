//! Streaming data feed listeners: each `Streaming` feed with a port and a
//! streaming protocol (`stcp`/`tcp`: plain TCP, `tls`: mTLS with this
//! server's CA) gets its own listener, an ordinary input whose events are
//! marked with the feed (`<source type="dataFeed">`, the official
//! `DataFeedFilter.filter`) and relayed into the feed's filter groups.
//! Listeners follow the feed store: created, changed and deleted feeds
//! start, restart and stop theirs.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

/// What a feed's listener marks its events with.
#[derive(Debug, Clone, PartialEq)]
pub struct FeedTag {
    pub uuid: String,
    pub name: String,
    pub tags: Vec<String>,
    /// The feed's filter groups: the IN groups its events are sent into.
    pub groups: BTreeSet<String>,
}

impl FeedTag {
    pub fn of(feed: &crate::datafeeds::DataFeed) -> Self {
        Self {
            uuid: feed.uuid.clone(),
            name: feed.name.clone(),
            tags: feed.tags.clone(),
            groups: feed.filter_groups.iter().cloned().collect(),
        }
    }

    /// The event as relayed: `<source>` appended.
    pub fn mark(&self, xml: &str) -> String {
        crate::cot::add_feed_source(xml, &self.uuid, &self.name, &self.tags)
    }
}

/// What a running listener was started for; a change restarts it.
#[derive(Debug, Clone, PartialEq)]
struct ListenerSpec {
    protocol: String,
    port: u16,
    tag: FeedTag,
}

fn spec(feed: &crate::datafeeds::DataFeed) -> Option<ListenerSpec> {
    let port = u16::try_from(feed.port?).ok().filter(|p| *p != 0)?;
    let protocol = match feed.protocol.as_str() {
        "stcp" | "tcp" => "tcp",
        "tls" => "tls",
        _ => return None,
    };
    (feed.feed_type == "Streaming").then(|| ListenerSpec {
        protocol: protocol.to_string(),
        port,
        tag: FeedTag::of(feed),
    })
}

/// Everything a feed listener needs from the server.
#[derive(Clone)]
pub struct FeedInputs {
    pub bind_ip: std::net::IpAddr,
    pub hub: super::hub::RelayHub,
    pub clients: super::connections::ConnectedClients,
    pub groups: Arc<crate::groups::GroupStore>,
    pub registry: Arc<crate::registry::DeviceRegistry>,
    pub tls_config: Arc<rustls::ServerConfig>,
    pub admission: super::admission::Admission,
}

/// Keeps one listener per streaming feed, following the store.
pub async fn run(store: Arc<crate::datafeeds::DataFeedStore>, inputs: FeedInputs) {
    let mut changes = store.changes();
    let mut running: HashMap<String, (ListenerSpec, tokio::task::JoinHandle<()>)> = HashMap::new();
    loop {
        let wanted: HashMap<String, ListenerSpec> = store
            .all()
            .iter()
            .filter_map(|f| spec(f).map(|s| (f.uuid.clone(), s)))
            .collect();
        running.retain(|uuid, (spec, task)| {
            let keep = wanted.get(uuid) == Some(spec) && !task.is_finished();
            if !keep {
                task.abort();
            }
            keep
        });
        for (uuid, spec) in wanted {
            if running.contains_key(&uuid) {
                continue;
            }
            match start(&inputs, &spec).await {
                Ok(task) => {
                    tracing::info!(feed = %spec.tag.name, port = spec.port, protocol = %spec.protocol, "data feed listening");
                    running.insert(uuid, (spec, task));
                }
                Err(error) => {
                    tracing::warn!(feed = %spec.tag.name, port = spec.port, %error, "data feed can't listen");
                }
            }
        }
        if changes.changed().await.is_err() {
            return;
        }
    }
}

async fn start(
    inputs: &FeedInputs,
    spec: &ListenerSpec,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let addr = std::net::SocketAddr::new(inputs.bind_ip, spec.port);
    let tag = Arc::new(spec.tag.clone());
    if spec.protocol == "tls" {
        let relay = super::tls::TlsRelay::bind(
            addr,
            Arc::clone(&inputs.tls_config),
            inputs.hub.clone(),
            Arc::clone(&inputs.registry),
            inputs.clients.clone(),
        )
        .await?
        .with_groups(Arc::clone(&inputs.groups))
        .with_admission(inputs.admission.clone())
        .with_feed(tag);
        Ok(tokio::spawn(async move {
            let _ = relay.run().await;
        }))
    } else {
        let relay = super::tcp::TcpRelay::bind(addr, inputs.hub.clone(), inputs.clients.clone())
            .await?
            .with_groups(Arc::clone(&inputs.groups))
            .with_admission(inputs.admission.clone())
            .with_feed(tag);
        Ok(tokio::spawn(async move {
            let _ = relay.run().await;
        }))
    }
}
