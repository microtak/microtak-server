//! The latest CoT event per uid -- what the official server reads back from
//! its `cot_router` table for a mission's `/cot` endpoint
//! (`getLatestCotForUids`) and for the `details` of a mission's uids
//! (`MissionServiceDefaultImpl.hydrate(UidDetails, CotElement)`).
//!
//! Fed from the relay hub (every relayed event; control messages never
//! get there). Kept in memory and saved to `data_dir/latest-cot.json`
//! (atomically, at most every few seconds) so a restart doesn't forget
//! markers that devices only send once.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;
use serde::{Deserialize, Serialize};

/// Bound on remembered uids; the oldest are forgotten first.
const MAX_UIDS: usize = 50_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatestEvent {
    /// The `<event>` element as received, without an XML declaration.
    pub xml: String,
    pub server_time_ms: i64,
}

#[derive(Default)]
struct State {
    events: HashMap<String, LatestEvent>,
    dirty: bool,
}

pub struct LatestCot {
    state: RwLock<State>,
    path: Option<PathBuf>,
}

impl LatestCot {
    pub fn in_memory() -> Self {
        Self { state: RwLock::new(State::default()), path: None }
    }

    /// Loads `path` if it exists (a damaged file starts empty).
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let events = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self { state: RwLock::new(State { events, dirty: false }), path: Some(path) }
    }

    /// Remembers `xml` as `uid`'s latest event.
    pub fn record(&self, uid: &str, xml: &str, server_time_ms: i64) {
        let xml = strip_declaration(xml).to_string();
        let mut state = self.state.write().unwrap();
        if state.events.len() >= MAX_UIDS && !state.events.contains_key(uid)
            && let Some(oldest) = state.events.iter().min_by_key(|(_, e)| e.server_time_ms).map(|(k, _)| k.clone()) {
                state.events.remove(&oldest);
            }
        state.events.insert(uid.to_string(), LatestEvent { xml, server_time_ms });
        state.dirty = true;
    }

    pub fn get(&self, uid: &str) -> Option<LatestEvent> {
        self.state.read().unwrap().events.get(uid).cloned()
    }

    /// Writes the file if anything changed since the last save.
    pub fn save_if_dirty(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let snapshot = {
            let mut state = self.state.write().unwrap();
            if !state.dirty {
                return Ok(());
            }
            state.dirty = false;
            serde_json::to_vec(&state.events).expect("serializable")
        };
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, snapshot)?;
        std::fs::rename(&tmp, path)
    }

    /// `UidDetails` for `uid` from its latest event, as the official
    /// `hydrate(UidDetails, CotElement)` derives them; `None` if no event
    /// is known.
    pub fn uid_details(&self, uid: &str) -> Option<serde_json::Value> {
        self.get(uid).map(|event| uid_details(&event.xml))
    }
}

impl LatestCot {
    /// Records every event relayed through the hub (control messages are
    /// never published there) and saves at most every five seconds.
    pub fn spawn_feed(self: std::sync::Arc<Self>, mut rx: tokio::sync::broadcast::Receiver<crate::transport::hub::Outbound>) {
        tokio::spawn(async move {
            let mut save = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tokio::select! {
                    message = rx.recv() => match message {
                        Ok(message) => {
                            if let Ok(event) = crate::cot::Event::from_xml(strip_declaration(&message.xml)) {
                                self.record(&event.uid, &message.xml, crate::cot::now_unix_millis());
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    },
                    _ = save.tick() => {
                        if let Err(error) = self.save_if_dirty() {
                            tracing::warn!(%error, "saving the latest CoT per uid failed");
                        }
                    }
                }
            }
        });
    }
}

fn strip_declaration(xml: &str) -> &str {
    let trimmed = xml.trim_start();
    if trimmed.starts_with("<?xml")
        && let Some(end) = trimmed.find("?>") {
            return trimmed[end + 2..].trim_start();
        }
    trimmed
}

fn attributes(e: &quick_xml::events::BytesStart<'_>) -> HashMap<String, String> {
    e.attributes()
        .flatten()
        .filter_map(|a| {
            let key = String::from_utf8(a.key.as_ref().to_vec()).ok()?;
            let value = a.normalized_value(quick_xml::XmlVersion::Implicit1_0).ok()?.into_owned();
            Some((key, value))
        })
        .collect()
}

/// The official mapping: `type` from the event; `location` from the point
/// unless lat and lon are both 0 (`cot.lat != 0 && cot.lon != 0`); from the
/// direct children of `<detail>`: `color@argb|value`, `strokeColor@value`,
/// `link_attr@color`, `bullseye@edgeToCenter` (only for
/// `u-r-b-bullseye`: `true` → `-65536`, else `-16711936`),
/// `attachment_list@hashes` (a JSON-ish list, brackets and quotes
/// stripped), `title@title`, `_medevac_@title`, `model@name|category` (only
/// for `u-d-v-m`); `callsign` from `contact@callsign`, falling back to the
/// title, overridden by a medevac title; `iconsetPath` from
/// `usericon@iconsetpath`.
pub fn uid_details(xml: &str) -> serde_json::Value {
    let mut reader = Reader::from_str(xml);
    let mut depth = 0usize;
    let mut in_detail_at: Option<usize> = None;
    let (mut cot_type, mut lat, mut lon) = (None::<String>, 0f64, 0f64);
    let (mut color, mut attachments, mut title, mut medevac) = (None, None::<Vec<String>>, None, None::<String>);
    let (mut name, mut category, mut callsign, mut iconset) = (None, None, None, None);
    loop {
        let (element, empty) = match reader.read_event() {
            Ok(XmlEvent::Start(e)) => (e.into_owned(), false),
            Ok(XmlEvent::Empty(e)) => (e.into_owned(), true),
            Ok(XmlEvent::End(_)) => {
                depth = depth.saturating_sub(1);
                if in_detail_at == Some(depth) {
                    in_detail_at = None;
                }
                continue;
            }
            Ok(XmlEvent::Eof) | Err(_) => break,
            Ok(_) => continue,
        };
        let tag = String::from_utf8_lossy(element.name().as_ref()).into_owned();
        let attrs = attributes(&element);
        match (depth, tag.as_str()) {
            (0, "event") => cot_type = attrs.get("type").cloned(),
            (1, "point") => {
                lat = attrs.get("lat").and_then(|v| v.parse().ok()).unwrap_or(0.0);
                lon = attrs.get("lon").and_then(|v| v.parse().ok()).unwrap_or(0.0);
            }
            (1, "detail") if !empty => in_detail_at = Some(1),
            (2, child) if in_detail_at == Some(1) => {
                let ty = cot_type.as_deref().unwrap_or("");
                match child {
                    "color" => {
                        if let Some(v) = attrs.get("argb").or_else(|| attrs.get("value")) {
                            color = Some(v.clone());
                        }
                    }
                    "strokeColor" => {
                        if let Some(v) = attrs.get("value") {
                            color = Some(v.clone());
                        }
                    }
                    "link_attr" => {
                        if let Some(v) = attrs.get("color") {
                            color = Some(v.clone());
                        }
                    }
                    "bullseye" if ty == "u-r-b-bullseye" => {
                        if let Some(v) = attrs.get("edgeToCenter") {
                            color = Some(if v == "true" { "-65536" } else { "-16711936" }.to_string());
                        }
                    }
                    "attachment_list" => {
                        if let Some(v) = attrs.get("hashes") {
                            let inner = v.get(1..v.len().saturating_sub(1)).unwrap_or("").replace('"', "");
                            attachments = Some(inner.split(',').map(String::from).collect());
                        }
                    }
                    "title" => title = attrs.get("title").cloned(),
                    "_medevac_" => medevac = attrs.get("title").cloned(),
                    "model" if ty == "u-d-v-m" => {
                        name = attrs.get("name").cloned();
                        category = attrs.get("category").cloned();
                    }
                    "contact" => callsign = attrs.get("callsign").cloned(),
                    "usericon" => iconset = attrs.get("iconsetpath").cloned(),
                    _ => {}
                }
            }
            _ => {}
        }
        if !empty {
            depth += 1;
        }
    }
    let mut callsign = callsign.or_else(|| title.clone());
    if medevac.as_deref().is_some_and(|m| !m.is_empty()) {
        callsign = medevac;
    }
    let mut details = serde_json::Map::new();
    let mut put = |k: &str, v: Option<serde_json::Value>| {
        if let Some(v) = v {
            details.insert(k.to_string(), v);
        }
    };
    put("type", cot_type.map(Into::into));
    put("callsign", callsign.map(Into::into));
    put("title", title.map(Into::into));
    put("iconsetPath", iconset.map(Into::into));
    put("color", color.map(Into::into));
    put("attachments", attachments.map(Into::into));
    put("name", name.map(Into::into));
    put("category", category.map(Into::into));
    if lat != 0.0 && lon != 0.0 {
        put("location", Some(serde_json::json!({ "lat": lat, "lon": lon })));
    }
    serde_json::Value::Object(details)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKER: &str = r#"<?xml version="1.0" encoding="UTF-8"?><event version="2.0" uid="m-1" type="a-u-G" how="h-g-i-g-o" time="2026-10-17T20:00:00Z" start="2026-10-17T20:00:00Z" stale="2026-10-18T20:00:00Z"><point lat="52.52" lon="13.41" hae="0" ce="9999999" le="9999999"/><detail><contact callsign="Rally &amp; point"/><color argb="-1"/><usericon iconsetpath="COT_MAPPING_2525B/a-u/a-u-G"/><attachment_list hashes="[&quot;h1&quot;,&quot;h2&quot;]"/><link uid="x" relation="p-p"><color argb="-5"/></link></detail></event>"#;

    #[test]
    fn details_follow_the_official_mapping() {
        assert_eq!(
            uid_details(MARKER),
            serde_json::json!({
                "type": "a-u-G",
                "callsign": "Rally & point",
                "iconsetPath": "COT_MAPPING_2525B/a-u/a-u-G",
                "color": "-1",
                "attachments": ["h1", "h2"],
                "location": { "lat": 52.52, "lon": 13.41 }
            }),
            "only direct children of <detail> count"
        );
    }

    #[test]
    fn title_medevac_bullseye_and_zero_points() {
        let xml = r#"<event version="2.0" uid="b" type="u-r-b-bullseye" how="h-e" time="t" start="t" stale="t"><point lat="0" lon="0" hae="0" ce="0" le="0"/><detail><title title="Bulls"/><bullseye edgeToCenter="true"/></detail></event>"#;
        assert_eq!(
            uid_details(xml),
            serde_json::json!({ "type": "u-r-b-bullseye", "callsign": "Bulls", "title": "Bulls", "color": "-65536" })
        );
        let medevac = r#"<event version="2.0" uid="m" type="b-r-f-h-c" how="h-e" time="t" start="t" stale="t"><point lat="1" lon="2" hae="0" ce="0" le="0"/><detail><contact callsign="X"/><_medevac_ title="MED-1"/></detail></event>"#;
        assert_eq!(uid_details(medevac)["callsign"], "MED-1");
    }

    #[test]
    fn the_latest_event_is_kept_and_saved() {
        let path = std::env::temp_dir().join(format!("microtak-latest-cot-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = LatestCot::load(&path);
        store.record("m-1", MARKER, 1);
        store.record("m-1", &MARKER.replace("Rally", "Moved"), 2);
        assert!(store.get("m-1").unwrap().xml.starts_with("<event "), "declaration stripped");
        store.save_if_dirty().unwrap();
        let reloaded = LatestCot::load(&path);
        assert_eq!(reloaded.uid_details("m-1").unwrap()["callsign"], "Moved & point");
        assert_eq!(reloaded.get("m-1").unwrap().server_time_ms, 2);
        std::fs::remove_file(&path).ok();
    }
}
