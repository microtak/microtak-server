//! Mission notifications and streaming mission content, as the official
//! server does them (`DistributedSubscriptionManager`,
//! `StreamingEndpointRewriteFilter`):
//!
//! - **Live subscribers**: clients subscribed through the API while
//!   connected (`missionSubscribe`); a disconnect or `DELETE …/subscription`
//!   ends it (`missionDisconnect`), the stored subscription stays.
//! - **Changes** (`announceMissionChange`): a `t-x-m-c…` event to each live
//!   subscriber -- content (`t-x-m-c`, one per change, with the change as
//!   `<MissionChanges>` XML), logs (`-l`), keywords (`-k`, `-k-u`, `-k-c`),
//!   metadata (`-m`).
//! - **Announcements** (`broadcastMissionAnnouncement`): create
//!   (`t-x-m-n`), delete (`t-x-m-d`), keyword and metadata changes, to every
//!   connection whose groups meet the mission's, except the author.
//! - **Invitations** (`t-x-m-i`, with the invitation token and role) and
//!   **role changes** (`t-x-m-r`) to the clients concerned.
//! - **Streaming content**: an event with `<marti><dest mission=…>` from a
//!   client whose subscription may write adds its uid to that mission and
//!   goes to the mission's live subscribers.
//!
//! The notification XML follows `createMissionMessage` (dom4j, attributes
//! in the order the official code sets them; sent like the pong, without
//! an XML declaration) and the JAXB marshalling of
//! `MissionChanges` (properties in name order, the JAXB RI default).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use serde_json::Value;
use tokio::sync::broadcast;

use super::envelope::{cot_date_millis, random_uuid};
use crate::groups::GroupStore;
use crate::latest_cot::LatestCot;
use crate::missions::{ChangeRecord, Content, MissionRecord, MissionStore, Permission, Role};
use crate::sync::ResourceStore;
use crate::transport::hub::Outbound;

/// `SubscriptionManagerLite.ChangeType` → CoT type (`createMissionChangeMessage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Content,
    Log,
    Keyword,
    UidKeyword,
    ResourceKeyword,
    Metadata,
    MissionLayer,
    ExternalData,
}

impl ChangeKind {
    fn cot_type(self) -> &'static str {
        match self {
            ChangeKind::Content => "t-x-m-c",
            ChangeKind::Log => "t-x-m-c-l",
            ChangeKind::Keyword => "t-x-m-c-k",
            ChangeKind::UidKeyword => "t-x-m-c-k-u",
            ChangeKind::ResourceKeyword => "t-x-m-c-k-c",
            ChangeKind::Metadata => "t-x-m-c-m",
            ChangeKind::MissionLayer => "t-x-m-c-h",
            ChangeKind::ExternalData => "t-x-m-c-e",
        }
    }
}

/// What `broadcastMissionAnnouncement` supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Announcement {
    Create,
    Delete,
    Keyword,
    Metadata,
}

pub struct MissionNotifier {
    hub: broadcast::Sender<Outbound>,
    store: Arc<MissionStore>,
    resources: Arc<ResourceStore>,
    latest_cot: Arc<LatestCot>,
    groups: Arc<GroupStore>,
    /// mission guid → live subscriber client uids.
    live: RwLock<HashMap<String, BTreeSet<String>>>,
}

pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// `DateUtil.toCotTime`: whole seconds.
fn cot_time(ms: i64) -> String {
    let full = cot_date_millis(ms);
    format!(
        "{}Z",
        full.rsplit_once('.').map(|(head, _)| head).unwrap_or(&full)
    )
}

/// `createMissionMessage`: the seed `<event how type version>` plus uid,
/// start, time, stale (+20 s); `<mission type tool>` plus name, guid,
/// authorUid, uid, token (each only if set), then `inner`.
#[allow(clippy::too_many_arguments)]
pub fn mission_message(
    mission_guid: &str,
    mission_name: &str,
    cot_type: &str,
    msg_type: &str,
    author_uid: &str,
    tool: &str,
    token: Option<&str>,
    inner: Option<&str>,
    now_ms: i64,
) -> String {
    let (now, stale) = (cot_time(now_ms), cot_time(now_ms + 20_000));
    let mut mission = format!(
        r#"<mission type="{}" tool="{}" name="{}" guid="{}""#,
        escape(msg_type),
        escape(tool),
        escape(mission_name),
        escape(mission_guid)
    );
    if !author_uid.is_empty() {
        mission.push_str(&format!(r#" authorUid="{}""#, escape(author_uid)));
    }
    if let Some(token) = token.filter(|t| !t.is_empty()) {
        mission.push_str(&format!(r#" token="{}""#, escape(token)));
    }
    match inner {
        Some(inner) => mission.push_str(&format!(">{inner}</mission>")),
        None => mission.push_str("/>"),
    }
    format!(
        r#"<event how="h-g-i-g-o" type="{cot_type}" version="2.0" uid="{uid}" start="{now}" time="{now}" stale="{stale}"><point ce="9999999" le="9999999" hae="0" lat="0" lon="0"/><detail>{mission}</detail></event>"#,
        uid = random_uuid(),
    )
}

/// JAXB `Resource`: the properties in name order, arrays as repeated
/// elements, absent ones omitted.
fn resource_xml(resource: &Value) -> String {
    let mut out = String::from("<contentResource>");
    if let Some(map) = resource.as_object() {
        for (key, value) in map {
            match value {
                Value::Array(items) => {
                    for item in items {
                        out.push_str(&format!("<{key}>{}</{key}>", escape(&text(item))));
                    }
                }
                Value::Null => {}
                other => out.push_str(&format!("<{key}>{}</{key}>", escape(&text(other)))),
            }
        }
    }
    out.push_str("</contentResource>");
    out
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// JAXB `UidDetails`: attributes in field order, then `<attachment>`s and
/// `<location lat lon/>`.
fn details_xml(details: &Value) -> String {
    let mut out = String::from("<details");
    for key in [
        "type",
        "callsign",
        "title",
        "iconsetPath",
        "color",
        "name",
        "category",
    ] {
        if let Some(v) = details.get(key).and_then(|v| v.as_str()) {
            out.push_str(&format!(r#" {key}="{}""#, escape(v)));
        }
    }
    let attachments = details
        .get("attachments")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let location = details.get("location");
    if attachments.is_empty() && location.is_none() {
        out.push_str("/>");
        return out;
    }
    out.push('>');
    for a in attachments {
        out.push_str(&format!("<attachment>{}</attachment>", escape(&text(&a))));
    }
    if let Some(location) = location {
        out.push_str(&format!(
            r#"<location lat="{}" lon="{}"/>"#,
            text(&location["lat"]),
            text(&location["lon"])
        ));
    }
    out.push_str("</details>");
    out
}

impl MissionNotifier {
    pub fn new(
        hub: broadcast::Sender<Outbound>,
        store: Arc<MissionStore>,
        resources: Arc<ResourceStore>,
        latest_cot: Arc<LatestCot>,
        groups: Arc<GroupStore>,
    ) -> Self {
        Self {
            hub,
            store,
            resources,
            latest_cot,
            groups,
            live: RwLock::new(HashMap::new()),
        }
    }

    /// `missionSubscribe`: `client_uid` now receives this mission's changes.
    pub fn connect(&self, guid: &str, client_uid: &str) {
        self.live
            .write()
            .unwrap()
            .entry(guid.to_string())
            .or_default()
            .insert(client_uid.to_string());
    }

    /// `missionDisconnect`.
    pub fn disconnect(&self, guid: &str, client_uid: &str) {
        if let Some(uids) = self.live.write().unwrap().get_mut(guid) {
            uids.remove(client_uid);
        }
    }

    /// A client went away: it leaves every mission's live subscribers.
    pub fn client_disconnected(&self, client_uid: &str) {
        for uids in self.live.write().unwrap().values_mut() {
            uids.remove(client_uid);
        }
    }

    /// The mission's live subscribers (`getMissionSubscriptions(guid, true)`).
    pub fn live_subscribers(&self, guid: &str) -> BTreeSet<String> {
        self.live
            .read()
            .unwrap()
            .get(guid)
            .cloned()
            .unwrap_or_default()
    }

    fn send_to(&self, uids: Vec<String>, xml: String) {
        if !uids.is_empty() {
            let _ = self.hub.send(Outbound::server_to(uids, xml));
        }
    }

    /// A CoT event to these clients (mission content from an imported
    /// package).
    pub fn send_event(&self, uids: Vec<String>, xml: String) {
        self.send_to(uids, xml);
    }

    /// One change as the official `commonUtil.toXml(new MissionChanges(change))`.
    pub fn change_xml(&self, change: &ChangeRecord) -> String {
        self.change_xml_with(change, None, None)
    }

    /// [`Self::change_xml`] with the hydrated `externalData` (JAXB orders it
    /// by its property, `externalMissionData`: after `creatorUid`).
    pub fn change_xml_with(
        &self,
        change: &ChangeRecord,
        external: Option<&serde_json::Value>,
        map_layer_xml: Option<&str>,
    ) -> String {
        let mut xml = String::from("<MissionChanges><MissionChange>");
        if let Some(Content::Hash(hash)) = &change.content {
            let resource = self
                .resources
                .by_hash(hash, None)
                .into_iter()
                .next()
                .map(|r| r.resource_json())
                .unwrap_or_else(|| serde_json::json!({ "hash": hash }));
            xml.push_str(&resource_xml(&resource));
        }
        if let Some(Content::Uid(uid)) = &change.content {
            xml.push_str(&format!("<contentUid>{}</contentUid>", escape(uid)));
        }
        xml.push_str(&format!(
            "<creatorUid>{}</creatorUid>",
            escape(&change.creator_uid)
        ));
        if let Some(ext) = external {
            // ExternalMissionData properties: id (uid), name, notes, tool,
            // urlData, urlDisplay (urlView); nulls left out.
            xml.push_str("<externalData>");
            for (key, element) in [
                ("uid", "uid"),
                ("name", "name"),
                ("notes", "notes"),
                ("tool", "tool"),
                ("urlData", "urlData"),
                ("urlView", "urlView"),
            ] {
                if let Some(v) = ext.get(key).and_then(|v| v.as_str()) {
                    xml.push_str(&format!("<{element}>{}</{element}>", escape(v)));
                }
            }
            xml.push_str("</externalData>");
        }
        xml.push_str("<isFederatedChange>false</isFederatedChange>");
        if let Some(layer) = map_layer_xml {
            xml.push_str(layer);
        }
        xml.push_str(&format!(
            "<missionGuid>{}</missionGuid>",
            escape(&change.mission_guid)
        ));
        xml.push_str(&format!(
            "<missionName>{}</missionName>",
            escape(&change.mission_name)
        ));
        xml.push_str(&format!(
            "<timestamp>{}</timestamp>",
            cot_date_millis(change.timestamp_ms)
        ));
        let kind = serde_json::to_value(change.change_type)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        xml.push_str(&format!("<type>{kind}</type>"));
        if let Some(Content::Uid(uid)) = &change.content
            && let Some(details) = self.latest_cot.uid_details(uid)
        {
            xml.push_str(&details_xml(&details));
        }
        xml.push_str("</MissionChange></MissionChanges>");
        xml
    }

    /// `announceMissionChange` to the live subscribers (`topic:` ones are
    /// routed by topic in the official server, not to a connection).
    pub fn announce(
        &self,
        mission: &MissionRecord,
        kind: ChangeKind,
        author_uid: &str,
        changes: Option<&str>,
    ) {
        let xml = mission_message(
            &mission.guid,
            &mission.name,
            kind.cot_type(),
            "CHANGE",
            author_uid,
            &mission.tool,
            None,
            changes,
            crate::cot::now_unix_millis(),
        );
        let uids: Vec<String> = self
            .live_subscribers(&mission.guid)
            .into_iter()
            .filter(|u| !u.starts_with("topic:"))
            .collect();
        self.send_to(uids, xml);
    }

    /// The content changes just recorded, one notification each.
    pub fn announce_content(
        &self,
        mission: &MissionRecord,
        changes: &[ChangeRecord],
        author_uid: &str,
    ) {
        for change in changes {
            self.announce(
                mission,
                ChangeKind::Content,
                author_uid,
                Some(&self.change_xml(change)),
            );
        }
    }

    /// `broadcastMissionAnnouncement`.
    pub fn broadcast(&self, mission: &MissionRecord, announcement: Announcement, author_uid: &str) {
        let (cot_type, msg_type) = match announcement {
            Announcement::Create => ("t-x-m-n", "CREATE"),
            Announcement::Delete => ("t-x-m-d", "DELETE"),
            Announcement::Keyword => (ChangeKind::Keyword.cot_type(), "CHANGE"),
            Announcement::Metadata => (ChangeKind::Metadata.cot_type(), "CHANGE"),
        };
        let xml = mission_message(
            &mission.guid,
            &mission.name,
            cot_type,
            msg_type,
            author_uid,
            &mission.tool,
            None,
            None,
            crate::cot::now_unix_millis(),
        );
        let skip = (!author_uid.is_empty()).then(|| author_uid.to_string());
        let _ = self.hub.send(Outbound::server_broadcast(
            mission.groups.clone(),
            skip,
            xml,
        ));
    }

    /// `commonUtil.toXml(missionLayer)`: JAXB `missionLayer`, properties in
    /// name order (after, name, parentUid, type, uid), absent ones omitted.
    pub fn layer_xml(layer: &crate::missions::LayerRecord, parent_uid: Option<&str>) -> String {
        let mut xml = String::from("<missionLayer>");
        if let Some(after) = &layer.after {
            xml.push_str(&format!("<after>{}</after>", escape(after)));
        }
        if let Some(name) = &layer.name {
            xml.push_str(&format!("<name>{}</name>", escape(name)));
        }
        if let Some(parent) = parent_uid {
            xml.push_str(&format!("<parentUid>{}</parentUid>", escape(parent)));
        }
        xml.push_str(&format!(
            "<type>{}</type><uid>{}</uid></missionLayer>",
            layer.layer_type.name(),
            escape(&layer.uid)
        ));
        xml
    }

    /// `commonUtil.toXml(role)`.
    pub fn role_xml(role: Role) -> String {
        let permissions: String = role
            .permissions()
            .iter()
            .map(|p| {
                format!(
                    r#"<permission type="{}"/>"#,
                    serde_json::to_value(p)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .unwrap_or_default()
                )
            })
            .collect();
        format!(
            r#"<role type="{}"><permissions>{permissions}</permissions></role>"#,
            role.name()
        )
    }

    /// `sendMissionInvite` (`t-x-m-i`) to `uids`.
    pub fn invite(
        &self,
        mission: &MissionRecord,
        uids: Vec<String>,
        author_uid: &str,
        token: &str,
        role: Role,
    ) {
        let xml = mission_message(
            &mission.guid,
            &mission.name,
            "t-x-m-i",
            "INVITE",
            author_uid,
            &mission.tool,
            Some(token),
            Some(&Self::role_xml(role)),
            crate::cot::now_unix_millis(),
        );
        self.send_to(uids, xml);
    }

    /// `sendMissionRoleChange` (`t-x-m-r`) to `client_uid`.
    pub fn role_change(
        &self,
        mission: &MissionRecord,
        client_uid: &str,
        author_uid: &str,
        role: Option<Role>,
    ) {
        let role_xml = role.map(Self::role_xml);
        let xml = mission_message(
            &mission.guid,
            &mission.name,
            "t-x-m-r",
            "INVITE",
            author_uid,
            &mission.tool,
            None,
            role_xml.as_deref(),
            crate::cot::now_unix_millis(),
        );
        self.send_to(vec![client_uid.to_string()], xml);
    }

    /// The live clients a mission invitation goes to (`missionInvite`):
    /// the client uid itself; for a callsign, the connected uid whose
    /// latest report carries it; for a username, that user's connection;
    /// for a group, its connected members.
    pub fn invitees(
        &self,
        kind: crate::missions::InvitationType,
        invitee: &str,
        connected: &[(Option<String>, Option<String>)],
    ) -> Vec<String> {
        use crate::missions::InvitationType as T;
        let mut uids = Vec::new();
        match kind {
            T::ClientUid => uids.push(invitee.to_string()),
            T::Callsign => {
                for (_, uid) in connected {
                    if let Some(uid) = uid {
                        let callsign = self
                            .latest_cot
                            .uid_details(uid)
                            .and_then(|d| d["callsign"].as_str().map(String::from));
                        if callsign.as_deref() == Some(invitee) {
                            uids.push(uid.clone());
                        }
                    }
                }
            }
            T::UserName => {
                uids.extend(
                    connected
                        .iter()
                        .filter(|(cn, _)| cn.as_deref() == Some(invitee))
                        .filter_map(|(_, uid)| uid.clone()),
                );
            }
            T::Group => {
                for (cn, uid) in connected {
                    if let (Some(cn), Some(uid)) = (cn, uid)
                        && self.groups.all_group_names(cn).contains(invitee)
                    {
                        uids.push(uid.clone());
                    }
                }
            }
            T::Team => {}
        }
        uids.sort();
        uids.dedup();
        uids
    }
}

impl crate::transport::hub::StreamingMissions for MissionNotifier {
    /// `processTracksByMissionName` / `…ByGuid`.
    fn route(
        &self,
        client_uid: Option<&str>,
        username: &str,
        names: &[String],
        guids: &[String],
        event_uid: &str,
    ) -> Vec<String> {
        let client_uid = client_uid.unwrap_or("");
        let groups = self.groups.all_group_names(username);
        let mut recipients = BTreeSet::new();
        let mut missions: BTreeMap<String, MissionRecord> = BTreeMap::new();
        for name in names {
            if let Some(m) = self
                .store
                .by_name(name, |m| m.groups.iter().any(|g| groups.contains(g)))
            {
                missions.insert(m.guid.clone(), m);
            }
        }
        for guid in guids {
            if let Some(m) = self
                .store
                .by_guid(guid)
                .filter(|m| !m.deleted && m.groups.iter().any(|g| groups.contains(g)))
            {
                missions.insert(m.guid.clone(), m);
            }
        }
        for mission in missions.values() {
            let Some(sub) = self
                .store
                .find_subscription(&mission.guid, client_uid, username)
            else {
                tracing::debug!(mission = %mission.name, client_uid, "no mission subscription for streamed content");
                continue;
            };
            if !sub.role.has(Permission::MissionWrite) {
                tracing::warn!(mission = %mission.name, client_uid, "illegal attempt to add streaming content to mission");
                continue;
            }
            for uid in self.live_subscribers(&mission.guid) {
                if uid != client_uid {
                    recipients.insert(uid);
                }
            }
            let now = crate::cot::now_unix_millis();
            if self
                .store
                .add_content(
                    &mission.guid,
                    Content::Uid(event_uid.to_string()),
                    client_uid,
                    now,
                )
                .is_ok()
            {
                let changes = self
                    .store
                    .changes(&mission.guid, crate::missions::Window::ALL, false)
                    .unwrap_or_default();
                if let Some(latest) = changes.first() {
                    self.announce_content(mission, std::slice::from_ref(latest), client_uid);
                }
            }
        }
        recipients.into_iter().collect()
    }

    fn client_disconnected(&self, client_uid: &str) {
        MissionNotifier::client_disconnected(self, client_uid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mission_messages_follow_create_mission_message() {
        let xml = mission_message(
            "g-1",
            "Ops & Co",
            "t-x-m-c",
            "CHANGE",
            "ANDROID-1",
            "public",
            None,
            Some("<MissionChanges/>"),
            1_760_716_800_689,
        );
        let uid_start = xml.find(r#" uid=""#).unwrap() + 6;
        let uid = &xml[uid_start..uid_start + 36];
        assert_eq!(
            xml,
            format!(
                r#"<event how="h-g-i-g-o" type="t-x-m-c" version="2.0" uid="{uid}" start="2025-10-17T16:00:00Z" time="2025-10-17T16:00:00Z" stale="2025-10-17T16:00:20Z"><point ce="9999999" le="9999999" hae="0" lat="0" lon="0"/><detail><mission type="CHANGE" tool="public" name="Ops &amp; Co" guid="g-1" authorUid="ANDROID-1"><MissionChanges/></mission></detail></event>"#
            )
        );
        let create = mission_message(
            "g-1", "Ops", "t-x-m-n", "CREATE", "", "public", None, None, 0,
        );
        assert!(
            create.contains(r#"<mission type="CREATE" tool="public" name="Ops" guid="g-1"/>"#),
            "{create}"
        );
    }

    #[test]
    fn role_xml_is_jaxb_shaped() {
        assert_eq!(
            MissionNotifier::role_xml(Role::ReadOnlySubscriber),
            r#"<role type="MISSION_READONLY_SUBSCRIBER"><permissions><permission type="MISSION_READ"/></permissions></role>"#
        );
    }

    fn notifier() -> (
        MissionNotifier,
        broadcast::Receiver<Outbound>,
        Arc<MissionStore>,
        Arc<LatestCot>,
    ) {
        let (tx, rx) = broadcast::channel(16);
        let store = Arc::new(MissionStore::in_memory());
        let latest = Arc::new(LatestCot::in_memory());
        let n = MissionNotifier::new(
            tx,
            Arc::clone(&store),
            Arc::new(ResourceStore::in_memory()),
            Arc::clone(&latest),
            Arc::new(GroupStore::in_memory()),
        );
        (n, rx, store, latest)
    }

    fn mission(store: &MissionStore) -> MissionRecord {
        store
            .create(
                crate::missions::NewMission {
                    guid: "6f1c0000-0000-4000-8000-000000000001".into(),
                    name: "Ops".into(),
                    fields: Default::default(),
                    tool: "public".into(),
                    creator_uid: "ANDROID-1".into(),
                    groups: BTreeSet::from(["__ANON__".to_string()]),
                    password_hash: None,
                    default_role: None,
                    invite_only: false,
                },
                1_000,
            )
            .unwrap()
    }

    /// `MissionChanges` XML: properties in name order, `details` (the
    /// `uidDetails` property) last.
    #[test]
    fn a_uid_change_as_jaxb_marshals_it() {
        let (n, _rx, store, latest) = notifier();
        let m = mission(&store);
        latest.record("m-1", r#"<event version="2.0" uid="m-1" type="a-h-G" how="h-e" time="t" start="t" stale="t"><point lat="1.5" lon="2.5" hae="0" ce="0" le="0"/><detail><contact callsign="X"/></detail></event>"#, 1);
        store
            .add_content(
                &m.guid,
                Content::Uid("m-1".into()),
                "ANDROID-2",
                1_760_716_800_005,
            )
            .unwrap();
        let change = store
            .changes(&m.guid, crate::missions::Window::ALL, false)
            .unwrap()[0]
            .clone();
        assert_eq!(
            n.change_xml(&change),
            r#"<MissionChanges><MissionChange><contentUid>m-1</contentUid><creatorUid>ANDROID-2</creatorUid><isFederatedChange>false</isFederatedChange><missionGuid>6f1c0000-0000-4000-8000-000000000001</missionGuid><missionName>Ops</missionName><timestamp>2025-10-17T16:00:00.5Z</timestamp><type>ADD_CONTENT</type><details type="a-h-G" callsign="X"><location lat="1.5" lon="2.5"/></details></MissionChange></MissionChanges>"#
        );
    }

    /// `processTracksByMissionName`: only a subscription that may write adds
    /// streamed content; without one nothing is added or routed.
    #[test]
    fn streamed_content_needs_a_writing_subscription() {
        use crate::transport::hub::StreamingMissions;
        let (n, _rx, store, _) = notifier();
        let m = mission(&store);
        store
            .subscribe(
                &m.guid,
                "ANDROID-R",
                "reader",
                Role::ReadOnlySubscriber,
                1,
                |id| id.into(),
            )
            .unwrap();
        store
            .subscribe(&m.guid, "ANDROID-W", "writer", Role::Subscriber, 1, |id| {
                id.into()
            })
            .unwrap();
        n.connect(&m.guid, "ANDROID-R");
        n.connect(&m.guid, "ANDROID-W");
        let names = vec!["Ops".to_string()];

        assert!(
            n.route(Some("ANDROID-X"), "nobody", &names, &[], "u-1")
                .is_empty(),
            "no subscription"
        );
        assert!(
            n.route(Some("ANDROID-R"), "reader", &names, &[], "u-2")
                .is_empty(),
            "read-only"
        );
        assert!(
            !store
                .by_guid(&m.guid)
                .unwrap()
                .has(&Content::Uid("u-2".into()))
        );

        assert_eq!(
            n.route(Some("ANDROID-W"), "writer", &names, &[], "u-3"),
            ["ANDROID-R"],
            "the other live subscribers"
        );
        assert!(
            store
                .by_guid(&m.guid)
                .unwrap()
                .has(&Content::Uid("u-3".into()))
        );
        assert_eq!(
            n.route(
                Some("ANDROID-W"),
                "writer",
                &[],
                std::slice::from_ref(&m.guid),
                "u-4"
            ),
            ["ANDROID-R"],
            "by guid too"
        );
    }

    #[test]
    fn changes_go_to_live_subscribers_only_and_disconnects_end_it() {
        let (n, mut rx, store, _) = notifier();
        let m = mission(&store);
        n.announce(&m, ChangeKind::Log, "A", None);
        assert!(rx.try_recv().is_err(), "no live subscribers, nothing sent");
        n.connect(&m.guid, "ANDROID-B");
        n.connect(&m.guid, "topic:x");
        n.announce(&m, ChangeKind::Log, "A", None);
        let sent = rx.try_recv().unwrap();
        assert_eq!(
            sent.dest_uids.as_deref(),
            Some(&["ANDROID-B".to_string()][..])
        );
        assert!(sent.xml.contains(r#"type="t-x-m-c-l""#));
        n.client_disconnected("ANDROID-B");
        n.announce(&m, ChangeKind::Log, "A", None);
        assert!(rx.try_recv().is_err());
    }
}
