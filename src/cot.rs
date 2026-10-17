//! Cursor-on-Target (CoT) event model: XML parsing/serialization.
//!
//! Covers the `<event>` envelope, `<point>`, and the `<detail>` sub-elements
//! MicroTAK actually understands and acts on (contact identity, GeoChat,
//! individual addressing) as defined in
//! `wiki/ATAK-Communications-Architecture.md` (§1/§4). See
//! `wiki/MicroTAK-Test-Plan.md` for the full CoT test-case catalog this
//! module is meant to satisfy.
//!
//! **What `detail` models**: only the sub-elements MicroTAK acts on
//! (contact callsign/endpoint, GeoChat, individual addressing, remarks,
//! `link`); anything else is ignored by the model. That no longer loses
//! data on the wire: relays forward each event's **original XML** (see
//! `transport::codec::DecodedItem::Event`) -- before 2026-09-29 they
//! re-serialised this model, silently stripping `takv`, `__group`, marker
//! icons/colours, shapes and every other unmodelled element (TC-COT-10).

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CotError {
    #[error("CoT XML deserialization failed: {0}")]
    Xml(#[from] quick_xml::DeError),
    #[error("CoT XML serialization failed: {0}")]
    XmlSerialize(#[from] quick_xml::SeError),
    #[error("invalid timestamp {field}: {value}")]
    InvalidTimestamp { field: &'static str, value: String },
}

/// A CoT `<event>` element.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename = "event")]
pub struct Event {
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "@uid")]
    pub uid: String,
    #[serde(rename = "@type")]
    pub cot_type: String,
    #[serde(rename = "@how")]
    pub how: String,
    #[serde(rename = "@time")]
    pub time: String,
    #[serde(rename = "@start")]
    pub start: String,
    #[serde(rename = "@stale")]
    pub stale: String,
    pub point: Point,
    #[serde(rename = "detail", skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<Detail>,
}

/// A CoT `<point>` element (WGS84).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Point {
    #[serde(rename = "@lat")]
    pub lat: f64,
    #[serde(rename = "@lon")]
    pub lon: f64,
    #[serde(rename = "@hae")]
    pub hae: f64,
    #[serde(rename = "@ce")]
    pub ce: f64,
    #[serde(rename = "@le")]
    pub le: f64,
}

/// The open-schema `<detail>` container — see this module's doc comment for
/// what's modeled vs. dropped.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Detail {
    #[serde(rename = "contact", skip_serializing_if = "Option::is_none", default)]
    pub contact: Option<Contact>,
    #[serde(rename = "__chat", skip_serializing_if = "Option::is_none", default)]
    pub chat: Option<Chat>,
    #[serde(rename = "marti", skip_serializing_if = "Option::is_none", default)]
    pub marti: Option<Marti>,
    #[serde(rename = "remarks", skip_serializing_if = "Option::is_none", default)]
    pub remarks: Option<Remarks>,
    /// `<link>` elements -- e.g. a marker's or chat message's creator
    /// (`relation="p-p"`). Real clients interleave these with other detail
    /// children, hence quick-xml's `overlapped-lists` feature.
    #[serde(rename = "link", skip_serializing_if = "Vec::is_empty", default)]
    pub links: Vec<Link>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Link {
    #[serde(rename = "@uid", skip_serializing_if = "Option::is_none", default)]
    pub uid: Option<String>,
    #[serde(rename = "@relation", skip_serializing_if = "Option::is_none", default)]
    pub relation: Option<String>,
    #[serde(rename = "@type", skip_serializing_if = "Option::is_none", default)]
    pub link_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Contact {
    #[serde(rename = "@callsign", skip_serializing_if = "Option::is_none", default)]
    pub callsign: Option<String>,
    /// Where the device can be reached (`host:port:proto`); only a device's
    /// own position report carries one -- see [`Event::is_situational_awareness`].
    #[serde(rename = "@endpoint", skip_serializing_if = "Option::is_none", default)]
    pub endpoint: Option<String>,
}

/// GeoChat detail (`t-x-c-t` events) — see `docs/TEST-PLAN.md` §7 for the
/// routing rules built on this.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Chat {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@chatroom")]
    pub chatroom: String,
    #[serde(
        rename = "@senderCallsign",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub sender_callsign: Option<String>,
    #[serde(
        rename = "@groupOwner",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub group_owner: Option<String>,
    #[serde(rename = "chatgrp", skip_serializing_if = "Option::is_none", default)]
    pub chatgrp: Option<ChatGroup>,
}

/// Team-chat membership. Real CoT carries an arbitrary number of `uidN`
/// attributes (`uid0`, `uid1`, ... `uidN`), not a fixed count — captured
/// via a flattened attribute map rather than fixed fields (see
/// [`ChatGroup::member_uids`]).
///
/// **Known simplification**: the real CoT `<__chat>` schema also carries a
/// `hierarchy` sub-tag alongside `chatgrp`. A confirmed real bug in a
/// reference TAK server implementation traced *partial* GeoChat delivery
/// (some recipients get a message, others silently don't) to exactly this
/// field being missing from its model — MicroTAK doesn't model `hierarchy`
/// either yet, and routes purely off `chatgrp`'s `uidN` attributes. Worth
/// revisiting against a real multi-hop ATAK team-chat configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatGroup {
    #[serde(rename = "@id", skip_serializing_if = "Option::is_none", default)]
    pub id: Option<String>,
    #[serde(flatten)]
    attributes: std::collections::BTreeMap<String, String>,
}

impl ChatGroup {
    /// The team member `uid`s addressed by this chat group, unordered (set
    /// membership is what matters for delivery, not attribute order).
    pub fn member_uids(&self) -> Vec<&str> {
        self.attributes
            .iter()
            .filter_map(|(key, value)| {
                let suffix = key.strip_prefix("@uid")?;
                (!suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()))
                    .then_some(value.as_str())
            })
            .collect()
    }
}

/// Individual-addressing block (`<marti><dest .../></marti>`).
///
/// **Known simplification**: MicroTAK's routing only acts on `Dest::uid`,
/// not `Dest::callsign` — `uid` is the identity MicroTAK tracks robustly
/// (bound at the device registry level for authenticated connections);
/// callsign is arbitrary free text with no uniqueness guarantee or
/// registry backing. A real ATAK client addressing an individual chat
/// purely by callsign (no `uid` attribute) won't be routed correctly yet —
/// a documented gap, not a silent one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Marti {
    #[serde(rename = "dest", default)]
    pub dest: Vec<Dest>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dest {
    #[serde(rename = "@uid", skip_serializing_if = "Option::is_none", default)]
    pub uid: Option<String>,
    #[serde(rename = "@callsign", skip_serializing_if = "Option::is_none", default)]
    pub callsign: Option<String>,
    /// Streaming mission content (`StreamingEndpointRewriteFilter.MISSION_ATTR`).
    #[serde(rename = "@mission", skip_serializing_if = "Option::is_none", default)]
    pub mission: Option<String>,
    #[serde(
        rename = "@mission-guid",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub mission_guid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Remarks {
    #[serde(rename = "$text", default)]
    pub text: String,
}

/// ATAK's broadcast chat room. Its `chatgrp` names the sender and the room
/// itself (`uid0=<sender> uid1="All Chat Rooms"`), not recipients -- a
/// message to it goes to everyone (the official TAK Server routes chat on
/// `<marti><dest>` only and leaves room filtering to clients).
pub const ALL_CHAT_ROOMS: &str = "All Chat Rooms";

/// `SubmissionService.controlMsgTypes` of the official server.
const CONTROL_TYPES: [&str; 11] = [
    "t-b",
    "t-b-a",
    "t-b-c",
    "t-b-q",
    "t-x-c-f",
    "t-x-c-t",
    "t-x-c-t-r",
    "t-x-takp-q",
    "t-x-c-m",
    "t-x-c-i-e",
    "t-x-c-i-d",
];

/// The official server's answer to a ping (`SubmissionService.sendPong`),
/// as dom4j serializes it: uid `takPong`, times in `DateUtil.toCotTime`
/// (`yyyy-MM-dd'T'HH:mm:ss'Z'`), stale 20 seconds later.
pub fn pong_xml(now_unix_millis: i64) -> String {
    let now = cot_time(now_unix_millis);
    let stale = cot_time(now_unix_millis + 20_000);
    format!(
        r#"<event version="2.0" uid="takPong" type="t-x-c-t-r" how="h-g-i-g-o" time="{now}" start="{now}" stale="{stale}"> <point ce="9999999" le="9999999" hae="0" lat="0" lon="0"/></event>"#
    )
}

fn cot_time(unix_millis: i64) -> String {
    let dt = time::OffsetDateTime::from_unix_timestamp(unix_millis.div_euclid(1000))
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

/// The event without its first `/event/detail/marti` element, as the
/// official server forwards CoT (`StreamingEndpointRewriteFilter` detaches
/// `MARTI_XPATH` from every streamed event). Unchanged if there is none.
pub fn strip_marti(xml: &str) -> std::borrow::Cow<'_, str> {
    use quick_xml::events::Event as X;
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut path: Vec<Vec<u8>> = Vec::new();
    loop {
        let before = reader.buffer_position() as usize;
        match reader.read_event() {
            Ok(X::Start(e)) => {
                let name = e.name().as_ref().to_vec();
                if name == b"marti" && path == [b"event".to_vec(), b"detail".to_vec()] {
                    let end_name = e.name().as_ref().to_vec();
                    if reader
                        .read_to_end(quick_xml::name::QName(&end_name))
                        .is_err()
                    {
                        return std::borrow::Cow::Borrowed(xml);
                    }
                    let after = reader.buffer_position() as usize;
                    return std::borrow::Cow::Owned(format!("{}{}", &xml[..before], &xml[after..]));
                }
                path.push(name);
            }
            Ok(X::Empty(e)) => {
                if e.name().as_ref() == b"marti" && path == [b"event".to_vec(), b"detail".to_vec()]
                {
                    let after = reader.buffer_position() as usize;
                    return std::borrow::Cow::Owned(format!("{}{}", &xml[..before], &xml[after..]));
                }
            }
            Ok(X::End(_)) => {
                path.pop();
            }
            Ok(X::Eof) | Err(_) => return std::borrow::Cow::Borrowed(xml),
            Ok(_) => {}
        }
    }
}

/// Now, in Unix milliseconds.
pub fn now_unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Event {
    /// Parse a single `<event>...</event>` XML document.
    ///
    /// Does NOT handle stream framing (multiple concatenated events with no
    /// separator) — that's the transport layer's job (see `wiki/MicroTAK-Test-Plan.md`
    /// §Transport, TC-COT-STREAM-*). This only parses one already-isolated event.
    pub fn from_xml(xml: &str) -> Result<Self, CotError> {
        Ok(quick_xml::de::from_str(xml)?)
    }

    /// Serialize back to a CoT XML `<event>` document.
    pub fn to_xml(&self) -> Result<String, CotError> {
        Ok(quick_xml::se::to_string(self)?)
    }

    /// True for GeoChat events: type `b-t-f` (uid
    /// `GeoChat.<sender>.<room>.<id>`, as ATAK and OmniTAK send it).
    pub fn is_chat(&self) -> bool {
        self.cot_type == "b-t-f" || self.cot_type.starts_with("b-t-f-")
    }

    /// Control messages, which the official server consumes instead of
    /// brokering or storing (`SubmissionService.controlMsgTypes`, matched
    /// lowercased): subscription, filter, ping (`t-x-c-t`) and pong,
    /// protocol negotiation, metrics and incognito messages.
    pub fn is_control(&self) -> bool {
        CONTROL_TYPES.contains(&self.cot_type.to_ascii_lowercase().as_str())
    }

    /// A TAK ping, answered with [`pong_xml`].
    pub fn is_ping(&self) -> bool {
        self.cot_type.eq_ignore_ascii_case("t-x-c-t")
    }

    /// Whether this is a device's own situational-awareness report (its
    /// position/identity "PLI"), as opposed to content it authored
    /// (markers, chat, shapes): a `uid` plus a `<contact>` carrying both a
    /// `callsign` and an `endpoint`. The same definition the official TAK
    /// Server uses (`CotEventContainer.isSituationalAwarenessMessage`) --
    /// markers carry a callsign but no endpoint; chat carries neither.
    pub fn is_situational_awareness(&self) -> bool {
        let Some(contact) = self.detail.as_ref().and_then(|d| d.contact.as_ref()) else {
            return false;
        };
        let non_empty =
            |value: &Option<String>| value.as_deref().is_some_and(|v| !v.trim().is_empty());
        !self.uid.trim().is_empty() && non_empty(&contact.callsign) && non_empty(&contact.endpoint)
    }

    /// The uids this event names as its producer: `<link relation="p-p">`
    /// -- a marker's creator, a GeoChat message's sender.
    pub fn producer_uids(&self) -> Vec<&str> {
        self.detail
            .iter()
            .flat_map(|detail| detail.links.iter())
            .filter(|link| link.relation.as_deref() == Some("p-p"))
            .filter_map(|link| link.uid.as_deref())
            .collect()
    }

    /// The set of `uid`s this event is individually/team addressed to, if
    /// any (`<marti><dest uid=.../></marti>` and/or `chatgrp`'s `uidN`
    /// attributes, unioned). `None` means this event carries no addressing
    /// info at all and should be broadcast, not that it has zero
    /// recipients — see `docs/TEST-PLAN.md` §7/§9 routing rules.
    /// The missions this event is addressed to (`<marti><dest mission=…>`
    /// / `mission-guid=…`): (names, guids).
    pub fn dest_missions(&self) -> (Vec<String>, Vec<String>) {
        let Some(marti) = self.detail.as_ref().and_then(|d| d.marti.as_ref()) else {
            return (Vec::new(), Vec::new());
        };
        let names = marti
            .dest
            .iter()
            .filter_map(|d| d.mission.clone())
            .collect();
        let guids = marti
            .dest
            .iter()
            .filter(|d| d.mission.is_none())
            .filter_map(|d| d.mission_guid.clone())
            .collect();
        (names, guids)
    }

    pub fn addressed_uids(&self) -> Option<Vec<&str>> {
        let detail = self.detail.as_ref()?;
        let mut uids = Vec::new();

        if let Some(marti) = &detail.marti {
            uids.extend(marti.dest.iter().filter_map(|d| d.uid.as_deref()));
        }
        if let Some(chat) = &detail.chat
            && chat.chatroom != ALL_CHAT_ROOMS
            && let Some(chatgrp) = &chat.chatgrp
        {
            uids.extend(chatgrp.member_uids());
        }

        if uids.is_empty() { None } else { Some(uids) }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const MINIMAL_EVENT_PUB: &str = MINIMAL_EVENT;
    const MINIMAL_EVENT: &str = r#"<event version="2.0" uid="TEST-UID-1" type="a-f-G-U-C" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.2500" lon="10.4000" hae="10.0" ce="5.0" le="3.0"/></event>"#;

    #[test]
    fn parses_minimal_event() {
        let event = Event::from_xml(MINIMAL_EVENT).expect("should parse");
        assert_eq!(event.uid, "TEST-UID-1");
        assert_eq!(event.cot_type, "a-f-G-U-C");
        assert_eq!(event.point.lat, 53.25);
        assert!(event.detail.is_none());
    }

    #[test]
    fn round_trips_minimal_event() {
        let event = Event::from_xml(MINIMAL_EVENT).expect("should parse");
        let xml = event.to_xml().expect("should serialize");
        let reparsed = Event::from_xml(&xml).expect("should reparse own output");
        assert_eq!(event, reparsed);
    }

    /// This test used to only check `detail.is_some()` -- which passed even
    /// though the old `RawDetail` (a bare `$text`-only passthrough) never
    /// actually captured `<contact>`'s attributes at all. Checking the real
    /// value is what makes this test meaningful.
    #[test]
    fn parses_contact_callsign_from_detail() {
        let xml = r#"<event version="2.0" uid="TEST-UID-2" type="a-f-G-U-C" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/><detail><contact callsign="ALPHA-1"/></detail></event>"#;
        let event = Event::from_xml(xml).expect("should parse");
        assert_eq!(
            event.detail.unwrap().contact.unwrap().callsign.as_deref(),
            Some("ALPHA-1")
        );
    }

    #[test]
    fn round_trips_detail_with_contact_and_chat() {
        let xml = r#"<event version="2.0" uid="TEST-UID-3" type="b-t-f" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/><detail><contact callsign="ALPHA-1"/><__chat id="chat1" chatroom="All Chat Rooms" senderCallsign="ALPHA-1"><chatgrp id="chat1" uid0="UID-A" uid1="UID-B"/></__chat><remarks>hello</remarks></detail></event>"#;
        let event = Event::from_xml(xml).expect("should parse");
        let xml2 = event.to_xml().expect("should serialize");
        let reparsed = Event::from_xml(&xml2).expect("should reparse own output");
        assert_eq!(event, reparsed);

        let detail = event.detail.unwrap();
        assert_eq!(detail.remarks.unwrap().text, "hello");
        let chatgrp = detail.chat.unwrap().chatgrp.unwrap();
        let mut members = chatgrp.member_uids();
        members.sort();
        assert_eq!(members, vec!["UID-A", "UID-B"]);
    }

    /// `t-x-c-t` is the TAK ping, not chat (official
    /// `SubmissionService.controlMsgTypes`); GeoChat is `b-t-f`.
    #[test]
    fn pings_are_control_messages_not_chat() {
        let mut event = Event::from_xml(MINIMAL_EVENT).unwrap();
        assert!(!event.is_control());
        for control in [
            "t-b",
            "t-b-a",
            "t-b-c",
            "t-b-q",
            "t-x-c-f",
            "t-x-c-t",
            "t-x-c-t-r",
            "t-x-takp-q",
            "t-x-c-m",
            "t-x-c-i-e",
            "t-x-c-i-d",
        ] {
            event.cot_type = control.to_string();
            assert!(event.is_control(), "{control}");
            assert!(!event.is_chat(), "{control}");
        }
        event.cot_type = "T-X-C-T".to_string();
        assert!(
            event.is_control(),
            "matched case-insensitively, as official"
        );
        event.cot_type = "t-x-c-t-x".to_string();
        assert!(!event.is_control(), "exact types only");
        event.cot_type = "t-x-takp-v".to_string();
        assert!(
            !event.is_control(),
            "the server's own version announcement is not in the set"
        );
    }

    /// `StreamingEndpointRewriteFilter`: the first `/event/detail/marti`
    /// is removed from forwarded events; nothing else changes.
    #[test]
    fn marti_is_stripped_from_forwarded_events() {
        let xml = r#"<?xml version="1.0"?><event version="2.0" uid="u" type="b-t-f" how="h-g-i-g-o" time="t" start="t" stale="t"><point lat="1" lon="2" hae="0" ce="0" le="0"/><detail><__chat id="c" chatroom="Ops"/><marti><dest uid="A"/><dest mission="Ops"/></marti><remarks>hi</remarks></detail></event>"#;
        assert_eq!(
            strip_marti(xml),
            r#"<?xml version="1.0"?><event version="2.0" uid="u" type="b-t-f" how="h-g-i-g-o" time="t" start="t" stale="t"><point lat="1" lon="2" hae="0" ce="0" le="0"/><detail><__chat id="c" chatroom="Ops"/><remarks>hi</remarks></detail></event>"#
        );
        let empty = r#"<event version="2.0" uid="u" type="a" how="h" time="t" start="t" stale="t"><detail><marti/></detail></event>"#;
        assert_eq!(
            strip_marti(empty),
            r#"<event version="2.0" uid="u" type="a" how="h" time="t" start="t" stale="t"><detail></detail></event>"#
        );
        let nested = r#"<event version="2.0" uid="u" type="a" how="h" time="t" start="t" stale="t"><detail><link><marti/></link></detail></event>"#;
        assert!(
            matches!(strip_marti(nested), std::borrow::Cow::Borrowed(_)),
            "only /event/detail/marti"
        );
        let event = Event::from_xml(strip_declaration_for_test(xml)).unwrap();
        assert_eq!(event.dest_missions(), (vec!["Ops".to_string()], vec![]));
    }

    fn strip_declaration_for_test(xml: &str) -> &str {
        &xml[xml.find("<event").unwrap()..]
    }

    /// The official pong (`SubmissionService.sendPong`): uid `takPong`,
    /// times in `DateUtil.toCotTime` (whole seconds), stale 20 s later.
    #[test]
    fn the_pong_is_the_official_one() {
        assert_eq!(
            pong_xml(1_760_716_800_689),
            r#"<event version="2.0" uid="takPong" type="t-x-c-t-r" how="h-g-i-g-o" time="2025-10-17T16:00:00Z" start="2025-10-17T16:00:00Z" stale="2025-10-17T16:00:20Z"> <point ce="9999999" le="9999999" hae="0" lat="0" lon="0"/></event>"#
        );
        let pong = Event::from_xml(&pong_xml(0)).unwrap();
        assert_eq!(pong.cot_type, "t-x-c-t-r");
    }

    /// Real client traffic, shaped like ATAK/OmniTAK sends it.
    pub(crate) const ATAK_SA: &str = r#"<event version="2.0" uid="ANDROID-abc123" type="a-f-G-U-C" how="h-e" time="2026-09-29T12:00:00Z" start="2026-09-29T12:00:00Z" stale="2026-09-29T12:06:00Z"><point lat="53.25" lon="10.4" hae="12.0" ce="9.9" le="9999999.0"/><detail><takv os="34" version="5.6.0" device="GOOGLE PIXEL 10" platform="ATAK-CIV"/><contact endpoint="*:-1:stcp" callsign="ALPHA-1"/><uid Droid="ALPHA-1"/><precisionlocation altsrc="GPS" geopointsrc="GPS"/><__group role="Team Member" name="Cyan"/><status battery="88"/><track course="0.0" speed="0.0"/></detail></event>"#;
    pub(crate) const ATAK_CHAT: &str = r#"<event version="2.0" uid="GeoChat.ANDROID-abc123.All Chat Rooms.5f1e2d3c" type="b-t-f" how="h-g-i-g-o" time="2026-09-29T12:01:00Z" start="2026-09-29T12:01:00Z" stale="2026-09-30T12:01:00Z"><point lat="53.25" lon="10.4" hae="12.0" ce="9.9" le="9999999.0"/><detail><__chat parent="RootContactGroup" groupOwner="false" messageId="5f1e2d3c" chatroom="All Chat Rooms" id="All Chat Rooms" senderCallsign="ALPHA-1"><chatgrp uid0="ANDROID-abc123" uid1="All Chat Rooms" id="All Chat Rooms"/></__chat><link uid="ANDROID-abc123" type="a-f-G-U-C" relation="p-p"/><remarks source="BAO.F.ATAK.ANDROID-abc123" to="All Chat Rooms" time="2026-09-29T12:01:00Z">hello team</remarks></detail></event>"#;
    pub(crate) const ATAK_MARKER: &str = r#"<event version="2.0" uid="0d1c2b3a-4f5e-6d7c-8b9a-0f1e2d3c4b5a" type="a-h-G" how="h-g-i-g-o" time="2026-09-29T12:02:00Z" start="2026-09-29T12:02:00Z" stale="2026-10-29T12:02:00Z"><point lat="53.26" lon="10.41" hae="0.0" ce="9999999.0" le="9999999.0"/><detail><status readiness="true"/><archive/><link uid="ANDROID-abc123" production_time="2026-09-29T12:02:00Z" type="a-f-G-U-C" parent_callsign="ALPHA-1" relation="p-p"/><contact callsign="H.1"/><remarks/><archive/><usericon iconsetpath="COT_MAPPING_2525B/a-h/a-h-G"/><link uid="ANDROID-other" relation="c-c"/><color argb="-1"/></detail></event>"#;

    #[test]
    fn only_a_devices_own_report_counts_as_situational_awareness() {
        assert!(Event::from_xml(ATAK_SA).unwrap().is_situational_awareness());
        let chat = Event::from_xml(ATAK_CHAT).unwrap();
        assert!(!chat.is_situational_awareness());
        assert!(chat.is_chat(), "real GeoChat is b-t-f");
        let marker = Event::from_xml(ATAK_MARKER).unwrap();
        assert!(
            !marker.is_situational_awareness(),
            "a marker has a callsign but no endpoint"
        );
        assert!(
            !Event::from_xml(MINIMAL_EVENT)
                .unwrap()
                .is_situational_awareness()
        );
    }

    /// `<link>` elements interleaved with other detail children still parse
    /// (quick-xml `overlapped-lists`), and only `p-p` links name a producer.
    #[test]
    fn producer_uids_come_from_p_p_links_even_when_interleaved() {
        assert_eq!(
            Event::from_xml(ATAK_MARKER).unwrap().producer_uids(),
            vec!["ANDROID-abc123"]
        );
        assert_eq!(
            Event::from_xml(ATAK_CHAT).unwrap().producer_uids(),
            vec!["ANDROID-abc123"]
        );
        assert!(Event::from_xml(ATAK_SA).unwrap().producer_uids().is_empty());
    }

    #[test]
    fn addressed_uids_unions_marti_dest_and_chatgrp() {
        let xml = r#"<event version="2.0" uid="u" type="b-t-f" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/><detail><marti><dest uid="UID-DIRECT"/></marti><__chat id="c" chatroom="Team"><chatgrp id="c" uid0="UID-TEAM-A"/></__chat></detail></event>"#;
        let event = Event::from_xml(xml).unwrap();
        let mut uids = event.addressed_uids().unwrap();
        uids.sort();
        assert_eq!(uids, vec!["UID-DIRECT", "UID-TEAM-A"]);
    }

    /// A real ATAK "All Chat Rooms" message is a broadcast: its chatgrp
    /// lists the sender and the room name, not recipients.
    #[test]
    fn all_chat_rooms_messages_are_broadcast() {
        assert!(
            Event::from_xml(ATAK_CHAT)
                .unwrap()
                .addressed_uids()
                .is_none()
        );
    }

    #[test]
    fn addressed_uids_is_none_without_any_addressing() {
        let event = Event::from_xml(MINIMAL_EVENT).unwrap();
        assert!(event.addressed_uids().is_none());
    }

    /// TC-CHAT-05: a GeoChat event missing `<remarks>` -- a real client is
    /// known to send this -- must still parse cleanly.
    #[test]
    fn parses_chat_missing_remarks() {
        let xml = r#"<event version="2.0" uid="u" type="b-t-f" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/><detail><__chat id="c" chatroom="All Chat Rooms"/></detail></event>"#;
        let event = Event::from_xml(xml).expect("should parse even without remarks");
        assert!(event.detail.unwrap().remarks.is_none());
    }

    #[test]
    fn rejects_missing_required_attribute() {
        // `uid` is missing entirely.
        let xml = r#"<event version="2.0" type="a-f-G-U-C" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/></event>"#;
        assert!(Event::from_xml(xml).is_err());
    }

    #[test]
    fn rejects_malformed_xml() {
        let xml = r#"<event version="2.0" uid="TEST-UID-3"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/>"#; // unclosed <event>
        assert!(Event::from_xml(xml).is_err());
    }

    #[test]
    fn accepts_stale_before_time() {
        // The official server does not appear to reject this at parse time
        // per wiki/MicroTAK-Test-Plan.md TC-COT-VALID-03 — `stale` is a
        // client-side display hint, not a server-enforced ordering rule.
        // MicroTAK's parser mirrors that: parsing succeeds, and any policy
        // decision about "already-stale on arrival" belongs to a later
        // validation/acceptance layer, not this module.
        let xml = r#"<event version="2.0" uid="TEST-UID-4" type="a-f-G-U-C" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2020-01-01T00:00:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/></event>"#;
        assert!(Event::from_xml(xml).is_ok());
    }
}
