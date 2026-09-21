//! Cursor-on-Target (CoT) event model: XML parsing/serialization.
//!
//! Covers the `<event>` envelope and `<point>` as defined in
//! `wiki/ATAK-Communications-Architecture.md` (§1). `detail` is treated as an
//! opaque raw XML blob for now — no sub-element modeling yet (chat/group/status/etc).
//! See `wiki/EdgeTAK-Test-Plan.md` for the full CoT test-case catalog this module
//! is meant to satisfy.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CotError {
    #[error("CoT XML (de)serialization failed: {0}")]
    Xml(#[from] quick_xml::DeError),
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
    /// Raw inner XML of `<detail>...</detail>`, unparsed. `None` if the event
    /// has no detail block at all.
    #[serde(rename = "detail", skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<RawDetail>,
}

/// Placeholder for the open-schema `<detail>` container. Only a raw string
/// passthrough today; see `wiki/EdgeTAK-Test-Plan.md` for planned sub-element
/// modeling (contact, __chat, group, status, precisionlocation, __geofence).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RawDetail {
    #[serde(rename = "$text", default)]
    pub raw: String,
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

impl Event {
    /// Parse a single `<event>...</event>` XML document.
    ///
    /// Does NOT handle stream framing (multiple concatenated events with no
    /// separator) — that's the transport layer's job (see `wiki/EdgeTAK-Test-Plan.md`
    /// §Transport, TC-COT-STREAM-*). This only parses one already-isolated event.
    pub fn from_xml(xml: &str) -> Result<Self, CotError> {
        Ok(quick_xml::de::from_str(xml)?)
    }

    /// Serialize back to a CoT XML `<event>` document.
    pub fn to_xml(&self) -> Result<String, CotError> {
        Ok(quick_xml::se::to_string(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn preserves_detail_passthrough() {
        let xml = r#"<event version="2.0" uid="TEST-UID-2" type="a-f-G-U-C" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/><detail><contact callsign="ALPHA-1"/></detail></event>"#;
        let event = Event::from_xml(xml).expect("should parse");
        assert!(event.detail.is_some());
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
        // per wiki/EdgeTAK-Test-Plan.md TC-COT-VALID-03 — `stale` is a
        // client-side display hint, not a server-enforced ordering rule.
        // EdgeTAK's parser mirrors that: parsing succeeds, and any policy
        // decision about "already-stale on arrival" belongs to a later
        // validation/acceptance layer, not this module.
        let xml = r#"<event version="2.0" uid="TEST-UID-4" type="a-f-G-U-C" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2020-01-01T00:00:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/></event>"#;
        assert!(Event::from_xml(xml).is_ok());
    }
}
