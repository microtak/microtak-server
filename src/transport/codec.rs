//! Incremental CoT XML stream decoder.
//!
//! Real ATAK clients send every CoT event on a persistent stream as its own
//! complete XML document (`<?xml version="1.0"?><event>...</event>`), with
//! no framing/delimiter between them — a receiver has to behave like a
//! streaming XML parser, tolerating a declaration (and an event) split
//! across arbitrary TCP read boundaries. See `docs/TEST-PLAN.md` §2 for the
//! full list of test cases this module is built against (TC-STREAM-01..05).
//!
//! # Design
//!
//! This decoder does not attempt full streaming XML well-formedness
//! checking. It scans for two top-level shapes only — a `<?xml ...?>`
//! declaration and an `<event>...</event>` document — using literal
//! substring search for the closing `</event>` tag, which is safe because a
//! CoT `<event>` never nests another `<event>` inside itself. Once a
//! complete `<event>...</event>` slice is isolated, it's handed to
//! [`crate::cot::Event::from_xml`] for real parsing.
//!
//! **Known simplification**: this means a genuinely malformed *interior* of
//! an otherwise well-bounded event (e.g. a mismatched inner tag, an
//! unescaped `&`) is treated the same as a semantically-invalid-but-
//! well-formed event (TC-STREAM-05: skip and continue), rather than as a
//! fatal stream error (TC-STREAM-04). Only leading bytes that aren't a
//! prefix of either `<?xml` or `<event` are treated as a fatal stream
//! error. A stricter implementation would need a real incremental XML
//! well-formedness scanner; revisit if this proves too lenient in practice.

use std::fmt;

use thiserror::Error;

use crate::cot::{CotError, Event};

const XML_DECL_PREFIX: &[u8] = b"<?xml";
const EVENT_PREFIX: &[u8] = b"<event";
const EVENT_CLOSE: &[u8] = b"</event>";

/// Default cap on how many bytes may be buffered while waiting for a
/// closing `</event>` tag, before giving up and treating it as a stream
/// error. Guards against unbounded memory growth from a misbehaving/hostile
/// client that never closes an event (see `docs/TEST-PLAN.md` TC-LIMIT-01 /
/// TC-COT-09).
pub const DEFAULT_MAX_BUFFERED: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("unexpected byte(s) in CoT stream (not an XML declaration or <event>): {0:?}")]
    UnexpectedContent(Vec<u8>),
    #[error("buffered {buffered} bytes waiting for a closing tag, exceeding the {limit}-byte limit")]
    TooLarge { buffered: usize, limit: usize },
}

/// One decoded unit of stream progress.
#[derive(Debug)]
pub enum DecodedItem {
    /// A complete, valid CoT event.
    Event(Event),
    /// A complete, well-bounded `<event>...</event>` document that failed to
    /// parse as a valid CoT event (missing required attribute, malformed
    /// inner XML, etc). Per TC-STREAM-05, this does NOT terminate the
    /// stream — the connection stays open and decoding continues.
    Skipped { xml: String, error: CotError },
}

impl fmt::Display for DecodedItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodedItem::Event(e) => write!(f, "Event(uid={})", e.uid),
            DecodedItem::Skipped { error, .. } => write!(f, "Skipped({error})"),
        }
    }
}

/// Incremental decoder: feed it raw bytes as they arrive off the wire, get
/// back zero or more [`DecodedItem`]s. Transport-agnostic — has no
/// knowledge of sockets, TLS, or any particular I/O type, which is what
/// makes it directly unit-testable with plain byte slices.
pub struct StreamDecoder {
    buf: Vec<u8>,
    max_buffered: usize,
}

impl Default for StreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamDecoder {
    pub fn new() -> Self {
        Self::with_max_buffered(DEFAULT_MAX_BUFFERED)
    }

    pub fn with_max_buffered(max_buffered: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_buffered,
        }
    }

    /// Feed newly-received bytes and drain as many complete items as the
    /// buffer now contains. Returns `Err` only for a fatal, stream-ending
    /// condition (TC-STREAM-04) — the caller should disconnect the client.
    /// A per-event semantic error is reported as `Ok(DecodedItem::Skipped)`
    /// and does not end the stream (TC-STREAM-05).
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<DecodedItem>, StreamError> {
        self.buf.extend_from_slice(data);
        let mut items = Vec::new();

        loop {
            trim_leading_whitespace(&mut self.buf);
            if self.buf.is_empty() {
                break;
            }

            match classify(&self.buf) {
                Shape::Declaration => {
                    if let Some(end) = find(&self.buf, b"?>") {
                        self.buf.drain(..end + 2);
                        continue;
                    }
                    self.check_size_limit()?;
                    break; // need more data to complete the declaration
                }
                Shape::Event => {
                    if let Some(end) = find(&self.buf, EVENT_CLOSE) {
                        let xml_bytes: Vec<u8> =
                            self.buf.drain(..end + EVENT_CLOSE.len()).collect();
                        let xml = String::from_utf8_lossy(&xml_bytes).into_owned();
                        match Event::from_xml(&xml) {
                            Ok(event) => items.push(DecodedItem::Event(event)),
                            Err(error) => items.push(DecodedItem::Skipped { xml, error }),
                        }
                        continue;
                    }
                    self.check_size_limit()?;
                    break; // need more data to complete the event
                }
                Shape::AmbiguousPrefix => {
                    // Buffer is a strict prefix of "<?xml" or "<event" so
                    // far (e.g. a declaration/tag split byte-by-byte across
                    // reads) — wait for more data before deciding.
                    self.check_size_limit()?;
                    break;
                }
                Shape::Unknown => {
                    let bad = std::mem::take(&mut self.buf);
                    return Err(StreamError::UnexpectedContent(bad));
                }
            }
        }

        Ok(items)
    }

    fn check_size_limit(&self) -> Result<(), StreamError> {
        if self.buf.len() > self.max_buffered {
            Err(StreamError::TooLarge {
                buffered: self.buf.len(),
                limit: self.max_buffered,
            })
        } else {
            Ok(())
        }
    }
}

enum Shape {
    Declaration,
    Event,
    AmbiguousPrefix,
    Unknown,
}

fn classify(buf: &[u8]) -> Shape {
    if starts_with(buf, XML_DECL_PREFIX) {
        return Shape::Declaration;
    }
    if starts_with(buf, EVENT_PREFIX) {
        return Shape::Event;
    }
    if is_strict_prefix_of(buf, XML_DECL_PREFIX) || is_strict_prefix_of(buf, EVENT_PREFIX) {
        return Shape::AmbiguousPrefix;
    }
    Shape::Unknown
}

fn starts_with(buf: &[u8], needle: &[u8]) -> bool {
    buf.len() >= needle.len() && &buf[..needle.len()] == needle
}

/// True if `buf` is shorter than `needle` but matches it byte-for-byte so
/// far — i.e. `buf` might still turn into `needle` with more data.
fn is_strict_prefix_of(buf: &[u8], needle: &[u8]) -> bool {
    buf.len() < needle.len() && needle.starts_with(buf)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn trim_leading_whitespace(buf: &mut Vec<u8>) {
    let end = buf
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(buf.len());
    buf.drain(..end);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_xml(uid: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><event version="2.0" uid="{uid}" type="a-f-G-U-C" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/></event>"#
        )
    }

    #[test]
    fn tc_stream_01_decodes_multiple_concatenated_events_with_declarations() {
        let mut decoder = StreamDecoder::new();
        let stream = format!("{}{}", event_xml("A"), event_xml("B"));
        let items = decoder.feed(stream.as_bytes()).expect("no stream error");
        assert_eq!(items.len(), 2);
        assert!(matches!(&items[0], DecodedItem::Event(e) if e.uid == "A"));
        assert!(matches!(&items[1], DecodedItem::Event(e) if e.uid == "B"));
    }

    #[test]
    fn tc_stream_02_handles_declaration_split_across_feeds() {
        let mut decoder = StreamDecoder::new();
        let full = event_xml("SPLIT-DECL");
        // Split mid-declaration: "<?xm" | "l version=...?><event ...>"
        let (first, second) = full.split_at(4);
        assert!(decoder.feed(first.as_bytes()).unwrap().is_empty());
        let items = decoder.feed(second.as_bytes()).unwrap();
        assert_eq!(items.len(), 1);
        assert!(matches!(&items[0], DecodedItem::Event(e) if e.uid == "SPLIT-DECL"));
    }

    #[test]
    fn tc_stream_03_handles_event_split_at_arbitrary_byte_boundary() {
        let mut decoder = StreamDecoder::new();
        let full = event_xml("SPLIT-EVENT");
        // Split well inside the <event> element, not at a tag boundary.
        let midpoint = full.len() / 2;
        let (first, second) = full.split_at(midpoint);
        assert!(decoder.feed(first.as_bytes()).unwrap().is_empty());
        let items = decoder.feed(second.as_bytes()).unwrap();
        assert_eq!(items.len(), 1);
        assert!(matches!(&items[0], DecodedItem::Event(e) if e.uid == "SPLIT-EVENT"));
    }

    #[test]
    fn tc_stream_03b_handles_byte_by_byte_feed() {
        let mut decoder = StreamDecoder::new();
        let full = event_xml("BYTE-BY-BYTE");
        let mut items = Vec::new();
        for byte in full.as_bytes() {
            items.extend(decoder.feed(&[*byte]).unwrap());
        }
        assert_eq!(items.len(), 1);
        assert!(matches!(&items[0], DecodedItem::Event(e) if e.uid == "BYTE-BY-BYTE"));
    }

    #[test]
    fn tc_stream_04_rejects_unexpected_leading_content() {
        let mut decoder = StreamDecoder::new();
        let err = decoder
            .feed(b"this is not a CoT stream at all")
            .expect_err("should be a fatal stream error");
        assert!(matches!(err, StreamError::UnexpectedContent(_)));
    }

    #[test]
    fn tc_stream_05_skips_semantically_invalid_event_and_keeps_decoding() {
        let mut decoder = StreamDecoder::new();
        // Missing required `uid` attribute -- well-formed XML, invalid CoT.
        let bad = r#"<event version="2.0" type="a-f-G-U-C" how="m-g" time="2026-09-21T12:00:00Z" start="2026-09-21T12:00:00Z" stale="2026-09-21T12:05:00Z"><point lat="53.25" lon="10.4" hae="10.0" ce="5.0" le="3.0"/></event>"#;
        let stream = format!("{bad}{}", event_xml("AFTER-BAD"));
        let items = decoder.feed(stream.as_bytes()).unwrap();
        assert_eq!(items.len(), 2);
        assert!(matches!(&items[0], DecodedItem::Skipped { .. }));
        assert!(matches!(&items[1], DecodedItem::Event(e) if e.uid == "AFTER-BAD"));
    }

    #[test]
    fn enforces_max_buffered_size_tc_limit_01() {
        let mut decoder = StreamDecoder::with_max_buffered(16);
        // A declaration that never closes, larger than the 16-byte cap.
        let err = decoder
            .feed(b"<?xml version=\"1.0\" this never closes")
            .expect_err("should hit the size limit");
        assert!(matches!(err, StreamError::TooLarge { .. }));
    }

    #[test]
    fn tolerates_whitespace_between_events() {
        let mut decoder = StreamDecoder::new();
        let stream = format!("{}\n\n  {}", event_xml("WS-A"), event_xml("WS-B"));
        let items = decoder.feed(stream.as_bytes()).unwrap();
        assert_eq!(items.len(), 2);
    }
}
