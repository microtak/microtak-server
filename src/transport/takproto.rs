//! TAK Protocol version 1: streaming protobuf on the CoT TLS port, as the
//! official TAK Server speaks it on a `protocol="tls"` (`COTPROTOTLS`)
//! input (`NioNettyTlsServerHandler`, `StreamingProtoBufOrCoTProtocol`,
//! `StreamingProtoBufHelper` @ 5.7-RELEASE-14).
//!
//! After the TLS session is authenticated the server announces
//! `t-x-takp-v`; a client answering `t-x-takp-q` with version `1` gets
//! `t-x-takp-r status='true'` and from then on both directions are frames
//! of `0xbf`, a varint length and a `TakMessage`.

use prost::Message;

/// `StreamingProtoBufHelper.MAGIC`.
pub const MAGIC: u8 = 0xbf;
/// `StreamingProtoBufHelper.TAK_PROTO_VERSION`.
pub const TAK_PROTO_VERSION: &str = "1";
/// `StreamingProtoBufProtocol.MAX_SIZE`: larger outbound messages become a
/// file transfer.
pub const MAX_SIZE: usize = 65536;

#[derive(Clone, PartialEq, Message)]
pub struct TakMessage {
    #[prost(message, optional, tag = "1")]
    pub tak_control: Option<TakControl>,
    #[prost(message, optional, tag = "2")]
    pub cot_event: Option<CotEvent>,
    #[prost(uint64, tag = "3")]
    pub submission_time: u64,
    #[prost(uint64, tag = "4")]
    pub creation_time: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct TakControl {
    #[prost(uint32, tag = "1")]
    pub min_proto_version: u32,
    #[prost(uint32, tag = "2")]
    pub max_proto_version: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct CotEvent {
    #[prost(string, tag = "1")]
    pub r#type: String,
    #[prost(string, tag = "2")]
    pub access: String,
    #[prost(string, tag = "3")]
    pub qos: String,
    #[prost(string, tag = "4")]
    pub opex: String,
    #[prost(string, tag = "16")]
    pub caveat: String,
    #[prost(string, tag = "17")]
    pub releaseable_to: String,
    #[prost(string, tag = "5")]
    pub uid: String,
    #[prost(uint64, tag = "6")]
    pub send_time: u64,
    #[prost(uint64, tag = "7")]
    pub start_time: u64,
    #[prost(uint64, tag = "8")]
    pub stale_time: u64,
    #[prost(string, tag = "9")]
    pub how: String,
    #[prost(double, tag = "10")]
    pub lat: f64,
    #[prost(double, tag = "11")]
    pub lon: f64,
    #[prost(double, tag = "12")]
    pub hae: f64,
    #[prost(double, tag = "13")]
    pub ce: f64,
    #[prost(double, tag = "14")]
    pub le: f64,
    #[prost(message, optional, tag = "15")]
    pub detail: Option<Detail>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Detail {
    #[prost(string, tag = "1")]
    pub xml_detail: String,
    #[prost(message, optional, tag = "2")]
    pub contact: Option<Contact>,
    #[prost(message, optional, tag = "3")]
    pub group: Option<Group>,
    #[prost(message, optional, tag = "4")]
    pub precision_location: Option<PrecisionLocation>,
    #[prost(message, optional, tag = "5")]
    pub status: Option<Status>,
    #[prost(message, optional, tag = "6")]
    pub takv: Option<Takv>,
    #[prost(message, optional, tag = "7")]
    pub track: Option<Track>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Contact {
    #[prost(string, tag = "1")]
    pub endpoint: String,
    #[prost(string, tag = "2")]
    pub callsign: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Group {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub role: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct PrecisionLocation {
    #[prost(string, tag = "1")]
    pub geopointsrc: String,
    #[prost(string, tag = "2")]
    pub altsrc: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Status {
    #[prost(uint32, tag = "1")]
    pub battery: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct Takv {
    #[prost(string, tag = "1")]
    pub device: String,
    #[prost(string, tag = "2")]
    pub platform: String,
    #[prost(string, tag = "3")]
    pub os: String,
    #[prost(string, tag = "4")]
    pub version: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Track {
    #[prost(double, tag = "1")]
    pub speed: f64,
    #[prost(double, tag = "2")]
    pub course: f64,
}

// --- framing ------------------------------------------------------------------

/// `convertGeneratedMessageV3ToProtoBufBytes`: magic, varint size, message.
pub fn frame(msg: &TakMessage) -> Vec<u8> {
    let body = msg.encode_to_vec();
    let mut out = Vec::with_capacity(body.len() + 6);
    out.push(MAGIC);
    prost::encoding::encode_varint(body.len() as u64, &mut out);
    out.extend_from_slice(&body);
    out
}

#[derive(Debug, thiserror::Error)]
#[error("unparseable TAK protocol message: {0}")]
pub struct FrameError(#[from] prost::DecodeError);

/// `convertAndSubmitProtoBufBytesAsCot`'s parser: a frame split across
/// reads is kept for the next one; a read whose next byte isn't the magic
/// byte is dropped from there; an unparseable message is an error (the
/// official handler force-closes the connection).
#[derive(Default)]
pub struct FrameDecoder {
    leftovers: Vec<u8>,
}

impl FrameDecoder {
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<TakMessage>, FrameError> {
        let mut buf = std::mem::take(&mut self.leftovers);
        buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < buf.len() {
            if buf[pos] != MAGIC {
                tracing::warn!(
                    byte = buf[pos],
                    "TAK protocol: no magic byte, dropping the rest of this read"
                );
                return Ok(out);
            }
            let start = pos;
            pos += 1;
            // readSize: 7 bits per byte, low group first.
            let (mut size, mut shift, mut complete) = (0usize, 0u32, false);
            while pos < buf.len() {
                let b = buf[pos];
                pos += 1;
                size |= ((b & 0x7f) as usize) << shift;
                if b & 0x80 == 0 {
                    complete = true;
                    break;
                }
                shift += 7;
            }
            if !complete || buf.len() - pos < size {
                self.leftovers = buf[start..].to_vec();
                return Ok(out);
            }
            out.push(TakMessage::decode(&buf[pos..pos + size])?);
            pos += size;
        }
        Ok(out)
    }
}

// --- a minimal dom4j-like tree ------------------------------------------------

#[derive(Debug, Clone)]
enum Node {
    Element(Element),
    Text(String),
    CData(String),
    Comment(String),
}

#[derive(Debug, Clone, Default)]
struct Element {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
}

impl Element {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn element(&self, name: &str) -> Option<&Element> {
        self.children.iter().find_map(|n| match n {
            Node::Element(e) if e.name == name => Some(e),
            _ => None,
        })
    }

    fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    fn remove_first(&mut self, name: &str) {
        if let Some(i) = self
            .children
            .iter()
            .position(|n| matches!(n, Node::Element(e) if e.name == name))
        {
            self.children.remove(i);
        }
    }

    /// dom4j `asXML()`: double-quoted attributes, `<x/>` when empty.
    fn as_xml(&self, out: &mut String) {
        out.push('<');
        out.push_str(&self.name);
        for (k, v) in &self.attrs {
            out.push_str(&format!(" {k}=\"{}\"", escape_attr(v)));
        }
        if self.children.is_empty() {
            out.push_str("/>");
            return;
        }
        out.push('>');
        for child in &self.children {
            match child {
                Node::Element(e) => e.as_xml(out),
                Node::Text(t) => out.push_str(&escape_text(t)),
                Node::CData(t) => out.push_str(&format!("<![CDATA[{t}]]>")),
                Node::Comment(t) => out.push_str(&format!("<!--{t}-->")),
            }
        }
        out.push_str(&format!("</{}>", self.name));
    }
}

fn escape_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attr(s: &str) -> String {
    escape_text(s).replace('"', "&quot;")
}

fn parse_root(xml: &str) -> Option<Element> {
    use quick_xml::events::Event as X;
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut stack: Vec<Element> = Vec::new();
    let element = |e: &quick_xml::events::BytesStart| -> Option<Element> {
        let mut el = Element {
            name: String::from_utf8_lossy(e.name().as_ref()).into_owned(),
            ..Default::default()
        };
        for a in e.attributes() {
            let a = a.ok()?;
            let value = a
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .ok()?
                .into_owned();
            el.attrs
                .push((String::from_utf8_lossy(a.key.as_ref()).into_owned(), value));
        }
        Some(el)
    };
    loop {
        match reader.read_event().ok()? {
            X::Start(e) => stack.push(element(&e)?),
            X::Empty(e) => {
                let el = element(&e)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(el)),
                    None => return Some(el),
                }
            }
            X::End(_) => {
                let el = stack.pop()?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(el)),
                    None => return Some(el),
                }
            }
            X::Text(t) => {
                if let Some(parent) = stack.last_mut() {
                    parent
                        .children
                        .push(Node::Text(t.decode().ok()?.into_owned()));
                }
            }
            X::GeneralRef(r) => {
                // Entity references inside text: resolved like a parser would.
                if let Some(parent) = stack.last_mut() {
                    let name = String::from_utf8_lossy(&r).into_owned();
                    let text = match name.as_str() {
                        "amp" => "&".to_string(),
                        "lt" => "<".to_string(),
                        "gt" => ">".to_string(),
                        "quot" => "\"".to_string(),
                        "apos" => "'".to_string(),
                        n if n.starts_with("#x") => u32::from_str_radix(&n[2..], 16)
                            .ok()
                            .and_then(char::from_u32)?
                            .to_string(),
                        n if n.starts_with('#') => n[1..]
                            .parse::<u32>()
                            .ok()
                            .and_then(char::from_u32)?
                            .to_string(),
                        _ => return None,
                    };
                    match parent.children.last_mut() {
                        Some(Node::Text(prev)) => prev.push_str(&text),
                        _ => parent.children.push(Node::Text(text)),
                    }
                }
            }
            X::CData(t) => {
                if let Some(parent) = stack.last_mut() {
                    parent
                        .children
                        .push(Node::CData(String::from_utf8_lossy(&t).into_owned()));
                }
            }
            X::Comment(t) => {
                if let Some(parent) = stack.last_mut() {
                    parent
                        .children
                        .push(Node::Comment(String::from_utf8_lossy(&t).into_owned()));
                }
            }
            X::Eof => return None,
            _ => {}
        }
    }
}

// --- conversion ---------------------------------------------------------------

/// `DateUtil.millisFromCotTimeStr`: with or without fractional seconds.
fn cot_millis(s: &str) -> u64 {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|t| (t.unix_timestamp_nanos() / 1_000_000).max(0) as u64)
        .unwrap_or(0)
}

/// `NumericUtil.parseDoubleOrDefault`.
fn double_or(s: Option<&str>, default: f64) -> f64 {
    s.and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

/// `StreamingProtoBufHelper.cot2protoBuf`; `received_ms` is the server's
/// creation/submission time of the message.
pub fn cot_to_proto(xml: &str, received_ms: u64) -> Option<TakMessage> {
    let root = parse_root(xml)?;
    let s = |k: &str| root.attr(k).unwrap_or("").to_string();
    let mut event = CotEvent {
        r#type: s("type"),
        uid: s("uid"),
        how: s("how"),
        send_time: root.attr("time").map(cot_millis).unwrap_or(0),
        start_time: root.attr("start").map(cot_millis).unwrap_or(0),
        stale_time: root.attr("stale").map(cot_millis).unwrap_or(0),
        caveat: s("caveat"),
        releaseable_to: s("releasableTo"),
        opex: s("opex"),
        qos: s("qos"),
        access: s("access"),
        ..Default::default()
    };
    if let Some(point) = root.element("point") {
        event.lat = double_or(point.attr("lat"), 0.0);
        event.lon = double_or(point.attr("lon"), 0.0);
        event.hae = double_or(point.attr("hae"), 0.0);
        event.ce = double_or(point.attr("ce"), 999_999.0);
        event.le = double_or(point.attr("le"), 999_999.0);
    }
    if let Some(detail) = root.element("detail") {
        let mut detail = detail.clone();
        let mut d = Detail::default();
        let exactly = |e: &Element, names: &[&str]| {
            e.attrs.len() == names.len() && names.iter().all(|n| e.attr(n).is_some())
        };
        if let Some(c) = detail.element("contact").cloned()
            && let Some(callsign) = c.attr("callsign")
        {
            let endpoint = c.attr("endpoint");
            if (endpoint.is_none() && c.attrs.len() == 1)
                || (endpoint.is_some() && c.attrs.len() == 2)
            {
                d.contact = Some(Contact {
                    callsign: callsign.into(),
                    endpoint: endpoint.unwrap_or("").into(),
                });
                detail.remove_first("contact");
            }
        }
        if let Some(g) = detail.element("__group").cloned()
            && exactly(&g, &["name", "role"])
        {
            d.group = Some(Group {
                name: g.attr("name").unwrap_or("").into(),
                role: g.attr("role").unwrap_or("").into(),
            });
            detail.remove_first("__group");
        }
        if let Some(p) = detail.element("precisionlocation").cloned()
            && exactly(&p, &["geopointsrc", "altsrc"])
        {
            d.precision_location = Some(PrecisionLocation {
                geopointsrc: p.attr("geopointsrc").unwrap_or("").into(),
                altsrc: p.attr("altsrc").unwrap_or("").into(),
            });
            detail.remove_first("precisionlocation");
        }
        if let Some(st) = detail.element("status").cloned()
            && exactly(&st, &["battery"])
        {
            let battery = st
                .attr("battery")
                .and_then(|b| b.trim().parse::<i64>().ok())
                .unwrap_or(0);
            d.status = Some(Status {
                battery: battery as u32,
            });
            detail.remove_first("status");
        }
        if let Some(t) = detail.element("takv").cloned()
            && exactly(&t, &["device", "platform", "os", "version"])
        {
            let a = |k: &str| t.attr(k).unwrap_or("").to_string();
            d.takv = Some(Takv {
                device: a("device"),
                platform: a("platform"),
                os: a("os"),
                version: a("version"),
            });
            detail.remove_first("takv");
        }
        if let Some(t) = detail.element("track").cloned()
            && exactly(&t, &["speed", "course"])
        {
            d.track = Some(Track {
                speed: double_or(t.attr("speed"), 0.0),
                course: double_or(t.attr("course"), 0.0),
            });
            detail.remove_first("track");
        }
        let mut rest = String::new();
        for e in detail.elements() {
            e.as_xml(&mut rest);
        }
        d.xml_detail = rest;
        event.detail = Some(d);
    }
    Some(TakMessage {
        cot_event: Some(event),
        submission_time: received_ms,
        creation_time: received_ms,
        ..Default::default()
    })
}

/// Java's `Double.toString`.
pub fn java_double(v: f64) -> String {
    if v == 0.0 {
        return if v.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        };
    }
    let abs = v.abs();
    if (1e-3..1e7).contains(&abs) {
        let s = format!("{v}");
        if s.contains('.') { s } else { format!("{s}.0") }
    } else {
        let s = format!("{v:e}");
        let (mantissa, exp) = s.split_once('e').unwrap_or((&s, "0"));
        let mantissa = if mantissa.contains('.') {
            mantissa.to_string()
        } else {
            format!("{mantissa}.0")
        };
        format!("{mantissa}E{exp}")
    }
}

/// `StreamingProtoBufHelper.proto2cot`, serialized as dom4j does
/// (`CotEventContainer.asXml`).
pub fn proto_to_cot(msg: &TakMessage) -> Option<String> {
    let e = msg.cot_event.as_ref()?;
    let time = |ms: u64| crate::cot::cot_time(ms as i64);
    let mut event = Element {
        name: "event".into(),
        ..Default::default()
    };
    let attr = |el: &mut Element, k: &str, v: String| el.attrs.push((k.into(), v));
    attr(&mut event, "version", "2.0".into());
    attr(&mut event, "uid", e.uid.clone());
    attr(&mut event, "type", e.r#type.clone());
    attr(&mut event, "how", e.how.clone());
    attr(&mut event, "time", time(e.send_time));
    attr(&mut event, "start", time(e.start_time));
    attr(&mut event, "stale", time(e.stale_time));
    for (k, v) in [
        ("caveat", &e.caveat),
        ("releasableTo", &e.releaseable_to),
        ("opex", &e.opex),
        ("qos", &e.qos),
        ("access", &e.access),
    ] {
        if !v.is_empty() {
            attr(&mut event, k, v.clone());
        }
    }
    let mut point = Element {
        name: "point".into(),
        ..Default::default()
    };
    for (k, v) in [
        ("lat", e.lat),
        ("lon", e.lon),
        ("hae", e.hae),
        ("ce", e.ce),
        ("le", e.le),
    ] {
        attr(&mut point, k, java_double(v));
    }
    event.children.push(Node::Element(point));
    if let Some(d) = &e.detail {
        let mut detail = Element {
            name: "detail".into(),
            ..Default::default()
        };
        let mut add = |name: &str, attrs: Vec<(&str, String)>| {
            detail.children.push(Node::Element(Element {
                name: name.into(),
                attrs: attrs.into_iter().map(|(k, v)| (k.into(), v)).collect(),
                children: vec![],
            }));
        };
        if let Some(c) = &d.contact {
            let mut a = vec![("callsign", c.callsign.clone())];
            if !c.endpoint.is_empty() {
                a.push(("endpoint", c.endpoint.clone()));
            }
            add("contact", a);
        }
        if let Some(g) = &d.group {
            add(
                "__group",
                vec![("name", g.name.clone()), ("role", g.role.clone())],
            );
        }
        if let Some(p) = &d.precision_location {
            add(
                "precisionlocation",
                vec![
                    ("geopointsrc", p.geopointsrc.clone()),
                    ("altsrc", p.altsrc.clone()),
                ],
            );
        }
        if let Some(st) = &d.status {
            add("status", vec![("battery", (st.battery as i32).to_string())]);
        }
        if let Some(t) = &d.takv {
            add(
                "takv",
                vec![
                    ("device", t.device.clone()),
                    ("platform", t.platform.clone()),
                    ("os", t.os.clone()),
                    ("version", t.version.clone()),
                ],
            );
        }
        if let Some(t) = &d.track {
            add(
                "track",
                vec![
                    ("speed", java_double(t.speed)),
                    ("course", java_double(t.course)),
                ],
            );
        }
        if !d.xml_detail.is_empty() {
            let wrapped = parse_root(&format!("<detail>{}</detail>", d.xml_detail))?;
            for sub in wrapped.elements() {
                if [
                    "contact",
                    "__group",
                    "precisionlocation",
                    "status",
                    "takv",
                    "track",
                ]
                .contains(&sub.name.as_str())
                {
                    detail.remove_first(&sub.name);
                }
                detail.children.push(Node::Element(sub.clone()));
            }
        }
        event.children.push(Node::Element(detail));
    }
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    event.as_xml(&mut out);
    Some(out)
}

/// `Constants.XML_HEADER`.
pub const XML_HEADER: &str = "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>";

/// An `<event>` without any XML declaration before it.
pub fn event_body(xml: &str) -> &str {
    xml.find("<event").map(|i| &xml[i..]).unwrap_or(xml)
}

/// `StreamingProtoBufProtocol.convertCotToProtoBufBytes`: the framed
/// message; one over [`MAX_SIZE`] becomes a file transfer pointing at
/// `/Marti/api/cot/xml/{uid}` (`createFileTransferRequest`, `None` without
/// a server URL, as the official server needs `takServerHost`).
pub fn encode_outbound(xml: &str, received_ms: u64, cot_url_base: Option<&str>) -> Option<Vec<u8>> {
    let msg = cot_to_proto(xml, received_ms)?;
    if msg.encoded_len() <= MAX_SIZE {
        return Some(frame(&msg));
    }
    let base = cot_url_base?;
    let uid = msg
        .cot_event
        .as_ref()
        .map(|e| e.uid.clone())
        .unwrap_or_default();
    let data = format!("{XML_HEADER}{}", event_body(xml));
    let hash = crate::content_store::hex_sha256(data.as_bytes());
    let url = format!("{base}/Marti/api/cot/xml/{uid}");
    let now = received_ms as i64;
    let (t, stale) = (
        crate::cot::cot_time(now),
        crate::cot::cot_time(now + 100_000),
    );
    let transfer = format!(
        "{XML_HEADER}<event version='2.0' uid='{hash}' type='b-f-t-r' time='{t}' start='{t}' stale='{stale}' how='h-e'><point lat='0.0' lon='0.0' hae='9999999.0' ce='9999999' le='9999999' /><detail><fileshare sha256='{hash}' senderUid='{hash}' name='{uid}.cot' filename='{uid}.cot' senderUrl='{url}' sizeInBytes='{}' senderCallsign='takserver'/><marti></marti></detail></event>",
        data.len()
    );
    cot_to_proto(&transfer, received_ms).map(|m| frame(&m))
}

// --- negotiation --------------------------------------------------------------

/// `buildProtocolAnnouncement`.
pub fn announcement(uuid: &str, server_version: &str, now_ms: i64) -> String {
    let (t, stale) = (
        crate::cot::cot_time(now_ms),
        crate::cot::cot_time(now_ms + 60_000),
    );
    format!(
        "<?xml version='1.0' encoding='UTF-8' standalone='yes'?><event version='2.0' uid='{uuid}' type='t-x-takp-v' time='{t}' start='{t}' stale='{stale}' how='m-g'><point lat='0.0' lon='0.0' hae='0.0' ce='999999' le='999999'/><detail><TakControl><TakProtocolSupport version='{TAK_PROTO_VERSION}'/><TakServerVersionInfo serverVersion='{server_version}' apiVersion='3'/></TakControl></detail></event>"
    )
}

/// `buildProtocolResponse`.
pub fn response(uuid: &str, status: bool, now_ms: i64) -> String {
    let (t, stale) = (
        crate::cot::cot_time(now_ms),
        crate::cot::cot_time(now_ms + 60_000),
    );
    format!(
        "<?xml version='1.0' encoding='UTF-8' standalone='yes'?><event version='2.0' uid='{uuid}' type='t-x-takp-r' time='{t}' start='{t}' stale='{stale}' how='m-g'><point lat='0.0' lon='0.0' hae='0.0' ce='999999' le='999999'/><detail><TakControl><TakResponse status='{status}'/></TakControl></detail></event>"
    )
}

/// `/event/detail/TakControl/TakRequest/@version` of a `t-x-takp-q`.
pub fn requested_version(xml: &str) -> Option<String> {
    let start = xml.find("<event")?;
    let root = parse_root(&xml[start..])?;
    root.element("detail")?
        .element("TakControl")?
        .element("TakRequest")?
        .attr("version")
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SA: &str = r#"<?xml version='1.0' encoding='UTF-8' standalone='yes'?><event version='2.0' uid='ANDROID-1' type='a-f-G-U-C' how='m-g' time='2026-10-18T10:00:00.123Z' start='2026-10-18T10:00:00.123Z' stale='2026-10-18T10:06:00Z' access='Undefined'><point lat='52.5' lon='13.4' hae='34.0' ce='9999999.0' le='9999999.0'/><detail><contact callsign='ALPHA' endpoint='*:-1:stcp'/><__group name='Cyan' role='Team Member'/><precisionlocation geopointsrc='GPS' altsrc='GPS'/><status battery='87'/><takv device='Pixel' platform='ATAK-CIV' os='34' version='5.6.0'/><track speed='1.5' course='270.0'/><uid Droid='ALPHA'/><remarks>a &amp; b</remarks></detail></event>"#;

    #[test]
    fn frames_are_magic_varint_message() {
        let msg = TakMessage {
            submission_time: 1,
            ..Default::default()
        };
        let framed = frame(&msg);
        assert_eq!(framed[0], MAGIC);
        assert_eq!(framed[1] as usize, msg.encoded_len());
        let big = TakMessage {
            cot_event: Some(CotEvent {
                uid: "x".repeat(300),
                ..Default::default()
            }),
            ..Default::default()
        };
        let framed = frame(&big);
        assert_eq!(big.encoded_len(), 306);
        assert_eq!(
            &framed[1..3],
            &[0xb2, 0x02],
            "varint of 306, low 7 bits first"
        );
        let mut decoder = FrameDecoder::default();
        // Split across reads, two frames.
        let both = [frame(&msg), frame(&big)].concat();
        let (a, b) = both.split_at(3);
        assert!(decoder.feed(a).unwrap().is_empty());
        assert_eq!(decoder.feed(b).unwrap(), vec![msg.clone(), big.clone()]);
    }

    #[test]
    fn a_frame_without_the_magic_byte_stops_parsing_and_garbage_is_an_error() {
        let mut decoder = FrameDecoder::default();
        let mut bytes = vec![0x00];
        bytes.extend(frame(&TakMessage::default()));
        assert!(
            decoder.feed(&bytes).unwrap().is_empty(),
            "the rest of that read is dropped"
        );
        assert_eq!(
            decoder.feed(&frame(&TakMessage::default())).unwrap().len(),
            1,
            "the next read starts afresh"
        );
        assert!(
            decoder.feed(&[MAGIC, 3, 0xff, 0xff, 0xff]).is_err(),
            "unparseable message: force close"
        );
    }

    #[test]
    fn cot_to_proto_like_the_official_helper() {
        let msg = cot_to_proto(SA, 1_000).unwrap();
        let e = msg.cot_event.clone().unwrap();
        assert_eq!(
            (
                e.r#type.as_str(),
                e.uid.as_str(),
                e.how.as_str(),
                e.access.as_str()
            ),
            ("a-f-G-U-C", "ANDROID-1", "m-g", "Undefined")
        );
        assert_eq!(
            (e.send_time, e.stale_time),
            (1_792_317_600_123, 1_792_317_960_000)
        );
        assert_eq!(
            (e.lat, e.lon, e.hae, e.ce, e.le),
            (52.5, 13.4, 34.0, 9_999_999.0, 9_999_999.0)
        );
        let d = e.detail.unwrap();
        assert_eq!(
            d.contact,
            Some(Contact {
                callsign: "ALPHA".into(),
                endpoint: "*:-1:stcp".into()
            })
        );
        assert_eq!(
            d.group,
            Some(Group {
                name: "Cyan".into(),
                role: "Team Member".into()
            })
        );
        assert_eq!(d.status, Some(Status { battery: 87 }));
        assert_eq!(d.takv.unwrap().platform, "ATAK-CIV");
        assert_eq!(
            d.track,
            Some(Track {
                speed: 1.5,
                course: 270.0
            })
        );
        assert_eq!(
            d.xml_detail, r#"<uid Droid="ALPHA"/><remarks>a &amp; b</remarks>"#,
            "the rest, as dom4j asXML"
        );
        assert_eq!((msg.submission_time, msg.creation_time), (1_000, 1_000));
        // A known element with anything extra stays XML.
        let extra = SA.replace(
            "<status battery='87'/>",
            "<status battery='87' readiness='true'/>",
        );
        let d = cot_to_proto(&extra, 1)
            .unwrap()
            .cot_event
            .unwrap()
            .detail
            .unwrap();
        assert!(
            d.status.is_none()
                && d.xml_detail
                    .starts_with(r#"<status battery="87" readiness="true"/>"#),
            "{}",
            d.xml_detail
        );
        // contact: callsign alone, or callsign + endpoint; an empty endpoint isn't set.
        let lone = SA.replace(
            "<contact callsign='ALPHA' endpoint='*:-1:stcp'/>",
            "<contact callsign='ALPHA' endpoint=''/>",
        );
        assert_eq!(
            cot_to_proto(&lone, 1)
                .unwrap()
                .cot_event
                .unwrap()
                .detail
                .unwrap()
                .contact,
            Some(Contact {
                callsign: "ALPHA".into(),
                endpoint: String::new()
            })
        );
    }

    #[test]
    fn proto_to_cot_like_the_official_helper() {
        let msg = cot_to_proto(SA, 1_000).unwrap();
        let xml = proto_to_cot(&msg).unwrap();
        assert!(
            xml.starts_with(r#"<?xml version="1.0" encoding="UTF-8"?>"#),
            "{xml}"
        );
        assert!(
            xml.contains(r#"<event version="2.0" uid="ANDROID-1" type="a-f-G-U-C" how="m-g" time="2026-10-18T10:00:00Z" start="2026-10-18T10:00:00Z" stale="2026-10-18T10:06:00Z" access="Undefined"><point lat="52.5" lon="13.4" hae="34.0" ce="9999999.0" le="9999999.0"/>"#),
            "{xml}"
        );
        assert!(
            xml.contains(r#"<detail><contact callsign="ALPHA" endpoint="*:-1:stcp"/><__group name="Cyan" role="Team Member"/><precisionlocation geopointsrc="GPS" altsrc="GPS"/><status battery="87"/><takv device="Pixel" platform="ATAK-CIV" os="34" version="5.6.0"/><track speed="1.5" course="270.0"/><uid Droid="ALPHA"/><remarks>a &amp; b</remarks></detail></event>"#),
            "{xml}"
        );
        // An xmlDetail element of a known name replaces the proto one.
        let mut msg = msg;
        let d = msg.cot_event.as_mut().unwrap().detail.as_mut().unwrap();
        d.xml_detail = r#"<contact callsign="BRAVO"/>"#.into();
        let xml = proto_to_cot(&msg).unwrap();
        assert!(
            xml.contains(r#"<detail><__group"#)
                && xml.contains(r#"<contact callsign="BRAVO"/></detail>"#),
            "{xml}"
        );
        assert!(
            crate::cot::Event::from_xml(
                xml.trim_start_matches(r#"<?xml version="1.0" encoding="UTF-8"?>"#)
                    .trim()
            )
            .is_ok()
        );
    }

    #[test]
    fn java_double_to_string() {
        for (v, s) in [
            (52.5, "52.5"),
            (34.0, "34.0"),
            (9_999_999.0, "9999999.0"),
            (1e7, "1.0E7"),
            (0.001, "0.001"),
            (0.0001, "1.0E-4"),
            (-13.25, "-13.25"),
            (0.0, "0.0"),
            (1.2345e-5, "1.2345E-5"),
        ] {
            assert_eq!(java_double(v), s);
        }
    }

    #[test]
    fn negotiation_messages() {
        let a = announcement("n-1", "MicroTAK 0.11.0", 0);
        assert_eq!(
            a,
            "<?xml version='1.0' encoding='UTF-8' standalone='yes'?><event version='2.0' uid='n-1' type='t-x-takp-v' time='1970-01-01T00:00:00Z' start='1970-01-01T00:00:00Z' stale='1970-01-01T00:01:00Z' how='m-g'><point lat='0.0' lon='0.0' hae='0.0' ce='999999' le='999999'/><detail><TakControl><TakProtocolSupport version='1'/><TakServerVersionInfo serverVersion='MicroTAK 0.11.0' apiVersion='3'/></TakControl></detail></event>"
        );
        assert!(
            response("n-1", true, 0).contains("type='t-x-takp-r'")
                && response("n-1", true, 0).contains("<TakResponse status='true'/>")
        );
        let q = r#"<event version="2.0" uid="ANDROID-1" type="t-x-takp-q" time="t" start="t" stale="t" how="m-g"><point lat="0" lon="0" hae="0" ce="999999" le="999999"/><detail><TakControl><TakRequest version="1"/></TakControl></detail></event>"#;
        assert_eq!(requested_version(q).as_deref(), Some("1"));
        assert_eq!(requested_version(SA), None);
    }
    #[test]
    fn large_outbound_messages_become_a_file_transfer() {
        let big = SA.replace(
            "<remarks>a &amp; b</remarks>",
            &format!("<remarks>{}</remarks>", "x".repeat(70_000)),
        );
        assert!(
            encode_outbound(&big, 5, None).is_none(),
            "dropped without a server URL"
        );
        let framed = encode_outbound(&big, 5, Some("https://ops.example.com:8443")).unwrap();
        let msg = FrameDecoder::default().feed(&framed).unwrap().remove(0);
        let e = msg.cot_event.unwrap();
        assert_eq!(e.r#type, "b-f-t-r");
        let hash = crate::content_store::hex_sha256(
            format!("{XML_HEADER}{}", event_body(&big)).as_bytes(),
        );
        assert_eq!(e.uid, hash);
        let xml = e.detail.unwrap().xml_detail;
        assert!(
            xml.contains("senderUrl=\"https://ops.example.com:8443/Marti/api/cot/xml/ANDROID-1\"")
                && xml.contains("senderCallsign=\"takserver\"")
                && xml.contains("name=\"ANDROID-1.cot\""),
            "{xml}"
        );
        assert!(
            encode_outbound(SA, 5, None).is_some(),
            "small messages need no URL"
        );
    }
}
