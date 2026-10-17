//! The official `FileManagerApi` (`tak.server.filemanager`): the file
//! list, download, HEAD and metadata PUT under `/Marti/api/files`. Delete
//! and count live in [`super::content`].
//!
//! | Route | Official source |
//! |---|---|
//! | `GET /api/files/metadata` | `getFileMetadata`: `FileManagerServiceDefaultImpl` queries, `buildResourceEntry` |
//! | `GET /api/files/{hash}` | `getFile` |
//! | `HEAD /api/files/{hash}` | `getFileHead` |
//! | `PUT /api/files/{hash}/metadata` | `putMetadata` |

use std::collections::BTreeSet;

use axum::body::Body;
use axum::extract::{Path, RawQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use serde_json::{Value, json};

use super::PeerIdentity;
use super::content::SyncState;
use crate::missions::Content;
use crate::sync::ResourceRecord;

const KBYTES: u64 = 1024;
const MBYTES: u64 = 1_048_576;
const GBYTES: u64 = 1_073_741_824;

/// The HTML 4 entities ESAPI's `HTMLEntityCodec` names.
const ENTITIES: &[(u32, &str)] = &[(34, "quot"), (38, "amp"), (60, "lt"), (62, "gt"), (160, "nbsp"), (161, "iexcl"), (162, "cent"), (163, "pound"), (164, "curren"), (165, "yen"), (166, "brvbar"), (167, "sect"), (168, "uml"), (169, "copy"), (170, "ordf"), (171, "laquo"), (172, "not"), (173, "shy"), (174, "reg"), (175, "macr"), (176, "deg"), (177, "plusmn"), (178, "sup2"), (179, "sup3"), (180, "acute"), (181, "micro"), (182, "para"), (183, "middot"), (184, "cedil"), (185, "sup1"), (186, "ordm"), (187, "raquo"), (188, "frac14"), (189, "frac12"), (190, "frac34"), (191, "iquest"), (192, "Agrave"), (193, "Aacute"), (194, "Acirc"), (195, "Atilde"), (196, "Auml"), (197, "Aring"), (198, "AElig"), (199, "Ccedil"), (200, "Egrave"), (201, "Eacute"), (202, "Ecirc"), (203, "Euml"), (204, "Igrave"), (205, "Iacute"), (206, "Icirc"), (207, "Iuml"), (208, "ETH"), (209, "Ntilde"), (210, "Ograve"), (211, "Oacute"), (212, "Ocirc"), (213, "Otilde"), (214, "Ouml"), (215, "times"), (216, "Oslash"), (217, "Ugrave"), (218, "Uacute"), (219, "Ucirc"), (220, "Uuml"), (221, "Yacute"), (222, "THORN"), (223, "szlig"), (224, "agrave"), (225, "aacute"), (226, "acirc"), (227, "atilde"), (228, "auml"), (229, "aring"), (230, "aelig"), (231, "ccedil"), (232, "egrave"), (233, "eacute"), (234, "ecirc"), (235, "euml"), (236, "igrave"), (237, "iacute"), (238, "icirc"), (239, "iuml"), (240, "eth"), (241, "ntilde"), (242, "ograve"), (243, "oacute"), (244, "ocirc"), (245, "otilde"), (246, "ouml"), (247, "divide"), (248, "oslash"), (249, "ugrave"), (250, "uacute"), (251, "ucirc"), (252, "uuml"), (253, "yacute"), (254, "thorn"), (255, "yuml"), (338, "OElig"), (339, "oelig"), (352, "Scaron"), (353, "scaron"), (376, "Yuml"), (402, "fnof"), (710, "circ"), (732, "tilde"), (913, "Alpha"), (914, "Beta"), (915, "Gamma"), (916, "Delta"), (917, "Epsilon"), (918, "Zeta"), (919, "Eta"), (920, "Theta"), (921, "Iota"), (922, "Kappa"), (923, "Lambda"), (924, "Mu"), (925, "Nu"), (926, "Xi"), (927, "Omicron"), (928, "Pi"), (929, "Rho"), (931, "Sigma"), (932, "Tau"), (933, "Upsilon"), (934, "Phi"), (935, "Chi"), (936, "Psi"), (937, "Omega"), (945, "alpha"), (946, "beta"), (947, "gamma"), (948, "delta"), (949, "epsilon"), (950, "zeta"), (951, "eta"), (952, "theta"), (953, "iota"), (954, "kappa"), (955, "lambda"), (956, "mu"), (957, "nu"), (958, "xi"), (959, "omicron"), (960, "pi"), (961, "rho"), (962, "sigmaf"), (963, "sigma"), (964, "tau"), (965, "upsilon"), (966, "phi"), (967, "chi"), (968, "psi"), (969, "omega"), (977, "thetasym"), (978, "upsih"), (982, "piv"), (8194, "ensp"), (8195, "emsp"), (8201, "thinsp"), (8204, "zwnj"), (8205, "zwj"), (8206, "lrm"), (8207, "rlm"), (8211, "ndash"), (8212, "mdash"), (8216, "lsquo"), (8217, "rsquo"), (8218, "sbquo"), (8220, "ldquo"), (8221, "rdquo"), (8222, "bdquo"), (8224, "dagger"), (8225, "Dagger"), (8226, "bull"), (8230, "hellip"), (8240, "permil"), (8242, "prime"), (8243, "Prime"), (8249, "lsaquo"), (8250, "rsaquo"), (8254, "oline"), (8260, "frasl"), (8364, "euro"), (8465, "image"), (8472, "weierp"), (8476, "real"), (8482, "trade"), (8501, "alefsym"), (8592, "larr"), (8593, "uarr"), (8594, "rarr"), (8595, "darr"), (8596, "harr"), (8629, "crarr"), (8656, "lArr"), (8657, "uArr"), (8658, "rArr"), (8659, "dArr"), (8660, "hArr"), (8704, "forall"), (8706, "part"), (8707, "exist"), (8709, "empty"), (8711, "nabla"), (8712, "isin"), (8713, "notin"), (8715, "ni"), (8719, "prod"), (8721, "sum"), (8722, "minus"), (8727, "lowast"), (8730, "radic"), (8733, "prop"), (8734, "infin"), (8736, "ang"), (8743, "and"), (8744, "or"), (8745, "cap"), (8746, "cup"), (8747, "int"), (8756, "there4"), (8764, "sim"), (8773, "cong"), (8776, "asymp"), (8800, "ne"), (8801, "equiv"), (8804, "le"), (8805, "ge"), (8834, "sub"), (8835, "sup"), (8836, "nsub"), (8838, "sube"), (8839, "supe"), (8853, "oplus"), (8855, "otimes"), (8869, "perp"), (8901, "sdot"), (8968, "lceil"), (8969, "rceil"), (8970, "lfloor"), (8971, "rfloor"), (9001, "lang"), (9002, "rang"), (9674, "loz"), (9824, "spades"), (9827, "clubs"), (9829, "hearts"), (9830, "diams")];

/// ESAPI `encodeForHTML`: alphanumerics and `,.-_ ` stay, control
/// characters become U+FFFD, the rest a named or hex entity.
pub fn esapi_encode_for_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || ",.-_ ".contains(c) {
            out.push(c);
            continue;
        }
        let code = c as u32;
        let code = if (code <= 0x1f && !matches!(c, '\t' | '\n' | '\r')) || (0x7f..=0x9f).contains(&code) { 0xfffd } else { code };
        match ENTITIES.binary_search_by_key(&code, |(k, _)| *k) {
            Ok(i) => out.push_str(&format!("&{};", ENTITIES[i].1)),
            Err(_) => out.push_str(&format!("&#x{code:x};")),
        }
    }
    out
}

/// `buildResourceEntry`'s size: whole B, kB, MB or GB.
fn size_label(size: u64) -> String {
    if size < 1024 {
        format!("{size}B")
    } else if size < MBYTES {
        format!("{}kB", size / KBYTES)
    } else if size < GBYTES {
        format!("{}MB", size / MBYTES)
    } else {
        format!("{}GB", size / GBYTES)
    }
}

/// `java.sql.Timestamp.toString()` in UTC: `yyyy-mm-dd hh:mm:ss.f`, the
/// fraction without trailing zeros (`.0` if none).
fn timestamp_string(millis: i64) -> String {
    let secs = millis.div_euclid(1000);
    let ms = millis.rem_euclid(1000);
    let base = crate::marti::envelope::cot_date(secs);
    // cot_date: yyyy-MM-ddTHH:mm:ssZ
    let base = base.trim_end_matches('Z').replacen('T', " ", 1);
    let base = base.split('.').next().unwrap_or("").to_string();
    let fraction = if ms == 0 { "0".to_string() } else { format!("{ms:03}").trim_end_matches('0').to_string() };
    format!("{base}.{fraction}")
}

/// `Instant.ofEpochSecond(e).toString()` without its `Z`, or `none`.
fn expiration_string(expiration: Option<i64>) -> String {
    match expiration {
        Some(e) if e >= 0 => crate::marti::envelope::cot_date(e).trim_end_matches('Z').split('.').next().unwrap_or("").to_string(),
        _ => "none".into(),
    }
}

/// SQL `LIKE` with `%` and `_`.
fn like(value: &str, pattern: &str) -> bool {
    fn go(v: &[char], p: &[char]) -> bool {
        match p.first() {
            None => v.is_empty(),
            Some('%') => (0..=v.len()).any(|i| go(&v[i..], &p[1..])),
            Some('_') => !v.is_empty() && go(&v[1..], &p[1..]),
            Some(c) => v.first() == Some(c) && go(&v[1..], &p[1..]),
        }
    }
    let v: Vec<char> = value.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    go(&v, &p)
}

fn query_pairs(raw: Option<&str>) -> Vec<(String, String)> {
    serde_urlencoded::from_str::<Vec<(String, String)>>(raw.unwrap_or("")).unwrap_or_default()
}

/// What Spring's `MediaType.parseMediaType` accepts: `type/subtype`, tokens.
fn valid_media_type(m: &str) -> bool {
    let essence = m.split(';').next().unwrap_or("").trim();
    let token = |t: &str| !t.is_empty() && t.chars().all(|c| c.is_ascii_graphic() && !"()<>@,;:\\\"/[]?={}".contains(c));
    matches!(essence.split_once('/'), Some((t, s)) if token(t) && token(s))
}

fn param<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn viewer_groups(state: &SyncState, identity: &PeerIdentity) -> Option<BTreeSet<String>> {
    if state.admin_common_name.as_deref() == Some(identity.0.as_str()) {
        None
    } else {
        Some(state.groups.all_group_names(&identity.0))
    }
}

/// `dao.latestCallsign(uid)`: the callsign last reported for that uid.
fn latest_callsign(state: &SyncState, uid: &str) -> String {
    state.latest_cot.get(uid).map(|e| super::contacts::callsign(&e.xml)).unwrap_or_default()
}

/// `buildResourceEntry`.
fn resource_entry(state: &SyncState, r: &ResourceRecord, groups: Option<&BTreeSet<String>>, all: &[ResourceRecord]) -> Value {
    // getKeywordsForResource: every row with this hash, "none" if empty.
    let mut keywords: Vec<String> = all.iter().filter(|o| o.hash == r.hash).flat_map(|o| o.keywords.clone()).collect();
    if keywords.is_empty() {
        keywords.push("none".into());
    }
    // getGroupNamesForBitVectorString(vector, the caller's groups).
    let names: BTreeSet<&String> = r.visible_in.iter().filter(|g| groups.is_none_or(|mine| mine.contains(*g))).collect();
    json!({
        "Name": r.name,
        "User": r.submission_user,
        "Creator": esapi_encode_for_html(&latest_callsign(state, &r.uid)),
        "Size": size_label(r.size),
        "Time": timestamp_string(r.submission_time_millis),
        "MimeType": r.mime_type,
        "Keywords": keywords.join(","),
        "Expiration": expiration_string(r.expiration),
        "Hash": r.hash,
        "Groups": names.into_iter().cloned().collect::<Vec<_>>().join(","),
        "Tool": r.tool,
    })
}

/// `getFileMetadata`.
pub async fn list(State(state): State<SyncState>, Extension(identity): Extension<PeerIdentity>, RawQuery(raw): RawQuery) -> Response {
    let pairs = query_pairs(raw.as_deref());
    let int = |k: &str| param(&pairs, k).and_then(|v| v.parse::<i64>().ok()).unwrap_or(-1);
    let (page, limit) = (int("page"), int("limit"));
    let mission = param(&pairs, "mission").unwrap_or("");
    let mission_package = param(&pairs, "missionPackage") == Some("true");
    let name = param(&pairs, "name").unwrap_or("");
    let ascending = param(&pairs, "ascending") != Some("false");
    let sort = param(&pairs, "sort").unwrap_or("");
    let groups = viewer_groups(&state, &identity);
    let all = state.resources.all();
    let mut files: Vec<ResourceRecord> = state.resources.visible(groups.as_ref());
    // No ORDER BY: rows in the order stored (sorts below are stable).
    files.sort_by_key(|r| r.primary_key);
    if mission.trim().is_empty() && mission_package {
        files.retain(|r| r.keywords.iter().any(|k| k == "missionpackage"));
    } else if !mission.trim().is_empty() {
        // getResourcesByMission: joined to every mission of that name.
        let hashes: BTreeSet<String> = state
            .missions
            .list()
            .into_iter()
            .filter(|m| m.name == mission)
            .flat_map(|m| m.hashes().filter_map(|c| match &c.content { Content::Hash(h) => Some(h.clone()), _ => None }).collect::<Vec<_>>())
            .collect();
        files.retain(|r| hashes.contains(&r.hash));
    }
    if !name.trim().is_empty() {
        let pattern = format!("%{name}%");
        files.retain(|r| r.name.as_deref().is_some_and(|n| like(n, &pattern)));
    }
    // getResourceColumnName: name, updateTime, size; anything else unsorted.
    let key = |r: &ResourceRecord| -> (Option<String>, i64, u64) { (r.name.clone(), r.submission_time_millis, r.size) };
    let sorted = match sort {
        "name" => { files.sort_by(|a, b| key(a).0.cmp(&key(b).0)); true }
        "updateTime" => { files.sort_by_key(|r| r.submission_time_millis); true }
        "size" => { files.sort_by_key(|r| r.size); true }
        _ => false,
    };
    if sorted && !ascending {
        files.reverse();
    }
    if page != -1 && limit != -1 && limit != 0 {
        let offset = page.saturating_mul(limit);
        files = if offset < 0 || limit < 0 { Vec::new() } else { files.into_iter().skip(offset as usize).take(limit as usize).collect() };
    }
    let entries: Vec<Value> = files.iter().map(|r| resource_entry(&state, r, groups.as_ref(), &all)).collect();
    crate::marti::envelope::api_response("Files", entries).into_response()
}

/// `getFile`: the bytes with the stored type, as an attachment. No content:
/// `new ByteArrayResource(null)` (400); a missing or invalid type or name:
/// 500 with the bytes.
pub async fn get_file(State(state): State<SyncState>, Extension(identity): Extension<PeerIdentity>, Path(hash): Path<String>) -> Response {
    let groups = viewer_groups(&state, &identity);
    let hash = hash.to_ascii_lowercase();
    let metadata = state.resources.by_hash(&hash, groups.as_ref());
    let bytes = if metadata.is_empty() { None } else { state.content.get(&hash).ok().flatten() };
    let Some(bytes) = bytes else {
        return crate::marti::missions::ApiError::BadRequest("Byte array must not be null".into()).into_response();
    };
    let first = &metadata[0];
    let mime = first.mime_type.as_deref().filter(|m| valid_media_type(m));
    match (mime, first.name.as_deref()) {
        (Some(mime), Some(name)) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime)
            .header(header::CONTENT_LENGTH, bytes.len())
            .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", super::content::urlencode_filename(name)))
            .body(Body::from(bytes))
            .unwrap(),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, bytes).into_response(),
    }
}

/// `getFileHead`: a HEAD answer carries no body.
pub async fn head_file() -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")]).into_response()
}

/// `putMetadata`: `user` and `expiration` on the caller's rows when given;
/// keywords always replaced (empty when none are given). Errors swallowed.
pub async fn put_metadata(
    State(state): State<SyncState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(hash): Path<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    let pairs = query_pairs(raw.as_deref());
    let groups = viewer_groups(&state, &identity);
    let hash = hash.to_ascii_lowercase();
    let keys: Vec<i64> = state.resources.by_hash(&hash, groups.as_ref()).iter().map(|r| r.primary_key).collect();
    if let Some(user) = param(&pairs, "user").filter(|u| !u.is_empty()) {
        let _ = state.resources.set_submission_user(&keys, user);
    }
    if let Some(expiration) = param(&pairs, "expiration").filter(|e| !e.is_empty()).and_then(|e| e.parse::<i64>().ok()) {
        let _ = state.resources.set_expiration_keys(&keys, Some(expiration).filter(|e| *e >= 0));
    }
    // @RequestParam List<String>: repeated or comma-separated values.
    let keywords: Vec<String> = pairs
        .iter()
        .filter(|(k, _)| k == "keywords")
        .flat_map(|(_, v)| v.split(',').map(str::to_string).collect::<Vec<_>>())
        .filter(|k| !k.is_empty())
        .collect();
    let _ = state.resources.set_keywords(&hash, keywords);
    StatusCode::OK.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esapi_html_encoding() {
        assert_eq!(esapi_encode_for_html("ALPHA-1 lead_2, ok."), "ALPHA-1 lead_2, ok.");
        assert_eq!(esapi_encode_for_html("<a&\"'/>"), "&lt;a&amp;&quot;&#x27;&#x2f;&gt;");
        assert_eq!(esapi_encode_for_html("Jörg\u{1}"), "J&ouml;rg&#xfffd;");
    }

    #[test]
    fn sizes_times_and_expirations() {
        assert_eq!((size_label(1023), size_label(2048), size_label(5 * MBYTES + 1), size_label(3 * GBYTES)), ("1023B".into(), "2kB".into(), "5MB".into(), "3GB".into()));
        assert_eq!(timestamp_string(1_792_279_546_665), "2026-10-17 23:25:46.665");
        assert_eq!(timestamp_string(1_792_279_546_000), "2026-10-17 23:25:46.0");
        assert_eq!(timestamp_string(1_792_279_546_500), "2026-10-17 23:25:46.5");
        assert_eq!(expiration_string(Some(1_800_000_000)), "2027-01-15T08:00:00");
        assert_eq!(expiration_string(None), "none");
    }

    #[test]
    fn sql_like() {
        assert!(like("b-plain.txt", "%plain%"));
        assert!(like("a_b", "a_b") && like("axb", "a_b"));
        assert!(!like("Plain", "%plain%"), "LIKE is case-sensitive");
    }
}
