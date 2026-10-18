//! Mission packages: the archive a mission exports
//! (`MissionServiceDefaultImpl.archiveMission`, `MissionPackage.save`) and
//! importing a data package into a mission (`addMissionPackage`).
//!
//! The manifest is `MANIFEST/manifest.xml` as JAXB writes
//! `MissionPackageManifest` with formatted output: version 2, the mission's
//! parameters, one `Content` per file (CoT files carry their uid as a
//! `Parameter`), its groups and its default role with the role's
//! permissions.
//!
//! Import handles packages without `changes.json` (plain data packages:
//! every `.cot` file becomes mission content and goes to the live
//! subscribers, every other file becomes an Enterprise Sync resource in the
//! mission). Offline change sets (`changes.json`) are not replayed yet.

use std::io::{Cursor, Read};

use crate::missions::{Content, MissionRecord};

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn attr(name: &str, value: Option<&str>) -> String {
    value
        .map(|v| format!(r#" {name}="{}""#, escape(v)))
        .unwrap_or_default()
}

/// Java's `Double.toString` for the values a position takes.
fn java_double(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e7 {
        format!("{v:.1}")
    } else {
        format!("{v}")
    }
}

pub struct ArchiveFile {
    pub zip_entry: String,
    pub bytes: Vec<u8>,
    /// `resourceToContentType` attributes, in `ContentType`'s field order.
    pub attributes: Vec<(&'static str, String)>,
    /// A CoT file's uid (`addCotFile`).
    pub uid_parameter: Option<String>,
}

/// The manifest, as JAXB formats it (4-space indent).
pub fn manifest_xml(
    parameters: &[(&str, Option<String>)],
    files: &[ArchiveFile],
    groups: &[String],
    role: Option<(&str, Vec<String>)>,
) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<MissionPackageManifest version=\"2\">\n    <Configuration>\n",
    );
    for (name, value) in parameters {
        xml.push_str(&format!(
            "        <Parameter{}{}/>\n",
            attr("name", Some(name)),
            attr("value", value.as_deref())
        ));
    }
    xml.push_str("    </Configuration>\n");
    // JAXB writes an empty list as an empty element.
    xml.push_str(if files.is_empty() {
        "    <Contents/>\n"
    } else {
        "    <Contents>\n"
    });
    for file in files {
        let mut attrs = format!(r#" zipEntry="{}" ignore="false""#, escape(&file.zip_entry));
        for (k, v) in &file.attributes {
            attrs.push_str(&format!(r#" {k}="{}""#, escape(v)));
        }
        match &file.uid_parameter {
            Some(uid) => xml.push_str(&format!(
                "        <Content{attrs}>\n            <Parameter name=\"uid\" value=\"{}\"/>\n        </Content>\n",
                escape(uid)
            )),
            None => xml.push_str(&format!("        <Content{attrs}/>\n")),
        }
    }
    if !files.is_empty() {
        xml.push_str("    </Contents>\n");
    }
    if !groups.is_empty() {
        xml.push_str("    <Groups>\n");
        for g in groups {
            xml.push_str(&format!("        <Group name=\"{}\"/>\n", escape(g)));
        }
        xml.push_str("    </Groups>\n");
    }
    if let Some((role, permissions)) = role {
        xml.push_str(&format!("    <Role name=\"{}\">\n", escape(role)));
        for p in permissions {
            xml.push_str(&format!("        <Permissions name=\"{}\"/>\n", escape(&p)));
        }
        xml.push_str("    </Role>\n");
    }
    xml.push_str("</MissionPackageManifest>\n");
    xml
}

/// The official `archiveMission` parameters, in order.
pub fn archive_parameters(
    mission: &MissionRecord,
    server_name: &str,
) -> Vec<(&'static str, Option<String>)> {
    vec![
        ("uid", Some(super::envelope::random_uuid())),
        ("name", Some(mission.name.clone())),
        ("mission_guid", Some(mission.guid.clone())),
        ("password_hash", mission.password_hash.clone()),
        ("creatorUid", Some(mission.creator_uid.clone())),
        ("create_time", Some(mission.create_time_ms.to_string())),
        ("expiration", Some(mission.fields.expiration.to_string())),
        ("chatroom", Some(mission.fields.chat_room.clone())),
        ("description", Some(mission.fields.description.clone())),
        ("tool", Some(mission.tool.clone())),
        ("onReceiveImport", Some("true".into())),
        ("onReceiveDelete", Some("false".into())),
        ("mission_name", Some(mission.name.clone())),
        ("mission_label", Some(mission.name.clone())),
        (
            "mission_uid",
            Some(format!("{server_name}-8443-ssl-{}", mission.name)),
        ),
        ("mission_server", Some(format!("{server_name}:8443:ssl"))),
    ]
}

/// `resourceToContentType` from a resource's JSON.
pub fn content_attributes(resource: &serde_json::Value) -> Vec<(&'static str, String)> {
    let s = |k: &str| resource.get(k).and_then(|v| v.as_str()).map(String::from);
    let f = |k: &str| resource.get(k).and_then(|v| v.as_f64()).map(java_double);
    let mut out: Vec<(&'static str, String)> = Vec::new();
    let keywords: Vec<String> = resource
        .get("keywords")
        .and_then(|k| k.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    out.push(("keywords", keywords.join(",")));
    for (name, value) in [
        ("mimeType", s("mimeType")),
        ("name", s("name")),
        ("submitter", s("submitter")),
        ("uid", s("uid")),
        ("creatorUid", s("creatorUid")),
        (
            "size",
            resource
                .get("size")
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string()),
        ),
        ("tool", s("tool")),
        ("latitude", f("latitude")),
        ("longitude", f("longitude")),
        ("altitude", f("altitude")),
        ("submissionTime", s("submissionTime")),
        ("filename", s("filename")),
    ] {
        if let Some(v) = value {
            out.push((name, v));
        }
    }
    out
}

/// The zip: `cot/`, `contents/`, the files, `MANIFEST/`, the manifest
/// (`MissionPackage.save`, entries written in that order).
pub fn build_archive(manifest: &str, files: &[ArchiveFile]) -> Vec<u8> {
    let mut entries: Vec<(String, Vec<u8>)> = vec![
        ("cot/".into(), Vec::new()),
        ("contents/".into(), Vec::new()),
    ];
    entries.extend(files.iter().map(|f| (f.zip_entry.clone(), f.bytes.clone())));
    entries.push(("MANIFEST/".into(), Vec::new()));
    entries.push(("MANIFEST/manifest.xml".into(), manifest.as_bytes().to_vec()));
    crate::zip::stored(&entries)
}

/// `MissionPackage.extractMissionPackage`: every non-directory entry.
pub fn extract(package: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(package)).map_err(|e| e.to_string())?;
    let mut files = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        if entry.is_dir() {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        let name = entry.name().map_err(|e| e.to_string())?.into_owned();
        files.push((name, bytes));
    }
    Ok(files)
}

/// `trimByteOrderMark`.
pub fn trim_bom(s: &str) -> &str {
    s.strip_prefix('\u{feff}').unwrap_or(s)
}

/// The content uid of an imported CoT file.
pub fn cot_uid(xml: &str) -> Option<String> {
    let xml = trim_bom(xml);
    let start = xml.find("<event")?;
    crate::cot::Event::from_xml(&xml[start..])
        .ok()
        .map(|e| e.uid)
}

/// What an import adds: hashes come from Enterprise Sync, uids from CoT.
pub fn content_of(hash_or_uid: &str, is_cot: bool) -> Content {
    if is_cot {
        Content::Uid(hash_or_uid.to_string())
    } else {
        Content::Hash(hash_or_uid.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_is_jaxb_formatted() {
        let files = vec![ArchiveFile {
            zip_entry: "cot/m-1.cot".into(),
            bytes: b"<event/>".to_vec(),
            attributes: vec![],
            uid_parameter: Some("m-1".into()),
        }];
        let xml = manifest_xml(
            &[("uid", Some("u".into())), ("password_hash", None)],
            &files,
            &["__ANON__".to_string()],
            Some((
                "MISSION_SUBSCRIBER",
                vec!["MISSION_READ".into(), "MISSION_WRITE".into()],
            )),
        );
        assert_eq!(
            xml,
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<MissionPackageManifest version=\"2\">\n    <Configuration>\n        <Parameter name=\"uid\" value=\"u\"/>\n        <Parameter name=\"password_hash\"/>\n    </Configuration>\n    <Contents>\n        <Content zipEntry=\"cot/m-1.cot\" ignore=\"false\">\n            <Parameter name=\"uid\" value=\"m-1\"/>\n        </Content>\n    </Contents>\n    <Groups>\n        <Group name=\"__ANON__\"/>\n    </Groups>\n    <Role name=\"MISSION_SUBSCRIBER\">\n        <Permissions name=\"MISSION_READ\"/>\n        <Permissions name=\"MISSION_WRITE\"/>\n    </Role>\n</MissionPackageManifest>\n"
        );
    }

    #[test]
    fn an_archive_round_trips_through_extract() {
        let zip = build_archive(
            "<m/>",
            &[ArchiveFile {
                zip_entry: "contents/0_a.txt".into(),
                bytes: b"a".to_vec(),
                attributes: vec![],
                uid_parameter: None,
            }],
        );
        let files = extract(&zip).unwrap();
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            ["contents/0_a.txt", "MANIFEST/manifest.xml"],
            "directories are skipped"
        );
    }

    #[test]
    fn imported_cot_keeps_its_uid() {
        let xml = "\u{feff}<?xml version=\"1.0\"?><event version=\"2.0\" uid=\"pin-9\" type=\"a-u-G\" how=\"h-g-i-g-o\" time=\"t\" start=\"t\" stale=\"t\"><point lat=\"0\" lon=\"0\" hae=\"0\" ce=\"0\" le=\"0\"/><detail/></event>";
        assert_eq!(cot_uid(xml).as_deref(), Some("pin-9"));
        assert_eq!(java_double(53.0), "53.0");
        assert_eq!(java_double(53.25), "53.25");
    }
}
