//! The official URL authorization (`security-context.xml`'s
//! `FilterSecurityInterceptor`): an ordered table of ant patterns, the
//! first match decides which roles may call a path. On the Marti API port
//! (the official 8443 connector: admin UI, WebTAK and non-admin UI
//! enabled, client certificates required) every user holds
//! `ROLE_ANONYMOUS`, `ROLE_NON_ADMIN_UI` and `ROLE_WEBTAK`; the admin also
//! `ROLE_ADMIN` and, through the role hierarchy, `ROLE_READONLY`
//! (`AuthenticatorUtil.setUserRolesBasedOnRequestPort`). Nobody there holds
//! `ROLE_NO_CLIENT_CERT`, `ROLE_FEDERATE`, `ROLE_XMPP` or
//! `ROLE_NONEXISTENT`.
//!
//! So: whatever the table doesn't open is admin-only (`/Marti/**`), and a
//! DELETE not explicitly allowed is refused for everyone (`/Marti/**`
//! DELETE → `ROLE_NONEXISTENT`).

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

pub(crate) struct Rule {
    pub method: Option<&'static str>,
    pub pattern: &'static str,
    pub access: &'static [&'static str],
}

// Generated from TAK-Product-Center/Server @ 5187abd
// src/takserver-core/src/main/resources/security-context.xml, in order.
pub(crate) const RULES: &[Rule] = &[
    Rule { method: None, pattern: "/Marti/api/plugins/*/submit", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/plugins/*/submit/result", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/users/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/datafeeds/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/inputs/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/inputs/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/missions/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/maplayers/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/maplayers/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/injectors/cot/uid/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/federategroups/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/federategroups/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/federategroupsmap/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/federategroupsmap/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/federate-outbound-groups-hop-limit/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/federate-outbound-groups-hop-limit/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/federatecagroups/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/federatecagroups/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/federates/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/federatedetails/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/federategroupconfig/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/groupprefix/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/outgoingconnections/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/outgoingconnections/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/outgoingconnectionstatus/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/federatecertificates/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/federatecertificates/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/federatecontacts/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/activeconnections/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/device/profile/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/config", access: &["ROLE_ADMIN"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/security/isSecure", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/vcm/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/xmpp/**", access: &["ROLE_XMPP"] },
    Rule { method: Some("POST"), pattern: "/Marti/api/xmpp/**", access: &["ROLE_XMPP"] },
    Rule { method: Some("PUT"), pattern: "/Marti/api/xmpp/**", access: &["ROLE_XMPP"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/xmpp/**", access: &["ROLE_XMPP"] },
    Rule { method: None, pattern: "/Marti/api/certadmin/cert/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/certadmin/cert/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/retention/policy/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/retention/service/schedule/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/retention/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/token/access", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/token/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/token/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/subscriptions/add/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/subscriptions/delete/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/sync/missionquery", access: &["ROLE_ANONYMOUS", "ROLE_FEDERATE"] },
    Rule { method: None, pattern: "/Marti/sync/missionupload", access: &["ROLE_ANONYMOUS", "ROLE_FEDERATE"] },
    Rule { method: None, pattern: "/Marti/sync/search", access: &["ROLE_ANONYMOUS", "ROLE_FEDERATE"] },
    Rule { method: None, pattern: "/Marti/CotQueryServlet", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/cot/search/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/tls/makeClientKeyStore", access: &["ROLE_NO_CLIENT_CERT"] },
    Rule { method: None, pattern: "/Marti/api/tls/config", access: &["ROLE_NO_CLIENT_CERT"] },
    Rule { method: None, pattern: "/Marti/api/tls/signClient", access: &["ROLE_NO_CLIENT_CERT"] },
    Rule { method: None, pattern: "/Marti/api/tls/signClient/v2", access: &["ROLE_NO_CLIENT_CERT"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/tls/profile/enrollment", access: &["ROLE_NO_CLIENT_CERT"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/tls/profile/tool/**", access: &["ROLE_NO_CLIENT_CERT"] },
    Rule { method: None, pattern: "/Marti/ExportMission.jsp", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/error/**", access: &["ROLE_ANONYMOUS", "ROLE_NO_CLIENT_CERT", "ROLE_FEDERATE"] },
    Rule { method: None, pattern: "/error", access: &["ROLE_ANONYMOUS", "ROLE_NO_CLIENT_CERT", "ROLE_FEDERATE"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/properties/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/menubar.html/**", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/api/missions/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/sync/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/cot/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/cops/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/properties/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/properties/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/files/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/files/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/groups/update/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/groups/activeForce", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/groups/user", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/groups/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/device/profile/tool/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/device/profile/connection", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/device/profile/enrollment", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/device/profile/*/missionpackage", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/clientEndPoints/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/contacts/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/clients/**", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/subscriptions/all/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/subscription/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("POST"), pattern: "/Marti/vcu/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/vcm/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("POST"), pattern: "/Marti/vcm/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/vcm/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("POST"), pattern: "/Marti/vcs/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/video/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/VideoManager.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/VideoUpload.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/VideoSend.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: Some("POST"), pattern: "/Marti/TracksKML/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("POST"), pattern: "/Marti/ErrorLog/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/ErrorLog/**", access: &["ROLE_ADMIN"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/ErrorLog/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/ErrorLogManager.jsp", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/Missions.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/Missions.js", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/MissionEditor.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/MissionInvite.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/MissionSend.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/citrap/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("POST"), pattern: "/Marti/api/citrap/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("PUT"), pattern: "/Marti/api/citrap/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/citrap/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/excheck/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("POST"), pattern: "/Marti/api/excheck/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("PUT"), pattern: "/Marti/api/excheck/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/excheck/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/ExCheck.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/api/subscriptions/*/filter", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/api/subscriptions/*/filter", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/version/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/node/id/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/footer.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/images/*", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/jquery/**", access: &["ROLE_NON_ADMIN_UI", "ROLE_NO_CLIENT_CERT"] },
    Rule { method: None, pattern: "/Marti/lib/**", access: &["ROLE_NON_ADMIN_UI", "ROLE_NO_CLIENT_CERT"] },
    Rule { method: None, pattern: "/Marti/mil-std-2525b/*", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/icons/*", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/api/home/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/util/isAdmin/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/api/util/user/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/sync/content", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/sync/missioncreate", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/icon/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/iconset/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/iconseturl/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: Some("GET"), pattern: "/Marti/api/cot/images/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/authentication.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: Some("DELETE"), pattern: "/Marti/**", access: &["ROLE_NONEXISTENT"] },
    Rule { method: Some("OPTIONS"), pattern: "/Marti/**", access: &["ROLE_NONEXISTENT"] },
    Rule { method: None, pattern: "/Marti/ContactsJson.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/index.html", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/ListDataFerryFiles.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/ListContacts.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/ListContactsRefresh.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/sync", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/KmlMasterSA/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/LatestKML", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/EnterpriseSync.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/ExportMissionKML/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/trackExport.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/GetTime", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/iconurl", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/api/cop/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/webtak/**", access: &["ROLE_WEBTAK"] },
    Rule { method: None, pattern: "/webtak-plugins/**", access: &["ROLE_WEBTAK"] },
    Rule { method: None, pattern: "/takproto/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/GeoCache/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/async/chat", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/draw/**", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/sync/upload", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/sync/delete", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/upload.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/sendMissionPackage.jsp", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/css/**", access: &["ROLE_NON_ADMIN_UI", "ROLE_NO_CLIENT_CERT"] },
    Rule { method: None, pattern: "/Marti/api/ver/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/actuator/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/metrics/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/mla/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/oauth/token", access: &["ROLE_NO_CLIENT_CERT"] },
    Rule { method: None, pattern: "/oauth/authorize", access: &["ROLE_NO_CLIENT_CERT"] },
    Rule { method: None, pattern: "/oauth/check_token", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/login/**", access: &["ROLE_NO_CLIENT_CERT"] },
    Rule { method: None, pattern: "/Marti/login/**", access: &["ROLE_NO_CLIENT_CERT"] },
    Rule { method: None, pattern: "/register/admin/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/register/**", access: &["#{@UserManagementAuthorizationProvider.role}"] },
    Rule { method: None, pattern: "/locate/**", access: &["#{@LocateAuthorizationProvider.role}"] },
    Rule { method: None, pattern: "/schedule/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/user-management/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/vbm/api/classification", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/vbm/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/Marti/MissionManager.html", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/api/pagedmissions", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/api/missioncount", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/vbm/api/config", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/api/util/isAdmin", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/api/security/isSecure", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/favicon.ico", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/tablesorter/**", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/static/**", access: &["ROLE_NON_ADMIN_UI"] },
    Rule { method: None, pattern: "/Marti/**", access: &["ROLE_ADMIN"] },
    Rule { method: None, pattern: "/**", access: &["ROLE_ANONYMOUS"] },
    Rule { method: None, pattern: "/Marti/documentation/**", access: &["ROLE_ADMIN"] },
];

/// Spring's `AntPathMatcher` for these patterns: `**` spans any number of
/// path segments (also none), `*` any characters within one segment.
fn ant_match(pattern: &str, path: &str) -> bool {
    let pattern: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match_segments(&pattern, &path)
}

fn match_segments(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.first() {
        None => path.is_empty(),
        Some(&"**") => (0..=path.len()).any(|skip| match_segments(&pattern[1..], &path[skip..])),
        Some(segment) => !path.is_empty() && match_segment(segment, path[0]) && match_segments(&pattern[1..], &path[1..]),
    }
}

fn match_segment(pattern: &str, segment: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == segment,
        Some((prefix, rest)) => {
            let Some(after_prefix) = segment.strip_prefix(prefix) else { return false };
            (0..=after_prefix.len()).filter(|i| after_prefix.is_char_boundary(*i)).any(|i| match_segment(rest, &after_prefix[i..]))
        }
    }
}

/// The roles of a user on the Marti API port.
fn roles(admin: bool) -> &'static [&'static str] {
    if admin {
        &["ROLE_ADMIN", "ROLE_READONLY", "ROLE_ANONYMOUS", "ROLE_NON_ADMIN_UI", "ROLE_WEBTAK"]
    } else {
        &["ROLE_ANONYMOUS", "ROLE_NON_ADMIN_UI", "ROLE_WEBTAK"]
    }
}

/// Whether the table lets a user (`admin` or not) call `method path`.
pub fn allowed(method: &str, path: &str, admin: bool) -> bool {
    // MicroTAK's own admin API (no official counterpart) checks for the
    // admin itself; the official table would refuse its DELETEs.
    if ant_match("/Marti/api/admin/**", path) {
        return true;
    }
    let rule = RULES
        .iter()
        .find(|r| r.method.is_none_or(|m| m.eq_ignore_ascii_case(method)) && ant_match(r.pattern, path));
    match rule {
        Some(rule) => rule.access.iter().any(|role| roles(admin).contains(role)),
        // No rule: Spring lets it through (`rejectPublicInvocations` is off).
        None => true,
    }
}

/// The middleware: a request the table refuses gets 403, as Spring
/// Security's access-denied handling answers.
pub async fn enforce(admin_common_name: Option<String>, request: Request, next: Next) -> Response {
    let admin = request
        .extensions()
        .get::<super::PeerIdentity>()
        .is_some_and(|identity| admin_common_name.as_deref() == Some(identity.0.as_str()));
    if allowed(request.method().as_str(), request.uri().path(), admin) {
        next.run(request).await
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ant_patterns_match_like_spring() {
        assert!(ant_match("/Marti/**", "/Marti"));
        assert!(ant_match("/Marti/**", "/Marti/api/missions/x"));
        assert!(ant_match("/Marti/api/subscriptions/*/filter", "/Marti/api/subscriptions/ANDROID-1/filter"));
        assert!(!ant_match("/Marti/api/subscriptions/*/filter", "/Marti/api/subscriptions/a/b/filter"));
        assert!(ant_match("/Marti/api/plugins/*/submit", "/Marti/api/plugins/p/submit"));
        assert!(!ant_match("/Marti/sync", "/Marti/sync/content"));
    }

    /// The official table, for the paths MicroTAK serves.
    #[test]
    fn the_official_rules_decide() {
        // open to every user
        for (m, p) in [
            ("GET", "/Marti/api/missions"),
            ("PUT", "/Marti/api/missions/Ops"),
            ("DELETE", "/Marti/api/missions/Ops"),
            ("GET", "/Marti/api/sync/search"),
            ("DELETE", "/Marti/api/files/abc"),
            ("GET", "/Marti/api/files/metadata/count"),
            ("GET", "/Marti/sync/content"),
            ("POST", "/Marti/sync/upload"),
            ("POST", "/Marti/sync/missionupload"),
            ("GET", "/Marti/sync/search"),
            ("GET", "/Marti/api/groups/all"),
            ("GET", "/Marti/api/contacts/all"),
            ("GET", "/Marti/api/clientEndPoints"),
            ("GET", "/Marti/api/subscriptions/all"),
            ("GET", "/Marti/api/version/config"),
            ("GET", "/Marti/api/pagedmissions"),
            ("GET", "/files/api/config"),
        ] {
            assert!(allowed(m, p, false), "{m} {p}");
        }
        // admin only
        for (m, p) in [
            ("GET", "/Marti/api/certadmin/cert"),
            ("DELETE", "/Marti/api/certadmin/cert/revoke/1"),
            ("GET", "/Marti/api/resources/abc"),
            ("POST", "/Marti/api/groups/update/x"),
        ] {
            assert!(!allowed(m, p, false), "{m} {p}");
            assert!(allowed(m, p, true), "{m} {p} for the admin");
        }
        // nobody: DELETE falls to `/Marti/** DELETE → ROLE_NONEXISTENT`
        assert!(!allowed("DELETE", "/Marti/sync/delete", true));
        assert!(allowed("DELETE", "/Marti/api/admin/devices/x/block", true), "MicroTAK's admin API decides itself");
        // enrollment paths need the no-client-cert role this port lacks
        assert!(!allowed("GET", "/Marti/api/tls/config", true));
    }
}
