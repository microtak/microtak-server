//! The official `validateClientUid` check (`clientUidMatchesCert`): a
//! device's own situational-awareness report must carry the `clientUid`
//! its certificate was enrolled for.
//!
//! Only SA messages are checked ([`Event::is_situational_awareness`]: a
//! `uid` plus a `<contact>` with a `callsign` *and* an `endpoint`) --
//! GeoChat, markers, shapes and routes carry their own uids. Officially:
//! - a certificate not on record passes,
//! - an SA with another uid than the certificate's ends the connection
//!   (`deleteSubscriptionssByCertificate`),
//! - a certificate enrolled without a `clientUid` can't match (the official
//!   comparison throws), so its SAs are dropped.
//!
//! Officially off by default (`<latestSA validateClientUid="false">`);
//! MicroTAK's `validate_client_uid` is on by default.
//!
//! One rule the official server doesn't have, at the owner's request (no
//! impersonation, [`impersonation`]): an event reusing the uid another
//! device's certificate was enrolled for, or naming that uid as its
//! producer (`<link relation="p-p">` -- a chat sender, a marker's
//! creator), is dropped, not relayed.

use crate::cot::Event;
use crate::registry::DeviceRegistry;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Relay,
    Drop(String),
    Disconnect(String),
}

/// `enrolled`: the connecting certificate as enrolled
/// ([`crate::registry::DeviceRegistry::enrolled_client_uid`]).
pub fn validate_client_uid(enrolled: Option<&Option<String>>, event: &Event) -> Verdict {
    if !event.is_situational_awareness() {
        return Verdict::Relay;
    }
    match enrolled {
        None => Verdict::Relay,
        Some(None) => Verdict::Drop("certificate enrolled without a clientUid".to_string()),
        Some(Some(client_uid)) if *client_uid == event.uid => Verdict::Relay,
        Some(Some(client_uid)) => Verdict::Disconnect(format!(
            "SA uid '{}' doesn't match the certificate's enrollment '{client_uid}'",
            event.uid
        )),
    }
}

/// The no-impersonation rule: `Drop` an event that claims, as its uid or
/// producer, the enrolled uid of another device than `mine` (this
/// certificate's enrolled uid).
pub fn impersonation(registry: &DeviceRegistry, mine: Option<&str>, event: &Event) -> Verdict {
    if let Some(owner) = registry.other_owner_of_enrolled_uid(&event.uid, mine) {
        return Verdict::Drop(format!("uid '{}' belongs to device '{owner}'", event.uid));
    }
    for producer in event.producer_uids() {
        if let Some(owner) = registry.other_owner_of_enrolled_uid(producer, mine) {
            return Verdict::Drop(format!(
                "claims to be produced by '{producer}', which belongs to device '{owner}'"
            ));
        }
    }
    Verdict::Relay
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::tests::{ATAK_CHAT, ATAK_MARKER, ATAK_SA};

    fn event(xml: &str) -> Event {
        Event::from_xml(xml).unwrap()
    }

    fn enrolled(uid: &str) -> Option<String> {
        Some(uid.to_string())
    }

    #[test]
    fn an_sa_with_the_certificates_client_uid_is_relayed() {
        assert_eq!(
            validate_client_uid(Some(&enrolled("ANDROID-abc123")), &event(ATAK_SA)),
            Verdict::Relay
        );
    }

    #[test]
    fn an_sa_with_another_uid_disconnects() {
        assert!(matches!(
            validate_client_uid(Some(&enrolled("ANDROID-other")), &event(ATAK_SA)),
            Verdict::Disconnect(_)
        ));
    }

    #[test]
    fn a_certificate_not_on_record_passes() {
        assert_eq!(validate_client_uid(None, &event(ATAK_SA)), Verdict::Relay);
    }

    #[test]
    fn a_certificate_without_a_client_uid_has_its_sas_dropped() {
        assert!(matches!(
            validate_client_uid(Some(&None), &event(ATAK_SA)),
            Verdict::Drop(_)
        ));
    }

    /// Chat and markers carry their own uids and are never checked.
    #[test]
    fn content_is_not_checked() {
        let other = enrolled("ANDROID-other");
        for xml in [ATAK_CHAT, ATAK_MARKER] {
            assert_eq!(
                validate_client_uid(Some(&other), &event(xml)),
                Verdict::Relay
            );
            assert_eq!(
                validate_client_uid(Some(&None), &event(xml)),
                Verdict::Relay
            );
        }
    }

    fn registry() -> DeviceRegistry {
        let registry = DeviceRegistry::in_memory();
        registry
            .enroll_with_client_uid("alpha", "c1", 1, Some("ANDROID-abc123"))
            .unwrap();
        registry
            .enroll_with_client_uid("mallory", "c2", 2, Some("ANDROID-mal"))
            .unwrap();
        registry
    }

    /// Alpha's SA (its uid), its chat and its marker (alpha as producer),
    /// sent by mallory.
    #[test]
    fn content_claiming_another_devices_enrolled_uid_is_dropped() {
        let registry = registry();
        for xml in [ATAK_SA, ATAK_CHAT, ATAK_MARKER] {
            assert!(
                matches!(
                    impersonation(&registry, Some("ANDROID-mal"), &event(xml)),
                    Verdict::Drop(_)
                ),
                "{xml}"
            );
        }
    }

    #[test]
    fn a_devices_own_content_and_unknown_uids_are_relayed() {
        let registry = registry();
        for xml in [ATAK_SA, ATAK_CHAT, ATAK_MARKER] {
            assert_eq!(
                impersonation(&registry, Some("ANDROID-abc123"), &event(xml)),
                Verdict::Relay
            );
            let unknown = xml.replace("ANDROID-abc123", "ANDROID-nobody");
            assert_eq!(
                impersonation(&registry, Some("ANDROID-mal"), &event(&unknown)),
                Verdict::Relay
            );
        }
    }
}
