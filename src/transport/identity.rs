//! What an authenticated (mTLS) connection may say, and as whom
//! (TC-TLS-04, revised 2026-09-29).
//!
//! A device's identity is its **own situational-awareness report** -- its
//! position/"PLI", recognised the way the official TAK Server does
//! ([`Event::is_situational_awareness`]: a `uid` plus a `<contact>` with a
//! `callsign` *and* an `endpoint`). Only those reports bind and must match
//! the device's uid; the first one binds it (trust on first use), and a
//! later one claiming a different uid ends the connection -- the same check
//! as the official server's optional `validateClientUid`.
//!
//! Everything else a device sends is content it *authored* -- GeoChat
//! messages (`b-t-f`, uid `GeoChat.<sender>.<room>.<id>`), markers, shapes,
//! routes, each with its own uid -- and is allowed, except that nothing may
//! impersonate another enrolled device:
//! - an event whose uid is another device's bound uid is dropped (it would
//!   overwrite that device's position/contact on everyone's map), and
//! - an event naming another device as its producer (`<link
//!   relation="p-p" uid=…>` -- a chat message's sender, a marker's creator)
//!   is dropped.
//!
//! Dropping (rather than disconnecting) for authored content keeps one bad
//! message from cutting a device off; the SA mismatch still disconnects,
//! as before and as in the official server.

use crate::cot::Event;
use crate::registry::{DeviceRegistry, RegistryError};

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Relay,
    Drop(String),
    Disconnect(String),
}

pub fn authorize(registry: &DeviceRegistry, common_name: &str, event: &Event) -> Verdict {
    if event.is_situational_awareness() {
        return match registry.bind_uid(common_name, &event.uid) {
            Ok(()) => Verdict::Relay,
            Err(error @ (RegistryError::UidOwnedByOtherDevice { .. }
            | RegistryError::DeviceUidMismatch { .. })) => Verdict::Disconnect(error.to_string()),
            Err(error) => Verdict::Disconnect(format!("identity check failed: {error}")),
        };
    }

    if let Some(owner) = registry.owner_of_uid(&event.uid)
        && owner != common_name
    {
        return Verdict::Drop(format!(
            "uid '{}' belongs to device '{owner}'",
            event.uid
        ));
    }
    for producer in event.producer_uids() {
        if let Some(owner) = registry.owner_of_uid(producer)
            && owner != common_name
        {
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

    fn registry_with(devices: &[&str]) -> DeviceRegistry {
        let registry = DeviceRegistry::in_memory();
        for device in devices {
            registry.enroll(device, "cert", 0).unwrap();
        }
        registry
    }

    fn event(xml: &str) -> Event {
        Event::from_xml(xml).unwrap()
    }

    fn with_uid(xml: &str, from: &str, to: &str) -> Event {
        event(&xml.replace(from, to))
    }

    #[test]
    fn a_devices_first_sa_binds_its_uid_and_later_ones_must_match() {
        let registry = registry_with(&["alpha"]);
        assert_eq!(authorize(&registry, "alpha", &event(ATAK_SA)), Verdict::Relay);
        assert_eq!(registry.find("alpha").unwrap().uid.as_deref(), Some("ANDROID-abc123"));
        assert_eq!(authorize(&registry, "alpha", &event(ATAK_SA)), Verdict::Relay);

        let other = with_uid(ATAK_SA, "ANDROID-abc123", "ANDROID-zzz");
        assert!(matches!(authorize(&registry, "alpha", &other), Verdict::Disconnect(_)));
    }

    #[test]
    fn an_sa_claiming_another_devices_uid_disconnects() {
        let registry = registry_with(&["alpha", "mallory"]);
        authorize(&registry, "alpha", &event(ATAK_SA));
        assert!(matches!(
            authorize(&registry, "mallory", &event(ATAK_SA)),
            Verdict::Disconnect(_)
        ));
        assert_eq!(registry.find("mallory").unwrap().uid, None);
    }

    /// The bug this fixes: chat and markers carry their own uids and must
    /// not be checked against the device's bound uid.
    #[test]
    fn a_devices_own_chat_and_markers_are_relayed() {
        let registry = registry_with(&["alpha"]);
        authorize(&registry, "alpha", &event(ATAK_SA));
        assert_eq!(authorize(&registry, "alpha", &event(ATAK_CHAT)), Verdict::Relay);
        assert_eq!(authorize(&registry, "alpha", &event(ATAK_MARKER)), Verdict::Relay);
        assert_eq!(registry.find("alpha").unwrap().uid.as_deref(), Some("ANDROID-abc123"));
    }

    /// Content sent before any SA doesn't bind the device to a chat or
    /// marker uid (which would later reject its real position).
    #[test]
    fn content_before_the_first_sa_binds_nothing() {
        let registry = registry_with(&["alpha"]);
        assert_eq!(authorize(&registry, "alpha", &event(ATAK_CHAT)), Verdict::Relay);
        assert_eq!(registry.find("alpha").unwrap().uid, None);
        assert_eq!(authorize(&registry, "alpha", &event(ATAK_SA)), Verdict::Relay);
        assert_eq!(registry.find("alpha").unwrap().uid.as_deref(), Some("ANDROID-abc123"));
    }

    /// A non-SA event reusing another device's uid would overwrite that
    /// device on everyone's map -- dropped.
    #[test]
    fn content_reusing_another_devices_uid_is_dropped() {
        let registry = registry_with(&["alpha", "mallory"]);
        authorize(&registry, "alpha", &event(ATAK_SA));
        let fake_position = with_uid(crate::cot::tests::MINIMAL_EVENT_PUB, "TEST-UID-1", "ANDROID-abc123");
        assert!(matches!(authorize(&registry, "mallory", &fake_position), Verdict::Drop(_)));
    }

    /// Chat "from" another device, or a marker "created by" another device
    /// (`link relation="p-p"`) -- dropped.
    #[test]
    fn content_naming_another_device_as_producer_is_dropped() {
        let registry = registry_with(&["alpha", "mallory"]);
        authorize(&registry, "alpha", &event(ATAK_SA));
        authorize(&registry, "mallory", &with_uid(ATAK_SA, "ANDROID-abc123", "ANDROID-mal"));
        assert!(matches!(authorize(&registry, "mallory", &event(ATAK_CHAT)), Verdict::Drop(_)));
        assert!(matches!(authorize(&registry, "mallory", &event(ATAK_MARKER)), Verdict::Drop(_)));
        // Its own chat is fine.
        let own_chat = with_uid(ATAK_CHAT, "ANDROID-abc123", "ANDROID-mal");
        assert_eq!(authorize(&registry, "mallory", &own_chat), Verdict::Relay);
    }

    /// Links to uids no device has bound (e.g. a marker linked to another
    /// marker, `relation="c-c"`, or an unenrolled producer) don't matter.
    #[test]
    fn links_to_unbound_uids_are_fine() {
        let registry = registry_with(&["alpha"]);
        assert_eq!(authorize(&registry, "alpha", &event(ATAK_MARKER)), Verdict::Relay);
    }
}
