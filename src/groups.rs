//! Groups ("channels"), mirroring the official TAK Server's model.
//!
//! Every identity (a device's certificate Common Name) is a member of
//! named groups, each membership carrying a **direction**, exactly as in
//! the official server (`com.bbn.marti.remote.groups.Direction`, confirmed
//! from `TAK-Product-Center/Server`'s source):
//!
//! - **IN** -- the identity may send *into* the group: its messages are
//!   tagged with its active IN groups.
//! - **OUT** -- the identity receives *from* the group: a message reaches it
//!   when one of the message's groups is among its active OUT groups
//!   (official `CommonGroupDirectedReachability.isReachable`).
//!
//! An identity with no memberships at all is in [`ANON_GROUP`] (`__ANON__`)
//! both ways -- the official server's anonymous assignment -- so a
//! deployment that never creates a group behaves exactly as before: everyone
//! reaches everyone. Plain-TCP (unauthenticated) connections are treated as
//! anonymous the same way.
//!
//! A device can switch its groups on and off (ATAK's channel selector;
//! official `PUT /Marti/api/groups/active` / `activebits`): inactive groups
//! are ignored for both sending and receiving. Each group has a stable
//! `bitpos`, which the `activebits` form refers to. Membership and
//! activation changes take effect for already-connected devices at once.
//!
//! Persisted like every other store: an append-only, replayable event log.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::eventlog::{EventLog, EventLogError};

/// The official server's anonymous group, and MicroTAK's default for any
/// identity without explicit memberships.
pub const ANON_GROUP: &str = "__ANON__";

#[derive(Debug, Error, PartialEq)]
pub enum GroupError {
    #[error("unknown group '{0}'")]
    NotFound(String),
    #[error("group '{0}' already exists")]
    AlreadyExists(String),
    #[error("invalid group name '{0}': 1-64 characters, no control characters, not '__ANON__'")]
    InvalidName(String),
    #[error("at least one group must stay active")]
    NoActiveGroup,
    #[error("event log error: {0}")]
    EventLog(String),
}

impl From<EventLogError> for GroupError {
    fn from(error: EventLogError) -> Self {
        GroupError::EventLog(error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Direction {
    In,
    Out,
}

/// Which directions a membership has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Membership {
    In,
    Out,
    Both,
}

impl Membership {
    pub fn includes(self, direction: Direction) -> bool {
        matches!(
            (self, direction),
            (Membership::Both, _) | (Membership::In, Direction::In) | (Membership::Out, Direction::Out)
        )
    }

    fn merge(self, other: Membership) -> Membership {
        if self == other { self } else { Membership::Both }
    }
}

/// A membership to hand out -- carried by invite tokens and password
/// accounts and applied when the device enrolls (like the official
/// server's user file `groupList` / `groupListIN` / `groupListOUT`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupGrant {
    pub name: String,
    pub membership: Membership,
}

/// Build grants from the official-style lists: `both` (IN+OUT), `ins`,
/// `outs`; a group named in more than one list gets the union.
pub fn grants_from(both: &[String], ins: &[String], outs: &[String]) -> Vec<GroupGrant> {
    let mut merged: BTreeMap<String, Membership> = BTreeMap::new();
    let lists = [(both, Membership::Both), (ins, Membership::In), (outs, Membership::Out)];
    for (names, membership) in lists {
        for name in names {
            merged
                .entry(name.clone())
                .and_modify(|m| *m = m.merge(membership))
                .or_insert(membership);
        }
    }
    merged
        .into_iter()
        .map(|(name, membership)| GroupGrant { name, membership })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupInfo {
    pub name: String,
    pub description: Option<String>,
    pub bitpos: u32,
    pub created_at_unix: i64,
    /// identity -> membership
    pub members: BTreeMap<String, Membership>,
}

/// One of an identity's memberships, as the official client API reports
/// it: one entry per (group, direction), with its active flag.
#[derive(Debug, Clone, PartialEq)]
pub struct MemberGroup {
    pub name: String,
    pub direction: Direction,
    pub bitpos: u32,
    pub created_at_unix: i64,
    pub description: Option<String>,
    pub active: bool,
}

struct GroupRecord {
    description: Option<String>,
    bitpos: u32,
    created_at_unix: i64,
}

#[derive(Default)]
struct State {
    groups: BTreeMap<String, GroupRecord>,
    /// identity -> group -> membership
    members: HashMap<String, BTreeMap<String, Membership>>,
    /// identity -> groups it has switched *off* (default: all on)
    inactive: HashMap<String, BTreeSet<String>>,
    next_bitpos: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum GroupEvent {
    Created {
        name: String,
        description: Option<String>,
        created_at_unix: i64,
    },
    Deleted {
        name: String,
    },
    MemberSet {
        identity: String,
        group: String,
        /// `None` removes the membership.
        membership: Option<Membership>,
    },
    ActiveSet {
        identity: String,
        inactive: Vec<String>,
    },
}

pub struct GroupStore {
    state: RwLock<State>,
    log: Option<EventLog<GroupEvent>>,
}

fn fresh_state() -> State {
    let mut state = State {
        next_bitpos: 1,
        ..State::default()
    };
    state.groups.insert(
        ANON_GROUP.to_string(),
        GroupRecord {
            description: Some("Default group for identities without explicit memberships".into()),
            bitpos: 0,
            created_at_unix: 0,
        },
    );
    state
}

fn validate_name(name: &str) -> Result<(), GroupError> {
    let ok = !name.trim().is_empty()
        && name.chars().count() <= 64
        && !name.chars().any(char::is_control)
        && name != ANON_GROUP;
    if ok { Ok(()) } else { Err(GroupError::InvalidName(name.to_string())) }
}

impl GroupStore {
    pub fn in_memory() -> Self {
        Self {
            state: RwLock::new(fresh_state()),
            log: None,
        }
    }

    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, GroupError> {
        let mut state = fresh_state();
        let log = EventLog::open_and_replay(path, &mut state, apply_event)?;
        Ok(Self {
            state: RwLock::new(state),
            log: Some(log),
        })
    }

    fn record(&self, state: &mut State, event: GroupEvent) -> Result<(), GroupError> {
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(state, &event);
        Ok(())
    }

    pub fn create(&self, name: &str, description: Option<String>, now_unix: i64) -> Result<(), GroupError> {
        validate_name(name)?;
        let mut state = self.state.write().unwrap();
        if state.groups.contains_key(name) {
            return Err(GroupError::AlreadyExists(name.to_string()));
        }
        self.record(
            &mut state,
            GroupEvent::Created {
                name: name.to_string(),
                description,
                created_at_unix: now_unix,
            },
        )
    }

    /// Delete a group and every membership in it. `__ANON__` can't be
    /// deleted.
    pub fn delete(&self, name: &str) -> Result<(), GroupError> {
        if name == ANON_GROUP {
            return Err(GroupError::InvalidName(name.to_string()));
        }
        let mut state = self.state.write().unwrap();
        if !state.groups.contains_key(name) {
            return Err(GroupError::NotFound(name.to_string()));
        }
        self.record(&mut state, GroupEvent::Deleted { name: name.to_string() })
    }

    pub fn exists(&self, name: &str) -> bool {
        self.state.read().unwrap().groups.contains_key(name)
    }

    /// The first granted group that doesn't exist (any more), if any.
    pub fn first_missing(&self, grants: &[GroupGrant]) -> Option<String> {
        let state = self.state.read().unwrap();
        grants
            .iter()
            .find(|g| !state.groups.contains_key(&g.name))
            .map(|g| g.name.clone())
    }

    /// Set (or, with `None`, remove) `identity`'s membership in `group`.
    pub fn set_member(&self, group: &str, identity: &str, membership: Option<Membership>) -> Result<(), GroupError> {
        let mut state = self.state.write().unwrap();
        if !state.groups.contains_key(group) {
            return Err(GroupError::NotFound(group.to_string()));
        }
        self.record(
            &mut state,
            GroupEvent::MemberSet {
                identity: identity.to_string(),
                group: group.to_string(),
                membership,
            },
        )
    }

    /// Add memberships (merging directions with any existing ones) -- how
    /// an invite token's or account's groups are applied at enrollment.
    /// Unknown groups are an error and nothing is applied.
    pub fn grant(&self, identity: &str, grants: &[GroupGrant]) -> Result<(), GroupError> {
        let mut state = self.state.write().unwrap();
        if let Some(missing) = grants.iter().find(|g| !state.groups.contains_key(&g.name)) {
            return Err(GroupError::NotFound(missing.name.clone()));
        }
        for GroupGrant { name: group, membership } in grants {
            let merged = match state.members.get(identity).and_then(|m| m.get(group)) {
                Some(existing) => existing.merge(*membership),
                None => *membership,
            };
            self.record(
                &mut state,
                GroupEvent::MemberSet {
                    identity: identity.to_string(),
                    group: group.clone(),
                    membership: Some(merged),
                },
            )?;
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<GroupInfo> {
        let state = self.state.read().unwrap();
        state
            .groups
            .iter()
            .map(|(name, record)| GroupInfo {
                name: name.clone(),
                description: record.description.clone(),
                bitpos: record.bitpos,
                created_at_unix: record.created_at_unix,
                members: state
                    .members
                    .iter()
                    .filter_map(|(identity, groups)| groups.get(name).map(|m| (identity.clone(), *m)))
                    .collect(),
            })
            .collect()
    }

    /// `identity`'s memberships (explicit, or the anonymous default), one
    /// entry per direction, with active flags.
    pub fn memberships(&self, identity: &str) -> Vec<MemberGroup> {
        let state = self.state.read().unwrap();
        let inactive = state.inactive.get(identity);
        effective_memberships(&state, identity)
            .into_iter()
            .flat_map(|(group, membership)| {
                [Direction::In, Direction::Out]
                    .into_iter()
                    .filter(move |d| membership.includes(*d))
                    .map(move |d| (group.clone(), d))
            })
            .filter_map(|(group, direction)| {
                let record = state.groups.get(&group)?;
                Some(MemberGroup {
                    active: !inactive.is_some_and(|off| off.contains(&group)),
                    name: group,
                    direction,
                    bitpos: record.bitpos,
                    created_at_unix: record.created_at_unix,
                    description: record.description.clone(),
                })
            })
            .collect()
    }

    /// The names of `identity`'s *active* groups in `direction` -- what
    /// routing uses. `None` means an unauthenticated connection, treated as
    /// anonymous.
    pub fn active_groups(&self, identity: Option<&str>, direction: Direction) -> BTreeSet<String> {
        let Some(identity) = identity else {
            return BTreeSet::from([ANON_GROUP.to_string()]);
        };
        let state = self.state.read().unwrap();
        let inactive = state.inactive.get(identity);
        effective_memberships(&state, identity)
            .into_iter()
            .filter(|(group, membership)| {
                membership.includes(direction) && !inactive.is_some_and(|off| off.contains(group))
            })
            .map(|(group, _)| group)
            .collect()
    }

    /// Every group `identity` belongs to in either direction, active or
    /// not -- what mission visibility is checked against.
    pub fn all_group_names(&self, identity: &str) -> BTreeSet<String> {
        let state = self.state.read().unwrap();
        effective_memberships(&state, identity).into_iter().map(|(g, _)| g).collect()
    }

    /// Switch `identity`'s groups on/off: `active` names the groups to keep
    /// on; its other memberships are switched off. At least one must stay
    /// on (otherwise the device would silently go dark).
    pub fn set_active(&self, identity: &str, active: &BTreeSet<String>) -> Result<(), GroupError> {
        let mut state = self.state.write().unwrap();
        let member_of: BTreeSet<String> =
            effective_memberships(&state, identity).into_iter().map(|(g, _)| g).collect();
        if member_of.intersection(active).next().is_none() {
            return Err(GroupError::NoActiveGroup);
        }
        let inactive: Vec<String> = member_of.difference(active).cloned().collect();
        self.record(
            &mut state,
            GroupEvent::ActiveSet {
                identity: identity.to_string(),
                inactive,
            },
        )
    }

    /// Group names by `bitpos` -- for the `activebits` form.
    pub fn names_for_bitpos(&self, bitpos: &[u32]) -> BTreeSet<String> {
        let state = self.state.read().unwrap();
        state
            .groups
            .iter()
            .filter(|(_, record)| bitpos.contains(&record.bitpos))
            .map(|(name, _)| name.clone())
            .collect()
    }
}

/// Explicit memberships, or `__ANON__` both ways when there are none.
fn effective_memberships(state: &State, identity: &str) -> Vec<(String, Membership)> {
    match state.members.get(identity) {
        Some(groups) if !groups.is_empty() => groups.iter().map(|(g, m)| (g.clone(), *m)).collect(),
        _ => vec![(ANON_GROUP.to_string(), Membership::Both)],
    }
}

fn apply_event(state: &mut State, event: &GroupEvent) {
    match event {
        GroupEvent::Created {
            name,
            description,
            created_at_unix,
        } => {
            let bitpos = state.next_bitpos;
            state.next_bitpos += 1;
            state.groups.insert(
                name.clone(),
                GroupRecord {
                    description: description.clone(),
                    bitpos,
                    created_at_unix: *created_at_unix,
                },
            );
        }
        GroupEvent::Deleted { name } => {
            state.groups.remove(name);
            for groups in state.members.values_mut() {
                groups.remove(name);
            }
            for off in state.inactive.values_mut() {
                off.remove(name);
            }
        }
        GroupEvent::MemberSet {
            identity,
            group,
            membership,
        } => {
            let groups = state.members.entry(identity.clone()).or_default();
            match membership {
                Some(m) => {
                    groups.insert(group.clone(), *m);
                }
                None => {
                    groups.remove(group);
                }
            }
        }
        GroupEvent::ActiveSet { identity, inactive } => {
            state
                .inactive
                .insert(identity.clone(), inactive.iter().cloned().collect());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// Official anonymous assignment: no memberships -> `__ANON__` both
    /// ways, so a deployment without groups behaves as before.
    #[test]
    fn identities_without_memberships_are_anonymous_both_ways() {
        let store = GroupStore::in_memory();
        assert_eq!(store.active_groups(Some("alpha"), Direction::In), set(&[ANON_GROUP]));
        assert_eq!(store.active_groups(Some("alpha"), Direction::Out), set(&[ANON_GROUP]));
        assert_eq!(store.active_groups(None, Direction::Out), set(&[ANON_GROUP]));
    }

    #[test]
    fn explicit_memberships_replace_the_anonymous_default_and_keep_direction() {
        let store = GroupStore::in_memory();
        store.create("Red", None, 1).unwrap();
        store.create("Blue", None, 1).unwrap();
        store.set_member("Red", "alpha", Some(Membership::Both)).unwrap();
        store.set_member("Blue", "alpha", Some(Membership::Out)).unwrap();
        assert_eq!(store.active_groups(Some("alpha"), Direction::In), set(&["Red"]));
        assert_eq!(store.active_groups(Some("alpha"), Direction::Out), set(&["Blue", "Red"]));
        assert_eq!(store.all_group_names("alpha"), set(&["Blue", "Red"]));
    }

    #[test]
    fn deactivated_groups_are_ignored_both_ways_and_one_must_stay_active() {
        let store = GroupStore::in_memory();
        store.create("Red", None, 1).unwrap();
        store.create("Blue", None, 1).unwrap();
        store.set_member("Red", "alpha", Some(Membership::Both)).unwrap();
        store.set_member("Blue", "alpha", Some(Membership::Both)).unwrap();
        store.set_active("alpha", &set(&["Red"])).unwrap();
        assert_eq!(store.active_groups(Some("alpha"), Direction::In), set(&["Red"]));
        assert_eq!(store.active_groups(Some("alpha"), Direction::Out), set(&["Red"]));
        assert_eq!(store.set_active("alpha", &set(&[])), Err(GroupError::NoActiveGroup));
        assert_eq!(store.set_active("alpha", &set(&["Green"])), Err(GroupError::NoActiveGroup));
        let flags: Vec<(String, bool)> = store
            .memberships("alpha")
            .into_iter()
            .filter(|m| m.direction == Direction::Out)
            .map(|m| (m.name, m.active))
            .collect();
        assert_eq!(flags, vec![("Blue".to_string(), false), ("Red".to_string(), true)]);
    }

    #[test]
    fn bitpos_is_stable_and_resolves_names() {
        let store = GroupStore::in_memory();
        store.create("Red", None, 1).unwrap();
        store.create("Blue", None, 1).unwrap();
        store.delete("Red").unwrap();
        store.create("Green", None, 1).unwrap();
        let bits: BTreeMap<String, u32> = store.list().into_iter().map(|g| (g.name, g.bitpos)).collect();
        assert_eq!(bits[ANON_GROUP], 0);
        assert_eq!(bits["Blue"], 2);
        assert_eq!(bits["Green"], 3, "a deleted group's bitpos is never reused");
        assert_eq!(store.names_for_bitpos(&[0, 3]), set(&[ANON_GROUP, "Green"]));
    }

    #[test]
    fn grant_merges_directions_and_is_all_or_nothing() {
        let store = GroupStore::in_memory();
        store.create("Red", None, 1).unwrap();
        store.grant("alpha", &grants_from(&[], &["Red".into()], &[])).unwrap();
        store.grant("alpha", &grants_from(&[], &[], &["Red".into()])).unwrap();
        assert_eq!(store.list().iter().find(|g| g.name == "Red").unwrap().members["alpha"], Membership::Both);
        assert_eq!(
            store.grant("beta", &grants_from(&["Red".into(), "Nope".into()], &[], &[])),
            Err(GroupError::NotFound("Nope".into()))
        );
        assert_eq!(store.all_group_names("beta"), set(&[ANON_GROUP]), "nothing applied");
    }

    #[test]
    fn grants_from_merges_the_official_lists() {
        let grants = grants_from(&["A".into()], &["B".into(), "C".into()], &["C".into()]);
        assert_eq!(
            grants,
            vec![
                GroupGrant { name: "A".into(), membership: Membership::Both },
                GroupGrant { name: "B".into(), membership: Membership::In },
                GroupGrant { name: "C".into(), membership: Membership::Both },
            ]
        );
    }

    #[test]
    fn names_are_validated_and_anon_is_protected() {
        let store = GroupStore::in_memory();
        for bad in ["", "  ", ANON_GROUP, "a\nb", &"x".repeat(65)] {
            assert!(matches!(store.create(bad, None, 1), Err(GroupError::InvalidName(_))), "{bad:?}");
        }
        assert!(store.delete(ANON_GROUP).is_err());
        store.create("Red", None, 1).unwrap();
        assert_eq!(store.create("Red", None, 1), Err(GroupError::AlreadyExists("Red".into())));
    }

    #[test]
    fn deleting_a_group_removes_its_memberships() {
        let store = GroupStore::in_memory();
        store.create("Red", None, 1).unwrap();
        store.set_member("Red", "alpha", Some(Membership::Both)).unwrap();
        store.delete("Red").unwrap();
        assert_eq!(store.all_group_names("alpha"), set(&[ANON_GROUP]));
    }

    #[test]
    fn persists_across_reload() {
        let dir = std::env::temp_dir().join(format!("microtak-groups-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("groups.log");
        std::fs::remove_file(&path).ok();
        {
            let store = GroupStore::load_or_create(&path).unwrap();
            store.create("Red", Some("red team".into()), 5).unwrap();
            store.create("Blue", None, 6).unwrap();
            store.set_member("Red", "alpha", Some(Membership::In)).unwrap();
            store.set_member("Blue", "alpha", Some(Membership::Both)).unwrap();
            store.set_active("alpha", &set(&["Blue"])).unwrap();
        }
        let store = GroupStore::load_or_create(&path).unwrap();
        assert_eq!(store.active_groups(Some("alpha"), Direction::In), set(&["Blue"]));
        let red = store.list().into_iter().find(|g| g.name == "Red").unwrap();
        assert_eq!((red.bitpos, red.description.as_deref()), (1, Some("red team")));
        std::fs::remove_dir_all(&dir).ok();
    }
}
