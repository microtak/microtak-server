//! Missions (Data Sync), modelled on the official TAK Server
//! (`TAK-Product-Center/Server`: `Mission`, `MissionChange`,
//! `MissionSubscription`, `MissionInvitation`, `LogEntry`,
//! `MissionServiceDefaultImpl`, `MissionChangeRepository`). The HTTP side
//! is [`crate::marti::missions`]; the wiki page `Official-Mission-API`
//! has the full contract this follows.
//!
//! What lives here is the state and its rules, independent of HTTP:
//! - missions keyed by **guid**; names are not unique (`POST` with
//!   `allowDupe` makes a second mission of the same name), a name lookup
//!   takes the newest visible, undeleted one;
//! - deletion keeps the mission (flagged), so a deleted name answers 410
//!   and its history stays;
//! - the change log (`CREATE_MISSION`, `DELETE_MISSION`, `ADD_CONTENT`,
//!   `REMOVE_CONTENT`), queried full or **squashed** exactly like the
//!   official SQL (`MissionChangeRepository.MISSION_CHANGES`);
//! - stored subscriptions (with their token and role), invitations, log
//!   entries.
//!
//! Persisted as an append-only, replayable event log
//! ([`crate::eventlog`]) in `official-missions.log`. Missions created by
//! MicroTAK ≤ 0.8 (`missions.log`, a different, non-official model) are not
//! migrated.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::eventlog::{EventLog, EventLogError};

#[derive(Debug, Error)]
pub enum MissionError {
    #[error("no mission with guid '{0}'")]
    NotFound(String),
    #[error("event log error: {0}")]
    EventLog(#[from] EventLogError),
}

/// `MissionPermission.Permission`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Permission {
    MissionRead,
    MissionWrite,
    MissionDelete,
    MissionSetRole,
    MissionSetPassword,
    MissionUpdateGroups,
    MissionManageFeeds,
    MissionManageLayers,
}

/// `MissionRole.Role`, with the official schema's permissions
/// (`V33__data_sync_phase3.sql`, `V37`, `V48`, `V73`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    #[serde(rename = "MISSION_OWNER")]
    Owner,
    #[serde(rename = "MISSION_SUBSCRIBER")]
    Subscriber,
    #[serde(rename = "MISSION_READONLY_SUBSCRIBER")]
    ReadOnlySubscriber,
}

impl Role {
    /// `MissionRole.defaultRole`.
    pub const DEFAULT: Role = Role::Subscriber;

    pub fn name(self) -> &'static str {
        match self {
            Role::Owner => "MISSION_OWNER",
            Role::Subscriber => "MISSION_SUBSCRIBER",
            Role::ReadOnlySubscriber => "MISSION_READONLY_SUBSCRIBER",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "MISSION_OWNER" => Some(Role::Owner),
            "MISSION_SUBSCRIBER" => Some(Role::Subscriber),
            "MISSION_READONLY_SUBSCRIBER" => Some(Role::ReadOnlySubscriber),
            _ => None,
        }
    }

    pub fn permissions(self) -> &'static [Permission] {
        use Permission::*;
        match self {
            Role::Owner => &[
                MissionRead,
                MissionWrite,
                MissionDelete,
                MissionSetRole,
                MissionSetPassword,
                MissionUpdateGroups,
                MissionManageFeeds,
                MissionManageLayers,
            ],
            Role::Subscriber => &[MissionRead, MissionWrite],
            Role::ReadOnlySubscriber => &[MissionRead],
        }
    }

    pub fn has(self, permission: Permission) -> bool {
        self.permissions().contains(&permission)
    }

    /// `MissionRole.hasAllPermissions`.
    pub fn has_all(self, other: Role) -> bool {
        other.permissions().iter().all(|p| self.has(*p))
    }
}

/// Mission content: an Enterprise Sync resource (by hash) or a CoT uid.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Content {
    Hash(String),
    Uid(String),
}

/// One entry of `Mission.uids` / `Mission.contents` (`Mission.MissionAdd`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentAdd {
    pub content: Content,
    pub timestamp_ms: i64,
    pub creator_uid: String,
}

/// The mission's own fields (`Mission`), as created or updated.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MissionFields {
    pub description: String,
    pub chat_room: String,
    pub base_layer: String,
    pub bbox: String,
    pub bounding_polygon: String,
    pub path: String,
    pub classification: String,
    /// `Mission.expiration`, -1 = none.
    pub expiration: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MissionRecord {
    pub guid: String,
    pub name: String,
    pub fields: MissionFields,
    pub tool: String,
    pub creator_uid: String,
    pub create_time_ms: i64,
    pub last_edited_ms: i64,
    pub groups: BTreeSet<String>,
    /// Argon2 PHC string; the official server uses BCrypt -- never exposed.
    pub password_hash: Option<String>,
    pub default_role: Option<Role>,
    pub invite_only: bool,
    /// `Mission.keywords`, a sorted set.
    pub keywords: BTreeSet<String>,
    /// Keywords per uid / hash (`mission_uid_keyword`,
    /// `mission_resource_keyword`), kept whether or not the item is in
    /// the mission, as the official tables are.
    pub content_keywords: BTreeMap<Content, Vec<String>>,
    /// Content, each with its latest add, in the order of those adds.
    pub contents: Vec<ContentAdd>,
    pub deleted: bool,
}

impl MissionRecord {
    pub fn password_protected(&self) -> bool {
        self.password_hash.is_some()
    }

    /// `MissionService.getDefaultRole`.
    pub fn effective_default_role(&self) -> Role {
        self.default_role.unwrap_or(Role::DEFAULT)
    }

    pub fn has(&self, content: &Content) -> bool {
        self.contents.iter().any(|c| &c.content == content)
    }

    pub fn uids(&self) -> impl Iterator<Item = &ContentAdd> {
        self.contents
            .iter()
            .filter(|c| matches!(c.content, Content::Uid(_)))
    }

    pub fn hashes(&self) -> impl Iterator<Item = &ContentAdd> {
        self.contents
            .iter()
            .filter(|c| matches!(c.content, Content::Hash(_)))
    }
}

/// `MissionChangeType` (the subset with an API here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    #[serde(rename = "CREATE_MISSION")]
    CreateMission,
    #[serde(rename = "DELETE_MISSION")]
    DeleteMission,
    #[serde(rename = "ADD_CONTENT")]
    AddContent,
    #[serde(rename = "REMOVE_CONTENT")]
    RemoveContent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeRecord {
    /// Store-wide increasing id; changes are returned newest id first
    /// (`MissionChange.compareTo`).
    pub id: u64,
    pub change_type: ChangeType,
    pub mission_guid: String,
    pub mission_name: String,
    pub content: Option<Content>,
    pub creator_uid: String,
    pub timestamp_ms: i64,
    pub server_time_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionRecord {
    /// The subscription's own id (`MissionSubscription.uid`, not exposed).
    pub id: String,
    pub token: String,
    pub client_uid: String,
    pub username: String,
    pub create_time_ms: i64,
    pub role: Role,
}

/// `MissionInvitation.Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InvitationType {
    ClientUid,
    Callsign,
    UserName,
    Group,
    Team,
}

impl InvitationType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "clientUid" => Some(Self::ClientUid),
            "callsign" => Some(Self::Callsign),
            "userName" => Some(Self::UserName),
            "group" => Some(Self::Group),
            "team" => Some(Self::Team),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::ClientUid => "clientUid",
            Self::Callsign => "callsign",
            Self::UserName => "userName",
            Self::Group => "group",
            Self::Team => "team",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvitationRecord {
    pub mission_guid: String,
    pub mission_name: String,
    pub invitee: String,
    pub invitation_type: InvitationType,
    pub creator_uid: String,
    pub create_time_ms: i64,
    pub token: String,
    pub role: Role,
}

/// `LogEntry`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LogEntryRecord {
    pub id: String,
    pub content: String,
    pub creator_uid: String,
    pub entry_uid: String,
    pub mission_names: Vec<String>,
    pub server_time_ms: i64,
    pub dtg_ms: Option<i64>,
    pub created_ms: Option<i64>,
    pub content_hashes: Vec<String>,
    pub keywords: Vec<String>,
}

/// `MissionLayer.Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LayerType {
    Group,
    Uid,
    Contents,
    Maplayer,
    Item,
}

impl LayerType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "GROUP" => Some(Self::Group),
            "UID" => Some(Self::Uid),
            "CONTENTS" => Some(Self::Contents),
            "MAPLAYER" => Some(Self::Maplayer),
            "ITEM" => Some(Self::Item),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Group => "GROUP",
            Self::Uid => "UID",
            Self::Contents => "CONTENTS",
            Self::Maplayer => "MAPLAYER",
            Self::Item => "ITEM",
        }
    }
}

/// A row of the official `mission_layer` table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LayerRecord {
    pub uid: String,
    pub name: Option<String>,
    pub layer_type: LayerType,
    /// `parent_node_uid` as stored (not checked to exist).
    pub parent: Option<String>,
    pub after: Option<String>,
}

/// A time window over `servertime` (`TimeUtils.validateTimeInterval`).
#[derive(Debug, Clone, Copy)]
pub struct Window {
    pub start_ms: i64,
    pub end_ms: i64,
}

impl Window {
    pub const ALL: Window = Window {
        start_ms: i64::MIN,
        end_ms: i64::MAX,
    };

    fn contains(&self, t: i64) -> bool {
        self.start_ms <= t && t <= self.end_ms
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Event {
    Created {
        mission: Box<MissionRecord>,
        change_id: u64,
    },
    FieldsSet {
        guid: String,
        fields: MissionFields,
        at_ms: i64,
    },
    PasswordSet {
        guid: String,
        password_hash: Option<String>,
        at_ms: i64,
    },
    DefaultRoleSet {
        guid: String,
        role: Option<Role>,
        at_ms: i64,
    },
    GroupsSet {
        guid: String,
        groups: BTreeSet<String>,
        at_ms: i64,
    },
    KeywordsSet {
        guid: String,
        keywords: BTreeSet<String>,
        at_ms: i64,
    },
    ContentKeywordsSet {
        guid: String,
        content: Content,
        keywords: Vec<String>,
    },
    Deleted {
        guid: String,
        creator_uid: String,
        at_ms: i64,
        change_id: u64,
    },
    ContentAdded {
        guid: String,
        content: Content,
        creator_uid: String,
        at_ms: i64,
        change_id: u64,
    },
    ContentRemoved {
        guid: String,
        content: Content,
        creator_uid: String,
        at_ms: i64,
        change_id: u64,
    },
    Subscribed {
        guid: String,
        subscription: SubscriptionRecord,
    },
    SubscriptionRoleSet {
        guid: String,
        id: String,
        role: Role,
    },
    Unsubscribed {
        guid: String,
        id: String,
    },
    Invited {
        invitation: InvitationRecord,
    },
    Uninvited {
        guid: String,
        invitee: String,
        invitation_type: InvitationType,
    },
    LogEntrySaved {
        entry: LogEntryRecord,
    },
    LogEntryDeleted {
        id: String,
    },
    LayerSaved {
        guid: String,
        layer: LayerRecord,
    },
    LayerNamed {
        guid: String,
        uid: String,
        name: String,
    },
    LayerParentSet {
        guid: String,
        uid: String,
        parent: Option<String>,
    },
    LayerAfterSet {
        guid: String,
        uid: String,
        after: Option<String>,
    },
    LayerDeleted {
        guid: String,
        uid: String,
    },
}

#[derive(Default)]
struct State {
    missions: BTreeMap<String, MissionRecord>,
    changes: Vec<ChangeRecord>,
    subscriptions: BTreeMap<String, Vec<SubscriptionRecord>>,
    invitations: Vec<InvitationRecord>,
    logs: BTreeMap<String, LogEntryRecord>,
    /// mission guid → layers, in insertion order.
    layers: BTreeMap<String, Vec<LayerRecord>>,
    next_change_id: u64,
}

fn apply(state: &mut State, event: &Event) {
    match event.clone() {
        Event::Created { mission, change_id } => {
            let mission = *mission;
            state.changes.push(ChangeRecord {
                id: change_id,
                change_type: ChangeType::CreateMission,
                mission_guid: mission.guid.clone(),
                mission_name: mission.name.clone(),
                content: None,
                creator_uid: mission.creator_uid.clone(),
                timestamp_ms: mission.create_time_ms,
                server_time_ms: mission.create_time_ms,
            });
            state.next_change_id = state.next_change_id.max(change_id + 1);
            state.missions.insert(mission.guid.clone(), mission);
        }
        Event::FieldsSet {
            guid,
            fields,
            at_ms,
        } => {
            if let Some(m) = state.missions.get_mut(&guid) {
                m.fields = fields;
                m.last_edited_ms = at_ms;
            }
        }
        Event::PasswordSet {
            guid,
            password_hash,
            at_ms,
        } => {
            if let Some(m) = state.missions.get_mut(&guid) {
                m.password_hash = password_hash;
                m.last_edited_ms = at_ms;
            }
        }
        Event::DefaultRoleSet { guid, role, at_ms } => {
            if let Some(m) = state.missions.get_mut(&guid) {
                m.default_role = role;
                m.last_edited_ms = at_ms;
            }
        }
        Event::GroupsSet {
            guid,
            groups,
            at_ms,
        } => {
            if let Some(m) = state.missions.get_mut(&guid) {
                m.groups = groups;
                m.last_edited_ms = at_ms;
            }
        }
        Event::KeywordsSet {
            guid,
            keywords,
            at_ms,
        } => {
            if let Some(m) = state.missions.get_mut(&guid) {
                m.keywords = keywords;
                m.last_edited_ms = at_ms;
            }
        }
        Event::ContentKeywordsSet {
            guid,
            content,
            keywords,
        } => {
            if let Some(m) = state.missions.get_mut(&guid) {
                if keywords.is_empty() {
                    m.content_keywords.remove(&content);
                } else {
                    m.content_keywords.insert(content, keywords);
                }
            }
        }
        Event::Deleted {
            guid,
            creator_uid,
            at_ms,
            change_id,
        } => {
            if let Some(m) = state.missions.get_mut(&guid) {
                m.deleted = true;
                state.changes.push(ChangeRecord {
                    id: change_id,
                    change_type: ChangeType::DeleteMission,
                    mission_guid: guid.clone(),
                    mission_name: m.name.clone(),
                    content: None,
                    creator_uid,
                    timestamp_ms: at_ms,
                    server_time_ms: at_ms,
                });
            }
            state.next_change_id = state.next_change_id.max(change_id + 1);
        }
        Event::ContentAdded {
            guid,
            content,
            creator_uid,
            at_ms,
            change_id,
        } => {
            if let Some(m) = state.missions.get_mut(&guid) {
                // An item shows its latest ADD_CONTENT change, ordered by it.
                m.contents.retain(|c| c.content != content);
                m.contents.push(ContentAdd {
                    content: content.clone(),
                    timestamp_ms: at_ms,
                    creator_uid: creator_uid.clone(),
                });
                state.changes.push(ChangeRecord {
                    id: change_id,
                    change_type: ChangeType::AddContent,
                    mission_guid: guid.clone(),
                    mission_name: m.name.clone(),
                    content: Some(content),
                    creator_uid,
                    timestamp_ms: at_ms,
                    server_time_ms: at_ms,
                });
            }
            state.next_change_id = state.next_change_id.max(change_id + 1);
        }
        Event::ContentRemoved {
            guid,
            content,
            creator_uid,
            at_ms,
            change_id,
        } => {
            if let Some(m) = state.missions.get_mut(&guid) {
                m.contents.retain(|c| c.content != content);
                state.changes.push(ChangeRecord {
                    id: change_id,
                    change_type: ChangeType::RemoveContent,
                    mission_guid: guid.clone(),
                    mission_name: m.name.clone(),
                    content: Some(content),
                    creator_uid,
                    timestamp_ms: at_ms,
                    server_time_ms: at_ms,
                });
            }
            state.next_change_id = state.next_change_id.max(change_id + 1);
        }
        Event::Subscribed { guid, subscription } => {
            state
                .subscriptions
                .entry(guid)
                .or_default()
                .push(subscription);
        }
        Event::SubscriptionRoleSet { guid, id, role } => {
            if let Some(sub) = state
                .subscriptions
                .get_mut(&guid)
                .and_then(|subs| subs.iter_mut().find(|s| s.id == id))
            {
                sub.role = role;
            }
        }
        Event::Unsubscribed { guid, id } => {
            if let Some(subs) = state.subscriptions.get_mut(&guid) {
                subs.retain(|s| s.id != id);
            }
        }
        Event::Invited { invitation } => {
            state.invitations.retain(|i| {
                !(i.mission_guid == invitation.mission_guid
                    && i.invitation_type == invitation.invitation_type
                    && i.invitee.eq_ignore_ascii_case(&invitation.invitee))
            });
            state.invitations.push(invitation);
        }
        Event::Uninvited {
            guid,
            invitee,
            invitation_type,
        } => {
            state.invitations.retain(|i| {
                !(i.mission_guid == guid
                    && i.invitation_type == invitation_type
                    && i.invitee.eq_ignore_ascii_case(&invitee))
            });
        }
        Event::LogEntrySaved { entry } => {
            state.logs.insert(entry.id.clone(), entry);
        }
        Event::LogEntryDeleted { id } => {
            state.logs.remove(&id);
        }
        Event::LayerSaved { guid, layer } => {
            state.layers.entry(guid).or_default().push(layer);
        }
        Event::LayerNamed { guid, uid, name } => {
            if let Some(l) = layer_mut(state, &guid, &uid) {
                l.name = Some(name);
            }
        }
        Event::LayerParentSet { guid, uid, parent } => {
            if let Some(l) = layer_mut(state, &guid, &uid) {
                l.parent = parent;
                // `setParent` also clears `after`.
                l.after = None;
            }
        }
        Event::LayerAfterSet { guid, uid, after } => {
            if let Some(l) = layer_mut(state, &guid, &uid) {
                l.after = after;
            }
        }
        Event::LayerDeleted { guid, uid } => {
            if let Some(layers) = state.layers.get_mut(&guid) {
                layers.retain(|l| l.uid != uid);
            }
        }
    }
}

fn layer_mut<'a>(state: &'a mut State, guid: &str, uid: &str) -> Option<&'a mut LayerRecord> {
    state
        .layers
        .get_mut(guid)?
        .iter_mut()
        .find(|l| l.uid == uid)
}

/// A layer with its children, as `MissionLayer` hydrates.
#[derive(Debug, Clone, PartialEq)]
pub struct LayerTree {
    pub layer: LayerRecord,
    pub children: Vec<LayerTree>,
}

/// `MissionLayer.sort`: siblings ordered by their `after` chain; left as
/// they are if two point to the same `after`, a uid repeats, there's a
/// cycle, or an `after` names no sibling.
pub fn sort_layers(unsorted: Vec<LayerRecord>) -> Vec<LayerRecord> {
    let mut afters = BTreeSet::new();
    let mut uids = BTreeSet::new();
    for l in &unsorted {
        if afters.contains(&l.after) || uids.contains(&l.uid) || has_cycle(l, &unsorted) {
            return unsorted;
        }
        afters.insert(l.after.clone());
        uids.insert(l.uid.clone());
    }
    if afters.iter().flatten().any(|a| !uids.contains(a)) {
        return unsorted;
    }
    let mut sorted = unsorted;
    loop {
        let mut moved = false;
        'outer: for outer in 0..sorted.len() {
            for inner in 0..sorted.len() {
                if inner == outer {
                    continue;
                }
                if sorted[inner].after.as_deref() == Some(sorted[outer].uid.as_str())
                    && inner != outer + 1
                {
                    if outer + 1 == sorted.len() {
                        let item = sorted.remove(inner);
                        sorted.push(item);
                    } else {
                        sorted.swap(inner, outer + 1);
                    }
                    moved = true;
                    break 'outer;
                }
            }
        }
        if !moved {
            return sorted;
        }
    }
}

fn has_cycle(check: &LayerRecord, layers: &[LayerRecord]) -> bool {
    let mut seen = BTreeSet::from([check.uid.clone()]);
    let mut current = check;
    while let Some(prev) = current
        .after
        .as_ref()
        .and_then(|a| layers.iter().find(|l| &l.uid == a))
    {
        if !seen.insert(prev.uid.clone()) {
            return true;
        }
        current = prev;
    }
    false
}

/// What a new mission is created with.
#[derive(Debug, Clone)]
pub struct NewMission {
    pub guid: String,
    pub name: String,
    pub fields: MissionFields,
    pub tool: String,
    pub creator_uid: String,
    pub groups: BTreeSet<String>,
    pub password_hash: Option<String>,
    pub default_role: Option<Role>,
    pub invite_only: bool,
}

pub struct MissionStore {
    state: RwLock<State>,
    log: Option<EventLog<Event>>,
}

impl MissionStore {
    pub fn in_memory() -> Self {
        Self {
            state: RwLock::new(State::default()),
            log: None,
        }
    }

    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, MissionError> {
        let mut state = State::default();
        let log = EventLog::open_and_replay(path, &mut state, apply)?;
        Ok(Self {
            state: RwLock::new(state),
            log: Some(log),
        })
    }

    fn record(&self, state: &mut State, event: Event) -> Result<(), MissionError> {
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply(state, &event);
        Ok(())
    }

    fn existing<'a>(state: &'a State, guid: &str) -> Result<&'a MissionRecord, MissionError> {
        state
            .missions
            .get(guid)
            .ok_or_else(|| MissionError::NotFound(guid.to_string()))
    }

    /// `MissionService.createMission`: stores the mission and its
    /// `CREATE_MISSION` change.
    pub fn create(&self, new: NewMission, now_ms: i64) -> Result<MissionRecord, MissionError> {
        let mut state = self.state.write().unwrap();
        let mission = MissionRecord {
            guid: new.guid,
            name: new.name.trim().to_string(),
            fields: new.fields,
            tool: new.tool,
            creator_uid: new.creator_uid,
            create_time_ms: now_ms,
            last_edited_ms: now_ms,
            groups: new.groups,
            password_hash: new.password_hash,
            default_role: new.default_role,
            invite_only: new.invite_only,
            keywords: BTreeSet::new(),
            content_keywords: BTreeMap::new(),
            contents: Vec::new(),
            deleted: false,
        };
        let change_id = state.next_change_id;
        self.record(
            &mut state,
            Event::Created {
                mission: Box::new(mission.clone()),
                change_id,
            },
        )?;
        Ok(mission)
    }

    pub fn by_guid(&self, guid: &str) -> Option<MissionRecord> {
        self.state.read().unwrap().missions.get(guid).cloned()
    }

    /// The newest undeleted mission called `name` (trimmed) among those
    /// `visible` accepts.
    pub fn by_name(
        &self,
        name: &str,
        visible: impl Fn(&MissionRecord) -> bool,
    ) -> Option<MissionRecord> {
        let name = name.trim();
        let state = self.state.read().unwrap();
        state
            .missions
            .values()
            .filter(|m| !m.deleted && m.name == name && visible(m))
            .max_by_key(|m| m.create_time_ms)
            .cloned()
    }

    /// Whether a mission called `name` was deleted and none of that name
    /// exists any more (`MissionService.isDeleted`, answered 410).
    pub fn is_deleted_name(&self, name: &str) -> bool {
        let name = name.trim();
        let state = self.state.read().unwrap();
        let mut same = state
            .missions
            .values()
            .filter(|m| m.name == name)
            .peekable();
        same.peek().is_some() && same.all(|m| m.deleted)
    }

    /// Every undeleted mission.
    pub fn list(&self) -> Vec<MissionRecord> {
        let state = self.state.read().unwrap();
        let mut missions: Vec<_> = state
            .missions
            .values()
            .filter(|m| !m.deleted)
            .cloned()
            .collect();
        missions.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then(a.create_time_ms.cmp(&b.create_time_ms))
        });
        missions
    }

    pub fn set_fields(
        &self,
        guid: &str,
        fields: MissionFields,
        now_ms: i64,
    ) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        Self::existing(&state, guid)?;
        self.record(
            &mut state,
            Event::FieldsSet {
                guid: guid.into(),
                fields,
                at_ms: now_ms,
            },
        )
    }

    pub fn set_password(
        &self,
        guid: &str,
        password_hash: Option<String>,
        now_ms: i64,
    ) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        Self::existing(&state, guid)?;
        self.record(
            &mut state,
            Event::PasswordSet {
                guid: guid.into(),
                password_hash,
                at_ms: now_ms,
            },
        )
    }

    pub fn set_default_role(
        &self,
        guid: &str,
        role: Option<Role>,
        now_ms: i64,
    ) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        Self::existing(&state, guid)?;
        self.record(
            &mut state,
            Event::DefaultRoleSet {
                guid: guid.into(),
                role,
                at_ms: now_ms,
            },
        )
    }

    pub fn set_groups(
        &self,
        guid: &str,
        groups: BTreeSet<String>,
        now_ms: i64,
    ) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        Self::existing(&state, guid)?;
        self.record(
            &mut state,
            Event::GroupsSet {
                guid: guid.into(),
                groups,
                at_ms: now_ms,
            },
        )
    }

    pub fn set_keywords(
        &self,
        guid: &str,
        keywords: BTreeSet<String>,
        now_ms: i64,
    ) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        Self::existing(&state, guid)?;
        self.record(
            &mut state,
            Event::KeywordsSet {
                guid: guid.into(),
                keywords,
                at_ms: now_ms,
            },
        )
    }

    /// Replaces the keywords of one uid or hash (duplicates dropped, as
    /// the official unique constraint does); empty clears them.
    pub fn set_content_keywords(
        &self,
        guid: &str,
        content: Content,
        keywords: Vec<String>,
    ) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        Self::existing(&state, guid)?;
        let mut unique = Vec::new();
        for k in keywords {
            if !unique.contains(&k) {
                unique.push(k);
            }
        }
        self.record(
            &mut state,
            Event::ContentKeywordsSet {
                guid: guid.into(),
                content,
                keywords: unique,
            },
        )
    }

    /// `MissionService.deleteMission`: flags it deleted, `DELETE_MISSION`.
    pub fn delete(
        &self,
        guid: &str,
        creator_uid: &str,
        now_ms: i64,
    ) -> Result<MissionRecord, MissionError> {
        let mut state = self.state.write().unwrap();
        Self::existing(&state, guid)?;
        let change_id = state.next_change_id;
        self.record(
            &mut state,
            Event::Deleted {
                guid: guid.into(),
                creator_uid: creator_uid.into(),
                at_ms: now_ms,
                change_id,
            },
        )?;
        Ok(state.missions[guid].clone())
    }

    /// Adds content (an `ADD_CONTENT` change even if it was already there,
    /// as the official server records one per request).
    pub fn add_content(
        &self,
        guid: &str,
        content: Content,
        creator_uid: &str,
        now_ms: i64,
    ) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        Self::existing(&state, guid)?;
        let change_id = state.next_change_id;
        self.record(
            &mut state,
            Event::ContentAdded {
                guid: guid.into(),
                content,
                creator_uid: creator_uid.into(),
                at_ms: now_ms,
                change_id,
            },
        )
    }

    pub fn remove_content(
        &self,
        guid: &str,
        content: Content,
        creator_uid: &str,
        now_ms: i64,
    ) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        Self::existing(&state, guid)?;
        let change_id = state.next_change_id;
        self.record(
            &mut state,
            Event::ContentRemoved {
                guid: guid.into(),
                content,
                creator_uid: creator_uid.into(),
                at_ms: now_ms,
                change_id,
            },
        )
    }

    /// The mission's changes in `window`, newest first. `squashed` follows
    /// `MissionChangeRepository.MISSION_CHANGES`: creates/deletes since the
    /// latest create; per (content, creator) only the latest add of content
    /// still in the mission, or the latest remove of content no longer in
    /// it -- rows are filtered by the window before squashing, as the SQL's
    /// `where` runs before its `group by`.
    pub fn changes(
        &self,
        guid: &str,
        window: Window,
        squashed: bool,
    ) -> Result<Vec<ChangeRecord>, MissionError> {
        let state = self.state.read().unwrap();
        let mission = Self::existing(&state, guid)?;
        let mine = state
            .changes
            .iter()
            .filter(|c| c.mission_guid == guid && window.contains(c.server_time_ms));
        let mut result: Vec<ChangeRecord> = if !squashed {
            mine.cloned().collect()
        } else {
            let latest_create = state
                .changes
                .iter()
                .filter(|c| c.mission_guid == guid && c.change_type == ChangeType::CreateMission)
                .map(|c| c.timestamp_ms)
                .max()
                .unwrap_or(i64::MIN);
            let mut squashed: BTreeMap<(u8, Content, String), ChangeRecord> = BTreeMap::new();
            let mut lifecycle = Vec::new();
            for change in mine {
                match (&change.change_type, &change.content) {
                    (ChangeType::CreateMission | ChangeType::DeleteMission, _) => {
                        if change.timestamp_ms >= latest_create {
                            lifecycle.push(change.clone());
                        }
                    }
                    (kind, Some(content)) => {
                        if change.timestamp_ms < mission.create_time_ms {
                            continue;
                        }
                        let present = mission.has(content);
                        let is_add = *kind == ChangeType::AddContent;
                        if is_add != present {
                            continue;
                        }
                        let key = (
                            u8::from(is_add),
                            content.clone(),
                            change.creator_uid.clone(),
                        );
                        // max(id), max(ts), max(servertime) per group
                        let entry = squashed.entry(key).or_insert_with(|| change.clone());
                        entry.id = entry.id.max(change.id);
                        entry.timestamp_ms = entry.timestamp_ms.max(change.timestamp_ms);
                        entry.server_time_ms = entry.server_time_ms.max(change.server_time_ms);
                    }
                    _ => {}
                }
            }
            lifecycle
                .into_iter()
                .chain(squashed.into_values())
                .collect()
        };
        result.sort_by_key(|c| std::cmp::Reverse(c.id));
        Ok(result)
    }

    // --- subscriptions --------------------------------------------------

    /// `MissionService.missionSubscribe`: the existing subscription for
    /// this client uid + username (its role raised to `role` if `role` has
    /// all of the old one's permissions), or a new one whose token
    /// `make_token(subscription_id)` mints.
    pub fn subscribe(
        &self,
        guid: &str,
        client_uid: &str,
        username: &str,
        role: Role,
        now_ms: i64,
        make_token: impl FnOnce(&str) -> String,
    ) -> Result<SubscriptionRecord, MissionError> {
        let mut state = self.state.write().unwrap();
        Self::existing(&state, guid)?;
        let existing = state
            .subscriptions
            .get(guid)
            .and_then(|subs| {
                subs.iter()
                    .find(|s| s.client_uid == client_uid && s.username == username)
            })
            .cloned();
        if let Some(mut sub) = existing {
            if sub.role != role && role.has_all(sub.role) {
                self.record(
                    &mut state,
                    Event::SubscriptionRoleSet {
                        guid: guid.into(),
                        id: sub.id.clone(),
                        role,
                    },
                )?;
                sub.role = role;
            }
            return Ok(sub);
        }
        let id = crate::marti::envelope::random_uuid();
        let subscription = SubscriptionRecord {
            token: make_token(&id),
            id,
            client_uid: client_uid.into(),
            username: username.into(),
            create_time_ms: now_ms,
            role,
        };
        self.record(
            &mut state,
            Event::Subscribed {
                guid: guid.into(),
                subscription: subscription.clone(),
            },
        )?;
        Ok(subscription)
    }

    pub fn subscriptions(&self, guid: &str) -> Vec<SubscriptionRecord> {
        self.state
            .read()
            .unwrap()
            .subscriptions
            .get(guid)
            .cloned()
            .unwrap_or_default()
    }

    pub fn subscription_by_id(&self, guid: &str, id: &str) -> Option<SubscriptionRecord> {
        self.subscriptions(guid).into_iter().find(|s| s.id == id)
    }

    pub fn find_subscription(
        &self,
        guid: &str,
        client_uid: &str,
        username: &str,
    ) -> Option<SubscriptionRecord> {
        self.subscriptions(guid)
            .into_iter()
            .find(|s| s.client_uid == client_uid && s.username == username)
    }

    /// Every stored subscription: (mission guid, mission name, client uid).
    pub fn all_subscriptions(&self) -> Vec<(String, String, String)> {
        let state = self.state.read().unwrap();
        state
            .subscriptions
            .iter()
            .flat_map(|(guid, subs)| {
                let name = state
                    .missions
                    .get(guid)
                    .map(|m| m.name.clone())
                    .unwrap_or_default();
                subs.iter()
                    .map(move |s| (guid.clone(), name.clone(), s.client_uid.clone()))
            })
            .collect()
    }

    /// `MissionService.setRoleByClientUidOrUsername`: by username if given,
    /// else by client uid. Returns how many subscriptions changed.
    pub fn set_subscription_role(
        &self,
        guid: &str,
        client_uid: &str,
        username: &str,
        role: Role,
    ) -> Result<usize, MissionError> {
        let mut state = self.state.write().unwrap();
        Self::existing(&state, guid)?;
        let ids: Vec<String> = state
            .subscriptions
            .get(guid)
            .map(|subs| {
                subs.iter()
                    .filter(|s| {
                        if !username.is_empty() {
                            s.username == username
                        } else {
                            s.client_uid == client_uid
                        }
                    })
                    .map(|s| s.id.clone())
                    .collect()
            })
            .unwrap_or_default();
        for id in &ids {
            self.record(
                &mut state,
                Event::SubscriptionRoleSet {
                    guid: guid.into(),
                    id: id.clone(),
                    role,
                },
            )?;
        }
        Ok(ids.len())
    }

    /// Deletes stored subscriptions (`deleteByMissionGuidAndClientUid…`):
    /// by client uid and username if a username is given, else by client
    /// uid alone.
    pub fn unsubscribe(
        &self,
        guid: &str,
        client_uid: &str,
        username: Option<&str>,
    ) -> Result<usize, MissionError> {
        let mut state = self.state.write().unwrap();
        let ids: Vec<String> = state
            .subscriptions
            .get(guid)
            .map(|subs| {
                subs.iter()
                    .filter(|s| {
                        s.client_uid == client_uid
                            && username.is_none_or(|u| u.is_empty() || s.username == u)
                    })
                    .map(|s| s.id.clone())
                    .collect()
            })
            .unwrap_or_default();
        for id in &ids {
            self.record(
                &mut state,
                Event::Unsubscribed {
                    guid: guid.into(),
                    id: id.clone(),
                },
            )?;
        }
        Ok(ids.len())
    }

    // --- invitations ------------------------------------------------------

    /// `MissionService.missionInvite`: `false` (and nothing stored) if the
    /// same invitee of the same type is already invited -- the official
    /// unique constraint.
    pub fn invite(&self, invitation: InvitationRecord) -> Result<bool, MissionError> {
        let mut state = self.state.write().unwrap();
        Self::existing(&state, &invitation.mission_guid)?;
        let duplicate = state.invitations.iter().any(|i| {
            i.mission_guid == invitation.mission_guid
                && i.invitation_type == invitation.invitation_type
                && i.invitee == invitation.invitee
        });
        if duplicate {
            return Ok(false);
        }
        self.record(&mut state, Event::Invited { invitation })?;
        Ok(true)
    }

    pub fn uninvite(
        &self,
        guid: &str,
        invitee: &str,
        invitation_type: InvitationType,
    ) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        self.record(
            &mut state,
            Event::Uninvited {
                guid: guid.into(),
                invitee: invitee.into(),
                invitation_type,
            },
        )
    }

    pub fn invitations(&self, guid: &str) -> Vec<InvitationRecord> {
        let state = self.state.read().unwrap();
        state
            .invitations
            .iter()
            .filter(|i| i.mission_guid == guid)
            .cloned()
            .collect()
    }

    /// Invitations of `invitation_type` for `invitee` (case-insensitive,
    /// `findAllMissionInvitationsByInviteeIgnoreCaseAndType`) on missions
    /// that still exist.
    pub fn invitations_for(
        &self,
        invitee: &str,
        invitation_type: InvitationType,
    ) -> Vec<InvitationRecord> {
        let state = self.state.read().unwrap();
        state
            .invitations
            .iter()
            .filter(|i| {
                i.invitation_type == invitation_type
                    && i.invitee.eq_ignore_ascii_case(invitee)
                    && state
                        .missions
                        .get(&i.mission_guid)
                        .is_some_and(|m| !m.deleted)
            })
            .cloned()
            .collect()
    }

    pub fn invitation_by_token(&self, token: &str) -> Option<InvitationRecord> {
        let state = self.state.read().unwrap();
        state.invitations.iter().find(|i| i.token == token).cloned()
    }

    // --- layers -----------------------------------------------------------------

    pub fn layer(&self, guid: &str, uid: &str) -> Option<LayerRecord> {
        let state = self.state.read().unwrap();
        state
            .layers
            .get(guid)?
            .iter()
            .find(|l| l.uid == uid)
            .cloned()
    }

    /// `findMissionLayers` + `sortMissionLayers`: the top-level layers with
    /// their descendants, each level sorted.
    pub fn layer_trees(&self, guid: &str) -> Vec<LayerTree> {
        let state = self.state.read().unwrap();
        let all = state.layers.get(guid).cloned().unwrap_or_default();
        fn build(all: &[LayerRecord], parent: Option<&str>) -> Vec<LayerTree> {
            let level: Vec<LayerRecord> = all
                .iter()
                .filter(|l| l.parent.as_deref() == parent)
                .cloned()
                .collect();
            sort_layers(level)
                .into_iter()
                .map(|layer| {
                    let children = build(all, Some(&layer.uid));
                    LayerTree { layer, children }
                })
                .collect()
        }
        build(&all, None)
    }

    /// One layer and its descendants (`hydrateMissionLayer`).
    pub fn layer_tree(&self, guid: &str, uid: &str) -> Option<LayerTree> {
        let layer = self.layer(guid, uid)?;
        let state = self.state.read().unwrap();
        let all = state.layers.get(guid).cloned().unwrap_or_default();
        fn children(all: &[LayerRecord], parent: &str) -> Vec<LayerTree> {
            let level: Vec<LayerRecord> = all
                .iter()
                .filter(|l| l.parent.as_deref() == Some(parent))
                .cloned()
                .collect();
            sort_layers(level)
                .into_iter()
                .map(|layer| LayerTree {
                    children: children(all, &layer.uid),
                    layer,
                })
                .collect()
        }
        Some(LayerTree {
            children: children(&all, uid),
            layer,
        })
    }

    /// `MissionLayerRepository.fixupAfter(uid, parent, after)`: the sibling
    /// (under `parent`) whose `after` is `after` now comes after `uid`.
    fn fixup_after(
        &self,
        state: &mut State,
        guid: &str,
        uid: Option<&str>,
        parent: Option<&str>,
        after: Option<&str>,
    ) -> Result<(), MissionError> {
        let targets: Vec<String> = state
            .layers
            .get(guid)
            .map(|layers| {
                layers
                    .iter()
                    .filter(|l| {
                        uid.is_none_or(|u| u != l.uid)
                            && l.parent.as_deref() == parent
                            && l.after.as_deref() == after
                    })
                    .map(|l| l.uid.clone())
                    .collect()
            })
            .unwrap_or_default();
        for target in targets {
            self.record(
                state,
                Event::LayerAfterSet {
                    guid: guid.into(),
                    uid: target,
                    after: uid.map(String::from),
                },
            )?;
        }
        Ok(())
    }

    /// `addMissionLayer` for a layer that doesn't exist yet: insert it
    /// after `after` under `parent`.
    pub fn add_layer(&self, guid: &str, layer: LayerRecord) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        Self::existing(&state, guid)?;
        self.fixup_after(
            &mut state,
            guid,
            Some(&layer.uid),
            layer.parent.as_deref(),
            layer.after.as_deref(),
        )?;
        self.record(
            &mut state,
            Event::LayerSaved {
                guid: guid.into(),
                layer,
            },
        )
    }

    pub fn rename_layer(&self, guid: &str, uid: &str, name: &str) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        self.record(
            &mut state,
            Event::LayerNamed {
                guid: guid.into(),
                uid: uid.into(),
                name: name.into(),
            },
        )
    }

    /// `setLayerParent`: take the layer out of its place, insert it after
    /// `after` under `parent`.
    pub fn move_layer(
        &self,
        guid: &str,
        uid: &str,
        parent: Option<&str>,
        after: Option<&str>,
    ) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        let Some(layer) = state
            .layers
            .get(guid)
            .and_then(|ls| ls.iter().find(|l| l.uid == uid))
            .cloned()
        else {
            return Err(MissionError::NotFound(uid.into()));
        };
        self.fixup_after(
            &mut state,
            guid,
            layer.after.as_deref(),
            layer.parent.as_deref(),
            Some(uid),
        )?;
        self.fixup_after(&mut state, guid, Some(uid), parent, after)?;
        if layer.parent.as_deref() != parent || layer.parent.is_none() {
            self.record(
                &mut state,
                Event::LayerParentSet {
                    guid: guid.into(),
                    uid: uid.into(),
                    parent: parent.map(String::from),
                },
            )?;
        }
        // `setAfter` only matches when the stored parent equals `parent`.
        let current_parent = state
            .layers
            .get(guid)
            .and_then(|ls| ls.iter().find(|l| l.uid == uid))
            .and_then(|l| l.parent.clone());
        if current_parent.as_deref() == parent {
            self.record(
                &mut state,
                Event::LayerAfterSet {
                    guid: guid.into(),
                    uid: uid.into(),
                    after: after.map(String::from),
                },
            )?;
        }
        Ok(())
    }

    /// Close the gap a layer leaves (`fixupAfter(layer.after, parent, uid)`)
    /// and delete it.
    pub fn delete_layer(&self, guid: &str, uid: &str) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        let Some(layer) = state
            .layers
            .get(guid)
            .and_then(|ls| ls.iter().find(|l| l.uid == uid))
            .cloned()
        else {
            return Ok(());
        };
        self.fixup_after(
            &mut state,
            guid,
            layer.after.as_deref(),
            layer.parent.as_deref(),
            Some(uid),
        )?;
        self.record(
            &mut state,
            Event::LayerDeleted {
                guid: guid.into(),
                uid: uid.into(),
            },
        )
    }

    // --- log entries ----------------------------------------------------------

    pub fn save_log_entry(&self, entry: LogEntryRecord) -> Result<LogEntryRecord, MissionError> {
        let mut state = self.state.write().unwrap();
        self.record(
            &mut state,
            Event::LogEntrySaved {
                entry: entry.clone(),
            },
        )?;
        Ok(entry)
    }

    pub fn delete_log_entry(&self, id: &str) -> Result<(), MissionError> {
        let mut state = self.state.write().unwrap();
        self.record(&mut state, Event::LogEntryDeleted { id: id.into() })
    }

    pub fn log_entry(&self, id: &str) -> Option<LogEntryRecord> {
        self.state.read().unwrap().logs.get(id).cloned()
    }

    pub fn all_log_entries(&self) -> Vec<LogEntryRecord> {
        self.state.read().unwrap().logs.values().cloned().collect()
    }

    /// Log entries naming `mission_name` with `servertime` in `window`,
    /// oldest first.
    pub fn log_entries_for(&self, mission_name: &str, window: Window) -> Vec<LogEntryRecord> {
        let state = self.state.read().unwrap();
        let mut entries: Vec<_> = state
            .logs
            .values()
            .filter(|e| {
                e.mission_names.iter().any(|n| n == mission_name)
                    && window.contains(e.server_time_ms)
            })
            .cloned()
            .collect();
        entries.sort_by_key(|e| e.server_time_ms);
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_mission(store: &MissionStore, name: &str, now_ms: i64) -> MissionRecord {
        store
            .create(
                NewMission {
                    guid: crate::marti::envelope::random_uuid(),
                    name: name.into(),
                    fields: MissionFields {
                        expiration: -1,
                        ..Default::default()
                    },
                    tool: "public".into(),
                    creator_uid: "ANDROID-1".into(),
                    groups: BTreeSet::from(["__ANON__".to_string()]),
                    password_hash: None,
                    default_role: None,
                    invite_only: false,
                },
                now_ms,
            )
            .unwrap()
    }

    #[test]
    fn the_official_roles_have_the_official_permissions() {
        assert_eq!(Role::Owner.permissions().len(), 8);
        assert_eq!(
            Role::Subscriber.permissions(),
            &[Permission::MissionRead, Permission::MissionWrite]
        );
        assert_eq!(
            Role::ReadOnlySubscriber.permissions(),
            &[Permission::MissionRead]
        );
        assert!(Role::Owner.has_all(Role::Subscriber));
        assert!(!Role::Subscriber.has_all(Role::Owner));
        assert!(Role::Subscriber.has_all(Role::ReadOnlySubscriber));
        assert_eq!(Role::DEFAULT, Role::Subscriber);
    }

    #[test]
    fn names_are_trimmed_and_the_newest_visible_mission_wins() {
        let store = MissionStore::in_memory();
        let first = new_mission(&store, "  Ops ", 1_000);
        assert_eq!(first.name, "Ops");
        let second = new_mission(&store, "Ops", 2_000);
        assert_eq!(store.by_name(" Ops", |_| true).unwrap().guid, second.guid);
        assert_eq!(
            store.by_name("Ops", |m| m.guid == first.guid).unwrap().guid,
            first.guid
        );
        assert!(store.by_name("Ops", |_| false).is_none());
    }

    #[test]
    fn a_deleted_mission_is_gone_by_name_but_answers_deleted() {
        let store = MissionStore::in_memory();
        let m = new_mission(&store, "Ops", 1_000);
        assert!(!store.is_deleted_name("Ops"));
        store.delete(&m.guid, "ANDROID-1", 2_000).unwrap();
        assert!(store.by_name("Ops", |_| true).is_none());
        assert!(store.is_deleted_name("Ops"));
        assert!(!store.is_deleted_name("Never"));
        assert!(store.list().is_empty());
        assert!(store.by_guid(&m.guid).unwrap().deleted);
    }

    fn summary(changes: &[ChangeRecord]) -> Vec<(ChangeType, Option<Content>, String)> {
        changes
            .iter()
            .map(|c| (c.change_type, c.content.clone(), c.creator_uid.clone()))
            .collect()
    }

    /// The official squashed view (`MISSION_CHANGES`): per content and
    /// creator only the latest add of what's still there or remove of
    /// what's gone, newest first; the full history keeps everything.
    #[test]
    fn changes_squash_like_the_official_sql() {
        let store = MissionStore::in_memory();
        let m = new_mission(&store, "Ops", 1_000);
        let hash = Content::Hash("a".repeat(64));
        let uid = Content::Uid("marker-1".into());
        store
            .add_content(&m.guid, hash.clone(), "A", 2_000)
            .unwrap();
        store
            .add_content(&m.guid, hash.clone(), "A", 3_000)
            .unwrap();
        store.add_content(&m.guid, uid.clone(), "A", 4_000).unwrap();
        store
            .remove_content(&m.guid, uid.clone(), "B", 5_000)
            .unwrap();

        let squashed = store.changes(&m.guid, Window::ALL, true).unwrap();
        assert_eq!(
            summary(&squashed),
            vec![
                (ChangeType::RemoveContent, Some(uid.clone()), "B".into()),
                (ChangeType::AddContent, Some(hash.clone()), "A".into()),
                (ChangeType::CreateMission, None, "ANDROID-1".into()),
            ]
        );
        let add = &squashed[1];
        assert_eq!(add.timestamp_ms, 3_000, "max(ts) of the squashed adds");

        let full = store.changes(&m.guid, Window::ALL, false).unwrap();
        assert_eq!(full.len(), 5);
        assert!(full.windows(2).all(|w| w[0].id > w[1].id), "newest first");

        let window = Window {
            start_ms: 4_500,
            end_ms: i64::MAX,
        };
        assert_eq!(
            summary(&store.changes(&m.guid, window, true).unwrap()),
            vec![(ChangeType::RemoveContent, Some(uid), "B".into())],
            "window filters rows before squashing"
        );
    }

    /// `missionSubscribe`: one subscription per client uid + username; a
    /// higher role upgrades it, a lower one doesn't downgrade.
    #[test]
    fn subscribing_again_reuses_and_only_upgrades() {
        let store = MissionStore::in_memory();
        let m = new_mission(&store, "Ops", 1_000);
        let first = store
            .subscribe(
                &m.guid,
                "ANDROID-1",
                "jz",
                Role::ReadOnlySubscriber,
                2_000,
                |id| format!("t-{id}"),
            )
            .unwrap();
        assert_eq!(first.token, format!("t-{}", first.id));
        let again = store
            .subscribe(
                &m.guid,
                "ANDROID-1",
                "jz",
                Role::Subscriber,
                3_000,
                |_| unreachable!(),
            )
            .unwrap();
        assert_eq!(
            (again.id.clone(), again.role),
            (first.id.clone(), Role::Subscriber)
        );
        let lower = store
            .subscribe(
                &m.guid,
                "ANDROID-1",
                "jz",
                Role::ReadOnlySubscriber,
                4_000,
                |_| unreachable!(),
            )
            .unwrap();
        assert_eq!(lower.role, Role::Subscriber);
        let other_user = store
            .subscribe(
                &m.guid,
                "ANDROID-1",
                "other",
                Role::Subscriber,
                5_000,
                |id| id.to_string(),
            )
            .unwrap();
        assert_ne!(other_user.id, first.id);
        assert_eq!(store.subscriptions(&m.guid).len(), 2);

        assert_eq!(
            store.unsubscribe(&m.guid, "ANDROID-1", Some("jz")).unwrap(),
            1
        );
        assert_eq!(store.subscriptions(&m.guid).len(), 1);
        assert_eq!(store.unsubscribe(&m.guid, "ANDROID-1", None).unwrap(), 1);
        assert!(store.subscriptions(&m.guid).is_empty());
    }

    /// `hydrateMission`: each item carries its latest ADD_CONTENT
    /// change's time and creator, items ordered by those changes.
    #[test]
    fn re_adding_content_updates_it_and_moves_it_last() {
        let store = MissionStore::in_memory();
        let m = new_mission(&store, "Ops", 1_000);
        let (a, b) = (Content::Uid("a".into()), Content::Uid("b".into()));
        store.add_content(&m.guid, a.clone(), "X", 2_000).unwrap();
        store.add_content(&m.guid, b.clone(), "X", 3_000).unwrap();
        store.add_content(&m.guid, a.clone(), "Y", 4_000).unwrap();
        let contents = store.by_guid(&m.guid).unwrap().contents;
        assert_eq!(
            contents
                .iter()
                .map(|c| c.content.clone())
                .collect::<Vec<_>>(),
            vec![b, a]
        );
        assert_eq!(
            (contents[1].timestamp_ms, contents[1].creator_uid.as_str()),
            (4_000, "Y")
        );
    }

    #[test]
    fn invitations_are_unique_and_match_case_insensitively() {
        let store = MissionStore::in_memory();
        let m = new_mission(&store, "Ops", 1_000);
        let invite = |role| InvitationRecord {
            mission_guid: m.guid.clone(),
            mission_name: m.name.clone(),
            invitee: "Alpha".into(),
            invitation_type: InvitationType::Callsign,
            creator_uid: "ANDROID-1".into(),
            create_time_ms: 2_000,
            token: format!("{role:?}"),
            role,
        };
        assert!(store.invite(invite(Role::ReadOnlySubscriber)).unwrap());
        assert!(
            !store.invite(invite(Role::Subscriber)).unwrap(),
            "a duplicate is refused"
        );
        let found = store.invitations_for("ALPHA", InvitationType::Callsign);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].role, Role::ReadOnlySubscriber);
        assert!(
            store
                .invitations_for("Alpha", InvitationType::UserName)
                .is_empty()
        );
        store
            .uninvite(&m.guid, "alpha", InvitationType::Callsign)
            .unwrap();
        assert!(store.invitations(&m.guid).is_empty());
    }

    fn layer(uid: &str, after: Option<&str>, parent: Option<&str>) -> LayerRecord {
        LayerRecord {
            uid: uid.into(),
            name: Some(uid.into()),
            layer_type: LayerType::Group,
            parent: parent.map(String::from),
            after: after.map(String::from),
        }
    }

    fn order(trees: &[LayerTree]) -> Vec<String> {
        trees.iter().map(|t| t.layer.uid.clone()).collect()
    }

    /// `MissionLayer.sort` and `fixupAfter`: inserting after a layer pushes
    /// its old follower behind the new one; moving and deleting close the
    /// gap.
    #[test]
    fn layers_keep_the_official_order() {
        let store = MissionStore::in_memory();
        let m = new_mission(&store, "Ops", 1_000);
        store.add_layer(&m.guid, layer("a", None, None)).unwrap();
        store
            .add_layer(&m.guid, layer("c", Some("a"), None))
            .unwrap();
        store
            .add_layer(&m.guid, layer("b", Some("a"), None))
            .unwrap();
        assert_eq!(
            order(&store.layer_trees(&m.guid)),
            ["a", "b", "c"],
            "b went between a and c"
        );
        store
            .add_layer(&m.guid, layer("first", None, None))
            .unwrap();
        assert_eq!(order(&store.layer_trees(&m.guid)), ["first", "a", "b", "c"]);

        store
            .add_layer(&m.guid, layer("child", None, Some("b")))
            .unwrap();
        assert_eq!(order(&store.layer_trees(&m.guid)[2].children), ["child"]);

        store
            .move_layer(&m.guid, "a", Some("b"), Some("child"))
            .unwrap();
        let trees = store.layer_trees(&m.guid);
        assert_eq!(order(&trees), ["first", "b", "c"]);
        assert_eq!(order(&trees[1].children), ["child", "a"]);

        store.delete_layer(&m.guid, "b").unwrap();
        assert_eq!(
            order(&store.layer_trees(&m.guid)),
            ["first", "c"],
            "c now follows first"
        );
    }

    #[test]
    fn a_broken_after_chain_stays_unsorted() {
        let unsorted = vec![layer("x", Some("missing"), None), layer("y", None, None)];
        assert_eq!(sort_layers(unsorted.clone()), unsorted);
        let cycle = vec![layer("p", Some("q"), None), layer("q", Some("p"), None)];
        assert_eq!(sort_layers(cycle.clone()), cycle);
    }

    #[test]
    fn everything_survives_a_restart() {
        let path = std::env::temp_dir().join(format!(
            "microtak-official-missions-{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let (guid, sub) = {
            let store = MissionStore::load_or_create(&path).unwrap();
            let m = new_mission(&store, "Ops", 1_000);
            store
                .add_content(&m.guid, Content::Uid("u".into()), "A", 2_000)
                .unwrap();
            store
                .set_keywords(&m.guid, BTreeSet::from(["k".to_string()]), 3_000)
                .unwrap();
            store
                .set_content_keywords(
                    &m.guid,
                    Content::Uid("not-in-mission".into()),
                    vec!["x".into(), "x".into()],
                )
                .unwrap();
            let sub = store
                .subscribe(&m.guid, "ANDROID-1", "jz", Role::Owner, 4_000, |id| {
                    id.into()
                })
                .unwrap();
            store
                .save_log_entry(LogEntryRecord {
                    id: "log-1".into(),
                    mission_names: vec!["Ops".into()],
                    ..Default::default()
                })
                .unwrap();
            (m.guid, sub)
        };
        let store = MissionStore::load_or_create(&path).unwrap();
        let m = store.by_guid(&guid).unwrap();
        assert_eq!(m.keywords, BTreeSet::from(["k".to_string()]));
        assert_eq!(
            m.content_keywords[&Content::Uid("not-in-mission".into())],
            vec!["x".to_string()]
        );
        assert!(m.has(&Content::Uid("u".into())));
        assert_eq!(store.subscription_by_id(&guid, &sub.id), Some(sub));
        assert_eq!(store.log_entries_for("Ops", Window::ALL).len(), 1);
        assert_eq!(store.changes(&guid, Window::ALL, false).unwrap().len(), 2);
        // new changes continue the id sequence
        store
            .add_content(&guid, Content::Uid("v".into()), "A", 5_000)
            .unwrap();
        let ids: Vec<u64> = store
            .changes(&guid, Window::ALL, false)
            .unwrap()
            .iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(ids, vec![2, 1, 0]);
        std::fs::remove_file(&path).ok();
    }
}
