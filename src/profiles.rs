//! Device profiles, as the official TAK Server keeps them (`device_profile`
//! and `device_profile_file`, `com.bbn.marti.device.profile`): named sets
//! of files (ATAK `.pref` files, data packages, ...) handed to devices as a
//! mission package when they enroll, when they connect, or when a tool asks.
//!
//! A profile reaches a user who shares one of its groups, in either
//! direction (the official `RemoteUtil.GROUP_CLAUSE` on group bit vectors);
//! "all groups" (`APPLY_TO_ALL_GROUPS`) reaches everyone. A new profile has
//! no groups, so it reaches nobody until an admin assigns some -- as
//! officially. Defaults on creation (`V26__device_profile.sql`): active,
//! applied on enrollment, not on connect, no tool.
//!
//! Metadata is an append-only, replayable event log like every other store;
//! file contents live in their own content-addressed store.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::content_store::{ContentStore, ContentStoreError};
use crate::eventlog::{EventLog, EventLogError};

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("no such profile")]
    NotFound,
    #[error("event log error: {0}")]
    EventLog(#[from] EventLogError),
    #[error("content store error: {0}")]
    Content(#[from] ContentStoreError),
}

/// Which profiles a request asks for (`getProfileFiles`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applies {
    OnEnrollment,
    OnConnect,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    pub id: i64,
    pub name: String,
    pub active: bool,
    pub apply_on_enrollment: bool,
    pub apply_on_connect: bool,
    pub tool: Option<String>,
    /// The groups it reaches (ignored when `all_groups`).
    pub groups: BTreeSet<String>,
    pub all_groups: bool,
    /// Last change, Unix milliseconds.
    pub updated_ms: i64,
}

impl Profile {
    /// `Profile.updateType`.
    pub fn kind(&self) -> &'static str {
        if self.apply_on_enrollment {
            "Enrollment"
        } else if self.apply_on_connect {
            "Connection"
        } else {
            "Tool"
        }
    }

    /// Whether a user in `user_groups` (either direction) may get it.
    pub fn reaches(&self, user_groups: &BTreeSet<String>) -> bool {
        self.all_groups || !self.groups.is_disjoint(user_groups)
    }

    fn has_tool(&self) -> bool {
        self.tool.as_deref().is_some_and(|t| !t.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileFile {
    pub id: i64,
    pub profile_id: i64,
    pub name: String,
    /// SHA-256 of the contents, in the profile content store.
    pub hash: String,
}

/// What `PUT /device/profile/{name}` changes (the official `save` of the
/// posted `Profile`).
#[derive(Debug, Clone)]
pub struct ProfileUpdate {
    pub name: String,
    pub active: bool,
    pub apply_on_enrollment: bool,
    pub apply_on_connect: bool,
    pub tool: Option<String>,
    pub groups: BTreeSet<String>,
    pub all_groups: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum ProfileEvent {
    Created {
        id: i64,
        name: String,
        groups: BTreeSet<String>,
        at_ms: i64,
    },
    Updated {
        id: i64,
        name: String,
        active: bool,
        apply_on_enrollment: bool,
        apply_on_connect: bool,
        tool: Option<String>,
        groups: BTreeSet<String>,
        all_groups: bool,
        at_ms: i64,
    },
    Deleted {
        id: i64,
    },
    FileAdded {
        id: i64,
        profile_id: i64,
        name: String,
        hash: String,
        at_ms: i64,
    },
    FileDeleted {
        id: i64,
        at_ms: i64,
    },
}

#[derive(Default)]
struct State {
    profiles: Vec<Profile>,
    files: Vec<ProfileFile>,
    next_profile_id: i64,
    next_file_id: i64,
}

fn touch(state: &mut State, profile_id: i64, at_ms: i64) {
    if let Some(p) = state.profiles.iter_mut().find(|p| p.id == profile_id) {
        p.updated_ms = at_ms;
    }
}

fn apply(state: &mut State, event: &ProfileEvent) {
    match event {
        ProfileEvent::Created {
            id,
            name,
            groups,
            at_ms,
        } => {
            state.next_profile_id = state.next_profile_id.max(*id);
            state.profiles.push(Profile {
                id: *id,
                name: name.clone(),
                active: true,
                apply_on_enrollment: true,
                apply_on_connect: false,
                tool: None,
                groups: groups.clone(),
                all_groups: false,
                updated_ms: *at_ms,
            });
        }
        ProfileEvent::Updated {
            id,
            name,
            active,
            apply_on_enrollment,
            apply_on_connect,
            tool,
            groups,
            all_groups,
            at_ms,
        } => {
            if let Some(p) = state.profiles.iter_mut().find(|p| p.id == *id) {
                p.name = name.clone();
                p.active = *active;
                p.apply_on_enrollment = *apply_on_enrollment;
                p.apply_on_connect = *apply_on_connect;
                p.tool = tool.clone();
                p.groups = groups.clone();
                p.all_groups = *all_groups;
                p.updated_ms = *at_ms;
            }
        }
        ProfileEvent::Deleted { id } => {
            state.profiles.retain(|p| p.id != *id);
            state.files.retain(|f| f.profile_id != *id);
        }
        ProfileEvent::FileAdded {
            id,
            profile_id,
            name,
            hash,
            at_ms,
        } => {
            state.next_file_id = state.next_file_id.max(*id);
            state.files.push(ProfileFile {
                id: *id,
                profile_id: *profile_id,
                name: name.clone(),
                hash: hash.clone(),
            });
            touch(state, *profile_id, *at_ms);
        }
        ProfileEvent::FileDeleted { id, at_ms } => {
            if let Some(i) = state.files.iter().position(|f| f.id == *id) {
                let file = state.files.remove(i);
                touch(state, file.profile_id, *at_ms);
            }
        }
    }
}

pub struct ProfileStore {
    state: RwLock<State>,
    log: Option<EventLog<ProfileEvent>>,
    content: ContentStore,
}

impl ProfileStore {
    /// A store keeping metadata at `log_path` and contents in `content_dir`.
    pub fn load_or_create(
        log_path: impl Into<PathBuf>,
        content_dir: PathBuf,
    ) -> Result<Self, ProfileError> {
        let mut state = State::default();
        let log = EventLog::open_and_replay(log_path, &mut state, apply)?;
        Ok(Self {
            state: RwLock::new(state),
            log: Some(log),
            content: ContentStore::open(content_dir).map_err(ContentStoreError::from)?,
        })
    }

    fn record(&self, state: &mut State, event: ProfileEvent) -> Result<(), ProfileError> {
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply(state, &event);
        Ok(())
    }

    /// Every profile, by id (`findAll(Sort.by("id"))`).
    pub fn all(&self) -> Vec<Profile> {
        let mut all = self.state.read().unwrap().profiles.clone();
        all.sort_by_key(|p| p.id);
        all
    }

    pub fn by_name(&self, name: &str) -> Option<Profile> {
        self.state
            .read()
            .unwrap()
            .profiles
            .iter()
            .find(|p| p.name == name)
            .cloned()
    }

    pub fn by_id(&self, id: i64) -> Option<Profile> {
        self.state
            .read()
            .unwrap()
            .profiles
            .iter()
            .find(|p| p.id == id)
            .cloned()
    }

    /// `createProfile`: `true` if created, `false` if the name exists.
    pub fn create(
        &self,
        name: &str,
        groups: BTreeSet<String>,
        now_ms: i64,
    ) -> Result<bool, ProfileError> {
        let mut state = self.state.write().unwrap();
        if state.profiles.iter().any(|p| p.name == name) {
            return Ok(false);
        }
        let id = state.next_profile_id + 1;
        self.record(
            &mut state,
            ProfileEvent::Created {
                id,
                name: name.to_string(),
                groups,
                at_ms: now_ms,
            },
        )?;
        Ok(true)
    }

    pub fn update(&self, id: i64, update: ProfileUpdate, now_ms: i64) -> Result<(), ProfileError> {
        let mut state = self.state.write().unwrap();
        if !state.profiles.iter().any(|p| p.id == id) {
            return Err(ProfileError::NotFound);
        }
        self.record(
            &mut state,
            ProfileEvent::Updated {
                id,
                name: update.name,
                active: update.active,
                apply_on_enrollment: update.apply_on_enrollment,
                apply_on_connect: update.apply_on_connect,
                tool: update.tool,
                groups: update.groups,
                all_groups: update.all_groups,
                at_ms: now_ms,
            },
        )
    }

    pub fn delete(&self, id: i64) -> Result<(), ProfileError> {
        let mut state = self.state.write().unwrap();
        if !state.profiles.iter().any(|p| p.id == id) {
            return Err(ProfileError::NotFound);
        }
        let hashes: Vec<String> = state
            .files
            .iter()
            .filter(|f| f.profile_id == id)
            .map(|f| f.hash.clone())
            .collect();
        self.record(&mut state, ProfileEvent::Deleted { id })?;
        self.forget(&state, hashes);
        Ok(())
    }

    /// A profile's files, by id (`findAllByProfileIdOrderById`).
    pub fn files(&self, profile_id: i64) -> Vec<ProfileFile> {
        let mut files: Vec<ProfileFile> = self
            .state
            .read()
            .unwrap()
            .files
            .iter()
            .filter(|f| f.profile_id == profile_id)
            .cloned()
            .collect();
        files.sort_by_key(|f| f.id);
        files
    }

    pub fn file(&self, id: i64) -> Option<ProfileFile> {
        self.state
            .read()
            .unwrap()
            .files
            .iter()
            .find(|f| f.id == id)
            .cloned()
    }

    pub fn add_file(
        &self,
        profile_id: i64,
        name: &str,
        bytes: &[u8],
        now_ms: i64,
    ) -> Result<ProfileFile, ProfileError> {
        let hash = self.content.put(bytes, None)?;
        let mut state = self.state.write().unwrap();
        if !state.profiles.iter().any(|p| p.id == profile_id) {
            return Err(ProfileError::NotFound);
        }
        let id = state.next_file_id + 1;
        self.record(
            &mut state,
            ProfileEvent::FileAdded {
                id,
                profile_id,
                name: name.to_string(),
                hash: hash.clone(),
                at_ms: now_ms,
            },
        )?;
        Ok(ProfileFile {
            id,
            profile_id,
            name: name.to_string(),
            hash,
        })
    }

    pub fn delete_file(&self, id: i64, now_ms: i64) -> Result<(), ProfileError> {
        let mut state = self.state.write().unwrap();
        let Some(hash) = state
            .files
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.hash.clone())
        else {
            return Err(ProfileError::NotFound);
        };
        self.record(&mut state, ProfileEvent::FileDeleted { id, at_ms: now_ms })?;
        self.forget(&state, vec![hash]);
        Ok(())
    }

    /// Remove contents no file refers to any more.
    fn forget(&self, state: &State, hashes: Vec<String>) {
        for hash in hashes {
            if !state.files.iter().any(|f| f.hash == hash) {
                self.content.remove(&hash);
            }
        }
    }

    pub fn contents(&self, file: &ProfileFile) -> Option<Vec<u8>> {
        self.content.get(&file.hash).ok().flatten()
    }

    /// `getProfileFiles`: the files of every active, tool-less profile
    /// applied `when` that reaches `user_groups`; with `changed_since_ms`,
    /// only profiles updated after it (`syncSecago`).
    pub fn files_for(
        &self,
        when: Applies,
        user_groups: &BTreeSet<String>,
        changed_since_ms: Option<i64>,
    ) -> Vec<ProfileFile> {
        self.matching(user_groups, changed_since_ms, |p| {
            !p.has_tool()
                && match when {
                    Applies::OnEnrollment => p.apply_on_enrollment,
                    Applies::OnConnect => p.apply_on_connect,
                }
        })
    }

    /// `getProfileFilesForTool`.
    pub fn files_for_tool(
        &self,
        tool: &str,
        user_groups: &BTreeSet<String>,
        changed_since_ms: Option<i64>,
    ) -> Vec<ProfileFile> {
        self.matching(user_groups, changed_since_ms, |p| {
            p.tool.as_deref() == Some(tool)
        })
    }

    fn matching(
        &self,
        user_groups: &BTreeSet<String>,
        changed_since_ms: Option<i64>,
        wanted: impl Fn(&Profile) -> bool,
    ) -> Vec<ProfileFile> {
        let profiles: Vec<i64> = self
            .all()
            .into_iter()
            .filter(|p| {
                p.active
                    && wanted(p)
                    && p.reaches(user_groups)
                    && changed_since_ms.is_none_or(|since| p.updated_ms > since)
            })
            .map(|p| p.id)
            .collect();
        profiles.into_iter().flat_map(|id| self.files(id)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (ProfileStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "microtak-profiles-{}-{}",
            std::process::id(),
            crate::marti::envelope::random_uuid()
        ));
        (
            ProfileStore::load_or_create(dir.join("profiles.log"), dir.join("content")).unwrap(),
            dir,
        )
    }

    fn groups(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_new_profile_has_the_official_defaults_and_reaches_nobody() {
        let (store, dir) = store();
        assert!(store.create("Field", BTreeSet::new(), 1_000).unwrap());
        assert!(!store.create("Field", BTreeSet::new(), 2_000).unwrap());
        let p = store.by_name("Field").unwrap();
        assert!(p.active && p.apply_on_enrollment && !p.apply_on_connect);
        assert_eq!(
            (p.kind(), p.tool.clone(), p.updated_ms),
            ("Enrollment", None, 1_000)
        );
        assert!(!p.reaches(&groups(&["__ANON__"])));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn files_go_to_users_sharing_a_group_when_the_profile_applies() {
        let (store, dir) = store();
        store.create("Red", groups(&["Red"]), 1_000).unwrap();
        let red = store.by_name("Red").unwrap();
        let file = store
            .add_file(red.id, "red.pref", b"<prefs/>", 2_000)
            .unwrap();
        assert_eq!(store.contents(&file).unwrap(), b"<prefs/>");
        assert_eq!(
            store.by_id(red.id).unwrap().updated_ms,
            2_000,
            "a new file updates it"
        );

        let on_enroll = |g: &[&str]| store.files_for(Applies::OnEnrollment, &groups(g), None);
        assert_eq!(on_enroll(&["Red", "Blue"]), vec![file.clone()]);
        assert!(on_enroll(&["Blue"]).is_empty());
        assert!(
            store
                .files_for(Applies::OnConnect, &groups(&["Red"]), None)
                .is_empty()
        );
        assert!(
            store
                .files_for(Applies::OnEnrollment, &groups(&["Red"]), Some(2_000))
                .is_empty()
        );
        assert_eq!(
            store
                .files_for(Applies::OnEnrollment, &groups(&["Red"]), Some(1_999))
                .len(),
            1
        );

        let update = |active, tool: Option<&str>, all_groups| ProfileUpdate {
            name: "Red".into(),
            active,
            apply_on_enrollment: false,
            apply_on_connect: true,
            tool: tool.map(String::from),
            groups: groups(&["Red"]),
            all_groups,
        };
        store
            .update(red.id, update(true, None, false), 3_000)
            .unwrap();
        assert_eq!(
            store
                .files_for(Applies::OnConnect, &groups(&["Red"]), None)
                .len(),
            1
        );
        assert!(on_enroll(&["Red"]).is_empty());
        store
            .update(red.id, update(false, None, true), 4_000)
            .unwrap();
        assert!(
            store
                .files_for(Applies::OnConnect, &groups(&["x"]), None)
                .is_empty(),
            "inactive"
        );
        store
            .update(red.id, update(true, None, true), 5_000)
            .unwrap();
        assert_eq!(
            store
                .files_for(Applies::OnConnect, &groups(&["x"]), None)
                .len(),
            1,
            "all groups"
        );
        store
            .update(red.id, update(true, Some("radio"), true), 6_000)
            .unwrap();
        assert!(
            store
                .files_for(Applies::OnConnect, &groups(&["x"]), None)
                .is_empty(),
            "a tool's"
        );
        assert_eq!(
            store.files_for_tool("radio", &groups(&["x"]), None).len(),
            1
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn persists_and_deletes_contents_with_the_last_file() {
        let (store, dir) = store();
        store.create("A", groups(&["G"]), 1).unwrap();
        let a = store.by_name("A").unwrap();
        let f1 = store.add_file(a.id, "one.pref", b"same", 2).unwrap();
        let f2 = store.add_file(a.id, "two.pref", b"same", 3).unwrap();
        drop(store);
        let store =
            ProfileStore::load_or_create(dir.join("profiles.log"), dir.join("content")).unwrap();
        assert_eq!(store.files(a.id), vec![f1.clone(), f2.clone()]);
        store.delete_file(f1.id, 4).unwrap();
        assert_eq!(store.contents(&f2).unwrap(), b"same", "still referenced");
        store.delete(a.id).unwrap();
        assert!(store.contents(&f2).is_none());
        assert!(store.by_name("A").is_none() && store.file(f2.id).is_none());
        assert!(matches!(store.delete(a.id), Err(ProfileError::NotFound)));
        std::fs::remove_dir_all(dir).ok();
    }
}
