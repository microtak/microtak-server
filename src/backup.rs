//! Periodic backup of [`crate::app::AppConfig::data_dir`]: a local mirror
//! plus optional offsite shipping via an external command (`rsync`, `scp`,
//! `aws s3 sync`, or anything else that takes a source directory).
//!
//! Built directly on top of [`crate::eventlog`]'s append-only design: every
//! persisted file either only ever grows (`devices.log`, `missions.log`) or
//! is immutable once written (`content/<hash>` blobs, `ca-cert.pem`,
//! `ca-key.pem`) — so a backup pass only ever needs to copy the *new* bytes
//! appended since the last pass, or skip a file entirely once it's already
//! fully present at the destination, rather than re-copying/re-transferring
//! the whole data directory every time. This is the concrete payoff the
//! event-log redesign (see `eventlog`'s own doc comment) was chosen for.
//!
//! Offsite shipping deliberately shells out to whatever tool the operator
//! already has (`rsync -a`, `scp`, `aws s3 sync`, ...) rather than
//! reimplementing any of those protocols or pulling in a heavy SDK —
//! consistent with this project's "lightweight" scope, and the same
//! approach this monorepo's own `opentakserver/backup.sh` already takes.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tracing::{error, info};

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("offsite command {command:?} exited with status {status}")]
    OffsiteCommandFailed {
        command: Vec<String>,
        status: std::process::ExitStatus,
    },
}

/// An external command that ships the local backup directory elsewhere,
/// e.g. `["rsync", "-a", "{src}/", "user@host:/backups/edgetak/"]` or
/// `["aws", "s3", "sync", "{src}", "s3://bucket/edgetak/"]`. Every
/// occurrence of the literal `{src}` in any argument is replaced with the
/// local backup directory's path before running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffsiteTarget {
    pub command: Vec<String>,
}

impl OffsiteTarget {
    /// `None` for an empty command -- offsite shipping is simply disabled,
    /// not a configuration error.
    pub fn new(command: Vec<String>) -> Option<Self> {
        if command.is_empty() {
            None
        } else {
            Some(Self { command })
        }
    }

    fn run(&self, src: &Path) -> Result<(), BackupError> {
        let src_str = src.to_string_lossy();
        let resolved: Vec<String> = self
            .command
            .iter()
            .map(|part| part.replace("{src}", &src_str))
            .collect();
        let (program, args) = resolved
            .split_first()
            .expect("OffsiteTarget::new rejects an empty command");
        let status = std::process::Command::new(program).args(args).status()?;
        if !status.success() {
            return Err(BackupError::OffsiteCommandFailed {
                command: resolved,
                status,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BackupReport {
    pub files_synced: usize,
    pub bytes_copied: u64,
    pub offsite_ran: bool,
}

pub struct BackupRunner {
    data_dir: PathBuf,
    backup_dir: PathBuf,
    offsite: Option<OffsiteTarget>,
}

impl BackupRunner {
    pub fn new(data_dir: PathBuf, backup_dir: PathBuf, offsite: Option<OffsiteTarget>) -> Self {
        Self {
            data_dir,
            backup_dir,
            offsite,
        }
    }

    /// Run one backup pass: mirror `data_dir` into `backup_dir`, then run
    /// the offsite command (if configured) against `backup_dir`.
    pub fn run_once(&self) -> Result<BackupReport, BackupError> {
        std::fs::create_dir_all(&self.backup_dir)?;
        let mut report = BackupReport::default();
        sync_dir(&self.data_dir, &self.backup_dir, &mut report)?;
        if let Some(offsite) = &self.offsite {
            offsite.run(&self.backup_dir)?;
            report.offsite_ran = true;
        }
        Ok(report)
    }

    /// Run [`Self::run_once`] every `interval`, forever -- an immediate
    /// first pass, then one per tick. A single pass's failure (e.g. an
    /// offsite host briefly unreachable, exactly the kind of thing a
    /// grid-down deployment should expect) is logged and retried next
    /// interval, never propagated as a reason to stop the whole server.
    pub async fn run_periodic(self, interval: Duration) -> ! {
        let mut ticker = tokio::time::interval(interval);
        loop {
            match self.run_once() {
                Ok(report) => info!(
                    files = report.files_synced,
                    bytes = report.bytes_copied,
                    offsite = report.offsite_ran,
                    "backup pass complete"
                ),
                Err(error) => error!(%error, "backup pass failed, will retry next interval"),
            }
            ticker.tick().await;
        }
    }
}

/// Recursively mirror `src` into `dest`, copying only bytes not already
/// present at the destination (see module doc comment). Skips in-progress
/// upload temp files (`content_store`'s `.tmp-*` naming) -- backing up a
/// partially-written upload would be pointless at best.
fn sync_dir(src: &Path, dest: &Path, report: &mut BackupReport) -> Result<(), BackupError> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_name = entry.file_name();
        if file_name.to_string_lossy().starts_with(".tmp-") {
            continue;
        }
        let dest_path = dest.join(&file_name);
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            sync_dir(&entry.path(), &dest_path, report)?;
        } else if file_type.is_file() {
            let copied = sync_file(&entry.path(), &dest_path)?;
            if copied > 0 {
                report.files_synced += 1;
                report.bytes_copied += copied;
            }
        }
    }
    Ok(())
}

/// Copy only the tail of `src` not already present at `dest`, appending it.
/// Correct as long as `dest`'s existing bytes are a true prefix of `src`'s
/// current content, which holds for our append-only event logs and our
/// write-once content blobs/certs. If `dest` is somehow *larger* than `src`
/// (shouldn't happen for any of these files, but would mean `dest` is
/// stale/corrupt in some other way) it's discarded and fully re-copied
/// rather than silently left mismatched.
fn sync_file(src: &Path, dest: &Path) -> Result<u64, BackupError> {
    let src_len = std::fs::metadata(src)?.len();
    let dest_len = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);

    if dest_len > src_len {
        std::fs::remove_file(dest)?;
        return sync_file(src, dest);
    }
    if dest_len == src_len {
        return Ok(0); // already fully backed up
    }

    let mut src_file = std::fs::File::open(src)?;
    src_file.seek(SeekFrom::Start(dest_len))?;
    let mut tail = Vec::new();
    src_file.read_to_end(&mut tail)?;
    let tail_len = tail.len() as u64;

    let mut dest_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dest)?;
    dest_file.write_all(&tail)?;
    dest_file.sync_data()?;

    Ok(tail_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(label: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("edgetak-backup-{label}-{}-{n}", std::process::id()))
    }

    #[test]
    fn copies_new_files_including_nested_directories() {
        let src = temp_dir("src-nested");
        let dest = temp_dir("dest-nested");
        std::fs::create_dir_all(src.join("content")).unwrap();
        std::fs::write(src.join("devices.log"), b"line one\n").unwrap();
        std::fs::write(src.join("content").join("abc123"), b"blob bytes").unwrap();

        let runner = BackupRunner::new(src.clone(), dest.clone(), None);
        let report = runner.run_once().unwrap();

        assert_eq!(report.files_synced, 2);
        assert_eq!(
            std::fs::read(dest.join("devices.log")).unwrap(),
            b"line one\n"
        );
        assert_eq!(
            std::fs::read(dest.join("content").join("abc123")).unwrap(),
            b"blob bytes"
        );

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dest).ok();
    }

    /// The core payoff of the event-log design: a second pass after the
    /// source log grows only copies the *new* tail, not the whole file
    /// again, and a pass with no growth at all copies nothing.
    #[test]
    fn subsequent_passes_only_copy_appended_growth() {
        let src = temp_dir("src-growth");
        let dest = temp_dir("dest-growth");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("missions.log"), b"event-one\n").unwrap();

        let runner = BackupRunner::new(src.clone(), dest.clone(), None);
        let first = runner.run_once().unwrap();
        assert_eq!(first.bytes_copied, "event-one\n".len() as u64);

        // No change: a second pass copies nothing.
        let second = runner.run_once().unwrap();
        assert_eq!(second.files_synced, 0);
        assert_eq!(second.bytes_copied, 0);

        // Append-only growth: a third pass copies only the new tail.
        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(src.join("missions.log"))
            .unwrap();
        log.write_all(b"event-two\n").unwrap();
        drop(log);

        let third = runner.run_once().unwrap();
        assert_eq!(third.files_synced, 1);
        assert_eq!(third.bytes_copied, "event-two\n".len() as u64);
        assert_eq!(
            std::fs::read(dest.join("missions.log")).unwrap(),
            b"event-one\nevent-two\n"
        );

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dest).ok();
    }

    /// If the destination is somehow larger than the source (stale/corrupt
    /// from some earlier state), it's discarded and fully re-copied rather
    /// than left mismatched.
    #[test]
    fn a_destination_larger_than_source_is_fully_recopied() {
        let src = temp_dir("src-shrink");
        let dest = temp_dir("dest-shrink");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(src.join("devices.log"), b"short").unwrap();
        std::fs::write(dest.join("devices.log"), b"this is much longer than short").unwrap();

        let runner = BackupRunner::new(src.clone(), dest.clone(), None);
        let report = runner.run_once().unwrap();

        assert_eq!(report.bytes_copied, 5);
        assert_eq!(std::fs::read(dest.join("devices.log")).unwrap(), b"short");

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dest).ok();
    }

    #[test]
    fn skips_in_progress_content_store_temp_files() {
        let src = temp_dir("src-tmp");
        let dest = temp_dir("dest-tmp");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join(".tmp-12345-1"), b"partial upload").unwrap();

        let runner = BackupRunner::new(src.clone(), dest.clone(), None);
        let report = runner.run_once().unwrap();

        assert_eq!(report.files_synced, 0);
        assert!(!dest.join(".tmp-12345-1").exists());

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dest).ok();
    }

    /// A configured offsite target actually runs, against the *backup*
    /// directory (not the live data directory), with `{src}` substituted.
    #[test]
    fn runs_the_configured_offsite_command_against_the_backup_dir() {
        let src = temp_dir("src-offsite");
        let dest = temp_dir("dest-offsite");
        let offsite_dest = temp_dir("offsite-destination");
        std::fs::create_dir_all(&src).unwrap();
        // Pre-create the offsite destination so `cp -r <backup-dir>
        // <offsite-dest>` nests the copy under it (matching real `cp`
        // semantics for an existing target directory) rather than
        // replacing/renaming into it.
        std::fs::create_dir_all(&offsite_dest).unwrap();
        std::fs::write(src.join("devices.log"), b"enrolled-device").unwrap();

        let offsite = OffsiteTarget::new(vec![
            "cp".to_string(),
            "-r".to_string(),
            "{src}".to_string(),
            offsite_dest.to_string_lossy().into_owned(),
        ]);
        let runner = BackupRunner::new(src.clone(), dest.clone(), offsite);
        let report = runner.run_once().unwrap();

        assert!(report.offsite_ran);
        let shipped_dir = offsite_dest.join(dest.file_name().unwrap());
        assert_eq!(
            std::fs::read(shipped_dir.join("devices.log")).unwrap(),
            b"enrolled-device"
        );

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dest).ok();
        std::fs::remove_dir_all(&offsite_dest).ok();
    }

    /// A failing offsite command (non-zero exit) surfaces as a real error,
    /// not a silently-ignored best-effort attempt.
    #[test]
    fn a_failing_offsite_command_is_a_reported_error() {
        let src = temp_dir("src-offsite-fail");
        let dest = temp_dir("dest-offsite-fail");
        std::fs::create_dir_all(&src).unwrap();

        let offsite = OffsiteTarget::new(vec!["false".to_string()]);
        let runner = BackupRunner::new(src.clone(), dest.clone(), offsite);
        let result = runner.run_once();

        assert!(matches!(
            result,
            Err(BackupError::OffsiteCommandFailed { .. })
        ));

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dest).ok();
    }

    #[test]
    fn no_command_means_offsite_shipping_is_disabled() {
        assert!(OffsiteTarget::new(vec![]).is_none());
    }

    /// [`BackupRunner::run_periodic`] actually performs real backup passes
    /// on its own schedule, not just once at construction.
    #[tokio::test]
    async fn run_periodic_performs_repeated_real_backup_passes() {
        let src = temp_dir("src-periodic");
        let dest = temp_dir("dest-periodic");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("devices.log"), b"initial\n").unwrap();

        let runner = BackupRunner::new(src.clone(), dest.clone(), None);
        let handle = tokio::spawn(runner.run_periodic(Duration::from_millis(20)));

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            std::fs::read(dest.join("devices.log")).unwrap(),
            b"initial\n",
            "the first tick should have already backed up the initial content"
        );

        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(src.join("devices.log"))
            .unwrap();
        log.write_all(b"more\n").unwrap();
        drop(log);

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            std::fs::read(dest.join("devices.log")).unwrap(),
            b"initial\nmore\n",
            "a later tick should have picked up the appended growth"
        );

        handle.abort();
        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&dest).ok();
    }
}
