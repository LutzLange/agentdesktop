use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
mod tests;

/// File identity across platforms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub volume: u64,
    pub file_id: u128,
}

/// Entry kind with file size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File { len: u64 },
    Folder,
    Link,
}

/// Snapshot of a file or folder at a point in time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileSnapshot {
    Absent,
    File {
        sha256: [u8; 32],
        identity: FileIdentity,
    },
    Folder {
        sha256: [u8; 32],
        identity: FileIdentity,
    },
    FolderIdentity {
        identity: FileIdentity,
    },
    Link {
        target_sha256: [u8; 32],
        identity: FileIdentity,
    },
    TooLarge {
        identity: FileIdentity,
        top_level_names_sha256: [u8; 32],
    },
    Unreadable {
        kind: io::ErrorKind,
    },
}

/// Mode for integrity root checking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootMode {
    Recursive,
    IdentityOnly,
}

/// An integrity check root path with its mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegrityRoot {
    pub path: PathBuf,
    pub mode: RootMode,
}

/// Kind of change detected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Modified,
    Replaced,
    Appeared,
    Disappeared,
    KindChanged,
}

impl std::fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeKind::Modified => write!(f, "modified"),
            ChangeKind::Replaced => write!(f, "replaced"),
            ChangeKind::Appeared => write!(f, "appeared"),
            ChangeKind::Disappeared => write!(f, "disappeared"),
            ChangeKind::KindChanged => write!(f, "kind_changed"),
        }
    }
}

/// A detected change between snapshots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub kind: ChangeKind,
    pub before: FileSnapshot,
    pub after: FileSnapshot,
}

/// Result of verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyResult {
    pub changed: Vec<(PathBuf, Change)>,
}

/// Filesystem operations for integrity checking.
pub trait IntegrityFs: Send + Sync {
    fn metadata(&self, p: &Path) -> io::Result<EntryKind>;
    fn read_bytes(&self, p: &Path) -> io::Result<Vec<u8>>;
    fn read_dir_names(&self, p: &Path) -> io::Result<Vec<OsString>>;
    fn file_identity(&self, p: &Path) -> io::Result<FileIdentity>;
    fn read_link(&self, p: &Path) -> io::Result<OsString>;
}

/// Real filesystem implementation.
pub struct RealFs;

pub const REAL_FS: RealFs = RealFs;

impl IntegrityFs for RealFs {
    fn metadata(&self, _p: &Path) -> io::Result<EntryKind> {
        todo!()
    }

    fn read_bytes(&self, _p: &Path) -> io::Result<Vec<u8>> {
        todo!()
    }

    fn read_dir_names(&self, _p: &Path) -> io::Result<Vec<OsString>> {
        todo!()
    }

    fn file_identity(&self, _p: &Path) -> io::Result<FileIdentity> {
        todo!()
    }

    fn read_link(&self, _p: &Path) -> io::Result<OsString> {
        todo!()
    }
}

/// Snapshot the given roots.
pub fn snapshot(roots: &[IntegrityRoot], fs: &dyn IntegrityFs) -> BTreeMap<PathBuf, FileSnapshot> {
    todo!()
}

/// Compute the difference between two snapshots.
pub fn diff(before: &FileSnapshot, after: &FileSnapshot) -> Option<Change> {
    todo!()
}

/// Verify current state against baseline.
pub fn verify(baseline: &BTreeMap<PathBuf, FileSnapshot>, fs: &dyn IntegrityFs) -> VerifyResult {
    todo!()
}

/// Return the list of executable-config paths to check.
pub fn integrity_paths(home: &Path, cwd: &Path) -> Vec<IntegrityRoot> {
    todo!()
}

/// Run periodic verification.
pub async fn run_periodic(
    baseline: BTreeMap<PathBuf, FileSnapshot>,
    fs: Arc<dyn IntegrityFs>,
    period: Duration,
    on_drift: Arc<dyn Fn(PathBuf, Change) + Send + Sync>,
) {
    todo!()
}
