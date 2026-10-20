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

const MAX_ENTRIES: usize = 1000;
const MAX_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

impl IntegrityFs for RealFs {
    fn metadata(&self, p: &Path) -> io::Result<EntryKind> {
        let meta = std::fs::symlink_metadata(p)?;
        if meta.is_symlink() {
            Ok(EntryKind::Link)
        } else if meta.is_dir() {
            Ok(EntryKind::Folder)
        } else {
            Ok(EntryKind::File { len: meta.len() })
        }
    }

    fn read_bytes(&self, p: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(p)
    }

    fn read_dir_names(&self, p: &Path) -> io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(p)? {
            let entry = entry?;
            names.push(entry.file_name());
        }
        Ok(names)
    }

    fn file_identity(&self, p: &Path) -> io::Result<FileIdentity> {
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
                FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo,
                GetFileInformationByHandleEx,
            };

            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(p)?;

            let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
            let success = unsafe {
                GetFileInformationByHandleEx(
                    file.as_raw_handle() as _,
                    FileIdInfo,
                    &mut info as *mut _ as *mut _,
                    std::mem::size_of::<FILE_ID_INFO>() as u32,
                )
            };

            if success == 0 {
                return Err(io::Error::last_os_error());
            }

            let file_id = u128::from_le_bytes(info.FileId.Identifier);
            let volume = info.VolumeSerialNumber as u64;

            Ok(FileIdentity { volume, file_id })
        }

        #[cfg(not(windows))]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::symlink_metadata(p)?;
            let volume = meta.dev();
            let file_id = meta.ino() as u128;
            Ok(FileIdentity { volume, file_id })
        }
    }

    fn read_link(&self, p: &Path) -> io::Result<OsString> {
        std::fs::read_link(p).map(|pb| pb.into_os_string())
    }
}

/// Snapshot the given roots.
pub fn snapshot(roots: &[IntegrityRoot], fs: &dyn IntegrityFs) -> BTreeMap<PathBuf, FileSnapshot> {
    let mut result = BTreeMap::new();
    for root in roots {
        let snap = snapshot_one(&root.path, root.mode, fs);
        result.insert(root.path.clone(), snap);
    }
    result
}

fn snapshot_one(path: &Path, mode: RootMode, fs: &dyn IntegrityFs) -> FileSnapshot {
    let kind = match fs.metadata(path) {
        Ok(k) => k,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return FileSnapshot::Absent,
        Err(e) if e.kind() == io::ErrorKind::NotADirectory => return FileSnapshot::Absent,
        Err(_e) => {
            // Retry once after 100 ms
            std::thread::sleep(Duration::from_millis(100));
            match fs.metadata(path) {
                Ok(k) => k,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return FileSnapshot::Absent,
                Err(e) if e.kind() == io::ErrorKind::NotADirectory => return FileSnapshot::Absent,
                Err(e) => return FileSnapshot::Unreadable { kind: e.kind() },
            }
        }
    };

    match kind {
        EntryKind::File { len } => {
            let identity = match fs.file_identity(path) {
                Ok(id) => id,
                Err(e) => return FileSnapshot::Unreadable { kind: e.kind() },
            };
            if len > MAX_BYTES {
                return FileSnapshot::TooLarge {
                    identity,
                    top_level_names_sha256: [0; 32],
                };
            }
            let bytes = match fs.read_bytes(path) {
                Ok(b) => b,
                Err(e) => return FileSnapshot::Unreadable { kind: e.kind() },
            };
            let sha256 = sha256_hash(&bytes);
            FileSnapshot::File { sha256, identity }
        }
        EntryKind::Folder => {
            let identity = match fs.file_identity(path) {
                Ok(id) => id,
                Err(e) => return FileSnapshot::Unreadable { kind: e.kind() },
            };
            if mode == RootMode::IdentityOnly {
                return FileSnapshot::FolderIdentity { identity };
            }
            // Recursive mode
            let mut entries_count = 0;
            let mut cumulative_bytes = 0u64;
            match snapshot_folder_recursive(path, fs, &mut entries_count, &mut cumulative_bytes) {
                Ok(sha256) => FileSnapshot::Folder { sha256, identity },
                Err(FolderError::TooLarge) => {
                    let top_level_names = match fs.read_dir_names(path) {
                        Ok(names) => names,
                        Err(_) => {
                            return FileSnapshot::TooLarge {
                                identity,
                                top_level_names_sha256: [0; 32],
                            };
                        }
                    };
                    let top_level_names_sha256 = hash_dir_names(&top_level_names);
                    FileSnapshot::TooLarge {
                        identity,
                        top_level_names_sha256,
                    }
                }
                Err(FolderError::Unreadable(kind)) => FileSnapshot::Unreadable { kind },
            }
        }
        EntryKind::Link => {
            let identity = match fs.file_identity(path) {
                Ok(id) => id,
                Err(e) => return FileSnapshot::Unreadable { kind: e.kind() },
            };
            let target_sha256 = match fs.read_link(path) {
                Ok(target) => {
                    #[cfg(unix)]
                    use std::os::unix::ffi::OsStrExt;
                    #[cfg(windows)]
                    use std::os::windows::ffi::OsStrExt;

                    #[cfg(unix)]
                    let bytes: &[u8] = target.as_bytes();
                    #[cfg(windows)]
                    let owned: Vec<u8> =
                        target.encode_wide().flat_map(|w| w.to_le_bytes()).collect();
                    #[cfg(windows)]
                    let bytes: &[u8] = &owned;

                    sha256_hash(bytes)
                }
                Err(_) => [0; 32],
            };
            FileSnapshot::Link {
                target_sha256,
                identity,
            }
        }
    }
}

enum FolderError {
    TooLarge,
    Unreadable(io::ErrorKind),
}

fn snapshot_folder_recursive(
    path: &Path,
    fs: &dyn IntegrityFs,
    entries_count: &mut usize,
    cumulative_bytes: &mut u64,
) -> Result<[u8; 32], FolderError> {
    *entries_count += 1;
    if *entries_count > MAX_ENTRIES {
        return Err(FolderError::TooLarge);
    }

    let names = fs
        .read_dir_names(path)
        .map_err(|e| FolderError::Unreadable(e.kind()))?;

    let mut children: Vec<(OsString, u8, [u8; 32])> = Vec::new();

    for name in names {
        *entries_count += 1;
        if *entries_count > MAX_ENTRIES {
            return Err(FolderError::TooLarge);
        }

        let child_path = path.join(&name);
        let kind = match fs.metadata(&child_path) {
            Ok(k) => k,
            Err(_) => continue, // Skip unreadable children
        };

        let (kind_byte, hash) = match kind {
            EntryKind::File { len } => {
                if *cumulative_bytes + len > MAX_BYTES {
                    return Err(FolderError::TooLarge);
                }
                let bytes = fs
                    .read_bytes(&child_path)
                    .map_err(|_| FolderError::TooLarge)?; // Treat read failure as too large
                *cumulative_bytes += len;
                (0u8, sha256_hash(&bytes))
            }
            EntryKind::Folder => {
                let hash =
                    snapshot_folder_recursive(&child_path, fs, entries_count, cumulative_bytes)?;
                (1u8, hash)
            }
            EntryKind::Link => {
                let target_hash = match fs.read_link(&child_path) {
                    Ok(target) => {
                        #[cfg(unix)]
                        use std::os::unix::ffi::OsStrExt;
                        #[cfg(windows)]
                        use std::os::windows::ffi::OsStrExt;

                        #[cfg(unix)]
                        let bytes: &[u8] = target.as_bytes();
                        #[cfg(windows)]
                        let owned: Vec<u8> =
                            target.encode_wide().flat_map(|w| w.to_le_bytes()).collect();
                        #[cfg(windows)]
                        let bytes: &[u8] = &owned;

                        sha256_hash(bytes)
                    }
                    Err(_) => [0; 32],
                };
                (2u8, target_hash)
            }
        };

        children.push((name, kind_byte, hash));
    }

    // Sort children by encoded name bytes
    children.sort_by(|a, b| {
        #[cfg(unix)]
        use std::os::unix::ffi::OsStrExt;
        #[cfg(windows)]
        use std::os::windows::ffi::OsStrExt;

        #[cfg(unix)]
        let a_bytes = a.0.as_bytes();
        #[cfg(unix)]
        let b_bytes = b.0.as_bytes();

        #[cfg(windows)]
        let a_bytes: Vec<u8> = a.0.encode_wide().flat_map(|w| w.to_le_bytes()).collect();
        #[cfg(windows)]
        let b_bytes: Vec<u8> = b.0.encode_wide().flat_map(|w| w.to_le_bytes()).collect();

        #[cfg(unix)]
        {
            a_bytes.cmp(b_bytes)
        }
        #[cfg(windows)]
        {
            a_bytes.cmp(&b_bytes)
        }
    });

    // Build the hash from sorted children
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;

    for (name, kind_byte, hash) in children {
        #[cfg(unix)]
        use std::os::unix::ffi::OsStrExt;
        #[cfg(windows)]
        use std::os::windows::ffi::OsStrExt;

        #[cfg(unix)]
        let name_bytes = name.as_bytes();
        #[cfg(windows)]
        let name_bytes: Vec<u8> = name.encode_wide().flat_map(|w| w.to_le_bytes()).collect();

        let len = name_bytes.len() as u32;
        hasher.update(len.to_le_bytes());
        hasher.update(name_bytes);
        hasher.update([kind_byte]);
        hasher.update(hash);
    }

    Ok(hasher.finalize().into())
}

fn hash_dir_names(names: &[OsString]) -> [u8; 32] {
    use sha2::Digest;
    let mut sorted = names.to_vec();
    sorted.sort_by(|a, b| {
        #[cfg(unix)]
        use std::os::unix::ffi::OsStrExt;
        #[cfg(windows)]
        use std::os::windows::ffi::OsStrExt;

        #[cfg(unix)]
        let a_bytes = a.as_bytes();
        #[cfg(unix)]
        let b_bytes = b.as_bytes();

        #[cfg(windows)]
        let a_bytes: Vec<u8> = a.encode_wide().flat_map(|w| w.to_le_bytes()).collect();
        #[cfg(windows)]
        let b_bytes: Vec<u8> = b.encode_wide().flat_map(|w| w.to_le_bytes()).collect();

        #[cfg(unix)]
        {
            a_bytes.cmp(b_bytes)
        }
        #[cfg(windows)]
        {
            a_bytes.cmp(&b_bytes)
        }
    });

    let mut hasher = sha2::Sha256::new();
    for name in sorted {
        #[cfg(unix)]
        use std::os::unix::ffi::OsStrExt;
        #[cfg(windows)]
        use std::os::windows::ffi::OsStrExt;

        #[cfg(unix)]
        let name_bytes = name.as_bytes();
        #[cfg(windows)]
        let name_bytes: Vec<u8> = name.encode_wide().flat_map(|w| w.to_le_bytes()).collect();

        let len = name_bytes.len() as u32;
        hasher.update(len.to_le_bytes());
        hasher.update(name_bytes);
    }
    hasher.finalize().into()
}

fn sha256_hash(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

/// Compute the difference between two snapshots.
pub fn diff(before: &FileSnapshot, after: &FileSnapshot) -> Option<Change> {
    use FileSnapshot::*;

    match (before, after) {
        (Absent, Absent) => None,
        (Absent, _) => Some(Change {
            kind: ChangeKind::Appeared,
            before: before.clone(),
            after: after.clone(),
        }),
        (_, Absent) => Some(Change {
            kind: ChangeKind::Disappeared,
            before: before.clone(),
            after: after.clone(),
        }),
        (
            File {
                identity: id1,
                sha256: h1,
            },
            File {
                identity: id2,
                sha256: h2,
            },
        ) => {
            if id1 != id2 {
                Some(Change {
                    kind: ChangeKind::Replaced,
                    before: before.clone(),
                    after: after.clone(),
                })
            } else if h1 != h2 {
                Some(Change {
                    kind: ChangeKind::Modified,
                    before: before.clone(),
                    after: after.clone(),
                })
            } else {
                None
            }
        }
        (
            Folder {
                identity: id1,
                sha256: h1,
            },
            Folder {
                identity: id2,
                sha256: h2,
            },
        ) => {
            if id1 != id2 {
                Some(Change {
                    kind: ChangeKind::Replaced,
                    before: before.clone(),
                    after: after.clone(),
                })
            } else if h1 != h2 {
                Some(Change {
                    kind: ChangeKind::Modified,
                    before: before.clone(),
                    after: after.clone(),
                })
            } else {
                None
            }
        }
        (FolderIdentity { identity: id1 }, FolderIdentity { identity: id2 }) => {
            if id1 != id2 {
                Some(Change {
                    kind: ChangeKind::Replaced,
                    before: before.clone(),
                    after: after.clone(),
                })
            } else {
                None
            }
        }
        (
            Link {
                identity: id1,
                target_sha256: h1,
            },
            Link {
                identity: id2,
                target_sha256: h2,
            },
        ) => {
            if id1 != id2 {
                Some(Change {
                    kind: ChangeKind::Replaced,
                    before: before.clone(),
                    after: after.clone(),
                })
            } else if h1 != h2 {
                Some(Change {
                    kind: ChangeKind::Modified,
                    before: before.clone(),
                    after: after.clone(),
                })
            } else {
                None
            }
        }
        (
            TooLarge {
                identity: id1,
                top_level_names_sha256: h1,
            },
            TooLarge {
                identity: id2,
                top_level_names_sha256: h2,
            },
        ) => {
            if id1 != id2 {
                Some(Change {
                    kind: ChangeKind::Replaced,
                    before: before.clone(),
                    after: after.clone(),
                })
            } else if h1 != h2 {
                Some(Change {
                    kind: ChangeKind::Modified,
                    before: before.clone(),
                    after: after.clone(),
                })
            } else {
                None
            }
        }
        (Unreadable { kind: k1 }, Unreadable { kind: k2 }) => {
            if k1 != k2 {
                Some(Change {
                    kind: ChangeKind::KindChanged,
                    before: before.clone(),
                    after: after.clone(),
                })
            } else {
                None
            }
        }
        _ => Some(Change {
            kind: ChangeKind::KindChanged,
            before: before.clone(),
            after: after.clone(),
        }),
    }
}

/// Verify current state against baseline.
pub fn verify(baseline: &BTreeMap<PathBuf, FileSnapshot>, fs: &dyn IntegrityFs) -> VerifyResult {
    let mut changed = Vec::new();
    for (path, before) in baseline {
        // Determine the mode from the snapshot type
        let mode = match before {
            FileSnapshot::FolderIdentity { .. } => RootMode::IdentityOnly,
            _ => RootMode::Recursive,
        };
        let after = snapshot_one(path, mode, fs);
        if let Some(change) = diff(before, &after) {
            changed.push((path.clone(), change));
        }
    }
    VerifyResult { changed }
}

/// Return the list of executable-config paths to check.
/// Every executable-config entry of `build_request`, plus workspace `.claude` and `.git` (identity only).
pub fn integrity_paths(home: &Path, cwd: &Path) -> Vec<IntegrityRoot> {
    vec![
        IntegrityRoot {
            path: home.join(".claude").join("settings.json"),
            mode: RootMode::Recursive,
        },
        IntegrityRoot {
            path: home.join(".claude").join("hooks"),
            mode: RootMode::Recursive,
        },
        IntegrityRoot {
            path: home.join(".claude").join("plugins"),
            mode: RootMode::Recursive,
        },
        IntegrityRoot {
            path: cwd.join(".claude"),
            mode: RootMode::IdentityOnly,
        },
        IntegrityRoot {
            path: cwd.join(".claude").join("settings.json"),
            mode: RootMode::Recursive,
        },
        IntegrityRoot {
            path: cwd.join(".claude").join("settings.local.json"),
            mode: RootMode::Recursive,
        },
        IntegrityRoot {
            path: cwd.join(".claude").join("hooks"),
            mode: RootMode::Recursive,
        },
        IntegrityRoot {
            path: cwd.join(".mcp.json"),
            mode: RootMode::Recursive,
        },
        IntegrityRoot {
            path: cwd.join(".git"),
            mode: RootMode::IdentityOnly,
        },
        IntegrityRoot {
            path: cwd.join("HEAD"),
            mode: RootMode::Recursive,
        },
        IntegrityRoot {
            path: cwd.join(".git").join("config"),
            mode: RootMode::Recursive,
        },
        IntegrityRoot {
            path: cwd.join(".git").join("hooks"),
            mode: RootMode::Recursive,
        },
        IntegrityRoot {
            path: cwd.join(".git").join("commondir"),
            mode: RootMode::Recursive,
        },
    ]
}

/// Run periodic verification.
pub async fn run_periodic(
    baseline: BTreeMap<PathBuf, FileSnapshot>,
    fs: Arc<dyn IntegrityFs>,
    period: Duration,
    on_drift: Arc<dyn Fn(PathBuf, Change) + Send + Sync>,
) {
    let mut last_observed: BTreeMap<PathBuf, FileSnapshot> = baseline.clone();

    // A fixed schedule: the first check is one period after the task starts,
    // and later checks stay on that schedule regardless of how long a verify
    // pass takes. Missed ticks are skipped, so after a long suspend one check
    // runs instead of a catch-up burst.
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;

        let baseline_clone = baseline.clone();
        let fs_clone = fs.clone();
        let result =
            tokio::task::spawn_blocking(move || verify(&baseline_clone, fs_clone.as_ref()))
                .await
                .unwrap_or_else(|_| VerifyResult {
                    changed: Vec::new(),
                });

        for (path, change) in result.changed {
            // Check if this is different from the last observed state
            let last = last_observed.get(&path);
            let should_notify = match last {
                Some(last_snap) => {
                    if let Some(incremental_change) = diff(last_snap, &change.after) {
                        // Update our tracking
                        last_observed.insert(path.clone(), change.after.clone());
                        // Notify with the incremental change
                        on_drift(path.clone(), incremental_change);
                        false // We already notified
                    } else {
                        false // No change from last observation
                    }
                }
                None => {
                    // First time seeing a change for this path
                    last_observed.insert(path.clone(), change.after.clone());
                    true
                }
            };

            if should_notify {
                on_drift(path.clone(), change);
            }
        }
    }
}
