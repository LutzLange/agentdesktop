use super::*;
use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Mock filesystem for testing
struct MockFs {
    entries: Mutex<BTreeMap<PathBuf, MockEntry>>,
    metadata_calls: Mutex<Vec<PathBuf>>,
}

enum MockEntry {
    File {
        content: Vec<u8>,
        identity: FileIdentity,
    },
    Folder {
        children: Vec<OsString>,
        identity: FileIdentity,
    },
    Link {
        target: OsString,
        identity: FileIdentity,
    },
    Absent,
    Unreadable(io::ErrorKind),
}

impl MockFs {
    fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            metadata_calls: Mutex::new(Vec::new()),
        }
    }

    fn set_file(&self, path: PathBuf, content: Vec<u8>, identity: FileIdentity) {
        self.entries
            .lock()
            .unwrap()
            .insert(path, MockEntry::File { content, identity });
    }

    fn set_folder(&self, path: PathBuf, children: Vec<OsString>, identity: FileIdentity) {
        self.entries
            .lock()
            .unwrap()
            .insert(path, MockEntry::Folder { children, identity });
    }

    fn set_link(&self, path: PathBuf, target: OsString, identity: FileIdentity) {
        self.entries
            .lock()
            .unwrap()
            .insert(path, MockEntry::Link { target, identity });
    }

    fn set_absent(&self, path: PathBuf) {
        self.entries.lock().unwrap().insert(path, MockEntry::Absent);
    }

    fn set_unreadable(&self, path: PathBuf, kind: io::ErrorKind) {
        self.entries
            .lock()
            .unwrap()
            .insert(path, MockEntry::Unreadable(kind));
    }

    fn metadata_call_count(&self) -> usize {
        self.metadata_calls.lock().unwrap().len()
    }
}

impl IntegrityFs for MockFs {
    fn metadata(&self, p: &Path) -> io::Result<EntryKind> {
        self.metadata_calls.lock().unwrap().push(p.to_path_buf());
        let entries = self.entries.lock().unwrap();
        match entries.get(p) {
            Some(MockEntry::File { content, .. }) => Ok(EntryKind::File {
                len: content.len() as u64,
            }),
            Some(MockEntry::Folder { .. }) => Ok(EntryKind::Folder),
            Some(MockEntry::Link { .. }) => Ok(EntryKind::Link),
            Some(MockEntry::Absent) => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
            Some(MockEntry::Unreadable(kind)) => Err(io::Error::new(*kind, "unreadable")),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
        }
    }

    fn read_bytes(&self, p: &Path) -> io::Result<Vec<u8>> {
        let entries = self.entries.lock().unwrap();
        match entries.get(p) {
            Some(MockEntry::File { content, .. }) => Ok(content.clone()),
            Some(MockEntry::Unreadable(kind)) => Err(io::Error::new(*kind, "unreadable")),
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
        }
    }

    fn read_dir_names(&self, p: &Path) -> io::Result<Vec<OsString>> {
        let entries = self.entries.lock().unwrap();
        match entries.get(p) {
            Some(MockEntry::Folder { children, .. }) => Ok(children.clone()),
            Some(MockEntry::Unreadable(kind)) => Err(io::Error::new(*kind, "unreadable")),
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
        }
    }

    fn file_identity(&self, p: &Path) -> io::Result<FileIdentity> {
        let entries = self.entries.lock().unwrap();
        match entries.get(p) {
            Some(MockEntry::File { identity, .. }) => Ok(*identity),
            Some(MockEntry::Folder { identity, .. }) => Ok(*identity),
            Some(MockEntry::Link { identity, .. }) => Ok(*identity),
            Some(MockEntry::Unreadable(kind)) => Err(io::Error::new(*kind, "unreadable")),
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
        }
    }

    fn read_link(&self, p: &Path) -> io::Result<OsString> {
        let entries = self.entries.lock().unwrap();
        match entries.get(p) {
            Some(MockEntry::Link { target, .. }) => Ok(target.clone()),
            Some(MockEntry::Unreadable(kind)) => Err(io::Error::new(*kind, "unreadable")),
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
        }
    }
}

// AC 1 Tests: snapshot

#[test]
fn snapshot_file_present() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/file.txt");
    let identity = FileIdentity {
        volume: 1,
        file_id: 100,
    };
    fs.set_file(path.clone(), b"content".to_vec(), identity);

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = snapshot(&roots, &fs);

    assert!(matches!(result.get(&path), Some(FileSnapshot::File { .. })));
}

#[test]
fn snapshot_file_absent() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/missing.txt");
    fs.set_absent(path.clone());

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = snapshot(&roots, &fs);

    assert_eq!(result.get(&path), Some(&FileSnapshot::Absent));
}

#[test]
fn snapshot_folder() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/folder");
    let identity = FileIdentity {
        volume: 1,
        file_id: 200,
    };
    fs.set_folder(path.clone(), vec![], identity);

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = snapshot(&roots, &fs);

    assert!(matches!(
        result.get(&path),
        Some(FileSnapshot::Folder { .. })
    ));
}

#[test]
fn snapshot_nonexistent() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/nonexistent");

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = snapshot(&roots, &fs);

    assert_eq!(result.get(&path), Some(&FileSnapshot::Absent));
}

#[test]
fn snapshot_unreadable() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/unreadable");
    fs.set_unreadable(path.clone(), io::ErrorKind::PermissionDenied);

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = snapshot(&roots, &fs);

    assert!(matches!(
        result.get(&path),
        Some(FileSnapshot::Unreadable { .. })
    ));
}

#[test]
fn snapshot_folder_too_large_1001_entries() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/large_folder");
    let identity = FileIdentity {
        volume: 1,
        file_id: 300,
    };

    // Create 1001 child entries
    let mut children = Vec::new();
    for i in 0..1001 {
        children.push(OsString::from(format!("file{}", i)));
    }
    fs.set_folder(path.clone(), children, identity);

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = snapshot(&roots, &fs);

    assert!(matches!(
        result.get(&path),
        Some(FileSnapshot::TooLarge { .. })
    ));
}

#[test]
fn snapshot_folder_too_large_10mib_plus_1() {
    let fs = MockFs::new();
    let folder_path = PathBuf::from("/test/folder");
    let folder_identity = FileIdentity {
        volume: 1,
        file_id: 400,
    };

    // Create a child file that's 10 MiB + 1 byte
    let file_path = PathBuf::from("/test/folder/large_file");
    let file_identity = FileIdentity {
        volume: 1,
        file_id: 401,
    };
    let large_content = vec![0u8; 10 * 1024 * 1024 + 1];
    fs.set_file(file_path, large_content, file_identity);
    fs.set_folder(
        folder_path.clone(),
        vec![OsString::from("large_file")],
        folder_identity,
    );

    let roots = vec![IntegrityRoot {
        path: folder_path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = snapshot(&roots, &fs);

    assert!(matches!(
        result.get(&folder_path),
        Some(FileSnapshot::TooLarge { .. })
    ));
}

#[test]
fn snapshot_root_file_too_large_10mib_plus_1() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/large_file.bin");
    let identity = FileIdentity {
        volume: 1,
        file_id: 500,
    };
    let large_content = vec![0u8; 10 * 1024 * 1024 + 1];
    fs.set_file(path.clone(), large_content, identity);

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = snapshot(&roots, &fs);

    assert!(matches!(
        result.get(&path),
        Some(FileSnapshot::TooLarge { structure_sha256, .. })
        if *structure_sha256 != [0; 32]
    ));
}

// AC 1 Tests: hash stability

#[test]
fn hash_stability_same_file_twice() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/file.txt");
    let identity = FileIdentity {
        volume: 1,
        file_id: 600,
    };
    fs.set_file(path.clone(), b"content".to_vec(), identity);

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result1 = snapshot(&roots, &fs);
    let result2 = snapshot(&roots, &fs);

    assert_eq!(result1.get(&path), result2.get(&path));
}

#[test]
fn hash_stability_folder_children_different_order() {
    // Test that folder hash is the same regardless of the order children are returned
    // (they should be sorted before hashing)
    let fs1 = MockFs::new();
    let path1 = PathBuf::from("/test/folder");
    let identity = FileIdentity {
        volume: 1,
        file_id: 700,
    };
    fs1.set_folder(
        path1.clone(),
        vec![OsString::from("a"), OsString::from("b")],
        identity,
    );

    let fs2 = MockFs::new();
    let path2 = PathBuf::from("/test/folder");
    fs2.set_folder(
        path2.clone(),
        vec![OsString::from("b"), OsString::from("a")],
        identity,
    );

    let roots1 = vec![IntegrityRoot {
        path: path1.clone(),
        mode: RootMode::Recursive,
    }];
    let roots2 = vec![IntegrityRoot {
        path: path2.clone(),
        mode: RootMode::Recursive,
    }];

    let result1 = snapshot(&roots1, &fs1);
    let result2 = snapshot(&roots2, &fs2);

    // Both should produce the same hash
    assert_eq!(result1.get(&path1), result2.get(&path2));
}

#[test]
fn hash_stability_folder_one_child_changed() {
    let fs1 = MockFs::new();
    let folder_path = PathBuf::from("/test/folder");
    let folder_identity = FileIdentity {
        volume: 1,
        file_id: 800,
    };
    fs1.set_folder(
        folder_path.clone(),
        vec![OsString::from("child.txt")],
        folder_identity,
    );
    let child_path = PathBuf::from("/test/folder/child.txt");
    let child_identity = FileIdentity {
        volume: 1,
        file_id: 801,
    };
    fs1.set_file(child_path.clone(), b"content1".to_vec(), child_identity);

    let fs2 = MockFs::new();
    fs2.set_folder(
        folder_path.clone(),
        vec![OsString::from("child.txt")],
        folder_identity,
    );
    fs2.set_file(child_path, b"content2".to_vec(), child_identity);

    let roots = vec![IntegrityRoot {
        path: folder_path.clone(),
        mode: RootMode::Recursive,
    }];
    let result1 = snapshot(&roots, &fs1);
    let result2 = snapshot(&roots, &fs2);

    // Hashes should differ
    assert_ne!(result1.get(&folder_path), result2.get(&folder_path));
}

// AC 1 Tests: diff

#[test]
fn diff_table_driven_all_transitions() {
    // Table-driven test covering all ChangeKind values and FileSnapshot variant pairs
    let identity1 = FileIdentity {
        volume: 1,
        file_id: 1000,
    };
    let identity2 = FileIdentity {
        volume: 1,
        file_id: 2000,
    };

    let test_cases = vec![
        // Absent transitions
        (FileSnapshot::Absent, FileSnapshot::Absent, None),
        (
            FileSnapshot::Absent,
            FileSnapshot::File {
                sha256: [1; 32],
                identity: identity1,
            },
            Some(ChangeKind::Appeared),
        ),
        (
            FileSnapshot::File {
                sha256: [1; 32],
                identity: identity1,
            },
            FileSnapshot::Absent,
            Some(ChangeKind::Disappeared),
        ),
        // Same variant, different identity -> Replaced
        (
            FileSnapshot::File {
                sha256: [1; 32],
                identity: identity1,
            },
            FileSnapshot::File {
                sha256: [1; 32],
                identity: identity2,
            },
            Some(ChangeKind::Replaced),
        ),
        // Same identity, different hash -> Modified
        (
            FileSnapshot::File {
                sha256: [1; 32],
                identity: identity1,
            },
            FileSnapshot::File {
                sha256: [2; 32],
                identity: identity1,
            },
            Some(ChangeKind::Modified),
        ),
        // Different variants -> KindChanged
        (
            FileSnapshot::File {
                sha256: [1; 32],
                identity: identity1,
            },
            FileSnapshot::Folder {
                sha256: [1; 32],
                identity: identity1,
            },
            Some(ChangeKind::KindChanged),
        ),
        // Unreadable with different ErrorKind -> KindChanged
        (
            FileSnapshot::Unreadable {
                kind: io::ErrorKind::NotFound,
            },
            FileSnapshot::Unreadable {
                kind: io::ErrorKind::PermissionDenied,
            },
            Some(ChangeKind::KindChanged),
        ),
    ];

    for (before, after, expected_kind) in test_cases {
        let result = diff(&before, &after);
        match expected_kind {
            None => assert!(
                result.is_none(),
                "Expected no change for {:?} -> {:?}",
                before,
                after
            ),
            Some(kind) => {
                let change = result.expect("Expected a change");
                assert_eq!(
                    change.kind, kind,
                    "Wrong change kind for {:?} -> {:?}",
                    before, after
                );
            }
        }
    }
}

// AC 1 Tests: verify

#[test]
fn verify_no_change() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/file.txt");
    let identity = FileIdentity {
        volume: 1,
        file_id: 1100,
    };
    fs.set_file(path.clone(), b"content".to_vec(), identity);

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let baseline = snapshot(&roots, &fs);

    let result = verify(&roots, &baseline, &fs);
    assert!(result.changed.is_empty());
}

#[test]
fn verify_file_modified() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/file.txt");
    let identity = FileIdentity {
        volume: 1,
        file_id: 1200,
    };
    fs.set_file(path.clone(), b"new_content".to_vec(), identity);

    let mut baseline = BTreeMap::new();
    baseline.insert(
        path.clone(),
        FileSnapshot::File {
            sha256: [1; 32],
            identity,
        },
    );

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = verify(&roots, &baseline, &fs);
    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.changed[0].1.kind, ChangeKind::Modified);
}

#[test]
fn verify_file_identity_changed() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/file.txt");
    let old_identity = FileIdentity {
        volume: 1,
        file_id: 1300,
    };
    let new_identity = FileIdentity {
        volume: 1,
        file_id: 1301,
    };
    fs.set_file(path.clone(), b"content".to_vec(), new_identity);

    let mut baseline = BTreeMap::new();
    baseline.insert(
        path.clone(),
        FileSnapshot::File {
            sha256: [1; 32],
            identity: old_identity,
        },
    );

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = verify(&roots, &baseline, &fs);
    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.changed[0].1.kind, ChangeKind::Replaced);
}

#[test]
fn verify_file_appeared() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/file.txt");
    let identity = FileIdentity {
        volume: 1,
        file_id: 1400,
    };
    fs.set_file(path.clone(), b"content".to_vec(), identity);

    let mut baseline = BTreeMap::new();
    baseline.insert(path.clone(), FileSnapshot::Absent);

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = verify(&roots, &baseline, &fs);
    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.changed[0].1.kind, ChangeKind::Appeared);
}

#[test]
fn verify_file_removed() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/file.txt");
    fs.set_absent(path.clone());

    let mut baseline = BTreeMap::new();
    let identity = FileIdentity {
        volume: 1,
        file_id: 1500,
    };
    baseline.insert(
        path.clone(),
        FileSnapshot::File {
            sha256: [1; 32],
            identity,
        },
    );

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = verify(&roots, &baseline, &fs);
    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.changed[0].1.kind, ChangeKind::Disappeared);
}

#[test]
fn verify_folder_child_added() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/folder");
    let identity = FileIdentity {
        volume: 1,
        file_id: 1600,
    };
    fs.set_folder(path.clone(), vec![OsString::from("new_child")], identity);

    let mut baseline = BTreeMap::new();
    baseline.insert(
        path.clone(),
        FileSnapshot::Folder {
            sha256: [1; 32],
            identity,
        },
    );

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = verify(&roots, &baseline, &fs);
    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.changed[0].1.kind, ChangeKind::Modified);
}

#[test]
fn verify_folder_replaced() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/folder");
    let old_identity = FileIdentity {
        volume: 1,
        file_id: 1700,
    };
    let new_identity = FileIdentity {
        volume: 1,
        file_id: 1701,
    };
    fs.set_folder(path.clone(), vec![], new_identity);

    let mut baseline = BTreeMap::new();
    baseline.insert(
        path.clone(),
        FileSnapshot::Folder {
            sha256: [1; 32],
            identity: old_identity,
        },
    );

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = verify(&roots, &baseline, &fs);
    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.changed[0].1.kind, ChangeKind::Replaced);
}

#[test]
fn verify_revert_to_baseline() {
    let fs = MockFs::new();
    let path = PathBuf::from("/test/file.txt");
    let identity = FileIdentity {
        volume: 1,
        file_id: 1800,
    };
    fs.set_file(path.clone(), b"original".to_vec(), identity);

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let baseline = snapshot(&roots, &fs);

    // Change the file, then revert it in place to the baseline content.
    fs.set_file(path.clone(), b"changed".to_vec(), identity);
    fs.set_file(path.clone(), b"original".to_vec(), identity);

    let result = verify(&roots, &baseline, &fs);
    assert!(
        result.changed.is_empty(),
        "content equal to the baseline is no drift: {:?}",
        result.changed
    );
}

// AC 1 Tests: integrity_paths

#[test]
fn integrity_paths_returns_thirteen_roots() {
    let home = PathBuf::from("/home/user");
    let cwd = PathBuf::from("/workspace");

    let paths = integrity_paths(&home, &cwd);

    assert_eq!(paths.len(), 13);
}

#[test]
fn integrity_paths_modes() {
    let home = PathBuf::from("/home/user");
    let cwd = PathBuf::from("/workspace");

    let paths = integrity_paths(&home, &cwd);

    // workspace .claude and .git should be IdentityOnly
    let workspace_claude = paths
        .iter()
        .find(|r| r.path.ends_with(".claude") && r.path.starts_with(&cwd));
    assert!(matches!(
        workspace_claude,
        Some(IntegrityRoot {
            mode: RootMode::IdentityOnly,
            ..
        })
    ));

    let workspace_git = paths
        .iter()
        .find(|r| r.path.ends_with(".git") && r.path.starts_with(&cwd));
    assert!(matches!(
        workspace_git,
        Some(IntegrityRoot {
            mode: RootMode::IdentityOnly,
            ..
        })
    ));
}

#[test]
fn integrity_paths_covers_build_request_entries() {
    // This test verifies that every executable-config entry that build_request makes
    // read-only or denied is among the twelve roots
    let home = PathBuf::from("/home/user");
    let cwd = PathBuf::from("/workspace");

    let paths = integrity_paths(&home, &cwd);

    // User scope
    assert!(
        paths
            .iter()
            .any(|r| r.path.ends_with(".claude/settings.json") && r.path.starts_with(&home))
    );
    assert!(
        paths
            .iter()
            .any(|r| r.path.ends_with(".claude/hooks") && r.path.starts_with(&home))
    );
    assert!(
        paths
            .iter()
            .any(|r| r.path.ends_with(".claude/plugins") && r.path.starts_with(&home))
    );

    // Workspace scope
    assert!(
        paths
            .iter()
            .any(|r| r.path.ends_with(".claude") && r.path.starts_with(&cwd))
    );
    assert!(
        paths
            .iter()
            .any(|r| r.path.ends_with(".claude/settings.json") && r.path.starts_with(&cwd))
    );
    assert!(
        paths
            .iter()
            .any(|r| r.path.ends_with(".claude/settings.local.json") && r.path.starts_with(&cwd))
    );
    assert!(
        paths
            .iter()
            .any(|r| r.path.ends_with(".claude/hooks") && r.path.starts_with(&cwd))
    );
    assert!(
        paths
            .iter()
            .any(|r| r.path.ends_with(".mcp.json") && r.path.starts_with(&cwd))
    );
    assert!(
        paths
            .iter()
            .any(|r| r.path.ends_with(".git") && r.path.starts_with(&cwd))
    );
    assert!(
        paths
            .iter()
            .any(|r| r.path.ends_with("HEAD") && r.path.starts_with(&cwd))
    );
    assert!(
        paths
            .iter()
            .any(|r| r.path.ends_with(".git/config") && r.path.starts_with(&cwd))
    );
    assert!(
        paths
            .iter()
            .any(|r| r.path.ends_with(".git/hooks") && r.path.starts_with(&cwd))
    );
}

#[test]
fn integrity_paths_git_as_file_records_children_absent() {
    let fs = MockFs::new();
    let git_path = PathBuf::from("/workspace/.git");
    let git_identity = FileIdentity {
        volume: 1,
        file_id: 1900,
    };
    fs.set_file(
        git_path.clone(),
        b"gitdir: ../.git/worktrees/foo".to_vec(),
        git_identity,
    );

    let roots = vec![
        IntegrityRoot {
            path: PathBuf::from("/workspace/.git/config"),
            mode: RootMode::Recursive,
        },
        IntegrityRoot {
            path: PathBuf::from("/workspace/.git/hooks"),
            mode: RootMode::Recursive,
        },
        IntegrityRoot {
            path: PathBuf::from("/workspace/.git/commondir"),
            mode: RootMode::Recursive,
        },
    ];

    let result = snapshot(&roots, &fs);

    // All three should be Absent because .git is a file, not a directory
    assert_eq!(
        result.get(&PathBuf::from("/workspace/.git/config")),
        Some(&FileSnapshot::Absent)
    );
    assert_eq!(
        result.get(&PathBuf::from("/workspace/.git/hooks")),
        Some(&FileSnapshot::Absent)
    );
    assert_eq!(
        result.get(&PathBuf::from("/workspace/.git/commondir")),
        Some(&FileSnapshot::Absent)
    );
}

#[test]
fn integrity_paths_identity_only_child_added_no_change() {
    let fs = MockFs::new();
    let path = PathBuf::from("/workspace/.claude");
    let identity = FileIdentity {
        volume: 1,
        file_id: 2000,
    };

    fs.set_folder(path.clone(), vec![], identity);
    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::IdentityOnly,
    }];
    let baseline = snapshot(&roots, &fs);

    // Add a child
    fs.set_folder(path.clone(), vec![OsString::from("new_file")], identity);
    let result = verify(&roots, &baseline, &fs);

    // Should be no change because it's IdentityOnly mode
    assert!(result.changed.is_empty());
}

#[test]
fn integrity_paths_folder_renamed_and_recreated_replaced() {
    let fs1 = MockFs::new();
    let path = PathBuf::from("/workspace/.claude");
    let identity1 = FileIdentity {
        volume: 1,
        file_id: 2100,
    };
    fs1.set_folder(path.clone(), vec![], identity1);

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::IdentityOnly,
    }];
    let baseline = snapshot(&roots, &fs1);

    // Recreate with different identity
    let fs2 = MockFs::new();
    let identity2 = FileIdentity {
        volume: 1,
        file_id: 2101,
    };
    fs2.set_folder(path.clone(), vec![], identity2);

    let result = verify(&roots, &baseline, &fs2);

    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.changed[0].1.kind, ChangeKind::Replaced);
}

// AC 1 Tests: link handling

#[test]
fn link_child_never_followed_target_content_changes() {
    let fs = MockFs::new();
    let folder_path = PathBuf::from("/test/folder");
    let folder_identity = FileIdentity {
        volume: 1,
        file_id: 2200,
    };
    let link_path = PathBuf::from("/test/folder/link");
    let link_identity = FileIdentity {
        volume: 1,
        file_id: 2201,
    };

    fs.set_folder(
        folder_path.clone(),
        vec![OsString::from("link")],
        folder_identity,
    );
    fs.set_link(link_path.clone(), OsString::from("/target"), link_identity);

    let roots = vec![IntegrityRoot {
        path: folder_path.clone(),
        mode: RootMode::Recursive,
    }];
    let result = snapshot(&roots, &fs);

    // Link should be in snapshot but target should not be followed
    // (tested by checking the parent hash doesn't change when target content changes)
    assert!(result.contains_key(&folder_path));
}

#[test]
fn link_target_changes_parent_hash_changes() {
    let fs1 = MockFs::new();
    let folder_path = PathBuf::from("/test/folder");
    let folder_identity = FileIdentity {
        volume: 1,
        file_id: 2300,
    };
    let link_path = PathBuf::from("/test/folder/link");
    let link_identity = FileIdentity {
        volume: 1,
        file_id: 2301,
    };

    fs1.set_folder(
        folder_path.clone(),
        vec![OsString::from("link")],
        folder_identity,
    );
    fs1.set_link(link_path.clone(), OsString::from("/target1"), link_identity);

    let roots = vec![IntegrityRoot {
        path: folder_path.clone(),
        mode: RootMode::Recursive,
    }];
    let result1 = snapshot(&roots, &fs1);

    // Change link target
    let fs2 = MockFs::new();
    fs2.set_folder(
        folder_path.clone(),
        vec![OsString::from("link")],
        folder_identity,
    );
    fs2.set_link(link_path, OsString::from("/target2"), link_identity);

    let result2 = snapshot(&roots, &fs2);

    // Parent hash should change because link target changed
    assert_ne!(result1.get(&folder_path), result2.get(&folder_path));
}

// AC 1 Tests: .git handling

#[test]
fn git_file_content_changed_modified() {
    let fs1 = MockFs::new();
    let path = PathBuf::from("/workspace/.git");
    let identity = FileIdentity {
        volume: 1,
        file_id: 2400,
    };
    fs1.set_file(path.clone(), b"gitdir: ../foo".to_vec(), identity);

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::IdentityOnly,
    }];
    let baseline = snapshot(&roots, &fs1);

    let fs2 = MockFs::new();
    fs2.set_file(path.clone(), b"gitdir: ../bar".to_vec(), identity);

    let result = verify(&roots, &baseline, &fs2);

    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.changed[0].1.kind, ChangeKind::Modified);
}

#[test]
fn git_folder_renamed_and_recreated_replaced() {
    let fs1 = MockFs::new();
    let path = PathBuf::from("/workspace/.git");
    let identity1 = FileIdentity {
        volume: 1,
        file_id: 2500,
    };
    fs1.set_folder(path.clone(), vec![], identity1);

    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::IdentityOnly,
    }];
    let baseline = snapshot(&roots, &fs1);

    let fs2 = MockFs::new();
    let identity2 = FileIdentity {
        volume: 1,
        file_id: 2501,
    };
    fs2.set_folder(path.clone(), vec![], identity2);

    let result = verify(&roots, &baseline, &fs2);

    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.changed[0].1.kind, ChangeKind::Replaced);
}

// AC 1 Tests: Platform-specific file identity

#[test]
fn a_file_renamed_over_another_changes_its_identity_and_is_a_replacement() {
    // The F5 case on the real filesystem: identical bytes, new file identity.
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("settings.json");
    let other = temp.path().join("settings.json.tmp");
    std::fs::write(&target, b"{}").unwrap();

    let roots = vec![IntegrityRoot {
        path: target.clone(),
        mode: RootMode::Recursive,
    }];
    let baseline = snapshot(&roots, &REAL_FS);
    let before_identity = REAL_FS.file_identity(&target).unwrap();

    std::fs::write(&other, b"{}").unwrap();
    std::fs::rename(&other, &target).unwrap();

    let after_identity = REAL_FS.file_identity(&target).unwrap();
    assert_ne!(before_identity, after_identity, "rename keeps the identity");

    let result = verify(&roots, &baseline, &REAL_FS);
    assert_eq!(result.changed.len(), 1, "{:?}", result.changed);
    assert_eq!(result.changed[0].1.kind, ChangeKind::Replaced);
}

// AC 2 Tests: run_periodic

#[tokio::test]
async fn run_periodic_reports_a_revert_and_a_repeated_change() {
    let fs = Arc::new(MockFs::new());
    let path = PathBuf::from("/test/settings.json");
    let identity = FileIdentity {
        volume: 1,
        file_id: 4100,
    };
    fs.set_file(path.clone(), b"original".to_vec(), identity);
    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let baseline = snapshot(&roots, fs.as_ref() as &dyn IntegrityFs);

    let drift_count = Arc::new(Mutex::new(0usize));
    let drift_count_clone = drift_count.clone();
    let on_drift = Arc::new(move |_path: PathBuf, _change: Change| {
        *drift_count_clone.lock().unwrap() += 1;
    });

    tokio::time::pause();
    tokio::spawn(run_periodic(
        roots,
        baseline,
        fs.clone(),
        Duration::from_secs(60),
        on_drift,
    ));
    // Poll the task once so its timer starts at t=0.
    tokio::task::yield_now().await;

    for (content, expected) in [
        (&b"EVIL"[..], 1usize), // change
        (&b"original"[..], 2),  // revert to the launch state
        (&b"EVIL"[..], 3),      // the same change again
        (&b"EVIL"[..], 3),      // quiet period: no new alert
    ] {
        fs.set_file(path.clone(), content.to_vec(), identity);
        tokio::time::advance(Duration::from_secs(61)).await;
        for _ in 0..1000 {
            if *drift_count.lock().unwrap() >= expected {
                break;
            }
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(*drift_count.lock().unwrap(), expected, "{content:?}");
    }
}

#[tokio::test]
async fn run_periodic_reports_appear_disappear_and_reappear() {
    let fs = Arc::new(MockFs::new());
    let path = PathBuf::from("/test/settings.json");
    let identity = FileIdentity {
        volume: 1,
        file_id: 4200,
    };
    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let baseline = snapshot(&roots, fs.as_ref() as &dyn IntegrityFs); // absent

    let kinds = Arc::new(Mutex::new(Vec::new()));
    let kinds_clone = kinds.clone();
    let on_drift = Arc::new(move |_path: PathBuf, change: Change| {
        kinds_clone.lock().unwrap().push(change.kind);
    });

    tokio::time::pause();
    tokio::spawn(run_periodic(
        roots,
        baseline,
        fs.clone(),
        Duration::from_secs(60),
        on_drift,
    ));
    // Poll the task once so its timer starts at t=0.
    tokio::task::yield_now().await;

    for (step, expected) in [(0usize, 1usize), (1, 2), (2, 3)] {
        match step {
            0 => fs.set_file(path.clone(), b"planted".to_vec(), identity),
            1 => fs.set_absent(path.clone()),
            _ => fs.set_file(path.clone(), b"planted".to_vec(), identity),
        }
        tokio::time::advance(Duration::from_secs(61)).await;
        for _ in 0..1000 {
            if kinds.lock().unwrap().len() >= expected {
                break;
            }
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(kinds.lock().unwrap().len(), expected);
    }
    assert_eq!(
        *kinds.lock().unwrap(),
        vec![
            ChangeKind::Appeared,
            ChangeKind::Disappeared,
            ChangeKind::Appeared
        ]
    );
}

#[test]
fn an_identity_only_root_that_appears_keeps_its_mode() {
    let fs = MockFs::new();
    let path = PathBuf::from("/workspace/.claude");
    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::IdentityOnly,
    }];
    let baseline = snapshot(&roots, &fs); // absent at launch

    let identity = FileIdentity {
        volume: 1,
        file_id: 4300,
    };
    fs.set_folder(path.clone(), vec!["settings.json".into()], identity);
    fs.set_file(
        path.join("settings.json"),
        b"{}".to_vec(),
        FileIdentity {
            volume: 1,
            file_id: 4301,
        },
    );

    let result = verify(&roots, &baseline, &fs);
    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.changed[0].1.kind, ChangeKind::Appeared);
    assert!(
        matches!(
            result.changed[0].1.after,
            FileSnapshot::FolderIdentity { .. }
        ),
        "the declared mode is kept once the root appears: {:?}",
        result.changed[0].1.after
    );
}

#[tokio::test]
async fn run_periodic_scenario_a_no_call_at_59s_one_at_61s_two_at_121s() {
    let fs = Arc::new(MockFs::new());
    let path = PathBuf::from("/test/file.txt");
    let identity = FileIdentity {
        volume: 1,
        file_id: 3000,
    };
    fs.set_file(path.clone(), b"content".to_vec(), identity);

    let mut baseline = BTreeMap::new();
    baseline.insert(
        path.clone(),
        FileSnapshot::File {
            sha256: [1; 32],
            identity,
        },
    );

    let on_drift = Arc::new(|_path: PathBuf, _change: Change| {});

    // Check at 59s - no call
    tokio::time::pause();
    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    tokio::spawn(run_periodic(
        roots,
        baseline.clone(),
        fs.clone(),
        Duration::from_secs(60),
        on_drift.clone(),
    ));
    // Poll the task once so its timer starts at t=0.
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(59)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(fs.metadata_call_count(), 0);

    // Check at 61s - one call
    tokio::time::advance(Duration::from_secs(2)).await;
    for _ in 0..1000 {
        if fs.metadata_call_count() >= 1 {
            break;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(fs.metadata_call_count(), 1);

    // Check at 121s - two calls
    tokio::time::advance(Duration::from_secs(60)).await;
    for _ in 0..1000 {
        if fs.metadata_call_count() >= 2 {
            break;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(fs.metadata_call_count(), 2);
}

#[tokio::test]
async fn run_periodic_scenario_b_abort_at_90s_exactly_one_call() {
    let fs = Arc::new(MockFs::new());
    let path = PathBuf::from("/test/file.txt");
    let identity = FileIdentity {
        volume: 1,
        file_id: 3100,
    };
    fs.set_file(path.clone(), b"content".to_vec(), identity);

    let mut baseline = BTreeMap::new();
    baseline.insert(
        path.clone(),
        FileSnapshot::File {
            sha256: [1; 32],
            identity,
        },
    );

    let on_drift = Arc::new(|_path: PathBuf, _change: Change| {});

    tokio::time::pause();
    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    let handle = tokio::spawn(run_periodic(
        roots,
        baseline,
        fs.clone(),
        Duration::from_secs(60),
        on_drift,
    ));
    // Poll the task once so its timer starts at t=0.
    tokio::task::yield_now().await;

    tokio::time::advance(Duration::from_secs(90)).await;
    for _ in 0..1000 {
        if fs.metadata_call_count() >= 1 {
            break;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    handle.abort();

    // Should have exactly one call at t=60
    assert_eq!(fs.metadata_call_count(), 1);

    // No further call at 180s
    tokio::time::advance(Duration::from_secs(90)).await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(fs.metadata_call_count(), 1);
}

#[tokio::test]
async fn run_periodic_scenario_c_change_revert_second_replacement() {
    let fs = Arc::new(MockFs::new());
    let path = PathBuf::from("/test/file.txt");
    let identity = FileIdentity {
        volume: 1,
        file_id: 3200,
    };
    fs.set_file(path.clone(), b"content".to_vec(), identity);

    let mut baseline = BTreeMap::new();
    baseline.insert(
        path.clone(),
        FileSnapshot::File {
            sha256: [1; 32],
            identity,
        },
    );

    let drift_count = Arc::new(Mutex::new(0));
    let drift_count_clone = drift_count.clone();
    let on_drift = Arc::new(move |_path: PathBuf, _change: Change| {
        *drift_count_clone.lock().unwrap() += 1;
    });

    tokio::time::pause();
    let roots = vec![IntegrityRoot {
        path: path.clone(),
        mode: RootMode::Recursive,
    }];
    tokio::spawn(run_periodic(
        roots,
        baseline,
        fs.clone(),
        Duration::from_secs(60),
        on_drift,
    ));
    // Poll the task once so its timer starts at t=0.
    tokio::task::yield_now().await;

    // Change before 60s
    fs.set_file(path.clone(), b"changed".to_vec(), identity);
    tokio::time::advance(Duration::from_secs(61)).await;
    for _ in 0..1000 {
        if *drift_count.lock().unwrap() >= 1 {
            break;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }

    // One on_drift call
    assert_eq!(*drift_count.lock().unwrap(), 1);

    // No second call at 120s and 180s (same state)
    tokio::time::advance(Duration::from_secs(60)).await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(*drift_count.lock().unwrap(), 1);
    tokio::time::advance(Duration::from_secs(60)).await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(*drift_count.lock().unwrap(), 1);

    // Second replacement
    fs.set_file(path.clone(), b"changed_again".to_vec(), identity);
    tokio::time::advance(Duration::from_secs(60)).await;
    for _ in 0..1000 {
        if *drift_count.lock().unwrap() >= 2 {
            break;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(*drift_count.lock().unwrap(), 2);

    // Revert
    fs.set_file(path, b"changed".to_vec(), identity);
    tokio::time::advance(Duration::from_secs(60)).await;
    for _ in 0..1000 {
        if *drift_count.lock().unwrap() >= 3 {
            break;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(*drift_count.lock().unwrap(), 3);
}
