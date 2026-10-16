//! Writer-owned tests for the launch module: what the spec-derived baseline
//! (`tests.rs`) leaves to the implementation.

use std::path::{Path, PathBuf};

use super::*;

#[test]
fn the_user_mode_pipe_admits_system_and_the_daemon_user_only() {
    assert_eq!(
        user_mode_pipe_sddl("S-1-5-21-1-2-3-1001"),
        "D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21-1-2-3-1001)"
    );
}

/// The read-only grant for `credential\` is only honoured when the directory
/// exists, so it is created before the request is built.
#[test]
fn the_credential_directory_exists_before_the_request_is_written() {
    let temp = tempfile::tempdir().unwrap();
    let launch_dir = temp.path().join("launches").join("0123456789abcdef");

    create_launch_dir(&launch_dir, "gateway-token").unwrap();

    assert!(launch_dir.join("credential").is_dir());
    assert_eq!(
        std::fs::read_to_string(launch_dir.join("credential").join("token")).unwrap(),
        "gateway-token"
    );
    assert!(launch_dir.join("tmp").is_dir());
    assert!(
        !launch_dir.join("request.json").exists(),
        "the request is built after the directories it grants exist"
    );
}

struct OnlyFiles(Vec<PathBuf>);

impl ProgramFs for OnlyFiles {
    fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
        Ok(path.to_owned())
    }

    fn is_file(&self, path: &Path) -> bool {
        self.0.contains(&path.to_owned())
    }
}

/// A trailing `;` in PATH is an empty directory entry; it must not make every
/// path count as "under a PATH directory".
#[test]
fn an_empty_path_entry_does_not_admit_a_claude_exe_anywhere() {
    let home = PathBuf::from("/home/dev");
    let elsewhere = PathBuf::from("/opt/other/claude.exe");
    let fs = OnlyFiles(vec![elsewhere.clone()]);
    let mut dirs = vec![PathBuf::new(), PathBuf::from("/opt/other")];
    assert_eq!(
        resolve_program(&home, &dirs, &fs),
        Ok(elsewhere),
        "the real PATH entry still resolves"
    );
    dirs.pop();
    assert!(
        resolve_program(&home, &dirs, &fs).is_err(),
        "the empty entry alone admits nothing"
    );
}

#[test]
fn the_executable_configuration_rule_covers_git_commondir_and_the_ide_directory_is_denied() {
    use std::collections::{BTreeMap, BTreeSet};

    let existing: BTreeSet<String> = [r"C:\ws\.git", r"C:\ws\.git\HEAD"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let exists = |path: &Path| existing.contains(path.to_str().unwrap());
    let request = build_request(&LaunchInput {
        launch_id: "0123456789abcdef".into(),
        executable: PathBuf::from(r"C:\Users\dev\.local\bin\claude.exe"),
        client_exe_dir: PathBuf::from(r"C:\Program Files\Agentdesktop"),
        cwd: PathBuf::from(r"C:\ws"),
        args: vec![],
        home: PathBuf::from(r"C:\Users\dev"),
        state_dir: PathBuf::from(r"C:\Users\dev\.local\state\agentdesktop"),
        launch_dir: PathBuf::from(
            r"C:\Users\dev\.local\state\agentdesktop\launches\0123456789abcdef",
        ),
        git_dir: None,
        program_files_claude: None,
        gateway_url: "https://gateway.example.com/".into(),
        base_env: BTreeMap::new(),
        exists: &exists,
    });
    let denied = request.filesystem.denied_paths;
    assert!(denied.contains(&r"C:\ws\.git\commondir".to_owned()));
    assert!(denied.contains(&r"C:\ws\.git\config".to_owned()));
    assert!(denied.contains(&r"C:\Users\dev\.claude\ide".to_owned()));
}

#[cfg(windows)]
#[test]
fn the_current_process_is_alive_only_with_its_own_start_time() {
    use std::os::windows::io::AsRawHandle;

    let pid = std::process::id();
    let handle = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "exit 0"])
        .spawn()
        .map(|mut child| {
            let _ = child.wait();
        });
    assert!(handle.is_ok());
    // The daemon's own process: alive with the true creation time, dead with
    // any other (a reused pid is not the launch).
    let current = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "ping -n 3 127.0.0.1 >NUL"])
        .spawn()
        .unwrap();
    let start = host::windows::creation_time(current.as_raw_handle() as _).unwrap();
    assert!(host::process_alive(current.id(), start));
    assert!(!host::process_alive(current.id(), start.wrapping_add(1)));
    assert!(!host::process_alive(pid, 0));
}
