//! Sandboxed launch of a managed program in a Windows AppContainer (MXC).
//!
//! PR 1 baseline: the types and signatures of the interface contract
//! (`specs/PR-1.md`), with `todo!()` bodies. The tests in `tests.rs` pin the
//! behaviour; the implementation replaces the stubs.

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use agentdesktop_core::{
    config::ContainmentStartupConfig,
    model::{ContainmentInfo, Launch, LlmGatewayCredential},
};
use async_trait::async_trait;
use axum::{Router, http::StatusCode};
use serde::Serialize;

use crate::api;

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------- AC 2 / AC 4

/// Startup snapshot for `daemon-info`. `None` when `daemon.containment` is
/// unconfigured; otherwise `available` only with
/// `user && windows && exists(executor) && !claude_settings_overridden`.
pub fn containment_info(
    cfg: Option<&ContainmentStartupConfig>,
    user: bool,
    windows: bool,
    claude_settings_overridden: bool,
    exists: &dyn Fn(&Path) -> bool,
) -> Option<ContainmentInfo> {
    let _ = (cfg, user, windows, claude_settings_overridden, exists);
    todo!("PR 1: containment_info")
}

/// Identity of the process at the other end of a pipe connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipePeer {
    /// SID string of the peer's token user; `None` when it could not be read.
    pub user_sid: Option<String>,
    /// Whether the peer runs in an AppContainer.
    pub app_container: bool,
}

/// `user_sid == daemon_sid` and `!app_container`; a missing peer or an
/// unreadable SID is never allowed.
pub fn peer_allowed(peer: Option<&PipePeer>, daemon_sid: Option<&str>) -> bool {
    let _ = (peer, daemon_sid);
    todo!("PR 1: peer_allowed")
}

/// Reads the identity of process `pid` (`TokenUser`, `TokenIsAppContainer`).
#[cfg(windows)]
pub fn peer_identity(pid: u32) -> anyhow::Result<PipePeer> {
    let _ = pid;
    todo!("PR 1: peer_identity")
}

/// `D:P(A;;GA;;;SY)(A;;GA;;;<sid>)`: the user-mode pipe admits SYSTEM and the
/// daemon's own user only.
pub fn user_mode_pipe_sddl(sid: &str) -> String {
    let _ = sid;
    todo!("PR 1: user_mode_pipe_sddl")
}

// ----------------------------------------------------------------------- AC 5

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathKind {
    pub is_dir: bool,
}

pub trait CwdFs {
    fn canonicalize(&self, p: &Path) -> io::Result<PathBuf>;
    fn kind(&self, p: &Path) -> io::Result<PathKind>;
}

/// Raw (uncanonicalised) directories the workspace must not be, or be under.
#[derive(Clone, Debug)]
pub struct CwdContext {
    pub home: PathBuf,
    pub state_dir: PathBuf,
    pub system_dirs: Vec<PathBuf>,
    pub denied: Vec<PathBuf>,
}

/// Canonicalises `cwd` and applies the workspace rules; returns the canonical
/// path (`\\?\` stripped) or the reason for the rejection.
pub fn validate_cwd(cwd: &Path, ctx: &CwdContext, fs: &dyn CwdFs) -> Result<PathBuf, String> {
    let _ = (cwd, ctx, fs);
    todo!("PR 1: validate_cwd")
}

// ----------------------------------------------------------------------- AC 6

pub trait ProgramFs {
    fn canonicalize(&self, p: &Path) -> io::Result<PathBuf>;
    fn is_file(&self, p: &Path) -> bool;
}

/// Finds the native `claude.exe` for the daemon's user: `<home>\.local\bin`
/// first, then each daemon `PATH` directory.
pub fn resolve_program(
    home: &Path,
    path_dirs: &[PathBuf],
    fs: &dyn ProgramFs,
) -> Result<PathBuf, String> {
    let _ = (home, path_dirs, fs);
    todo!("PR 1: resolve_program")
}

/// Rejects arguments `cmd.exe` would interpret and quotes the others.
pub fn check_args(args: &[String]) -> Result<Vec<String>, String> {
    let _ = args;
    todo!("PR 1: check_args")
}

// ----------------------------------------------------------------------- AC 7

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MxcRequest {
    pub version: String,
    pub containment: String,
    pub container_id: String,
    pub ui: MxcUi,
    pub process: MxcProcess,
    pub filesystem: MxcFilesystem,
    pub network: MxcNetwork,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MxcUi {
    pub disable: bool,
    pub clipboard: String,
    pub injection: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MxcProcess {
    pub command_line: String,
    pub cwd: String,
    pub inherit_default_env: bool,
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MxcFilesystem {
    #[serde(rename = "readwritePaths")]
    pub readwrite_paths: Vec<String>,
    #[serde(rename = "readonlyPaths")]
    pub readonly_paths: Vec<String>,
    #[serde(rename = "deniedPaths")]
    pub denied_paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MxcNetwork {
    pub egress: MxcEgress,
    pub ingress: MxcIngress,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MxcEgress {
    pub default: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MxcIngress {
    pub default: String,
    pub host_loopback: String,
}

/// Everything `build_request` may use. Paths are Windows-style strings in a
/// `PathBuf`; `exists` is called with `\`-joined paths.
pub struct LaunchInput<'a> {
    pub launch_id: String,
    pub executable: PathBuf,
    pub client_exe_dir: PathBuf,
    pub cwd: PathBuf,
    /// Already quoted by `check_args`.
    pub args: Vec<String>,
    pub home: PathBuf,
    pub state_dir: PathBuf,
    pub launch_dir: PathBuf,
    pub git_dir: Option<PathBuf>,
    pub program_files_claude: Option<PathBuf>,
    pub gateway_url: String,
    pub base_env: BTreeMap<String, String>,
    pub exists: &'a dyn Fn(&Path) -> bool,
}

pub fn build_request(input: &LaunchInput) -> MxcRequest {
    let _ = input;
    todo!("PR 1: build_request")
}

/// Creates `launch_dir` (private) and writes `request.json` (UTF-8, no BOM,
/// mode 0600) into it; returns the file's path.
pub fn write_request(launch_dir: &Path, request: &MxcRequest) -> anyhow::Result<PathBuf> {
    let _ = (launch_dir, request);
    todo!("PR 1: write_request")
}

// ----------------------------------------------------------------------- AC 8

/// When the credential refresh next runs: `max(expires_at - 50, now + 10)`.
pub fn refresh_at(expires_at: u64, now: u64) -> u64 {
    let _ = (expires_at, now);
    todo!("PR 1: refresh_at")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshInput {
    /// A credential with this (new) `expires_at`.
    Ok(u64),
    Status(StatusCode),
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshAction {
    Keep,
    Rewrite,
    Delete,
}

pub fn next_action(input: &RefreshInput, expires_at: u64, now: u64) -> RefreshAction {
    let _ = (input, expires_at, now);
    todo!("PR 1: next_action")
}

#[async_trait]
pub trait CredentialSource: Send + Sync {
    async fn credential(
        &self,
        client_id: &str,
        interactive: bool,
    ) -> Result<LlmGatewayCredential, (StatusCode, String)>;
}

// ----------------------------------------------------------------------- AC 9

pub trait LaunchChild: Send {
    fn try_wait(&mut self) -> io::Result<Option<i32>>;
    fn pid(&self) -> u32;
    /// Creation time of the process (FILETIME on Windows).
    fn start_time(&self) -> u64;
}

pub trait Executor: Send + Sync {
    fn spawn(
        &self,
        launch_id: &str,
        executor: &Path,
        request: &Path,
        log: &Path,
    ) -> io::Result<Box<dyn LaunchChild>>;
}

pub trait LaunchHost: Send + Sync {
    fn home(&self) -> PathBuf;
    fn path_dirs(&self) -> Vec<PathBuf>;
    fn base_env(&self) -> BTreeMap<String, String>;
    fn cwd_context(&self) -> CwdContext;
    fn cwd_fs(&self) -> &dyn CwdFs;
    fn program_fs(&self) -> &dyn ProgramFs;
    fn exists(&self, path: &Path) -> bool;
    fn git_dir(&self) -> Option<PathBuf>;
    fn program_files_claude(&self) -> Option<PathBuf>;
    fn client_exe_dir(&self) -> PathBuf;
    fn now(&self) -> u64;
}

/// Running launches plus the last 32 exited ones. Clones share state.
#[derive(Clone)]
pub struct LaunchRegistry {
    #[allow(dead_code)]
    launches: Arc<Mutex<Vec<Launch>>>,
}

impl LaunchRegistry {
    pub fn new() -> Self {
        Self {
            launches: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn insert(&self, launch: Launch) {
        let _ = launch;
        todo!("PR 1: LaunchRegistry::insert")
    }

    pub fn mark_exited(&self, launch_id: &str, exit_code: Option<i32>, ended_at: u64) {
        let _ = (launch_id, exit_code, ended_at);
        todo!("PR 1: LaunchRegistry::mark_exited")
    }

    pub fn set_credential_expiry(&self, launch_id: &str, expires_at: u64) {
        let _ = (launch_id, expires_at);
        todo!("PR 1: LaunchRegistry::set_credential_expiry")
    }

    /// Ordered by `started_at_unix_seconds` ascending.
    pub fn list(&self) -> Vec<Launch> {
        todo!("PR 1: LaunchRegistry::list")
    }
}

impl Default for LaunchRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct LaunchState {
    pub app: api::AppState,
    pub executor: Arc<dyn Executor>,
    pub credentials: Arc<dyn CredentialSource>,
    pub host: Arc<dyn LaunchHost>,
    pub registry: LaunchRegistry,
    pub availability: Option<ContainmentInfo>,
    /// The daemon's own SID; `Some` only for a Windows user-mode daemon.
    pub daemon_sid: Option<String>,
}

/// `POST /v1/launch` and `GET /v1/launches`, behind the peer check.
pub fn router(state: LaunchState) -> Router {
    let _ = state;
    todo!("PR 1: launch::router")
}

/// Removes what a previous daemon left behind in `<state_dir>\launches`:
/// `credential\` and `request.json` of every launch, and the whole launch
/// directory when `<launch_dir>\pid` (`"<pid> <start_time>"`) no longer names a
/// live process according to `alive(pid, start_time)`.
pub fn sweep(state_dir: &Path, alive: &dyn Fn(u32, u64) -> bool) -> anyhow::Result<()> {
    let _ = (state_dir, alive);
    todo!("PR 1: sweep")
}
