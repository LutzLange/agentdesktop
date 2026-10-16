//! Sandboxed launch of a managed program in a Windows AppContainer (MXC).
//!
//! `POST /v1/launch` writes an MXC request and a short-lived gateway credential
//! into a private launch directory, starts `wxc-exec.exe` on it and keeps the
//! credential fresh while the box runs. Everything that touches the host
//! (environment, filesystem, process creation, credentials) goes through the
//! traits below, so the behaviour is testable on every platform; the
//! production implementations live in [`host`].

use std::{
    collections::BTreeMap,
    io,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use agentdesktop_core::{
    config::{ContainmentStartupConfig, DaemonConfig, ProgramAuthentication},
    model::{
        ContainmentInfo, DaemonScope, Launch, LaunchRequest, LaunchStatus, LlmGatewayCredential,
    },
};
use anyhow::Context;
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;

use crate::{api, secure_fs};

pub mod host;
#[cfg(test)]
mod tests;

/// Provider id of the only program PR 1 can launch.
const PROGRAM: &str = "claude-code";
/// Exited launches kept in the registry after the running ones.
const KEPT_EXITED: usize = 32;
/// How long the handler watches a fresh box for an early exit.
const EARLY_EXIT_WATCH: Duration = Duration::from_secs(3);
/// Poll cadence for the exit of a running launch.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// How long one credential refresh may take.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(30);
/// Bytes of `wxc-exec.log` returned with an early-exit error.
const LOG_TAIL: usize = 4096;

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
    let cfg = cfg?;
    let executor = cfg.executor.display().to_string();
    let error = if !user {
        Some("requires user mode".to_owned())
    } else if !windows {
        Some("Windows only".to_owned())
    } else if !exists(&cfg.executor) {
        Some(format!("executor not found: {executor}"))
    } else if claude_settings_overridden {
        Some(
            "daemon.claudeCode.config must be unset for run (the box reads <home>\\.claude\\settings.json)"
                .to_owned(),
        )
    } else {
        None
    };
    Some(ContainmentInfo {
        executor,
        available: error.is_none(),
        error,
    })
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
    match (peer, daemon_sid) {
        (Some(peer), Some(daemon_sid)) => {
            !peer.app_container && peer.user_sid.as_deref() == Some(daemon_sid)
        }
        _ => false,
    }
}

/// Reads the identity of process `pid` (`TokenUser`, `TokenIsAppContainer`).
#[cfg(windows)]
pub use host::peer_identity;

/// `D:P(A;;GA;;;SY)(A;;GA;;;<sid>)`: the user-mode pipe admits SYSTEM and the
/// daemon's own user only.
pub fn user_mode_pipe_sddl(sid: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})")
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

/// Characters `cmd.exe` interprets inside a quoted path.
const PATH_FORBIDDEN: [char; 3] = ['"', '%', '!'];

/// Removes the `\\?\` (and `\\?\UNC\`) prefix `canonicalize` adds on Windows.
fn strip_verbatim(path: PathBuf) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path;
    };
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path
    }
}

/// The form two paths are compared in: as they are on Unix, lower-cased on
/// Windows (NTFS is case-insensitive by default).
fn comparable(path: &Path) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(path.to_string_lossy().to_lowercase())
    } else {
        path.to_owned()
    }
}

fn is_under(path: &Path, directory: &Path) -> bool {
    comparable(path).starts_with(comparable(directory))
}

/// A drive, volume or UNC share root: no normal component at all.
fn is_root(path: &Path) -> bool {
    !path
        .components()
        .any(|component| matches!(component, Component::Normal(_)))
}

/// Canonicalises `cwd` and applies the workspace rules; returns the canonical
/// path (`\\?\` stripped) or the reason for the rejection.
pub fn validate_cwd(cwd: &Path, ctx: &CwdContext, fs: &dyn CwdFs) -> Result<PathBuf, String> {
    let text = cwd.to_string_lossy();
    if text.contains(PATH_FORBIDDEN) {
        return Err("workspace path contains a character cmd.exe interprets".to_owned());
    }
    let canonical = fs
        .canonicalize(cwd)
        .map(strip_verbatim)
        .map_err(|error| format!("workspace {}: {error}", cwd.display()))?;
    match fs.kind(&canonical) {
        Ok(PathKind { is_dir: true }) => {}
        Ok(PathKind { is_dir: false }) => {
            return Err(format!("workspace {} is not a directory", cwd.display()));
        }
        Err(error) => return Err(format!("workspace {}: {error}", cwd.display())),
    }
    if is_root(&canonical) {
        return Err("workspace may not be a drive or share root".to_owned());
    }
    // Context directories are compared in their canonical form too, so a
    // junction or symlink to one of them is caught; a directory that does not
    // exist (such as `%ProgramFiles(x86)%` on ARM) still guards by its raw path.
    let canonical_dir = |raw: &Path| {
        fs.canonicalize(raw)
            .map(strip_verbatim)
            .unwrap_or_else(|_| raw.to_owned())
    };
    let home = canonical_dir(&ctx.home);
    if is_under(&home, &canonical) {
        return Err("workspace may not be the home directory or one of its ancestors".to_owned());
    }
    let mut guarded: Vec<(PathBuf, &str)> = vec![
        (canonical_dir(&ctx.state_dir), "the daemon state directory"),
        (home.join("AppData"), "AppData"),
        (home.join(".claude"), "the Claude Code directory"),
    ];
    guarded.extend(
        ctx.system_dirs
            .iter()
            .map(|dir| (canonical_dir(dir), "a system directory")),
    );
    guarded.extend(
        ctx.denied
            .iter()
            .map(|dir| (canonical_dir(dir), "a denied directory")),
    );
    for (directory, what) in guarded {
        if is_under(&canonical, &directory) {
            return Err(format!(
                "workspace may not be under {what} ({})",
                directory.display()
            ));
        }
    }
    Ok(canonical)
}

// ----------------------------------------------------------------------- AC 6

pub trait ProgramFs {
    fn canonicalize(&self, p: &Path) -> io::Result<PathBuf>;
    fn is_file(&self, p: &Path) -> bool;
}

const PROGRAM_NOT_FOUND: &str = "Claude Code native install (claude.exe) not found for this user; npm installs are not supported in the box";

/// Finds the native `claude.exe` for the daemon's user: `<home>\.local\bin`
/// first, then each daemon `PATH` directory.
pub fn resolve_program(
    home: &Path,
    path_dirs: &[PathBuf],
    fs: &dyn ProgramFs,
) -> Result<PathBuf, String> {
    let mut candidates = vec![home.join(".local").join("bin").join("claude.exe")];
    candidates.extend(path_dirs.iter().map(|dir| dir.join("claude.exe")));
    // A candidate counts only when it really lives under the user's home or a
    // PATH directory: both sides canonical, so a junction elsewhere is caught.
    let mut roots: Vec<PathBuf> = Vec::new();
    for root in std::iter::once(home).chain(path_dirs.iter().map(PathBuf::as_path)) {
        roots.push(root.to_owned());
        if let Ok(canonical) = fs.canonicalize(root) {
            roots.push(strip_verbatim(canonical));
        }
    }
    for candidate in candidates {
        if !fs.is_file(&candidate) {
            continue;
        }
        let Ok(canonical) = fs.canonicalize(&candidate).map(strip_verbatim) else {
            continue;
        };
        if roots.iter().any(|root| is_under(&canonical, root)) {
            return Ok(canonical);
        }
    }
    Err(PROGRAM_NOT_FOUND.to_owned())
}

/// Characters `cmd.exe` interprets even inside double quotes (`%`, `!`) or that
/// end or split the command (`" ^ & | < >`).
const ARG_FORBIDDEN: [char; 8] = ['"', '%', '^', '&', '|', '<', '>', '!'];

/// Rejects arguments `cmd.exe` would interpret and quotes the others.
pub fn check_args(args: &[String]) -> Result<Vec<String>, String> {
    args.iter()
        .map(|arg| {
            if arg.contains(ARG_FORBIDDEN)
                || arg
                    .chars()
                    .any(|character| character.is_control() && character != '\t')
            {
                return Err("argument contains a character cmd.exe interprets".to_owned());
            }
            if arg.is_empty() {
                return Ok("\"\"".to_owned());
            }
            if !arg.contains([' ', '\t']) {
                return Ok(arg.clone());
            }
            // Inside quotes a trailing backslash would escape the closing
            // quote; the Windows argument parser wants each one doubled.
            let trailing = arg.len() - arg.trim_end_matches('\\').len();
            Ok(format!(
                "\"{}{}\"",
                &arg[..arg.len() - trailing],
                "\\".repeat(trailing * 2)
            ))
        })
        .collect()
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

/// A path as the request carries it: `\` separators only.
fn win(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\")
}

fn join(base: &str, rest: &str) -> String {
    format!("{}\\{rest}", base.trim_end_matches('\\'))
}

/// Builds the MXC request. Pure: no host environment or filesystem reads
/// beyond `input.exists`.
pub fn build_request(input: &LaunchInput) -> MxcRequest {
    let exists = |path: &str| (input.exists)(Path::new(path));
    let cwd = win(&input.cwd);
    let home = win(&input.home);
    let launch_dir = win(&input.launch_dir);
    let executable = win(&input.executable);
    let client_exe_dir = win(&input.client_exe_dir);
    let exe_dir = executable
        .rsplit_once('\\')
        .map(|(dir, _)| dir.to_owned())
        .unwrap_or_default();
    let git_dir = input.git_dir.as_deref().map(win);
    let program_files_claude = input.program_files_claude.as_deref().map(win);
    let claude_dir = join(&home, ".claude");
    let tmp = join(&launch_dir, "tmp");
    let credential_dir = join(&launch_dir, "credential");

    let system_root = input
        .base_env
        .get("SystemRoot")
        .cloned()
        .unwrap_or_else(|| r"C:\Windows".to_owned());
    let mut path = vec![
        join(&system_root, "System32"),
        system_root.clone(),
        join(&system_root, r"System32\WindowsPowerShell\v1.0"),
    ];
    if let Some(git_dir) = &git_dir {
        path.push(join(git_dir, "cmd"));
    }
    path.push(exe_dir.clone());
    path.push(client_exe_dir.clone());

    let mut env = input.base_env.clone();
    env.insert("TERM".into(), "xterm-256color".into());
    env.insert("PATH".into(), path.join(";"));
    env.insert("TEMP".into(), tmp.clone());
    env.insert("TMP".into(), tmp.clone());
    env.insert("CLAUDE_CONFIG_DIR".into(), claude_dir.clone());
    env.insert("CLAUDE_CODE_USE_POWERSHELL_TOOL".into(), "1".into());
    env.insert("DISABLE_AUTOUPDATER".into(), "1".into());
    env.insert(
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".into(),
        "1".into(),
    );
    env.insert("ANTHROPIC_BASE_URL".into(), input.gateway_url.clone());
    env.insert(
        "AGENTDESKTOP_CREDENTIAL_FILE".into(),
        join(&credential_dir, "token"),
    );

    let mut command_line = format!(
        "cmd.exe /d /v:off /c start \"agentdesktop: claude\" /WAIT /D \"{cwd}\" \"{executable}\""
    );
    for arg in &input.args {
        command_line.push(' ');
        command_line.push_str(arg);
    }

    let mut readonly: Vec<String> = Vec::new();
    let mut denied: Vec<String> = Vec::new();
    // Runtime directories: granted read-only when they exist, simply absent
    // otherwise (nothing the box could create there matters).
    let runtime = [
        Some(exe_dir),
        Some(join(&home, r".local\share\claude")),
        git_dir,
        Some(client_exe_dir),
        program_files_claude,
        Some(credential_dir),
    ];
    for candidate in runtime.into_iter().flatten() {
        if exists(&candidate) && !readonly.contains(&candidate) {
            readonly.push(candidate);
        }
    }
    // Executable configuration: read-only when present, denied when absent, so
    // the box can neither change nor create it.
    let mut executable_config = vec![
        join(&claude_dir, "settings.json"),
        join(&claude_dir, "hooks"),
        join(&claude_dir, "plugins"),
        join(&cwd, r".claude\settings.json"),
        join(&cwd, r".claude\settings.local.json"),
        join(&cwd, r".claude\hooks"),
        join(&cwd, ".mcp.json"),
    ];
    let git = join(&cwd, ".git");
    if !exists(&git) {
        // No repository: deny `.git` so the box cannot `git init` one that
        // the user's tools later trust.
        denied.push(git);
    } else if ["HEAD", "config", "hooks"]
        .iter()
        .any(|name| exists(&join(&git, name)))
    {
        // A repository directory: git reads config and hooks unsandboxed later.
        executable_config.push(join(&git, "config"));
        executable_config.push(join(&git, "hooks"));
    }
    // A `.git` file (worktree, submodule) is left as it is.
    for path in executable_config {
        if exists(&path) {
            readonly.push(path);
        } else {
            denied.push(path);
        }
    }
    for secret in [
        join(&claude_dir, ".credentials.json"),
        join(&claude_dir, "history.jsonl"),
        join(&home, ".ssh"),
        join(&home, ".aws"),
        join(&home, ".azure"),
        join(&home, ".kube"),
    ] {
        denied.push(secret);
    }

    MxcRequest {
        version: "1.0.0".into(),
        containment: "processcontainer".into(),
        container_id: format!("agentdesktop-{}", input.launch_id),
        ui: MxcUi {
            disable: false,
            clipboard: "none".into(),
            injection: false,
        },
        process: MxcProcess {
            command_line,
            cwd: cwd.clone(),
            inherit_default_env: false,
            env,
        },
        filesystem: MxcFilesystem {
            readwrite_paths: vec![cwd, claude_dir, tmp],
            readonly_paths: readonly,
            denied_paths: denied,
        },
        network: MxcNetwork {
            egress: MxcEgress {
                default: "allow".into(),
            },
            ingress: MxcIngress {
                default: "allow".into(),
                host_loopback: "deny".into(),
            },
        },
    }
}

/// Creates `launch_dir` (private) and writes `request.json` (UTF-8, no BOM,
/// mode 0600) into it; returns the file's path.
pub fn write_request(launch_dir: &Path, request: &MxcRequest) -> anyhow::Result<PathBuf> {
    secure_fs::ensure_private_dir(launch_dir)?;
    let path = launch_dir.join("request.json");
    let contents = serde_json::to_vec_pretty(request).context("encode MXC request")?;
    secure_fs::atomic_write(&path, &contents, 0o600)?;
    Ok(path)
}

// ----------------------------------------------------------------------- AC 8

/// When the credential refresh next runs: `max(expires_at - 50, now + 10)`.
pub fn refresh_at(expires_at: u64, now: u64) -> u64 {
    expires_at.saturating_sub(50).max(now + 10)
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
    match input {
        RefreshInput::Ok(new_expiry) if *new_expiry > expires_at => RefreshAction::Rewrite,
        RefreshInput::Ok(_) => RefreshAction::Keep,
        // A policy or precondition failure: the box must lose the token now.
        RefreshInput::Status(StatusCode::CONFLICT | StatusCode::FAILED_DEPENDENCY) => {
            RefreshAction::Delete
        }
        // A transient failure: the still-valid token stays until it expires.
        RefreshInput::Status(_) | RefreshInput::Timeout => {
            if now > expires_at {
                RefreshAction::Delete
            } else {
                RefreshAction::Keep
            }
        }
    }
}

#[async_trait]
pub trait CredentialSource: Send + Sync {
    async fn credential(
        &self,
        client_id: &str,
        interactive: bool,
    ) -> Result<LlmGatewayCredential, (StatusCode, String)>;
}

/// The effective-configuration rules a launch needs; each failure names the
/// field.
pub(crate) fn preconditions(effective: &DaemonConfig) -> Result<(), String> {
    let Some(gateway) = effective.llm_gateway.as_ref() else {
        return Err("llmGateway (with authentication) must be configured for run".to_owned());
    };
    if gateway.authentication.is_none() {
        return Err("llmGateway.authentication must be configured for run".to_owned());
    }
    let Some(claude_code) = effective.programs.claude_code.as_ref() else {
        return Err("programs.claudeCode must be configured for run".to_owned());
    };
    if !claude_code.use_llm_gateway {
        return Err("programs.claudeCode.useLlmGateway must be true for run".to_owned());
    }
    if claude_code.auth == Some(ProgramAuthentication::Subscription) {
        return Err(
            "programs.claudeCode.auth: subscription sign-in is not available inside the box in PR 1"
                .to_owned(),
        );
    }
    if effective.sandbox.is_some() {
        return Err(
            "Claude Code's own sandbox is not available inside the box; remove `sandbox` or launch without `run`"
                .to_owned(),
        );
    }
    Ok(())
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
    launches: Arc<Mutex<Vec<Launch>>>,
}

impl LaunchRegistry {
    pub fn new() -> Self {
        Self {
            launches: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Launch>> {
        self.launches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn insert(&self, launch: Launch) {
        self.lock().push(launch);
    }

    pub fn mark_exited(&self, launch_id: &str, exit_code: Option<i32>, ended_at: u64) {
        let mut launches = self.lock();
        let Some(launch) = launches
            .iter_mut()
            .find(|launch| launch.launch_id == launch_id)
        else {
            return;
        };
        launch.status = LaunchStatus::Exited;
        launch.exit_code = exit_code;
        launch.ended_at_unix_seconds = Some(ended_at);
        // Keep every running launch and the most recently ended exits.
        let mut exited: Vec<usize> = launches
            .iter()
            .enumerate()
            .filter(|(_, launch)| launch.status == LaunchStatus::Exited)
            .map(|(index, _)| index)
            .collect();
        if exited.len() > KEPT_EXITED {
            exited.sort_by_key(|&index| {
                (
                    launches[index].ended_at_unix_seconds,
                    launches[index].started_at_unix_seconds,
                )
            });
            let mut drop: Vec<usize> = exited[..exited.len() - KEPT_EXITED].to_vec();
            drop.sort_unstable_by(|a, b| b.cmp(a));
            for index in drop {
                launches.remove(index);
            }
        }
    }

    pub fn set_credential_expiry(&self, launch_id: &str, expires_at: u64) {
        if let Some(launch) = self
            .lock()
            .iter_mut()
            .find(|launch| launch.launch_id == launch_id)
        {
            launch.credential_expires_at_unix_seconds = Some(expires_at);
        }
    }

    /// Ordered by `started_at_unix_seconds` ascending.
    pub fn list(&self) -> Vec<Launch> {
        let mut launches = self.lock().clone();
        launches.sort_by_key(|launch| launch.started_at_unix_seconds);
        launches
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
    Router::new()
        .route("/v1/launch", post(launch))
        .route("/v1/launches", get(launches))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// System mode has no user to launch for; in Windows user mode only the
/// daemon's own user outside an AppContainer may use the launch routes.
async fn guard(State(state): State<LaunchState>, request: Request, next: Next) -> Response {
    if state.app.daemon_info.scope == DaemonScope::System {
        return (
            StatusCode::CONFLICT,
            "containment needs the user-mode daemon (`agentdesktop daemon --user`); this is the system daemon",
        )
            .into_response();
    }
    if let Some(daemon_sid) = state.daemon_sid.as_deref()
        && !peer_allowed(request.extensions().get::<PipePeer>(), Some(daemon_sid))
    {
        return (
            StatusCode::FORBIDDEN,
            "launch is available to the daemon's own user only",
        )
            .into_response();
    }
    next.run(request).await
}

async fn launches(State(state): State<LaunchState>) -> Json<Vec<Launch>> {
    Json(state.registry.list())
}

type LaunchError = (StatusCode, String);

fn bad_request(message: String) -> LaunchError {
    (StatusCode::BAD_REQUEST, message)
}

async fn launch(
    State(state): State<LaunchState>,
    Json(request): Json<LaunchRequest>,
) -> Result<(StatusCode, Json<Launch>), LaunchError> {
    let executor = match state.availability.as_ref() {
        Some(info) if info.available => PathBuf::from(&info.executor),
        Some(info) => {
            return Err((
                StatusCode::CONFLICT,
                info.error
                    .clone()
                    .unwrap_or_else(|| "containment is unavailable".to_owned()),
            ));
        }
        None => {
            return Err((
                StatusCode::CONFLICT,
                "containment is not configured (daemon.containment.executor)".to_owned(),
            ));
        }
    };
    if request.program != PROGRAM {
        return Err(bad_request(format!("program must be {PROGRAM}")));
    }
    let host = state.host.clone();
    let cwd =
        validate_cwd(&request.cwd, &host.cwd_context(), host.cwd_fs()).map_err(bad_request)?;
    let args = check_args(&request.args).map_err(bad_request)?;
    let executable =
        resolve_program(&host.home(), &host.path_dirs(), host.program_fs()).map_err(bad_request)?;
    let effective =
        api::load_effective_config(&state.app.config, &state.app.state_dir).map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("read applied configuration: {error:#}"),
            )
        })?;
    preconditions(&effective).map_err(|message| (StatusCode::CONFLICT, message))?;
    let gateway_url = effective
        .llm_gateway
        .as_ref()
        .map(|gateway| gateway.url.as_str().trim_end_matches('/').to_owned())
        .unwrap_or_default();
    let credential = state.credentials.credential(PROGRAM, true).await?;

    let launch_id = format!("{:016x}", rand::random::<u64>());
    let state_dir = state.app.state_dir.clone();
    let launch_dir = state_dir.join("launches").join(&launch_id);
    let exists = |path: &Path| host.exists(path);
    let mxc = build_request(&LaunchInput {
        launch_id: launch_id.clone(),
        executable,
        client_exe_dir: host.client_exe_dir(),
        cwd: cwd.clone(),
        args,
        home: host.home(),
        state_dir,
        launch_dir: launch_dir.clone(),
        git_dir: host.git_dir(),
        program_files_claude: host.program_files_claude(),
        gateway_url,
        base_env: host.base_env(),
        exists: &exists,
    });
    let started =
        prepare_launch_dir(&launch_dir, &mxc, &credential.credential).and_then(|request_path| {
            let log_path = launch_dir.join("wxc-exec.log");
            state
                .executor
                .spawn(&launch_id, &executor, &request_path, &log_path)
                .map_err(|error| anyhow::anyhow!("start wxc-exec: {error}"))
                .map(|child| (child, log_path))
        });
    let (mut child, log_path) = match started {
        Ok(started) => started,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&launch_dir);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}")));
        }
    };
    let started_at = host.now();
    if let Err(error) = std::fs::write(
        launch_dir.join("pid"),
        format!("{} {}", child.pid(), child.start_time()),
    ) {
        tracing::warn!(launch_id, %error, "failed to record the launch pid");
    }

    // A box that dies within seconds (bad request, missing tier, MXC refusal)
    // is reported to the caller instead of lingering as a running launch.
    let deadline = tokio::time::Instant::now() + EARLY_EXIT_WATCH;
    loop {
        match child.try_wait() {
            Ok(None) => {}
            Ok(Some(code)) => {
                let tail = log_tail(&log_path);
                let _ = std::fs::remove_dir_all(&launch_dir);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "wxc-exec exited with code {code} within {}s: {tail}",
                        EARLY_EXIT_WATCH.as_secs()
                    ),
                ));
            }
            Err(error) => {
                let _ = std::fs::remove_dir_all(&launch_dir);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("watch wxc-exec: {error}"),
                ));
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let launch = Launch {
        launch_id: launch_id.clone(),
        program: PROGRAM.to_owned(),
        cwd,
        container_id: format!("agentdesktop-{launch_id}"),
        status: LaunchStatus::Running,
        exit_code: None,
        started_at_unix_seconds: started_at,
        ended_at_unix_seconds: None,
        credential_expires_at_unix_seconds: Some(credential.expires_at_unix_seconds),
    };
    state.registry.insert(launch.clone());
    tracing::info!(launch_id, cwd = %launch.cwd.display(), "sandboxed launch started");
    let refresh = tokio::spawn(refresh_task(
        state.credentials.clone(),
        host.clone(),
        state.registry.clone(),
        launch_id.clone(),
        launch_dir.join("credential").join("token"),
        credential.expires_at_unix_seconds,
    ));
    tokio::spawn(poll_task(
        child,
        refresh.abort_handle(),
        state.registry.clone(),
        host,
        launch_id,
        launch_dir,
        log_path,
    ));
    Ok((StatusCode::CREATED, Json(launch)))
}

/// Writes `request.json` and `credential\token` (both private) and creates
/// the box's `tmp`; returns the request path.
fn prepare_launch_dir(
    launch_dir: &Path,
    request: &MxcRequest,
    credential: &str,
) -> anyhow::Result<PathBuf> {
    let request_path = write_request(launch_dir, request)?;
    let credential_dir = launch_dir.join("credential");
    secure_fs::ensure_private_dir(&credential_dir)?;
    secure_fs::atomic_write(&credential_dir.join("token"), credential.as_bytes(), 0o600)?;
    std::fs::create_dir_all(launch_dir.join("tmp")).context("create launch tmp")?;
    Ok(request_path)
}

/// The last 4 KiB of the executor's log, for an early-exit error.
fn log_tail(log: &Path) -> String {
    let bytes = std::fs::read(log).unwrap_or_default();
    let start = bytes.len().saturating_sub(LOG_TAIL);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

/// Watches the executor: copies new log lines to the daemon log, and on exit
/// records it, stops the refresh and removes the launch directory.
async fn poll_task(
    mut child: Box<dyn LaunchChild>,
    refresh: tokio::task::AbortHandle,
    registry: LaunchRegistry,
    host: Arc<dyn LaunchHost>,
    launch_id: String,
    launch_dir: PathBuf,
    log_path: PathBuf,
) {
    let mut log_offset = 0u64;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        log_offset = copy_log_lines(&launch_id, &log_path, log_offset);
        let exit = match child.try_wait() {
            Ok(None) => continue,
            Ok(Some(code)) => Some(code),
            Err(error) => {
                tracing::warn!(launch_id, %error, "lost track of the launch; treating it as exited");
                None
            }
        };
        refresh.abort();
        registry.mark_exited(&launch_id, exit, host.now());
        if let Err(error) = std::fs::remove_dir_all(&launch_dir) {
            tracing::warn!(launch_id, %error, "failed to remove the launch directory");
        }
        tracing::info!(launch_id, exit_code = ?exit, "sandboxed launch exited");
        return;
    }
}

/// Logs the complete lines `wxc-exec.log` gained since `offset`; returns the
/// new offset.
fn copy_log_lines(launch_id: &str, log_path: &Path, offset: u64) -> u64 {
    use std::io::{Read, Seek, SeekFrom};

    let Ok(mut file) = std::fs::File::open(log_path) else {
        return offset;
    };
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return offset;
    }
    let mut text = String::new();
    if file.read_to_string(&mut text).is_err() {
        return offset;
    }
    let Some(complete) = text.rfind('\n') else {
        return offset;
    };
    for line in text[..complete].lines() {
        tracing::info!(launch_id, "wxc-exec: {line}");
    }
    offset + complete as u64 + 1
}

/// Re-fetches the credential shortly before it expires and rewrites the token
/// file; a policy refusal removes the token, a transient failure keeps it
/// until it expires.
async fn refresh_task(
    credentials: Arc<dyn CredentialSource>,
    host: Arc<dyn LaunchHost>,
    registry: LaunchRegistry,
    launch_id: String,
    token_path: PathBuf,
    mut expires_at: u64,
) {
    let mut next_at = refresh_at(expires_at, host.now());
    loop {
        let now = host.now();
        if next_at > now {
            tokio::time::sleep(Duration::from_secs(next_at - now)).await;
        }
        let now = host.now();
        let (input, fresh) =
            match tokio::time::timeout(REFRESH_TIMEOUT, credentials.credential(PROGRAM, false))
                .await
            {
                Ok(Ok(credential)) => (
                    RefreshInput::Ok(credential.expires_at_unix_seconds),
                    Some(credential),
                ),
                Ok(Err((status, body))) => {
                    tracing::warn!(launch_id, %status, body, "credential refresh refused");
                    (RefreshInput::Status(status), None)
                }
                Err(_) => {
                    tracing::warn!(launch_id, "credential refresh timed out");
                    (RefreshInput::Timeout, None)
                }
            };
        match next_action(&input, expires_at, now) {
            RefreshAction::Rewrite => {
                let credential = fresh.expect("a rewrite follows a fetched credential");
                match secure_fs::atomic_write(&token_path, credential.credential.as_bytes(), 0o600)
                {
                    Ok(()) => {
                        expires_at = credential.expires_at_unix_seconds;
                        registry.set_credential_expiry(&launch_id, expires_at);
                        next_at = refresh_at(expires_at, host.now());
                    }
                    Err(error) => {
                        tracing::warn!(launch_id, error = %format!("{error:#}"), "failed to rewrite the credential");
                        next_at = host.now() + 30;
                    }
                }
            }
            RefreshAction::Keep => {
                next_at = host.now()
                    + if matches!(input, RefreshInput::Ok(_)) {
                        10
                    } else {
                        30
                    };
            }
            RefreshAction::Delete => {
                match std::fs::remove_file(&token_path) {
                    Ok(()) | Err(_) => {}
                }
                tracing::warn!(
                    launch_id,
                    "credential removed; the box can no longer reach the gateway"
                );
                return;
            }
        }
    }
}

/// Removes what a previous daemon left behind in `<state_dir>\launches`:
/// `credential\` and `request.json` of every launch, and the whole launch
/// directory when `<launch_dir>\pid` (`"<pid> <start_time>"`) no longer names a
/// live process according to `alive(pid, start_time)`.
pub fn sweep(state_dir: &Path, alive: &dyn Fn(u32, u64) -> bool) -> anyhow::Result<()> {
    let launches = state_dir.join("launches");
    let entries = match std::fs::read_dir(&launches) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("read {}", launches.display()));
        }
    };
    for entry in entries {
        let entry = entry.with_context(|| format!("read {}", launches.display()))?;
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let launch_id = entry.file_name().to_string_lossy().into_owned();
        let live = std::fs::read_to_string(dir.join("pid"))
            .ok()
            .and_then(|text| parse_pid_file(&text))
            .is_some_and(|(pid, start_time)| alive(pid, start_time));
        if live {
            for secret in [dir.join("credential"), dir.join("request.json")] {
                let removed = if secret.is_dir() {
                    std::fs::remove_dir_all(&secret)
                } else {
                    std::fs::remove_file(&secret)
                };
                if let Err(error) = removed
                    && error.kind() != io::ErrorKind::NotFound
                {
                    return Err(error).with_context(|| format!("remove {}", secret.display()));
                }
            }
            tracing::info!(
                launch_id,
                "launch {launch_id} still running; its credential is no longer refreshed"
            );
        } else {
            std::fs::remove_dir_all(&dir)
                .with_context(|| format!("remove stale launch {}", dir.display()))?;
        }
    }
    Ok(())
}

fn parse_pid_file(text: &str) -> Option<(u32, u64)> {
    let mut parts = text.split_whitespace();
    let pid = parts.next()?.parse().ok()?;
    let start_time = parts.next()?.parse().ok()?;
    Some((pid, start_time))
}
