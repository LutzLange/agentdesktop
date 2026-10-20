//! MXC engine: Windows AppContainer request generation.

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::launch::{LaunchInput, plan::LaunchPlan};
use crate::launch::profile::CLAUDE_CODE;
use super::Engine;

/// MXC sandbox engine.
pub(crate) struct MxcEngine;

impl Engine for MxcEngine {
    fn name(&self) -> &'static str {
        "mxc"
    }

    fn container_id(&self, launch_id: &str) -> String {
        format!("agentdesktop-{}", launch_id)
    }

    fn request(&self, _plan: &LaunchPlan, _launch_id: &str) -> Result<Vec<u8>> {
        todo!()
    }
}

impl MxcEngine {
    fn to_request(&self, _plan: &LaunchPlan, _launch_id: &str) -> MxcRequest {
        todo!()
    }
}

#[derive(Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MxcRequest {
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
pub(crate) struct MxcUi {
    pub disable: bool,
    pub clipboard: String,
    pub injection: bool,
}

// No Debug: the env list carries the session pairing.
#[derive(Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MxcProcess {
    pub command_line: String,
    pub cwd: String,
    pub inherit_default_env: bool,
    /// `KEY=VALUE` entries: MXC 1.0.0 rejects an object here (lab-verified).
    pub env: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct MxcFilesystem {
    #[serde(rename = "readwritePaths")]
    pub readwrite_paths: Vec<String>,
    #[serde(rename = "readonlyPaths")]
    pub readonly_paths: Vec<String>,
    #[serde(rename = "deniedPaths")]
    pub denied_paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct MxcNetwork {
    pub egress: MxcEgress,
    pub ingress: MxcIngress,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct MxcEgress {
    pub default: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MxcIngress {
    pub default: String,
    pub host_loopback: String,
}

/// A path as the request carries it: `\` separators only.
fn win(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\")
}

fn join(base: &str, rest: &str) -> String {
    format!("{}\\{rest}", base.trim_end_matches('\\'))
}

/// Builds the MXC request. Pure: no host environment or filesystem reads
/// beyond `input.exists` and `input.is_dir`.
pub(crate) fn build_request(input: &LaunchInput) -> MxcRequest {
    let exists = |path: &str| (input.exists)(Path::new(path));
    let is_dir = |path: &str| (input.is_dir)(Path::new(path));
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
    env.insert("ANTHROPIC_BASE_URL".into(), input.relay_base_url.clone());
    env.insert("ANTHROPIC_AUTH_TOKEN".into(), "placeholder".into());
    env.insert(
        "ANTHROPIC_CUSTOM_HEADERS".into(),
        format!("{}: {}", crate::llm_proxy::PAIRING_HEADER, input.pairing),
    );
    env.insert("CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST".into(), "1".into());
    env.insert("HOME".into(), home.clone());

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
        // git reads the user's configuration before anything else; unreadable
        // means every git command fails in the box (lab L4e).
        Some(join(&home, ".gitconfig")),
        Some(join(&home, r".config\git\config")),
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
        join(&cwd, ".mcp.json"),
        // A `HEAD` file at the workspace root would let git treat the
        // workspace itself as a bare repository with box-written config.
        join(&cwd, "HEAD"),
    ];
    // MXC refuses a denied path whose parent folder does not exist
    // (lab-verified, 0x80070003), so a workspace without `.claude` gets the
    // folder itself denied instead of its three executable-config entries.
    let workspace_claude = join(&cwd, ".claude");
    let workspace_claude_entries = [
        join(&workspace_claude, "settings.json"),
        join(&workspace_claude, "settings.local.json"),
        join(&workspace_claude, "hooks"),
    ];
    if exists(&workspace_claude) || workspace_claude_entries.iter().any(|path| exists(path)) {
        executable_config.extend(workspace_claude_entries);
    } else {
        denied.push(workspace_claude);
    }
    let git = join(&cwd, ".git");
    if !exists(&git) {
        // No repository: deny `.git` so the box cannot `git init` one that
        // the user's tools later trust.
        denied.push(git);
    } else if is_dir(&git) {
        // A `.git` directory: emit config, hooks and commondir guards whether
        // or not they exist. An empty directory gets the same guards as a
        // populated repository (prevents `git init` into an existing empty
        // folder). `.git\HEAD` stays writable: git replaces it by rename on
        // every branch switch, and the root `HEAD` rule already blocks a
        // bare-repo fall-through.
        executable_config.push(join(&git, "config"));
        executable_config.push(join(&git, "hooks"));
        executable_config.push(join(&git, "commondir"));
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
        // IDE lock files carry auth tokens for the editor bridge.
        join(&claude_dir, "ide"),
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
            env: env
                .into_iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect(),
        },
        filesystem: MxcFilesystem {
            readwrite_paths: vec![
                cwd,
                claude_dir,
                tmp,
            ],
            readonly_paths: readonly,
            denied_paths: denied,
        },
        network: MxcNetwork {
            egress: MxcEgress {
                default: match input.egress {
                    agentdesktop_core::config::ContainmentEgress::Allow => "allow".into(),
                    agentdesktop_core::config::ContainmentEgress::Deny => "deny".into(),
                },
            },
            ingress: MxcIngress {
                default: "allow".into(),
                host_loopback: "allow".into(),
            },
        },
    }
}
