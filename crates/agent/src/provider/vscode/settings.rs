//! VS Code user `settings.json` management for the `githubModels` variant of
//! `copilotChat`: points Copilot Chat's CAPI endpoint
//! (`github.copilot.advanced.debug.overrideCapiUrl`) at the loopback proxy's
//! `/vscode-copilot-capi/<pairing>` route, so VS Code keeps GitHub's own
//! models and its own Copilot token while the daemon adds the gateway
//! identity. Mirrors `provider::vscode::reconcile` (the `ownModels` variant,
//! `chatLanguageModels.json`), merging through `provider::json_merge`.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use agentdesktop_core::config::{LlmGatewayConfig, VsCodeConfig, VsCodeCopilotChat};
use anyhow::Context;
use serde_json::{Value, json};
use tracing::warn;

use super::{VsCode, discovery};
use crate::provider::json_merge;
use crate::reconcile::ReconcilePlan;

/// The setting VS Code's Copilot Chat reads for its CAPI base URL (the legacy
/// name; `github.copilot.internal.capiUrl` is the newer alias).
pub(super) const OVERRIDE_KEY: &str = "github.copilot.advanced.debug.overrideCapiUrl";
const CAPI_ALIAS_KEY: &str = "github.copilot.internal.capiUrl";
const IGNORED_SETTINGS_KEY: &str = "settingsSync.ignoredSettings";
/// What the plan report calls the managed part of the file.
const DESCRIPTION: &str = "settings";
/// The file carries the pairing value, so a file we write is owner-only.
const FILE_MODE: u32 = 0o600;

/// The user's `settings.json` for the resolved home directory (per-OS VS Code
/// user profile root, shared with `chatLanguageModels.json` and MCP
/// discovery).
pub(super) fn settings_path(home: &Path) -> PathBuf {
    discovery::user_profile_root(home).join("settings.json")
}

/// The override URL for a listener and pairing: the pairing is the first path
/// segment of the `/vscode-copilot-capi` route, because VS Code cannot add a
/// header to these requests.
pub(super) fn override_url(listen: SocketAddr, pairing: &str) -> String {
    format!("http://{listen}{}/{pairing}", crate::llm_proxy::CAPI_ROUTE)
}

/// The managed part of `settings.json`: the CAPI override and the two
/// `settingsSync.ignoredSettings` entries that keep the override (and its
/// alias) from being synced to other machines.
pub(super) fn managed_settings(listen: SocketAddr, pairing: &str) -> Value {
    json!({
        OVERRIDE_KEY: override_url(listen, pairing),
        IGNORED_SETTINGS_KEY: [OVERRIDE_KEY, CAPI_ALIAS_KEY],
    })
}

fn options() -> json_merge::MergeOptions {
    json_merge::MergeOptions {
        mode: FILE_MODE,
        // Arrays merge and roll back by value, which is what the string
        // entries in settingsSync.ignoredSettings need.
        keyed_arrays: &[],
        // The file holds the pairing and possibly the user's own secrets.
        redact_diff: true,
    }
}

/// Plans the create/update/remove/conflict for the user `settings.json`.
///
/// Merges only when the program is set with `copilotChat: githubModels`,
/// uses the gateway, the gateway has `proxyUrl` and the loopback proxy is
/// available; removes the managed keys otherwise (with a warning when the
/// proxy is the missing part), the same decision shape as `reconcile::plan`.
pub(super) fn plan(
    path: &Path,
    proxy: Option<(SocketAddr, &str)>,
    configured: Option<(&VsCodeConfig, Option<&LlmGatewayConfig>)>,
    plan: &ReconcilePlan,
) -> anyhow::Result<()> {
    let state_path = json_merge::state_path(path);
    let active = matches!(
        configured,
        Some((config, Some(gateway)))
            if config.copilot_chat == VsCodeCopilotChat::GithubModels && gateway.proxy_url.is_some()
    );
    if !active {
        remove(path, &state_path, proxy, plan)?;
        return Ok(());
    }
    let Some((listen, pairing)) = proxy else {
        warn!(
            path = %path.display(),
            "programs.vscode uses copilotChat: githubModels but the local LLM proxy is not available, so VS Code is not pointed at the gateway; the reason is llmProxy.error in daemon-info (or daemon.llmProxy.listen is unset); removing the managed settings"
        );
        remove(path, &state_path, None, plan)?;
        return Ok(());
    };
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && !parent.exists()
    {
        plan.ensure_private_dir(parent);
    }
    json_merge::plan_merge_with(
        path,
        &state_path,
        managed_settings(listen, pairing),
        false,
        DESCRIPTION,
        VsCode::DISPLAY_NAME,
        options(),
        plan,
    )
}

/// Managed keys are removed through the sidecar when there is one, and by
/// value (an override pointing at this daemon's listener with its pairing)
/// when there is none.
fn remove(
    path: &Path,
    state_path: &Path,
    proxy: Option<(SocketAddr, &str)>,
    plan: &ReconcilePlan,
) -> anyhow::Result<()> {
    if !json_merge::plan_remove_with(
        path,
        state_path,
        DESCRIPTION,
        VsCode::DISPLAY_NAME,
        options(),
        plan,
    )? && let Some((listen, pairing)) = proxy
    {
        plan_remove_orphaned(path, &override_url(listen, pairing), plan)?;
    }
    Ok(())
}

/// Removal without a sidecar: an override equal to this daemon's own URL was
/// written for this daemon, so it and the two ignored-settings entries are
/// taken out; everything else stays, the file keeps its mode and is never
/// deleted here. An unreadable file is skipped with a warning.
fn plan_remove_orphaned(path: &Path, own_url: &str, plan: &ReconcilePlan) -> anyhow::Result<()> {
    let existing = match plan.read(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            warn!(error = %format!("{error:#}"), "skipping the VS Code settings file");
            return Ok(());
        }
    };
    let Ok(Value::Object(mut current)) = serde_json::from_slice::<Value>(&existing) else {
        tracing::debug!(
            path = %path.display(),
            "VS Code settings file is not a plain JSON object; leaving it alone (no sidecar, nothing known to remove)"
        );
        return Ok(());
    };
    if current.get(OVERRIDE_KEY).and_then(Value::as_str) != Some(own_url) {
        return Ok(());
    }
    current.remove(OVERRIDE_KEY);
    if let Some(entries) = current
        .get_mut(IGNORED_SETTINGS_KEY)
        .and_then(Value::as_array_mut)
    {
        entries.retain(|entry| entry != OVERRIDE_KEY && entry != CAPI_ALIAS_KEY);
        if entries.is_empty() {
            current.remove(IGNORED_SETTINGS_KEY);
        }
    }
    let mut contents = serde_json::to_vec_pretty(&Value::Object(current))
        .with_context(|| format!("serialize {} {DESCRIPTION}", VsCode::DISPLAY_NAME))?;
    contents.push(b'\n');
    plan.record_diff(
        VsCode::DISPLAY_NAME,
        DESCRIPTION,
        "update",
        path,
        None,
        None,
    );
    let mode = json_merge::current_mode(path).unwrap_or(FILE_MODE);
    plan.write_file(path, &contents, mode)
}
