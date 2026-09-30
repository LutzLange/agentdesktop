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
use serde::{Deserialize, Serialize};
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

// --- In-place JSONC edit (specs/PR-3c.md) -------------------------------
//
// `edit_settings`/`remove_settings` are the pure, filesystem-free core of the
// in-place edit: a lossless CST edit (`jsonc-parser`) of the user's own text,
// touching only the override key and the two `settingsSync.ignoredSettings`
// entries, plus the v2 sidecar that carries what removal must restore. The
// writer wires these into `plan`/`remove` in place of `json_merge`; this
// module is the interface contract's compile-only stub for the test author's
// spec-derived baseline (specs/PR-3c.md, "Interface contract for the test
// author"): `edit_settings`, `remove_settings` and `read_state` `todo!()`.

/// Why `edit_settings`/`remove_settings` refuse to touch the file (AC2/AC3):
/// anything beyond VS Code's own JSONC (comments, trailing commas), a
/// non-object root, `settingsSync.ignoredSettings` present and not an array,
/// or the override key or `settingsSync.ignoredSettings` appearing more than
/// once at the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SettingsConflict {
    Parse,
    NotAnObject,
    IgnoredNotArray,
    DuplicateKey,
}

/// The v2 sidecar (AC4): what removal must restore, without a whole-document
/// snapshot. `override_before` keeps an explicit JSON `null` as
/// `Some(Value::Null)`, distinct from the key being absent (`None`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SettingsState {
    pub version: u32,
    pub created: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "some_or_explicit_null"
    )]
    pub override_before: Option<Value>,
    pub added_ignored: Vec<String>,
    pub ignored_created: bool,
}

/// A present-but-`null` field deserializes to `Some(Value::Null)`; an absent
/// field is left at its `#[serde(default)]` (`None`) by serde before this
/// function is ever called.
fn some_or_explicit_null<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

/// The current sidecar version `edit_settings`/`remove_settings` write
/// (AC4); a sidecar without this shape (PR 3b's `MergeState`, no `version`)
/// is upgraded by `read_state` (AC7).
pub(super) const SETTINGS_STATE_VERSION: u32 = 2;

/// The outcome of `remove_settings` (AC5): the removal may be a no-op text
/// (`Unchanged`; distinct from an unchanged `edit_settings`, which returns the
/// new text unconditionally), rewritten text, or the whole file going away
/// (a file this daemon created that reduces to nothing but whitespace once
/// the managed keys are taken out).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Removal {
    Unchanged,
    Write(String),
    Delete,
}

/// In-place JSONC edit of `settings.json` (AC1-AC4): `text: None` is an
/// absent file (created as the golden text); an empty or whitespace-only
/// file is treated as `{}`. Sets the override to `url` (`set_value` in place
/// when the key exists, `append`ed otherwise) and ensures
/// `settingsSync.ignoredSettings` holds both `OVERRIDE_KEY` and
/// `CAPI_ALIAS_KEY`, creating the array when absent and appending only the
/// missing entries, user entries kept in order. `state` is the previous
/// sidecar (`None` on a first apply or when it could not be read, AC6); the
/// returned `SettingsState` is what removal needs afterwards.
pub(super) fn edit_settings(
    text: Option<&str>,
    url: &str,
    state: Option<&SettingsState>,
) -> Result<(String, SettingsState), SettingsConflict> {
    let _ = (text, url, state);
    todo!("writer: in-place JSONC edit of settings.json (specs/PR-3c.md AC1-AC4, AC6, AC7)")
}

/// In-place JSONC removal of the managed keys (AC5-AC7): the override is
/// restored to `state.override_before` (`set_value` when the property still
/// exists, appended when the user deleted it meanwhile, removed when there
/// was none); `state.added_ignored` entries are taken out of
/// `settingsSync.ignoredSettings`; the array property itself is removed when
/// `state.ignored_created` and it is now empty. Without a sidecar
/// (`state: None`), `own_url` is the daemon's own current override URL: an
/// override equal to it, and the two well-known entries, are removed by
/// value; an unparseable file is `Ok(Unchanged)` (not a conflict, matching
/// today's `plan_remove_orphaned`, settings.rs:157-163).
pub(super) fn remove_settings(
    text: &str,
    state: Option<&SettingsState>,
    own_url: Option<&str>,
) -> Result<Removal, SettingsConflict> {
    let _ = (text, state, own_url);
    todo!("writer: in-place JSONC removal of settings.json (specs/PR-3c.md AC5-AC7)")
}

/// Reads a sidecar (v2, or PR 3b's `MergeState` upgraded per AC7); `None`
/// when the bytes are not one of those two shapes (AC6: a warning, not a
/// hard error, at the call site).
pub(super) fn read_state(bytes: &[u8]) -> Option<SettingsState> {
    let _ = bytes;
    todo!("writer: v2 sidecar read, v1 MergeState upgraded (specs/PR-3c.md AC7)")
}

fn options() -> json_merge::MergeOptions {
    json_merge::MergeOptions {
        mode: FILE_MODE,
        // Arrays merge and roll back by value, which is what the string
        // entries in settingsSync.ignoredSettings need.
        keyed_arrays: &[],
        // The file holds the pairing and possibly the user's own secrets.
        redact_diff: true,
        // The override is the daemon's while managed: a hand edit of the URL
        // is replaced on the next apply and never becomes "the user's value"
        // that removal would put back (a stale override breaks Copilot Chat).
        owned_keys: &[OVERRIDE_KEY],
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
