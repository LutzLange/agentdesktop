//! VS Code user `settings.json` management for the `githubModels` variant of
//! `copilotChat` (specs/PR-3b.md): points Copilot Chat's CAPI endpoint
//! (`github.copilot.advanced.debug.overrideCapiUrl`) at the loopback proxy's
//! `/vscode-copilot-capi/<pairing>` route, so VS Code keeps GitHub's own
//! models and its own Copilot token while the daemon adds the gateway
//! identity. Mirrors `provider::vscode::reconcile` (the `ownModels` variant,
//! `chatLanguageModels.json`), merging through `provider::json_merge`.
//!
//! This module is the interface contract's compile-only stub for the test
//! author's spec-derived baseline (specs/PR-3b.md, "Interface contract for
//! the test author"): every function `todo!()`s: the writer fills them in.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use agentdesktop_core::config::{LlmGatewayConfig, VsCodeConfig};

use crate::reconcile::ReconcilePlan;

/// The user's `settings.json` for the resolved home directory (per-OS VS Code
/// user profile root, shared with `chatLanguageModels.json` and MCP
/// discovery), the file `overrideCapiUrl` and the two
/// `settingsSync.ignoredSettings` entries are merged into.
pub(super) fn settings_path(home: &Path) -> PathBuf {
    let _ = home;
    todo!("writer: per-OS VS Code user settings.json path (specs/PR-3b.md AC4)")
}

/// The managed part of `settings.json`: `github.copilot.advanced.debug.overrideCapiUrl`
/// pointed at the loopback proxy's path-pairing route for `listen` and
/// `pairing`, and the two `settingsSync.ignoredSettings` entries the daemon
/// owns (`github.copilot.advanced.debug.overrideCapiUrl` and
/// `github.copilot.internal.capiUrl`).
pub(super) fn managed_settings(listen: SocketAddr, pairing: &str) -> serde_json::Value {
    let _ = (listen, pairing);
    todo!("writer: managed settings.json document (specs/PR-3b.md AC4)")
}

/// Plans the create/update/remove/conflict for the user `settings.json` under
/// the `githubModels` variant of `copilotChat`.
///
/// Merges only when `configured` is `Some((config, Some(gateway)))` with
/// `config.copilot_chat == GithubModels`, `gateway.proxy_url.is_some()` and
/// `proxy.is_some()`; removes otherwise (with a warning when `proxy` is
/// `None`, matching a proxy-unavailable removal elsewhere), the same decision
/// shape as `reconcile::plan` (PR 3a, `chatLanguageModels.json`). The writer
/// calls this with `configured = None` when `githubModels` is active and
/// calls `reconcile::plan` (this crate's sibling module) with `configured =
/// None` too, since the `ownModels` file has nothing to manage under
/// `githubModels`; the test for that goes through `reconcile::plan` directly.
pub(super) fn plan(
    path: &Path,
    proxy: Option<(SocketAddr, &str)>,
    configured: Option<(&VsCodeConfig, Option<&LlmGatewayConfig>)>,
    plan: &ReconcilePlan,
) -> anyhow::Result<()> {
    let _ = (path, proxy, configured, plan);
    todo!("writer: settings.json plan (specs/PR-3b.md AC4)")
}
