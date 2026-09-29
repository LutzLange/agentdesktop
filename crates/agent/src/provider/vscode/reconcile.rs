use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use agentdesktop_core::config::{LlmGatewayConfig, VsCodeConfig};
use serde_json::Value;

use super::discovery;
use crate::reconcile::ReconcilePlan;

/// What the plan report calls the managed part of the file.
#[allow(dead_code)]
const DESCRIPTION: &str = "chat language models";
/// The file carries the pairing value, so a file we write is owner-only.
#[allow(dead_code)]
const FILE_MODE: u32 = 0o600;

/// `chatLanguageModels.json` inside the VS Code user profile directory for
/// `home` (the per-OS root VS Code itself reads, shared with MCP discovery).
pub(super) fn chat_models_path(home: &Path) -> PathBuf {
    discovery::user_profile_root(home).join("chatLanguageModels.json")
}

/// The JSON root ARRAY merged into `chatLanguageModels.json`: one vendor
/// entry named `agentdesktop` (VS Code's "Custom Endpoint" Copilot Chat
/// provider) pointed at the loopback proxy's `/vscode-copilot` route, with
/// one model entry per configured model. No secret `apiKey` is written: VS
/// Code's schema requires the field, but the pairing travels in
/// `requestHeaders` instead.
pub(super) fn managed_document(
    config: &VsCodeConfig,
    listen: SocketAddr,
    pairing: &str,
) -> anyhow::Result<Value> {
    let _ = (config, listen, pairing);
    todo!("PR 3a: written by the implementer (criterion 3)")
}

/// The single array agentdesktop manages by key: vendor entries by `name`, at
/// the document root (`field: ""`). Unlike the Copilot CLI's `providers.json`,
/// the vendor's `models` sub-array is not separately keyed: the whole vendor
/// entry is owned and replaced wholesale on every apply.
#[allow(dead_code)]
const KEYED: &[crate::provider::json_merge::KeyedArray] =
    &[crate::provider::json_merge::KeyedArray {
        field: "",
        keys: &["name"],
    }];

/// Plans the create/update/remove/conflict for `chatLanguageModels.json`.
///
/// With the program absent, the gateway off for it (`useLlmGateway: false` or
/// no top-level `llmGateway`), or no loopback proxy, the managed vendor entry
/// is removed and the user's own entries stay. Otherwise the managed document
/// is merged in. The vendor entry named `agentdesktop` belongs to agentdesktop
/// once it has written the file; before that, a user vendor entry under that
/// name is a conflict, unless it carries a pairing header on one of its
/// models (then it was written by an agentdesktop daemon whose sidecar is
/// gone, and it is replaced).
pub(super) fn plan(
    path: &Path,
    proxy: Option<(SocketAddr, &str)>,
    configured: Option<(&VsCodeConfig, Option<&LlmGatewayConfig>)>,
    plan: &ReconcilePlan,
) -> anyhow::Result<()> {
    let _ = (path, proxy, configured, plan);
    todo!("PR 3a: written by the implementer (criteria 3, 4, 5)")
}
