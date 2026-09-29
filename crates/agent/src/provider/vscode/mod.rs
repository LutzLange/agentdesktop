use std::path::PathBuf;

use agentdesktop_core::config::DaemonConfig;
use agentdesktop_core::model::Discovery;

use super::{Provider, ReconcileContext};
use crate::reconcile::ReconcilePlan;

pub(super) mod discovery;
pub(crate) mod reconcile;

#[cfg(test)]
mod tests;

/// VS Code: points Copilot Chat's "Custom Endpoint" model provider
/// (`chatLanguageModels.json`) at the loopback LLM proxy's `/vscode-copilot`
/// route. User mode only; `chat_models_path` is `None` for a system daemon,
/// which has no user profile to manage.
pub struct VsCode {
    pub chat_models_path: Option<PathBuf>,
}
impl VsCode {
    pub const ID: &'static str = "vscode";
    pub const DISPLAY_NAME: &'static str = "VS Code";
}

/// The user's `chatLanguageModels.json` from the daemon's environment (home
/// directory, per-OS VS Code user profile root).
pub fn default_vscode_chat_models_path() -> anyhow::Result<PathBuf> {
    todo!("PR 3a: written by the implementer (criterion 2)")
}

#[async_trait::async_trait]
impl Provider for VsCode {
    async fn discover(&self) -> Discovery {
        Discovery {
            agents: discovery::discover().into_iter().collect(),
            model_runtimes: Vec::new(),
        }
    }

    fn plan(&self, ctx: &ReconcileContext, config: &DaemonConfig) -> anyhow::Result<ReconcilePlan> {
        let _ = (ctx, config);
        todo!("PR 3a: written by the implementer (criteria 2, 3, 5)")
    }
}
