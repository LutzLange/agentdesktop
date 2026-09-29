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

/// The user's `chatLanguageModels.json` for the resolved home directory
/// (per-OS VS Code user profile root).
pub fn default_vscode_chat_models_path(home: &std::path::Path) -> PathBuf {
    reconcile::chat_models_path(home)
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
        let configured = config.programs.vscode.as_ref().map(|program| {
            let gateway = config
                .llm_gateway
                .as_ref()
                .filter(|_| program.use_llm_gateway);
            (program, gateway)
        });
        let proxy = ctx
            .llm_proxy
            .as_ref()
            .map(|proxy| (proxy.address, &*proxy.pairing));
        let plan = ReconcilePlan::default();
        // The file lives in the user's VS Code profile, so a system daemon has
        // no path and rejects the program before any provider writes.
        let Some(path) = self
            .chat_models_path
            .as_deref()
            .filter(|_| ctx.merge_user_settings)
        else {
            if configured.is_some() {
                anyhow::bail!(
                    "{} Copilot Chat reads its custom models from the user's own VS Code profile; remove programs.vscode or run agentdesktop with --user (daemon.user: true) so it can manage that file",
                    Self::DISPLAY_NAME
                );
            }
            return Ok(plan);
        };
        reconcile::plan(path, proxy, configured, &plan)?;
        Ok(plan)
    }
}
