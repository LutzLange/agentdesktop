//! Shared reconciliation orchestration, plan application, and dry-run reporting.
mod plan;
pub use plan::ReconcilePlan;

use crate::provider::{
    Provider, ReconcileContext, claude_code::ClaudeCode, claude_desktop::ClaudeDesktop,
    codex::Codex, copilot::Copilot, cursor::Cursor, grok::Grok, ollama::Ollama, opencode::OpenCode,
    vscode::VsCode,
};
use agentdesktop_core::{
    config::{DaemonConfig, ProgramsConfig},
    model::Discovery,
};
use serde_json::Value;
use similar::TextDiff;
use std::{
    cell::RefCell,
    fmt::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

// Preserve callers of the existing default-path helpers.
pub use crate::provider::{
    claude_code::default_claude_code_managed_settings_dir,
    claude_desktop::{
        default_claude_desktop_credential_helper_path, default_claude_desktop_managed_settings_path,
    },
    codex::default_codex_managed_config_path,
    copilot::default_copilot_providers_path,
    grok::default_grok_managed_config_path,
    opencode::{default_open_code_managed_config_path, default_open_code_plugin_path},
    vscode::{default_vscode_chat_models_path, default_vscode_settings_path},
};

#[derive(Clone)]
pub struct Reconciler {
    context: ReconcileContext,
    providers: Arc<Vec<Box<dyn Provider>>>,
}

impl Reconciler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        merge_user_settings: bool,
        claude_code_settings_path: PathBuf,
        claude_desktop_managed_settings_path: PathBuf,
        claude_desktop_credential_helper_path: PathBuf,
        codex_managed_config_path: PathBuf,
        open_code_managed_config_path: PathBuf,
        open_code_plugin_path: PathBuf,
        grok_managed_config_path: PathBuf,
        copilot_providers_path: Option<PathBuf>,
        vscode_chat_models_path: Option<PathBuf>,
        vscode_settings_path: Option<PathBuf>,
        credential_helper: PathBuf,
        socket: PathBuf,
    ) -> Self {
        Self {
            context: ReconcileContext {
                merge_user_settings,
                credential_helper,
                socket,
                llm_proxy: None,
            },
            providers: Arc::new(vec![
                Box::new(ClaudeCode {
                    settings_path: claude_code_settings_path,
                }),
                Box::new(ClaudeDesktop {
                    managed_settings_path: claude_desktop_managed_settings_path,
                    credential_helper_path: claude_desktop_credential_helper_path,
                }),
                Box::new(Codex {
                    managed_config_path: codex_managed_config_path,
                }),
                Box::new(OpenCode {
                    managed_config_path: open_code_managed_config_path,
                    plugin_path: open_code_plugin_path,
                }),
                Box::new(VsCode {
                    chat_models_path: vscode_chat_models_path,
                    settings_path: vscode_settings_path,
                }),
                Box::new(Cursor),
                Box::new(Grok {
                    managed_config_path: grok_managed_config_path,
                }),
                Box::new(Copilot {
                    providers_path: copilot_providers_path,
                }),
                Box::new(Ollama),
            ]),
        }
    }

    /// Attach the bound loopback LLM proxy so reconcilers can point client files at it.
    pub fn with_llm_proxy(mut self, llm_proxy: Option<crate::llm_proxy::LlmProxyContext>) -> Self {
        self.context.llm_proxy = llm_proxy;
        self
    }

    /// Plan every provider, including cleanup for disabled providers, before
    /// applying any writes. A later provider's failure leaves all files intact.
    pub fn plan(&self, config: &DaemonConfig) -> anyhow::Result<ReconcilePlan> {
        let mut plan = ReconcilePlan::default();
        for provider in self.providers.iter() {
            plan.append(provider.plan(&self.context, config)?)?;
        }
        Ok(plan)
    }

    pub async fn discover(&self) -> Discovery {
        let mut discovery = Discovery {
            agents: Vec::new(),
            model_runtimes: Vec::new(),
        };
        for provider in self.providers.iter() {
            let found = provider.discover().await;
            discovery.agents.extend(found.agents);
            discovery.model_runtimes.extend(found.model_runtimes);
        }
        discovery
    }

    pub fn apply(&self, config: &DaemonConfig) -> anyhow::Result<()> {
        self.plan(config)?.apply()
    }

    pub fn dry_run(&self, config: &DaemonConfig) -> anyhow::Result<()> {
        print!("{}", self.plan(config)?.render());
        Ok(())
    }

    /// Plans every provider like [`Reconciler::plan`], but a provider whose
    /// `plan` errors is recorded as `ProgramState::Failed` instead of
    /// aborting the rest (specs/PR-4.md, criterion 4).
    pub fn plan_with_report(&self, config: &DaemonConfig) -> AttributedPlan {
        let _ = config;
        todo!(
            "PR 4: Reconciler::plan_with_report - plan every provider, attributing operations \
             and observed paths to the provider that produced them, recording a Failed outcome \
             for a provider whose plan() errors and continuing with the rest"
        )
    }

    /// [`Reconciler::plan_with_report`] followed by [`AttributedPlan::apply`].
    pub fn apply_with_report(&self, config: &DaemonConfig) -> (ApplyReport, anyhow::Result<()>) {
        self.plan_with_report(config).apply()
    }
}

/// The precedence-ranked terminal state of one program's outcome from an
/// attributed apply, highest first: Failed > Conflict > Blocked > Inactive >
/// Applied/Removed > Unchanged (specs/PR-4.md, criterion 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramState {
    /// The program's operations were written by this apply.
    Applied,
    /// The program is configured; nothing needed to be written.
    Unchanged,
    /// The program is not configured; its managed content was removed by
    /// this apply.
    Removed,
    /// A managed file held conflicting or invalid existing configuration.
    Conflict,
    /// The program uses the gateway, a gateway is configured, and the
    /// loopback proxy is absent.
    Inactive,
    /// The program had operations, but none of them was written because the
    /// apply was refused or stopped.
    Blocked,
    /// The program's plan errored, its append failed, one of its writes
    /// failed, or one of its observed files changed before the apply.
    Failed,
}

/// One program's outcome from an attributed apply
/// (specs/PR-4.md, criterion 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramOutcome {
    /// The provider ID (`Provider::ID` on the concrete provider), for
    /// example `"claude-code"` or `"vscode"`.
    pub program: &'static str,
    pub state: ProgramState,
    pub detail: String,
}

/// Every reported program's outcome from one apply, in provider
/// registration order (specs/PR-4.md, criterion 1 and 3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    pub programs: Vec<ProgramOutcome>,
}

/// A plan attributed to the providers that produced it, ready to apply with
/// per-program reporting (specs/PR-4.md, criterion 4 and 5). Opaque: the
/// shape here is a placeholder for the implementation.
#[allow(dead_code)]
pub struct AttributedPlan {
    plan: ReconcilePlan,
    programs: Vec<&'static str>,
}

impl AttributedPlan {
    /// Applies with today's all-or-nothing rules (a failed plan or any
    /// conflict means nothing is written) and returns the first error as
    /// today, alongside the per-program report (specs/PR-4.md, criterion 4).
    pub fn apply(self) -> (ApplyReport, anyhow::Result<()>) {
        todo!(
            "PR 4: AttributedPlan::apply - apply with per-program attribution, precedence and \
             detail truncation to 1024 bytes"
        )
    }
}

/// The provider IDs reported as configured for `programs`: an exhaustive
/// destructure of [`ProgramsConfig`], so a new key does not compile until it
/// is mapped here (specs/PR-4.md, criterion 3).
pub fn configured_programs(programs: &ProgramsConfig) -> Vec<&'static str> {
    let _ = programs;
    todo!("PR 4: configured_programs - map each configured ProgramsConfig key to its provider ID")
}

#[derive(Default)]
struct DryRunReport {
    changes: RefCell<Vec<DryRunChange>>,
}

struct DryRunChange {
    display_name: String,
    description: String,
    action: String,
    path: PathBuf,
    before: Option<String>,
    after: Option<String>,
}

impl DryRunReport {
    fn record(
        &self,
        display_name: &str,
        description: &str,
        action: &str,
        path: &Path,
        before: Option<&[u8]>,
        after: Option<&[u8]>,
    ) {
        self.changes.borrow_mut().push(DryRunChange {
            display_name: display_name.to_owned(),
            description: description.to_owned(),
            action: action.to_owned(),
            path: path.to_owned(),
            before: before.map(|value| String::from_utf8_lossy(value).into_owned()),
            after: after.map(|value| String::from_utf8_lossy(value).into_owned()),
        });
    }

    fn render(&self) -> String {
        let changes = self.changes.borrow();
        let changed = changes
            .iter()
            .filter(|change| change.action != "unchanged" && change.action != "conflict")
            .count();
        let unchanged = changes
            .iter()
            .filter(|change| change.action == "unchanged")
            .count();
        let conflicts = changes
            .iter()
            .filter(|change| change.action == "conflict")
            .count();
        let mut output = String::from("Dry run — no files will be changed\n");

        for change in changes.iter().filter(|change| change.action != "unchanged") {
            let _ = write!(
                output,
                "\n{}  {} {}\n        {}\n",
                change.action.to_uppercase(),
                change.display_name,
                change.description,
                change.path.display()
            );
            if change.before.is_some() || change.after.is_some() {
                let (before, after) = normalized_diff(
                    change.before.as_deref().unwrap_or(""),
                    change.after.as_deref().unwrap_or(""),
                );
                let diff = TextDiff::from_lines(&before, &after)
                    .unified_diff()
                    .context_radius(3)
                    .header("current", "proposed")
                    .to_string();
                if !diff.is_empty() {
                    let _ = write!(output, "{diff}");
                }
            }
        }

        let noun = if changed == 1 { "change" } else { "changes" };
        let _ = write!(output, "\nSummary: {changed} {noun}, {unchanged} unchanged");
        if conflicts > 0 {
            let _ = write!(output, ", {conflicts} conflicts");
        }
        output.push('\n');
        output
    }
}

fn normalized_diff(before: &str, after: &str) -> (String, String) {
    match (
        serde_json::from_str::<Value>(before),
        serde_json::from_str::<Value>(after),
    ) {
        (Ok(before), Ok(after)) => (
            format!(
                "{}\n",
                serde_json::to_string_pretty(&before).expect("JSON value serializes")
            ),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&after).expect("JSON value serializes")
            ),
        ),
        _ => (before.to_owned(), after.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, path::PathBuf};

    use agentdesktop_core::config::parse_daemon;

    use super::{ApplyReport, DryRunReport, ProgramOutcome, ProgramState, Reconciler};

    #[test]
    fn dry_run_report_shows_changes_and_hides_unchanged_files() {
        let report = DryRunReport::default();
        report.record(
            "Claude Code",
            "settings",
            "update",
            Path::new("/home/user/.claude/settings.json"),
            Some(br#"{"keep":true}"#),
            Some(br#"{"managed":true,"keep":true}"#),
        );
        report.record(
            "Codex",
            "configuration",
            "unchanged",
            Path::new("/home/user/.codex/config.toml"),
            None,
            None,
        );

        let rendered = report.render();
        assert!(rendered.contains("UPDATE  Claude Code settings"));
        assert!(rendered.contains("+  \"managed\": true"));
        assert!(!rendered.contains("Codex configuration"));
        assert!(rendered.contains("Summary: 1 change, 1 unchanged"));
    }

    #[test]
    fn user_mode_rejects_claude_desktop_before_writing_other_settings() {
        let root = std::env::temp_dir().join(format!(
            "agentdesktop-reconcile-user-desktop-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let config = parse_daemon(
            r#"
programs:
  claudeCode: {}
  claudeDesktop: {}
"#,
        )
        .expect("valid configuration");
        let reconciler = Reconciler::new(
            true,
            root.join("claude/settings.json"),
            root.join("claude-desktop/settings.json"),
            root.join("claude-desktop/helper"),
            root.join("codex/config.toml"),
            root.join("opencode/config.json"),
            root.join("opencode/plugin.js"),
            root.join("grok/managed_config.toml"),
            Some(root.join("copilot/providers.json")),
            None,
            None,
            root.join("bin/agentdesktop"),
            root.join("agentdesktop.sock"),
        );

        let error = reconciler.apply(&config).expect_err("user mode must fail");

        assert!(
            error
                .to_string()
                .contains("Claude Desktop managed settings")
        );
        assert!(!root.exists(), "preflight failure must not write any files");
    }

    #[test]
    fn user_mode_rejects_grok_before_writing_other_settings() {
        let root = std::env::temp_dir().join(format!(
            "agentdesktop-reconcile-user-grok-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let config = parse_daemon(
            r#"
programs:
  claudeCode: {}
  grok: {}
"#,
        )
        .unwrap();
        let reconciler = Reconciler::new(
            true,
            root.join("claude/settings.json"),
            root.join("claude-desktop/settings.json"),
            root.join("claude-desktop/helper"),
            root.join("codex/config.toml"),
            root.join("opencode/config.json"),
            root.join("opencode/plugin.js"),
            root.join("grok/managed_config.toml"),
            Some(root.join("copilot/providers.json")),
            None,
            None,
            root.join("bin/agentdesktop"),
            root.join("agentdesktop.sock"),
        );

        let error = reconciler.apply(&config).expect_err("user mode must fail");
        assert!(error.to_string().contains("Grok Build"));
        assert!(!root.exists(), "preflight failure must not write any files");
    }

    #[test]
    fn copilot_directory_is_created_owner_only_through_the_reconciler() {
        // The private-directory request must survive `ReconcilePlan::append`,
        // which the daemon always goes through (the lab found it dropped once).
        let root = std::env::temp_dir().join(format!(
            "agentdesktop-reconcile-copilot-dir-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let config = parse_daemon(
            r#"
llmGateway:
  url: https://gateway.example.com
programs:
  copilot:
    models:
      gpt-4.1: {}
"#,
        )
        .unwrap();
        let providers = root.join("copilot/.copilot/providers.json");
        let reconciler = Reconciler::new(
            true,
            root.join("claude/settings.json"),
            root.join("claude-desktop/settings.json"),
            root.join("claude-desktop/helper"),
            root.join("codex/config.toml"),
            root.join("opencode/config.json"),
            root.join("opencode/plugin.js"),
            root.join("grok/managed_config.toml"),
            Some(providers.clone()),
            None,
            None,
            root.join("bin/agentdesktop"),
            root.join("agentdesktop.sock"),
        )
        .with_llm_proxy(Some(crate::llm_proxy::LlmProxyContext {
            address: "127.0.0.1:18095".parse().unwrap(),
            pairing: std::sync::Arc::from("PAIRING-RECONCILER"),
        }));
        reconciler.apply(&config).expect("apply");
        assert!(providers.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(providers.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "directory created through the reconciler");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vscode_directory_is_created_owner_only_through_the_reconciler() {
        // Same private-directory request as the Copilot CLI test above, for
        // the VS Code user profile directory.
        let root = std::env::temp_dir().join(format!(
            "agentdesktop-reconcile-vscode-dir-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let config = parse_daemon(
            r#"
llmGateway:
  url: https://gateway.example.com
programs:
  vscode:
    models:
      gpt-4.1-mini: {}
"#,
        )
        .unwrap();
        let chat_models = root.join("vscode/User/chatLanguageModels.json");
        let reconciler = Reconciler::new(
            true,
            root.join("claude/settings.json"),
            root.join("claude-desktop/settings.json"),
            root.join("claude-desktop/helper"),
            root.join("codex/config.toml"),
            root.join("opencode/config.json"),
            root.join("opencode/plugin.js"),
            root.join("grok/managed_config.toml"),
            Some(root.join("copilot/providers.json")),
            Some(chat_models.clone()),
            Some(chat_models.with_file_name("settings.json")),
            root.join("bin/agentdesktop"),
            root.join("agentdesktop.sock"),
        )
        .with_llm_proxy(Some(crate::llm_proxy::LlmProxyContext {
            address: "127.0.0.1:18095".parse().unwrap(),
            pairing: std::sync::Arc::from("PAIRING-RECONCILER"),
        }));
        reconciler.apply(&config).expect("apply");
        assert!(chat_models.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(chat_models.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "directory created through the reconciler");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn system_mode_rejects_copilot_before_writing_other_settings() {
        let root = std::env::temp_dir().join(format!(
            "agentdesktop-reconcile-system-copilot-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let config = parse_daemon(
            r#"
programs:
  claudeCode: {}
  copilot: {}
"#,
        )
        .unwrap();
        // The Copilot CLI program is the inverse of Grok: it manages a file in
        // the user's home, so a system daemon (no providers path) rejects it
        // before any provider writes.
        let reconciler = Reconciler::new(
            false,
            root.join("claude/settings.json"),
            root.join("claude-desktop/settings.json"),
            root.join("claude-desktop/helper"),
            root.join("codex/config.toml"),
            root.join("opencode/config.json"),
            root.join("opencode/plugin.js"),
            root.join("grok/managed_config.toml"),
            None,
            None,
            None,
            root.join("bin/agentdesktop"),
            root.join("agentdesktop.sock"),
        );

        let error = reconciler
            .apply(&config)
            .expect_err("system mode must fail");
        assert!(error.to_string().contains("GitHub Copilot CLI"), "{error}");
        assert!(error.to_string().contains("--user"), "{error}");
        assert!(!root.exists(), "preflight failure must not write any files");
    }

    #[cfg(windows)]
    #[test]
    fn windows_reconciles_system_grok_managed_config() {
        let fixture = Fixture::new();
        let config = parse_daemon("programs:\n  claudeCode: {}\n  grok: {}\n").unwrap();
        fixture.reconciler.apply(&config).unwrap();
        assert!(fixture.root.join("grok/managed_config.toml").exists());
    }

    #[test]
    fn dry_run_plans_create_update_and_remove_without_changing_files() {
        let root = std::env::temp_dir().join(format!(
            "agentdesktop-reconcile-dry-run-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let config = parse_daemon(
            r#"
programs:
  claudeCode: {}
  claudeDesktop: {}
  codex: {}
  openCode: {}
"#,
        )
        .expect("valid configuration");
        fs::create_dir_all(root.join("codex")).unwrap();
        fs::create_dir_all(root.join("claude")).unwrap();
        fs::create_dir_all(root.join("opencode")).unwrap();
        let user_claude = br#"{"theme":"dark"}\n"#;
        let old_codex =
            b"# Managed by Agentdesktop. Manual changes will be replaced.\nmodel = \"old\"\n";
        let old_plugin =
            b"// Managed by Agentdesktop. Manual changes will be replaced.\nold plugin\n";
        fs::write(root.join("claude/settings.json"), user_claude).unwrap();
        fs::write(root.join("codex/config.toml"), old_codex).unwrap();
        fs::write(root.join("opencode/plugin.js"), old_plugin).unwrap();
        let reconciler = Reconciler::new(
            false,
            root.join("claude/settings.json"),
            root.join("claude-desktop/settings.json"),
            root.join("claude-desktop/helper"),
            root.join("codex/config.toml"),
            root.join("opencode/config.json"),
            root.join("opencode/plugin.js"),
            root.join("grok/managed_config.toml"),
            Some(root.join("copilot/providers.json")),
            None,
            None,
            root.join("bin/agentdesktop"),
            root.join("agentdesktop.sock"),
        );

        reconciler.dry_run(&config).expect("dry run succeeds");

        assert_eq!(
            fs::read(root.join("claude/settings.json")).unwrap(),
            user_claude
        );
        assert!(!root.join("claude-desktop/settings.json").exists());
        assert!(!root.join("opencode/config.json").exists());
        assert_eq!(fs::read(root.join("codex/config.toml")).unwrap(), old_codex);
        assert_eq!(
            fs::read(root.join("opencode/plugin.js")).unwrap(),
            old_plugin
        );
        fs::remove_dir_all(root).unwrap();
    }

    struct Fixture {
        root: PathBuf,
        reconciler: Reconciler,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "agentdesktop-provider-plan-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            let reconciler = Reconciler::new(
                false,
                root.join("claude/settings.json"),
                root.join("desktop/settings.json"),
                root.join("desktop/helper"),
                root.join("codex/config.toml"),
                root.join("opencode/config.json"),
                root.join("opencode/plugin.js"),
                root.join("grok/managed_config.toml"),
                Some(root.join("copilot/providers.json")),
                None,
                None,
                root.join("bin/agentdesktop"),
                root.join("agentdesktop.sock"),
            );
            Self { root, reconciler }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn providers_plan_apply_repeat_and_remove_managed_files() {
        let fixture = Fixture::new();
        let config = parse_daemon(
            r#"
llmGateway:
  url: https://gateway.example.com
  authentication:
    type: controllerJwt
    audience: agentgateway
    allowedClientIds: [claude-code, claude-desktop, codex, opencode, grok]
programs:
  claudeCode: {}
  claudeDesktop: {}
  codex: {}
  openCode:
    model: company-model
    models:
      company-model: {}
  grok:
    model: grok-4.6
"#,
        )
        .unwrap();
        let plan = fixture.reconciler.plan(&config).unwrap();
        assert!(
            !fixture.root.exists(),
            "planning must not create directories or sidecars"
        );
        assert!(!plan.has_conflicts());
        plan.apply().unwrap();

        let paths = [
            "claude/settings.json",
            "claude/.settings.json.owner",
            "desktop/settings.json",
            "desktop/.settings.json.owner",
            "desktop/helper",
            "desktop/.helper.owner",
            "codex/config.toml",
            "opencode/config.json",
            "opencode/plugin.js",
            "grok/managed_config.toml",
        ];
        let contents: Vec<_> = paths
            .iter()
            .map(|path| fs::read(fixture.root.join(path)).unwrap())
            .collect();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(fixture.root.join("desktop/helper"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
        }
        let repeated = fixture.reconciler.plan(&config).unwrap();
        assert!(repeated.render().contains("Summary: 0 changes"));
        repeated.apply().unwrap();
        for (path, expected) in paths.iter().zip(contents) {
            assert_eq!(fs::read(fixture.root.join(path)).unwrap(), expected);
        }

        let disabled = parse_daemon("programs: {}").unwrap();
        let cleanup = fixture.reconciler.plan(&disabled).unwrap();
        assert!(paths.iter().all(|path| fixture.root.join(path).exists()));
        cleanup.apply().unwrap();
        assert!(paths.iter().all(|path| !fixture.root.join(path).exists()));
    }

    #[test]
    fn later_provider_conflict_prevents_all_writes() {
        let fixture = Fixture::new();
        let path = fixture.root.join("codex/config.toml");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let user_config = b"model = \"personal\"\n";
        fs::write(&path, user_config).unwrap();
        let config = parse_daemon("programs:\n  claudeCode: {}\n  codex: {}").unwrap();
        let plan = fixture.reconciler.plan(&config).unwrap();
        assert!(plan.has_conflicts());
        assert!(plan.render().contains("CONFLICT  Codex"));
        assert!(plan.apply().is_err());
        assert!(!fixture.root.join("claude").exists());
        assert_eq!(fs::read(path).unwrap(), user_config);
    }

    #[test]
    fn changed_settings_or_ownership_reject_plan_before_any_writes() {
        for changed in ["codex/config.toml", "claude/.settings.json.owner"] {
            let fixture = Fixture::new();
            let original = parse_daemon("programs:\n  claudeCode: {}\n  codex: {}").unwrap();
            fixture.reconciler.apply(&original).unwrap();
            let settings = fixture.root.join("claude/settings.json");
            let before = fs::read(&settings).unwrap();
            let update = parse_daemon(
                "programs:\n  claudeCode:\n    env:\n      COMPANY: updated\n  codex: {}",
            )
            .unwrap();
            let plan = fixture.reconciler.plan(&update).unwrap();
            let changed_path = fixture.root.join(changed);
            fs::write(&changed_path, b"externally changed").unwrap();
            let error = plan.apply().unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("changed since reconciliation was planned")
            );
            assert_eq!(fs::read(settings).unwrap(), before);
            assert_eq!(fs::read(changed_path).unwrap(), b"externally changed");
        }
    }

    #[test]
    fn providers_cannot_plan_writes_to_the_same_path() {
        let mut fixture = Fixture::new();
        let path = fixture.root.join("claude/settings.json");
        fixture.reconciler.providers = std::sync::Arc::new(vec![
            Box::new(super::ClaudeCode {
                settings_path: path.clone(),
            }),
            Box::new(super::Codex {
                managed_config_path: path,
            }),
        ]);
        let config = parse_daemon("programs:\n  claudeCode: {}\n  codex: {}").unwrap();
        let error = fixture.reconciler.apply(&config).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("multiple providers plan to modify")
        );
        assert!(!fixture.root.exists());
    }

    // --- PR 4: per-program configuration status (specs/PR-4.md) ------------

    fn new_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "agentdesktop-reconcile-pr4-{name}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    /// A user-mode reconciler with every provider's paths set (including
    /// Copilot CLI and VS Code), rooted at `root`.
    fn full_reconciler(root: &Path) -> Reconciler {
        Reconciler::new(
            true,
            root.join("claude/settings.json"),
            root.join("claude-desktop/settings.json"),
            root.join("claude-desktop/helper"),
            root.join("codex/config.toml"),
            root.join("opencode/config.json"),
            root.join("opencode/plugin.js"),
            root.join("grok/managed_config.toml"),
            Some(root.join("copilot/providers.json")),
            Some(root.join("vscode/User/chatLanguageModels.json")),
            Some(root.join("vscode/User/settings.json")),
            root.join("bin/agentdesktop"),
            root.join("agentdesktop.sock"),
        )
    }

    fn proxy_context(pairing: &str) -> crate::llm_proxy::LlmProxyContext {
        crate::llm_proxy::LlmProxyContext {
            address: "127.0.0.1:18095".parse().unwrap(),
            pairing: std::sync::Arc::from(pairing),
        }
    }

    fn program_outcome<'a>(report: &'a ApplyReport, program: &str) -> Option<&'a ProgramOutcome> {
        report
            .programs
            .iter()
            .find(|outcome| outcome.program == program)
    }

    /// A provider whose `plan` always fails with a caller-supplied message,
    /// for scenarios only the message shape matters for (detail truncation).
    struct FailWithMessage {
        message: String,
    }

    #[async_trait::async_trait]
    impl crate::provider::Provider for FailWithMessage {
        async fn discover(&self) -> agentdesktop_core::model::Discovery {
            agentdesktop_core::model::Discovery {
                agents: Vec::new(),
                model_runtimes: Vec::new(),
            }
        }

        fn plan(
            &self,
            _ctx: &crate::provider::ReconcileContext,
            _config: &agentdesktop_core::config::DaemonConfig,
        ) -> anyhow::Result<super::ReconcilePlan> {
            anyhow::bail!("{}", self.message)
        }
    }

    #[test]
    fn applied_then_unchanged_with_report() {
        let root = new_root("applied-unchanged");
        let config = parse_daemon(
            r#"
llmGateway:
  url: https://gateway.example.com
programs:
  claudeCode: {}
  copilot:
    models:
      gpt-4.1: {}
"#,
        )
        .unwrap();
        let reconciler = full_reconciler(&root).with_llm_proxy(Some(proxy_context("PAIRING-1")));

        let (report, result) = reconciler.apply_with_report(&config);
        result.expect("first apply succeeds");
        assert_eq!(
            program_outcome(&report, "claude-code").map(|outcome| outcome.state),
            Some(ProgramState::Applied)
        );
        assert_eq!(
            program_outcome(&report, "copilot").map(|outcome| outcome.state),
            Some(ProgramState::Applied)
        );

        let (report, result) = reconciler.apply_with_report(&config);
        result.expect("second apply succeeds");
        assert_eq!(
            program_outcome(&report, "claude-code").map(|outcome| outcome.state),
            Some(ProgramState::Unchanged)
        );
        assert_eq!(
            program_outcome(&report, "copilot").map(|outcome| outcome.state),
            Some(ProgramState::Unchanged)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn removed_then_absent_on_the_next_apply() {
        let root = new_root("removed-absent");
        let configured = parse_daemon(
            r#"
llmGateway:
  url: https://gateway.example.com
programs:
  copilot:
    models:
      gpt-4.1: {}
"#,
        )
        .unwrap();
        let reconciler = full_reconciler(&root).with_llm_proxy(Some(proxy_context("PAIRING-2")));
        reconciler
            .apply_with_report(&configured)
            .1
            .expect("apply configured");

        let disabled = parse_daemon("programs: {}").unwrap();
        let (report, result) = reconciler.apply_with_report(&disabled);
        result.expect("apply disabled");
        assert_eq!(
            program_outcome(&report, "copilot").map(|outcome| outcome.state),
            Some(ProgramState::Removed)
        );

        let (report, result) = reconciler.apply_with_report(&disabled);
        result.expect("apply disabled again");
        assert!(
            program_outcome(&report, "copilot").is_none(),
            "an unconfigured, idle provider gets no row"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn use_llm_gateway_false_reports_applied_or_unchanged() {
        let root = new_root("use-llm-gateway-false");
        let with_gateway = parse_daemon(
            r#"
llmGateway:
  url: https://gateway.example.com
programs:
  copilot:
    models:
      gpt-4.1: {}
"#,
        )
        .unwrap();
        let reconciler = full_reconciler(&root).with_llm_proxy(Some(proxy_context("PAIRING-3")));
        reconciler
            .apply_with_report(&with_gateway)
            .1
            .expect("apply with the gateway on");

        let gateway_off = parse_daemon(
            r#"
llmGateway:
  url: https://gateway.example.com
programs:
  copilot:
    useLlmGateway: false
"#,
        )
        .unwrap();
        let (report, result) = reconciler.apply_with_report(&gateway_off);
        result.expect("apply with the gateway off");
        assert_eq!(
            program_outcome(&report, "copilot").map(|outcome| outcome.state),
            Some(ProgramState::Applied),
            "the managed file is removed, so a configured program is Applied, not Removed"
        );

        let (report, result) = reconciler.apply_with_report(&gateway_off);
        result.expect("apply with the gateway off again");
        assert_eq!(
            program_outcome(&report, "copilot").map(|outcome| outcome.state),
            Some(ProgramState::Unchanged)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn conflict_blocks_other_programs_and_reports_blocked() {
        let root = new_root("conflict-blocked");
        fs::create_dir_all(root.join("codex")).unwrap();
        fs::write(root.join("codex/config.toml"), b"model = \"personal\"\n").unwrap();
        let config = parse_daemon("programs:\n  claudeCode: {}\n  codex: {}").unwrap();
        let reconciler = full_reconciler(&root);

        let (report, result) = reconciler.apply_with_report(&config);
        assert!(result.is_err(), "a conflict means nothing is written");
        assert_eq!(
            program_outcome(&report, "codex").map(|outcome| outcome.state),
            Some(ProgramState::Conflict)
        );
        let claude_code = program_outcome(&report, "claude-code").expect("claude-code is reported");
        assert_eq!(claude_code.state, ProgramState::Blocked);
        assert!(
            claude_code.detail.contains("codex"),
            "a blocked program's detail names the first conflicted program: {}",
            claude_code.detail
        );
        assert!(!root.join("claude").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn failed_provider_plan_does_not_stop_the_others() {
        let root = new_root("failed-plan-continues");
        // Grok Build's managed config lives in a system location, so a
        // user-mode daemon rejects it in `plan()` (see
        // `user_mode_rejects_grok_before_writing_other_settings` above) while
        // Claude Code plans normally: a real, deterministic plan failure.
        let reconciler = full_reconciler(&root);
        let config = parse_daemon("programs:\n  claudeCode: {}\n  grok: {}").unwrap();

        let (report, result) = reconciler.apply_with_report(&config);
        assert!(result.is_err());
        let grok = program_outcome(&report, "grok").expect("grok is reported");
        assert_eq!(grok.state, ProgramState::Failed);
        assert!(grok.detail.contains("Grok Build"), "{}", grok.detail);
        assert_eq!(
            program_outcome(&report, "claude-code").map(|outcome| outcome.state),
            Some(ProgramState::Blocked),
            "claude-code was still planned, but nothing is written because the apply fails"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn observed_file_mismatch_fails_its_owners_and_blocks_the_rest() {
        let root = new_root("observed-mismatch");
        let reconciler = full_reconciler(&root);
        let original = parse_daemon("programs:\n  claudeCode: {}\n  codex: {}").unwrap();
        reconciler
            .apply_with_report(&original)
            .1
            .expect("initial apply");

        let update =
            parse_daemon("programs:\n  claudeCode:\n    env:\n      COMPANY: updated\n  codex: {}")
                .unwrap();
        let attributed = reconciler.plan_with_report(&update);
        // Codex's file changes after planning but before apply.
        fs::write(root.join("codex/config.toml"), b"externally changed").unwrap();
        let (report, result) = attributed.apply();
        assert!(result.is_err());
        assert_eq!(
            program_outcome(&report, "codex").map(|outcome| outcome.state),
            Some(ProgramState::Failed)
        );
        assert_eq!(
            program_outcome(&report, "claude-code").map(|outcome| outcome.state),
            Some(ProgramState::Blocked)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn write_failure_orders_applied_failed_blocked() {
        // SAFETY: geteuid has no preconditions and does not dereference pointers.
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores directory permissions.
        }
        let root = new_root("write-failure-order");
        fs::create_dir_all(root.join("codex")).unwrap();
        let mut reconciler = full_reconciler(&root);
        reconciler.providers = std::sync::Arc::new(vec![
            Box::new(super::ClaudeCode {
                settings_path: root.join("claude/settings.json"),
            }),
            Box::new(super::Codex {
                managed_config_path: root.join("codex/config.toml"),
            }),
            Box::new(super::OpenCode {
                managed_config_path: root.join("opencode/config.json"),
                plugin_path: root.join("opencode/plugin.js"),
            }),
        ]);
        let config = parse_daemon(
            r#"
programs:
  claudeCode: {}
  codex: {}
  openCode:
    model: m
    models:
      m: {}
"#,
        )
        .unwrap();
        let attributed = reconciler.plan_with_report(&config);

        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.join("codex"), fs::Permissions::from_mode(0o500)).unwrap();
        let (report, result) = attributed.apply();
        // Restore permissions so the temp directory can be removed.
        fs::set_permissions(root.join("codex"), fs::Permissions::from_mode(0o700)).unwrap();

        assert!(result.is_err());
        assert_eq!(
            program_outcome(&report, "claude-code").map(|outcome| outcome.state),
            Some(ProgramState::Applied)
        );
        assert_eq!(
            program_outcome(&report, "codex").map(|outcome| outcome.state),
            Some(ProgramState::Failed)
        );
        assert_eq!(
            program_outcome(&report, "opencode").map(|outcome| outcome.state),
            Some(ProgramState::Blocked)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn copilot_and_vscode_own_models_go_inactive_when_the_proxy_is_absent() {
        let root = new_root("inactive-own-models");
        let config = parse_daemon(
            r#"
llmGateway:
  url: https://gateway.example.com
programs:
  copilot:
    models:
      gpt-4.1: {}
  vscode:
    models:
      gpt-4.1-mini: {}
"#,
        )
        .unwrap();
        let reconciler = full_reconciler(&root).with_llm_proxy(Some(proxy_context("PAIRING-5")));
        let (applied, result) = reconciler.apply_with_report(&config);
        result.expect("apply with the proxy available");
        assert_eq!(
            program_outcome(&applied, "copilot").map(|outcome| outcome.state),
            Some(ProgramState::Applied)
        );
        assert_eq!(
            program_outcome(&applied, "vscode").map(|outcome| outcome.state),
            Some(ProgramState::Applied)
        );

        // A restart (or a hot reload) without the proxy: from an applied
        // state, both programs go Inactive rather than being torn down as an
        // ordinary removal.
        let reconciler_without_proxy = full_reconciler(&root);
        let (report, result) = reconciler_without_proxy.apply_with_report(&config);
        result.expect("apply without the proxy still succeeds: files are removed, not written");
        for program in ["copilot", "vscode"] {
            let outcome = program_outcome(&report, program)
                .unwrap_or_else(|| panic!("{program} is reported"));
            assert_eq!(outcome.state, ProgramState::Inactive, "{program}");
            assert!(
                outcome.detail.contains("local LLM proxy not available"),
                "{program}: {}",
                outcome.detail
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn vscode_github_models_goes_inactive_when_the_proxy_is_absent() {
        let root = new_root("inactive-github-models");
        let config = parse_daemon(
            r#"
llmGateway:
  url: https://gateway.example.com
  proxyUrl: https://gateway.example.com/copilot-proxy
programs:
  vscode:
    copilotChat: githubModels
"#,
        )
        .unwrap();
        let reconciler = full_reconciler(&root);
        let (report, result) = reconciler.apply_with_report(&config);
        result.expect("apply without the proxy still succeeds");
        let outcome = program_outcome(&report, "vscode").expect("vscode is reported");
        assert_eq!(outcome.state, ProgramState::Inactive);
        assert!(
            outcome.detail.contains("local LLM proxy not available"),
            "{}",
            outcome.detail
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn vscode_conflict_on_one_file_outranks_inactive_on_the_other() {
        let root = new_root("vscode-conflict-outranks-inactive");
        let github_models = parse_daemon(
            r#"
llmGateway:
  url: https://gateway.example.com
  proxyUrl: https://gateway.example.com/copilot-proxy
programs:
  vscode:
    copilotChat: githubModels
"#,
        )
        .unwrap();
        let reconciler = full_reconciler(&root).with_llm_proxy(Some(proxy_context("PAIRING-7")));
        reconciler
            .apply_with_report(&github_models)
            .1
            .expect("apply githubModels with the proxy available");
        let settings_path = root.join("vscode/User/settings.json");
        assert!(settings_path.is_file(), "the override was written");

        // Break the shape the merge left in settings.json (an object) so its
        // removal below is a conflict, and switch to ownModels with no proxy
        // so the other managed file (chatLanguageModels.json) is Inactive in
        // the same apply: Conflict must outrank Inactive for the program.
        fs::write(&settings_path, b"[]\n").unwrap();
        let own_models = parse_daemon(
            r#"
llmGateway:
  url: https://gateway.example.com
programs:
  vscode:
    models:
      gpt-4.1-mini: {}
"#,
        )
        .unwrap();
        let reconciler = full_reconciler(&root);
        let (report, result) = reconciler.apply_with_report(&own_models);
        assert!(result.is_err(), "the conflict means nothing is written");
        let vscode = program_outcome(&report, "vscode").expect("vscode is reported");
        assert_eq!(
            vscode.state,
            ProgramState::Conflict,
            "conflict outranks inactive"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn discovery_only_and_unconfigured_idle_providers_get_no_row() {
        let root = new_root("no-row-for-idle");
        let reconciler = full_reconciler(&root);
        let config = parse_daemon("programs:\n  claudeCode: {}\n").unwrap();
        let (report, result) = reconciler.apply_with_report(&config);
        result.expect("apply succeeds");
        assert_eq!(
            program_outcome(&report, "claude-code").map(|outcome| outcome.state),
            Some(ProgramState::Applied)
        );
        for absent in [
            "cursor",
            "ollama",
            "codex",
            "claude-desktop",
            "grok",
            "copilot",
            "vscode",
            "opencode",
        ] {
            assert!(
                program_outcome(&report, absent).is_none(),
                "{absent} must get no row"
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn program_detail_is_truncated_to_1024_bytes() {
        let mut fixture = Fixture::new();
        // A multi-byte character straddles the 1024-byte cutoff so
        // truncation must land on a char boundary, not merely a byte count.
        let long_run = "a".repeat(1020);
        let message = format!("{long_run}\u{1F600}{long_run}");
        fixture.reconciler.providers = std::sync::Arc::new(vec![Box::new(FailWithMessage {
            message: message.clone(),
        })]);
        let config = parse_daemon("programs:\n  claudeCode: {}\n").unwrap();

        let (report, result) = fixture.reconciler.apply_with_report(&config);
        assert!(result.is_err());
        assert_eq!(
            report.programs.len(),
            1,
            "the one failing provider is reported"
        );
        let detail = &report.programs[0].detail;
        assert!(
            detail.len() <= 1024,
            "detail must be truncated to 1024 bytes: {} bytes",
            detail.len()
        );
        assert!(
            message.len() > 1024,
            "the untruncated message must exceed the limit"
        );
    }

    #[test]
    fn conflict_and_sidecar_failure_details_never_include_the_pairing() {
        const PAIRING: &str = "PAIRING-SECRET-13";

        // (a) A foreign "agentdesktop" vendor entry is a conflict.
        {
            let root = new_root("no-pairing-conflict");
            let chat_models = root.join("vscode/User/chatLanguageModels.json");
            fs::create_dir_all(chat_models.parent().unwrap()).unwrap();
            fs::write(
                &chat_models,
                serde_json::to_vec_pretty(&serde_json::json!([{
                    "name": "agentdesktop",
                    "vendor": "customendpoint",
                    "apiKey": "sk-user",
                    "apiType": "chat-completions",
                    "models": [{
                        "id": "not-ours",
                        "url": "https://not-ours.example.com/v1/chat/completions",
                    }],
                }]))
                .unwrap(),
            )
            .unwrap();
            let reconciler = full_reconciler(&root).with_llm_proxy(Some(proxy_context(PAIRING)));
            let config = parse_daemon(
                r#"
llmGateway:
  url: https://gateway.example.com
programs:
  vscode:
    models:
      gpt-4.1-mini: {}
"#,
            )
            .unwrap();
            let (report, result) = reconciler.apply_with_report(&config);
            assert!(result.is_err());
            let vscode = program_outcome(&report, "vscode").expect("vscode is reported");
            assert_eq!(vscode.state, ProgramState::Conflict);
            assert!(
                !vscode.detail.contains(PAIRING),
                "conflict detail must not leak the pairing: {}",
                vscode.detail
            );
            let _ = fs::remove_dir_all(&root);
        }

        // (b) A corrupted sidecar file is a plan error (Failed), not a conflict.
        {
            let root = new_root("no-pairing-sidecar");
            let reconciler = full_reconciler(&root).with_llm_proxy(Some(proxy_context(PAIRING)));
            let config = parse_daemon(
                r#"
llmGateway:
  url: https://gateway.example.com
programs:
  vscode:
    models:
      gpt-4.1-mini: {}
"#,
            )
            .unwrap();
            reconciler
                .apply_with_report(&config)
                .1
                .expect("initial apply");
            let sidecar = root.join("vscode/User/.chatLanguageModels.json.agentdesktop");
            assert!(sidecar.is_file(), "the sidecar was written");
            fs::write(&sidecar, b"{ not json").unwrap();

            let (report, result) = reconciler.apply_with_report(&config);
            assert!(result.is_err());
            let vscode = program_outcome(&report, "vscode").expect("vscode is reported");
            assert_eq!(vscode.state, ProgramState::Failed);
            assert!(
                !vscode.detail.contains(PAIRING),
                "sidecar parse failure detail must not leak the pairing: {}",
                vscode.detail
            );
            let _ = fs::remove_dir_all(&root);
        }
    }
}
