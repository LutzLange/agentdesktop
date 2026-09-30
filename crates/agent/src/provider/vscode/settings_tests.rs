//! Tests for VS Code's user `settings.json` management under the
//! `githubModels` variant of `copilotChat`, mirroring `provider::vscode::tests`
//! (`chatLanguageModels.json`) wherever the shape is shared.
//! `github_models_removes_the_managed_chat_language_models_entry_through_reconcile_plan`
//! exercises `reconcile::plan` with a `githubModels` config, which must plan a
//! removal of the custom-models entry.

use std::{collections::BTreeMap, fs, net::SocketAddr, path::PathBuf};

use agentdesktop_core::config::{LlmGatewayConfig, VsCodeConfig, VsCodeCopilotChat, VsCodeModel};
use serde_json::{Value, json};

use super::settings::{managed_settings, plan, settings_path};
use crate::reconcile::ReconcilePlan;

/// The two keys the daemon owns in `settings.json`.
const OVERRIDE_KEY: &str = "github.copilot.advanced.debug.overrideCapiUrl";
const CAPI_ALIAS_KEY: &str = "github.copilot.internal.capiUrl";
const IGNORED_SETTINGS_KEY: &str = "settingsSync.ignoredSettings";

const LISTEN: &str = "127.0.0.1:18095";
const PAIRING: &str = "PAIRING-FIXTURE";

fn listen_addr() -> SocketAddr {
    LISTEN.parse().unwrap()
}

fn override_url(listen: SocketAddr, pairing: &str) -> String {
    format!("http://{listen}/vscode-copilot-capi/{pairing}")
}

fn github_models_config() -> VsCodeConfig {
    VsCodeConfig {
        use_llm_gateway: true,
        copilot_chat: VsCodeCopilotChat::GithubModels,
        models: BTreeMap::new(),
    }
}

fn own_models_config() -> VsCodeConfig {
    let mut models = BTreeMap::new();
    models.insert("gpt-4.1-mini".to_owned(), VsCodeModel::default());
    VsCodeConfig {
        use_llm_gateway: true,
        copilot_chat: VsCodeCopilotChat::OwnModels,
        models,
    }
}

fn gateway_with_proxy() -> LlmGatewayConfig {
    LlmGatewayConfig {
        url: "https://gateway.example.com".parse().unwrap(),
        authentication: None,
        proxy_url: Some("https://gateway.example.com/copilot-proxy".parse().unwrap()),
        github_oauth: None,
    }
}

fn gateway_without_proxy_url() -> LlmGatewayConfig {
    LlmGatewayConfig {
        proxy_url: None,
        ..gateway_with_proxy()
    }
}

fn read(path: &std::path::Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn ignored_settings(document: &Value) -> Vec<String> {
    document[IGNORED_SETTINGS_KEY]
        .as_array()
        .unwrap_or_else(|| panic!("{IGNORED_SETTINGS_KEY} missing or not an array in {document}"))
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect()
}

fn apply_managed(
    path: &std::path::Path,
    listen: SocketAddr,
    pairing: &str,
    config: &VsCodeConfig,
    gateway: &LlmGatewayConfig,
) {
    let changes = ReconcilePlan::default();
    plan(
        path,
        Some((listen, pairing)),
        Some((config, Some(gateway))),
        &changes,
    )
    .unwrap();
    assert!(!changes.has_conflicts(), "{}", changes.render());
    changes.apply().unwrap();
}

fn apply_removal(
    path: &std::path::Path,
    proxy: Option<(SocketAddr, &str)>,
    configured: Option<(&VsCodeConfig, Option<&LlmGatewayConfig>)>,
) -> ReconcilePlan {
    let changes = ReconcilePlan::default();
    plan(path, proxy, configured, &changes).unwrap();
    changes
}

fn write_user_settings(path: &std::path::Path, document: &Value) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec_pretty(document).unwrap()).unwrap();
}

// --- Fresh apply -------------------------------------------------------

#[test]
fn fresh_file_gets_both_managed_keys_and_is_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let config = github_models_config();
    let gateway = gateway_with_proxy();

    apply_managed(&path, listen_addr(), PAIRING, &config, &gateway);

    let written = read(&path);
    assert_eq!(written[OVERRIDE_KEY], override_url(listen_addr(), PAIRING));
    let ignored = ignored_settings(&written);
    assert!(ignored.contains(&OVERRIDE_KEY.to_owned()), "{written}");
    assert!(ignored.contains(&CAPI_ALIAS_KEY.to_owned()), "{written}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "settings.json carries the pairing and must be owner-only"
        );
    }
    assert!(
        super::super::json_merge::state_path(&path).exists(),
        "a merge sidecar must be written alongside the created file"
    );
}

// --- User content survives re-apply and re-pairing --------------------

#[test]
fn user_keys_and_a_user_ignored_settings_entry_survive_reapply_and_repairing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    write_user_settings(
        &path,
        &json!({
            "editor.fontSize": 14,
            IGNORED_SETTINGS_KEY: ["some.other.userSetting"],
        }),
    );
    let config = github_models_config();
    let gateway = gateway_with_proxy();

    apply_managed(&path, listen_addr(), PAIRING, &config, &gateway);
    let after_first = read(&path);
    assert_eq!(after_first["editor.fontSize"], 14);
    let ignored = ignored_settings(&after_first);
    assert!(ignored.contains(&"some.other.userSetting".to_owned()));
    assert!(ignored.contains(&OVERRIDE_KEY.to_owned()));
    assert!(ignored.contains(&CAPI_ALIAS_KEY.to_owned()));

    // Re-apply unchanged: nothing lost, nothing duplicated.
    apply_managed(&path, listen_addr(), PAIRING, &config, &gateway);
    let after_reapply = read(&path);
    assert_eq!(after_reapply["editor.fontSize"], 14);
    let ignored = ignored_settings(&after_reapply);
    assert_eq!(
        ignored
            .iter()
            .filter(|entry| *entry == &"some.other.userSetting".to_owned())
            .count(),
        1
    );
    assert_eq!(
        ignored
            .iter()
            .filter(|entry| *entry == &OVERRIDE_KEY.to_owned())
            .count(),
        1
    );

    // Re-pairing (new listen address and pairing value, e.g. FRESH=1
    // re-enrollment): the URL changes, everything else is unchanged.
    let new_listen: SocketAddr = "127.0.0.1:18099".parse().unwrap();
    apply_managed(&path, new_listen, "PAIRING-NEW", &config, &gateway);
    let after_repair = read(&path);
    assert_eq!(after_repair["editor.fontSize"], 14);
    assert_eq!(
        after_repair[OVERRIDE_KEY],
        override_url(new_listen, "PAIRING-NEW")
    );
    let ignored = ignored_settings(&after_repair);
    assert!(ignored.contains(&"some.other.userSetting".to_owned()));
}

// --- Removal: one test per trigger, each keeping the user's keys -----

#[test]
fn removal_program_absent_keeps_user_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    write_user_settings(&path, &json!({"editor.fontSize": 14}));
    let config = github_models_config();
    let gateway = gateway_with_proxy();
    apply_managed(&path, listen_addr(), PAIRING, &config, &gateway);

    // `programs.vscode` removed entirely.
    apply_removal(&path, Some((listen_addr(), PAIRING)), None)
        .apply()
        .unwrap();

    let after = read(&path);
    assert_eq!(after["editor.fontSize"], 14);
    assert!(after.get(OVERRIDE_KEY).is_none(), "{after}");
}

#[test]
fn removal_own_models_keeps_user_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    write_user_settings(&path, &json!({"editor.fontSize": 14}));
    let github_models = github_models_config();
    let gateway = gateway_with_proxy();
    apply_managed(&path, listen_addr(), PAIRING, &github_models, &gateway);

    // `copilotChat` switched back to `ownModels`: settings.json has nothing
    // of this variant's to keep, even though the program is still configured
    // and the gateway is still on.
    let own_models = own_models_config();
    apply_removal(
        &path,
        Some((listen_addr(), PAIRING)),
        Some((&own_models, Some(&gateway))),
    )
    .apply()
    .unwrap();

    let after = read(&path);
    assert_eq!(after["editor.fontSize"], 14);
    assert!(after.get(OVERRIDE_KEY).is_none(), "{after}");
}

#[test]
fn removal_use_llm_gateway_false_keeps_user_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    write_user_settings(&path, &json!({"editor.fontSize": 14}));
    let config = github_models_config();
    let gateway = gateway_with_proxy();
    apply_managed(&path, listen_addr(), PAIRING, &config, &gateway);

    // `useLlmGateway: false`: the caller passes the program's config with the
    // gateway filtered to `None`.
    apply_removal(&path, Some((listen_addr(), PAIRING)), Some((&config, None)))
        .apply()
        .unwrap();

    let after = read(&path);
    assert_eq!(after["editor.fontSize"], 14);
    assert!(after.get(OVERRIDE_KEY).is_none(), "{after}");
}

#[test]
fn removal_no_top_level_gateway_keeps_user_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    write_user_settings(&path, &json!({"editor.fontSize": 14}));
    let config = github_models_config();
    let gateway = gateway_with_proxy();
    apply_managed(&path, listen_addr(), PAIRING, &config, &gateway);

    // No top-level `llmGateway` at all: same call shape as `useLlmGateway:
    // false` (the caller filters either way), a distinct real-world trigger.
    apply_removal(&path, Some((listen_addr(), PAIRING)), Some((&config, None)))
        .apply()
        .unwrap();

    let after = read(&path);
    assert_eq!(after["editor.fontSize"], 14);
    assert!(after.get(OVERRIDE_KEY).is_none(), "{after}");
}

#[test]
fn removal_no_proxy_url_keeps_user_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    write_user_settings(&path, &json!({"editor.fontSize": 14}));
    let config = github_models_config();
    let gateway = gateway_with_proxy();
    apply_managed(&path, listen_addr(), PAIRING, &config, &gateway);

    // `llmGateway.proxyUrl` unset: the gateway is still configured and used,
    // but this route has nowhere to forward to.
    let gateway_without_proxy = gateway_without_proxy_url();
    apply_removal(
        &path,
        Some((listen_addr(), PAIRING)),
        Some((&config, Some(&gateway_without_proxy))),
    )
    .apply()
    .unwrap();

    let after = read(&path);
    assert_eq!(after["editor.fontSize"], 14);
    assert!(after.get(OVERRIDE_KEY).is_none(), "{after}");
}

#[test]
fn removal_no_proxy_available_keeps_user_keys_with_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    write_user_settings(&path, &json!({"editor.fontSize": 14}));
    let config = github_models_config();
    let gateway = gateway_with_proxy();
    apply_managed(&path, listen_addr(), PAIRING, &config, &gateway);

    // `ctx.llm_proxy` is `None` (bind failed, proxy off) even though the
    // program is still configured with a usable gateway.
    apply_removal(&path, None, Some((&config, Some(&gateway))))
        .apply()
        .unwrap();

    let after = read(&path);
    assert_eq!(after["editor.fontSize"], 14);
    assert!(after.get(OVERRIDE_KEY).is_none(), "{after}");
}

#[test]
fn removal_of_a_created_and_emptied_file_deletes_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let config = github_models_config();
    let gateway = gateway_with_proxy();
    apply_managed(&path, listen_addr(), PAIRING, &config, &gateway);
    assert!(path.exists());

    // Emptied by hand afterwards: a file the merge created is removed whole,
    // not left as an empty object.
    fs::write(&path, "").unwrap();
    apply_removal(&path, Some((listen_addr(), PAIRING)), None)
        .apply()
        .unwrap();

    assert!(
        !path.exists(),
        "a settings.json we created and the user then emptied must be removed"
    );
    assert!(!super::super::json_merge::state_path(&path).exists());
}

// --- File mode ---------------------------------------------------------

#[cfg(unix)]
#[test]
fn mode_0644_becomes_0600_on_merge_and_removal_keeps_the_mode_it_finds() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    write_user_settings(&path, &json!({"editor.fontSize": 14}));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    let config = github_models_config();
    let gateway = gateway_with_proxy();
    apply_managed(&path, listen_addr(), PAIRING, &config, &gateway);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600,
        "an existing 0644 settings.json must be tightened on merge"
    );

    // The user (or another tool) sets an unusual mode after the merge;
    // removal must not loosen or tighten it further.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    apply_removal(&path, Some((listen_addr(), PAIRING)), None)
        .apply()
        .unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640,
        "removal must keep the mode it finds, not the merge's own 0600"
    );
}

// --- Redaction ---------------------------------------------------------

#[test]
fn redaction_keeps_the_pairing_out_of_render() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    let config = github_models_config();
    let gateway = gateway_with_proxy();

    let changes = ReconcilePlan::default();
    plan(
        &path,
        Some((listen_addr(), PAIRING)),
        Some((&config, Some(&gateway))),
        &changes,
    )
    .unwrap();
    assert!(
        !changes.render().contains(PAIRING),
        "the plan report must not leak the pairing value: {}",
        changes.render()
    );
}

// --- Pre-existing user override (json_merge rollback) -----------------

#[test]
fn preexisting_user_override_capi_url_is_overwritten_and_restored() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.json");
    write_user_settings(
        &path,
        &json!({ OVERRIDE_KEY: "http://someone-else.example:9999/other" }),
    );
    let config = github_models_config();
    let gateway = gateway_with_proxy();

    apply_managed(&path, listen_addr(), PAIRING, &config, &gateway);
    let after_merge = read(&path);
    assert_eq!(
        after_merge[OVERRIDE_KEY],
        override_url(listen_addr(), PAIRING)
    );

    apply_removal(&path, Some((listen_addr(), PAIRING)), None)
        .apply()
        .unwrap();
    let after_removal = read(&path);
    assert_eq!(
        after_removal[OVERRIDE_KEY], "http://someone-else.example:9999/other",
        "the user's own overrideCapiUrl, set before agentdesktop ever wrote the file, must be restored"
    );
}

// --- Comment / trailing comma conflicts -------------------------------

#[test]
fn comment_and_trailing_comma_conflicts() {
    let config = github_models_config();
    let gateway = gateway_with_proxy();
    for (name, contents) in [
        (
            "comment",
            "{\n  // a user comment\n  \"editor.fontSize\": 14\n}\n",
        ),
        ("trailing comma", "{\n  \"editor.fontSize\": 14,\n}\n"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, contents).unwrap();
        let before = fs::read(&path).unwrap();

        let changes = ReconcilePlan::default();
        plan(
            &path,
            Some((listen_addr(), PAIRING)),
            Some((&config, Some(&gateway))),
            &changes,
        )
        .unwrap();
        assert!(changes.has_conflicts(), "{name}: {}", changes.render());
        assert!(changes.apply().is_err(), "{name}");
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "{name}: a conflict must write nothing"
        );
    }
}

// --- settings_path per OS ----------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn settings_path_on_linux() {
    assert_eq!(
        settings_path(std::path::Path::new("/home/user")),
        PathBuf::from("/home/user/.config/Code/User/settings.json")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn settings_path_on_macos() {
    assert_eq!(
        settings_path(std::path::Path::new("/Users/user")),
        PathBuf::from("/Users/user/Library/Application Support/Code/User/settings.json")
    );
}

#[cfg(windows)]
#[test]
fn settings_path_on_windows() {
    assert_eq!(
        settings_path(std::path::Path::new(r"C:\Users\user")),
        PathBuf::from(r"C:\Users\user").join("AppData/Roaming/Code/User/settings.json")
    );
}

// --- managed_settings shape -------------------------------------------

#[test]
fn managed_settings_carries_both_keys() {
    let document = managed_settings(listen_addr(), PAIRING);
    assert_eq!(document[OVERRIDE_KEY], override_url(listen_addr(), PAIRING));
    let ignored = ignored_settings(&document);
    assert_eq!(ignored.len(), 2, "{document}");
    assert!(ignored.contains(&OVERRIDE_KEY.to_owned()));
    assert!(ignored.contains(&CAPI_ALIAS_KEY.to_owned()));
}

// --- githubModels removes the managed chatLanguageModels.json entry, through
// the existing reconcile::plan. Unlike every test above,
// this one exercises real (non-stub) code and should pass today. -----------

#[test]
fn github_models_removes_the_managed_chat_language_models_entry_through_reconcile_plan() {
    use super::reconcile::{chat_models_path, plan as chat_models_plan};

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let path = chat_models_path(home);
    let mut own_models = own_models_config();
    own_models.copilot_chat = VsCodeCopilotChat::OwnModels;
    let gateway = gateway_with_proxy();

    // The `ownModels` entry exists (a previous revision had it configured).
    let changes = ReconcilePlan::default();
    chat_models_plan(
        &path,
        Some((listen_addr(), PAIRING)),
        Some((&own_models, Some(&gateway))),
        &changes,
    )
    .unwrap();
    changes.apply().unwrap();
    assert!(path.exists());

    // `copilotChat` switches to `githubModels`: the writer calls
    // `reconcile::plan` with `configured = None`, since this file has nothing
    // to manage under that variant. It must plan (and apply) a removal.
    let changes = ReconcilePlan::default();
    chat_models_plan(&path, Some((listen_addr(), PAIRING)), None, &changes).unwrap();
    assert!(!changes.has_conflicts(), "{}", changes.render());
    changes.apply().unwrap();

    assert!(
        !path.exists(),
        "chatLanguageModels.json must be cleaned up once githubModels is active"
    );
}
