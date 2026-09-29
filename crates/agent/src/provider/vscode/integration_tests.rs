use std::time::Duration;

use agentdesktop_core::{DEFAULT_SOCKET_PATH, model::Discovery};
use anyhow::{Context, ensure};
use tracing::info;

use crate::common::{Container, Gateway};

const VERSION: &str = "1.136.2";
const USER_MCP: &str = "/home/tester/.config/Code/User/mcp.json";
const PROFILE_MCP: &str = "/home/tester/.config/Code/User/profiles/test/mcp.json";
const WORKSPACE_MCP: &str = "/home/tester/project/.vscode/mcp.json";
const COPILOT_MCP: &str = "/home/tester/.copilot/mcp-config.json";
const USER_SKILL: &str = "/home/tester/.copilot/skills/test/SKILL.md";
const WORKSPACE_SKILL: &str = "/home/tester/project/.github/skills/test/SKILL.md";

#[tokio::test]
async fn headless_discovery() -> anyhow::Result<()> {
    Container::run("vscode", "crates/agent/src/provider/vscode/testdata/Dockerfile", async |container| {
        info!("Checking installed VS Code CLI without a display");
        let installed = container.exec_as("tester", &["code", "--version"], Duration::from_secs(15)).await?;
        ensure!(installed.lines().next() == Some(VERSION), "unexpected VS Code version: {installed}");
        let extensions = container.exec_as("tester", &["code", "--list-extensions"], Duration::from_secs(15)).await?;
        ensure!(extensions.trim().is_empty(), "fresh installation has unexpected extensions: {extensions}");

        let files = [
            (USER_MCP, r#"{
                // User MCP settings support comments and trailing commas.
                "servers": { "user-docs": { "type": "http", "url": "https://example.test/mcp", "headers": { "Authorization": "fixture-secret" } }, },
            }"#),
            (PROFILE_MCP, r#"{"servers":{"profile-events":{"type":"sse","url":"https://example.test/events","disabled":true}}}"#),
            (WORKSPACE_MCP, r#"{"servers":{"workspace-local":{"type":"stdio","command":"fixture-command","args":["fixture-secret"],"env":{"TOKEN":"fixture-secret"}}}}"#),
            (COPILOT_MCP, r#"{"mcpServers":{"copilot-docs":{"type":"streamable-http","url":"https://example.test/copilot"}}}"#),
            (USER_SKILL, "---\nname: user-skill\ndescription: User test skill\n---\nfixture-body-not-metadata\n"),
            (WORKSPACE_SKILL, "---\nname: workspace-skill\ndescription: Workspace test skill\n---\nfixture-body-not-metadata\n"),
        ];
        for (path, contents) in files { container.write(path, contents).await?; }
        container.exec(&["chown", "-R", "tester:tester", "/home/tester"]).await?;
        container.write("/tmp/agentdesktop.yaml", "programs: {}\n").await?;
        container.start_process("daemon", &["agentdesktop", "daemon", "--config", "/tmp/agentdesktop.yaml"]).await?;
        container.wait_ready(&["agentdesktop", "status"]).await?;

        info!("Checking VS Code version, MCP servers, and skills through the daemon");
        let output = container.exec(&["curl", "--fail", "--silent", "--unix-socket", DEFAULT_SOCKET_PATH, "http://localhost/v1/discovery"]).await?;
        let discovery: Discovery = serde_json::from_str(&output)?;
        let agent = discovery.agents.iter().find(|agent| agent.kind == "vscode").context("VS Code was not discovered")?;
        ensure!(agent.version.as_deref() == Some(VERSION), "incorrect discovered version: {:?}", agent.version);
        ensure!(agent.executable.to_string_lossy().ends_with("/code"), "incorrect executable: {:?}", agent.executable);
        ensure!(agent.mcp_servers.len() == 4, "unexpected MCP servers: {:?}", agent.mcp_servers);
        for (name, transport, enabled, source, command, url) in [
            ("user-docs", "http", true, USER_MCP, None, Some("https://example.test/mcp")),
            ("profile-events", "sse", false, PROFILE_MCP, None, Some("https://example.test/events")),
            ("workspace-local", "stdio", true, WORKSPACE_MCP, Some("fixture-command"), None),
            ("copilot-docs", "http", true, COPILOT_MCP, None, Some("https://example.test/copilot")),
        ] {
            let server = agent.mcp_servers.iter().find(|server| server.name == name).with_context(|| format!("missing MCP server {name}"))?;
            ensure!(server.transport == transport && server.enabled == enabled && server.source == std::path::Path::new(source)
                && server.command.as_deref() == command && server.url.as_deref() == url, "incorrect MCP discovery: {server:?}");
        }
        ensure!(agent.skills.len() == 2, "unexpected skills: {:?}", agent.skills);
        for (path, name) in [(USER_SKILL, "user-skill"), (WORKSPACE_SKILL, "workspace-skill")] {
            ensure!(agent.skills.iter().any(|skill| skill.path == std::path::Path::new(path) && skill.front_matter.get("name").and_then(|value| value.as_str()) == Some(name)), "missing skill {name}");
        }
        ensure!(!output.contains("fixture-secret") && !output.contains("fixture-body-not-metadata"), "discovery exposed non-metadata content");
        container.stop_process("daemon").await?;
        for (path, contents) in files {
            ensure!(container.read(path).await? == contents, "discovery changed {path}");
        }
        Ok(())
    }).await
}

const CONFIG: &str = "/tmp/agentdesktop-chat.yaml";
const CHAT_MODELS: &str = "/home/tester/.config/Code/User/chatLanguageModels.json";
const CHAT_SIDECAR: &str = "/home/tester/.config/Code/User/.chatLanguageModels.json.agentdesktop";
const PAIRING: &str = "/home/tester/.local/state/agentdesktop/llm-proxy-pairing";
const SOCKET: &str = "/run/user/1000/agentdesktop.sock";
const LISTEN: &str = "127.0.0.1:18096";

/// The daemon runs as the user (`--user` through `runuser`, since the file
/// lives in the user's VS Code profile), writes `chatLanguageModels.json`
/// pointed at its loopback proxy, a client using the file's `url` and
/// `requestHeaders` reaches the gateway through the proxy, and removing the
/// program leaves the user's own vendor entry at the file's mode.
#[tokio::test]
async fn managed_chat_models_lifecycle() -> anyhow::Result<()> {
    Container::run("vscode", "crates/agent/src/provider/vscode/testdata/Dockerfile", async |container| {
        let gateway = Gateway::start().await?;
        let user_vendor = serde_json::json!([{
            "name": "my-own", "vendor": "customendpoint", "apiKey": "sk-user", "apiType": "chat-completions",
            "models": [{"id": "gpt-mine", "name": "mine", "url": "https://example.invalid/v1/chat/completions"}],
        }]);
        container.write(CHAT_MODELS, &serde_json::to_string_pretty(&user_vendor)?).await?;
        container.exec(&["chown", "-R", "tester:tester", "/home/tester/.config"]).await?;
        // A mode the daemon does not write itself, so "mode kept" can fail.
        container.exec(&["chmod", "640", CHAT_MODELS]).await?;
        let config = |with_program: bool| {
            let mut document = serde_json::json!({
                "daemon": { "user": true, "llmProxy": { "listen": LISTEN } },
                "llmGateway": { "url": gateway.url },
                "programs": {},
            });
            if with_program {
                document["programs"]["vscode"] =
                    serde_json::json!({ "models": { "gpt-4.1-mini": { "maxInputTokens": 128000 } } });
            }
            serde_json::to_string_pretty(&document).unwrap()
        };
        container.write(CONFIG, &config(true)).await?;
        container.exec(&["chown", "tester:tester", CONFIG]).await?;
        let daemon = ["runuser", "-u", "tester", "--", "agentdesktop", "daemon", "--config", CONFIG];
        container.start_process("daemon", &daemon).await?;
        container.wait_ready(&["agentdesktop", "--socket", SOCKET, "status"]).await?;

        info!("Checking the written chat language models file");
        let pairing = container.exec(&["cat", PAIRING]).await?;
        let pairing = pairing.trim().to_owned();
        let written: serde_json::Value = serde_json::from_str(&container.exec(&["cat", CHAT_MODELS]).await?)?;
        let vendors = written.as_array().cloned().context("chatLanguageModels.json is not an array")?;
        ensure!(vendors.iter().any(|vendor| vendor["name"] == "my-own"), "user vendor entry lost: {written}");
        let ours = vendors.iter().find(|vendor| vendor["name"] == "agentdesktop").cloned().context("managed vendor entry missing")?;
        let model = &ours["models"][0];
        ensure!(model["id"] == "gpt-4.1-mini" && model["url"] == format!("http://{LISTEN}/vscode-copilot/v1/chat/completions"), "unexpected model: {ours}");
        ensure!(model["requestHeaders"]["x-agentdesktop-pairing"] == pairing, "pairing header mismatch: {ours}");
        ensure!(ours["apiKey"] == "unused", "no secret may be written as apiKey: {ours}");
        let mode = container.exec(&["stat", "-c", "%a", CHAT_MODELS]).await?;
        ensure!(mode.trim() == "600", "a file the daemon writes is owner-only, got {mode}");
        container.exec(&["test", "-e", CHAT_SIDECAR]).await?;

        info!("Checking that a client using the file reaches the gateway through the proxy");
        let url = model["url"].as_str().context("model url")?.to_owned();
        let status = container.exec_as("tester", &["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-H", &format!("x-agentdesktop-pairing: {pairing}"), "-H", "authorization: Bearer client-token", "-H", "x-api-key: client-key", "-H", "content-type: application/json", "-X", "POST", &url, "-d", "{\"model\":\"gpt-4.1-mini\",\"messages\":[]}"], Duration::from_secs(15)).await?;
        // The stub knows no /v1/chat/completions route and answers 404, which
        // the proxy passes through; what matters is that the request arrived
        // upstream with the client's own Authorization and x-api-key stripped
        // (the curl sends both) and, with no gateway authentication configured
        // here, no Authorization added.
        let requests = gateway.requests();
        let upstream = requests.iter().find(|request| request["path"] == "/v1/chat/completions").with_context(|| format!("no request reached the gateway (client saw {status}): {requests:?}"))?;
        ensure!(upstream["authorization"].is_null() && upstream["apiKey"].is_null(), "client headers must not reach the gateway: {upstream}");

        info!("Removing the program");
        // The daemon wrote the file 600 while managed; the user then set 640
        // by hand, which removal must keep.
        container.exec(&["chmod", "640", CHAT_MODELS]).await?;
        container.write(CONFIG, &config(false)).await?;
        container.stop_process("daemon").await?;
        container.start_process("daemon", &daemon).await?;
        container.wait_ready(&["agentdesktop", "--socket", SOCKET, "status"]).await?;
        let remaining: serde_json::Value = serde_json::from_str(&container.exec(&["cat", CHAT_MODELS]).await?)?;
        let vendors = remaining.as_array().cloned().unwrap_or_default();
        ensure!(vendors.len() == 1 && vendors[0]["name"] == "my-own", "managed entry not removed: {remaining}");
        let mode = container.exec(&["stat", "-c", "%a", CHAT_MODELS]).await?;
        ensure!(mode.trim() == "640", "removal must keep the user's file mode, got {mode}");
        container.exec(&["test", "!", "-e", CHAT_SIDECAR]).await?;
        Ok(())
    })
    .await
}
