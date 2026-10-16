use std::{
    io::Read,
    path::{Path, PathBuf},
};

use agentdesktop_client as client;
use agentdesktop_core::{
    config::DaemonConfig,
    model::{
        Discovery, EnrollmentStatus, Health, LlmGatewayCredential, LlmGatewayLoginStatus,
        SessionCreated, SessionInfo, SessionRequest, TelemetryEventKind,
    },
};
use clap::Subcommand;
use serde::Deserialize;

const MAX_HOOK_INPUT_BYTES: u64 = 1024 * 1024;

#[derive(Subcommand)]
pub enum ClientCommand {
    /// Check whether the daemon is reachable.
    Status,
    /// Print the device's enrollment status and any pending sign-in URL.
    Enrollment,
    /// Discover locally installed agents.
    Discover,
    /// Print the daemon's local startup configuration.
    Config,
    /// Print a short-lived credential for an LLM gateway.
    Credential {
        /// Developer tool requesting the credential.
        #[arg(long, default_value = "agentdesktop")]
        client_id: String,
    },
    /// Sign in to the LLM gateway with OIDC device authorization and print
    /// the verification URL and code to approve from any device.
    Login,
    /// Handle an event emitted by a managed developer-tool hook.
    Hook {
        #[command(subcommand)]
        hook: HookCommand,
    },
    /// Manage the local LLM proxy.
    LlmProxy {
        #[command(subcommand)]
        command: LlmProxyCommand,
    },
}

#[derive(Subcommand)]
pub enum LlmProxyCommand {
    /// Manage sandbox sessions on the proxy.
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
}

#[derive(Subcommand)]
pub enum SessionCommand {
    /// Register a session and print its pairing as JSON.
    Create {
        /// Credential policy client ID the session presents to the gateway.
        #[arg(long)]
        client_id: String,
        /// Human-readable name for the session.
        #[arg(long)]
        label: String,
        /// Seconds without a request after which the session expires.
        #[arg(long)]
        ttl_seconds: Option<u64>,
    },
    /// List registered sessions.
    List,
    /// Revoke a session.
    Revoke {
        /// Session ID from `session create` or `session list`.
        id: String,
    },
}

/// The message printed for a failed `llm-proxy session` command: the daemon's
/// own text for a missing session, a hint at the bound, else the status and
/// body as the client reports them.
fn session_error_message(error: &anyhow::Error) -> String {
    match error.downcast_ref::<agentdesktop_client::StatusError>() {
        Some(status) if status.status == 404 && !status.body.is_empty() => status.body.clone(),
        Some(status) if status.status == 404 => {
            "this daemon has no session API (upgrade agentdesktop)".to_owned()
        }
        Some(status) if status.status == 429 => format!(
            "too many sessions ({}); revoke unused ones",
            crate::llm_proxy::sessions::MAX_SESSIONS
        ),
        Some(status) => status.to_string(),
        None => format!("{error:#}"),
    }
}

const SESSIONS_PATH: &str = "/v1/llm-proxy/sessions";

/// A session id as the daemon mints it: 16 lowercase hexadecimal characters.
fn valid_session_id(id: &str) -> bool {
    id.len() == 16
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

async fn run_session_command(command: SessionCommand, socket: &Path) -> anyhow::Result<()> {
    match command {
        SessionCommand::Create {
            client_id,
            label,
            ttl_seconds,
        } => {
            // The only place the pairing is shown: the caller passes it into
            // the sandboxed program's environment.
            let created: SessionCreated = client::post_json_response(
                socket,
                SESSIONS_PATH,
                &SessionRequest {
                    client_id,
                    label,
                    ttl_seconds,
                },
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&created)?);
        }
        SessionCommand::List => {
            let sessions: Vec<SessionInfo> = client::get(socket, SESSIONS_PATH).await?;
            for session in sessions {
                println!(
                    "{}\t{}\t{}\t{}",
                    session.id, session.client_id, session.label, session.expires_at_unix_seconds
                );
            }
        }
        SessionCommand::Revoke { id } => {
            if !valid_session_id(&id) {
                anyhow::bail!("session id must be 16 lowercase hexadecimal characters");
            }
            client::delete(socket, &format!("{SESSIONS_PATH}/{id}")).await?;
        }
    }
    Ok(())
}

#[derive(Subcommand)]
pub enum HookCommand {
    /// Report a Claude Code SessionStart event as telemetry.
    ClaudeSessionStart,
    /// Report a Claude Code PreToolUse event as telemetry.
    ClaudePreToolUse {
        /// Include tool input in the event.
        #[arg(long)]
        include_input: bool,
    },
}

#[derive(Deserialize)]
struct ClaudePreToolUseInput {
    hook_event_name: Option<String>,
    tool_name: String,
    tool_use_id: Option<String>,
    tool_input: serde_json::Value,
}

#[derive(Deserialize)]
struct ClaudeSessionStartInput {
    hook_event_name: Option<String>,
    session_id: String,
}

pub async fn run(command: ClientCommand, socket: PathBuf) -> anyhow::Result<()> {
    match command {
        ClientCommand::Status => {
            let health: Health = client::get(&socket, "/v1/health").await?;
            println!("{}", health.status);
        }
        ClientCommand::Enrollment => {
            let enrollment: EnrollmentStatus = client::get(&socket, "/v1/enrollment").await?;
            println!("{}", enrollment.status);
            if let Some(url) = enrollment.authorization_url {
                println!("Sign in at: {url}");
            }
            if let Some(code) = enrollment.user_code {
                println!("Code: {code}");
            }
        }
        ClientCommand::Login => {
            let login: LlmGatewayLoginStatus =
                client::post(&socket, "/v1/llm-gateway/login").await?;
            println!("{}", login.status);
            if let Some(url) = login.verification_url {
                println!("Sign in at: {url}");
            }
            if let Some(code) = login.user_code {
                println!("Code: {code}");
            }
        }
        ClientCommand::Discover => {
            let discovery: Discovery = client::get(&socket, "/v1/discovery").await?;
            if discovery.agents.is_empty() && discovery.model_runtimes.is_empty() {
                println!("No agents or models discovered");
            }
            for agent in discovery.agents {
                let version = agent.version.as_deref().unwrap_or("unknown version");
                println!(
                    "{}\t{}\t{}",
                    agent.kind,
                    version,
                    agent.executable.display()
                );
            }
            for runtime in discovery.model_runtimes {
                for model in runtime.models {
                    println!("{}\tmodel\t{}", runtime.kind, model.name);
                }
            }
        }
        ClientCommand::Config => {
            let config: DaemonConfig = client::get(&socket, "/v1/config").await?;
            print!(
                "{}",
                agentdesktop_core::serdes::yamlviajson::to_string(&config)?
            );
        }
        ClientCommand::Credential { client_id } => {
            let client_id: String =
                url::form_urlencoded::byte_serialize(client_id.as_bytes()).collect();
            let response: LlmGatewayCredential = client::get(
                &socket,
                &format!("/v1/llm-gateway/credential?client_id={client_id}"),
            )
            .await?;
            println!("{}", response.credential);
        }
        ClientCommand::LlmProxy {
            command: LlmProxyCommand::Session { command },
        } => run_session_command(command, &socket)
            .await
            .map_err(|error| anyhow::anyhow!(session_error_message(&error)))?,
        ClientCommand::Hook {
            hook: HookCommand::ClaudePreToolUse { include_input },
        } => {
            // Telemetry is deliberately fail-open: an unavailable daemon must
            // never prevent Claude Code from using a tool.
            let _ = report_claude_pre_tool_use(&socket, include_input).await;
        }
        ClientCommand::Hook {
            hook: HookCommand::ClaudeSessionStart,
        } => {
            // Telemetry is deliberately fail-open: an unavailable daemon must
            // never prevent Claude Code from starting a session.
            let _ = report_claude_session_start(&socket).await;
        }
    }

    Ok(())
}

async fn report_claude_pre_tool_use(
    socket: &std::path::Path,
    include_input: bool,
) -> anyhow::Result<()> {
    let input = read_hook_input()?;
    let event = parse_claude_pre_tool_use(&input, include_input)?;
    client::post_json(socket, "/v1/telemetry", &event).await
}

async fn report_claude_session_start(socket: &std::path::Path) -> anyhow::Result<()> {
    let input = read_hook_input()?;
    let input: ClaudeSessionStartInput = serde_json::from_slice(&input)?;
    if input
        .hook_event_name
        .as_deref()
        .is_some_and(|name| name != "SessionStart")
    {
        anyhow::bail!("expected a Claude Code SessionStart event");
    }
    if input.session_id.trim().is_empty() {
        anyhow::bail!("Claude hook event has no session ID");
    }
    client::post_json(
        socket,
        "/v1/telemetry",
        &TelemetryEventKind::SessionNew {
            client_id: claude_client_id(),
            session_id: input.session_id,
        },
    )
    .await
}

fn read_hook_input() -> anyhow::Result<Vec<u8>> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(MAX_HOOK_INPUT_BYTES + 1)
        .read_to_end(&mut input)?;
    if input.len() as u64 > MAX_HOOK_INPUT_BYTES {
        anyhow::bail!("Claude hook input exceeds {MAX_HOOK_INPUT_BYTES} bytes");
    }
    Ok(input)
}

fn parse_claude_pre_tool_use(
    input: &[u8],
    include_input: bool,
) -> anyhow::Result<TelemetryEventKind> {
    let input: ClaudePreToolUseInput = serde_json::from_slice(input)?;
    if input
        .hook_event_name
        .as_deref()
        .is_some_and(|name| name != "PreToolUse")
    {
        anyhow::bail!("expected a Claude Code PreToolUse event");
    }
    if input.tool_name.trim().is_empty() {
        anyhow::bail!("Claude hook event has no tool name");
    }

    Ok(TelemetryEventKind::ToolUse {
        client_id: claude_client_id(),
        tool_name: input.tool_name,
        tool_use_id: input.tool_use_id.filter(|id| !id.is_empty()),
        tool_input: include_input.then_some(input.tool_input),
    })
}

fn claude_client_id() -> String {
    claude_client_id_for_entrypoint(std::env::var("CLAUDE_CODE_ENTRYPOINT").ok().as_deref())
        .to_owned()
}

fn claude_client_id_for_entrypoint(entrypoint: Option<&str>) -> &'static str {
    match entrypoint {
        Some("claude-desktop" | "claude-desktop-3p") => "claude-desktop",
        _ => "claude-code",
    }
}

#[cfg(test)]
mod tests {
    use agentdesktop_core::model::TelemetryEventKind;
    use clap::Parser;

    use super::{
        ClientCommand, LlmProxyCommand, SessionCommand, parse_claude_pre_tool_use,
        session_error_message,
    };

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: ClientCommand,
    }

    fn session_command(args: &[&str]) -> Result<SessionCommand, clap::Error> {
        let mut argv = vec!["agentdesktop", "llm-proxy", "session"];
        argv.extend_from_slice(args);
        match TestCli::try_parse_from(argv)?.command {
            ClientCommand::LlmProxy {
                command: LlmProxyCommand::Session { command },
            } => Ok(command),
            _ => panic!("expected an llm-proxy session command"),
        }
    }

    #[test]
    fn parses_session_create_with_and_without_a_ttl() {
        let SessionCommand::Create {
            client_id,
            label,
            ttl_seconds,
        } = session_command(&[
            "create",
            "--client-id",
            "claude-code",
            "--label",
            "lab session",
            "--ttl-seconds",
            "120",
        ])
        .unwrap()
        else {
            panic!("expected create");
        };
        assert_eq!(client_id, "claude-code");
        assert_eq!(label, "lab session");
        assert_eq!(ttl_seconds, Some(120));

        let SessionCommand::Create { ttl_seconds, .. } =
            session_command(&["create", "--client-id", "my_tool", "--label", "x"]).unwrap()
        else {
            panic!("expected create");
        };
        assert_eq!(ttl_seconds, None);
    }

    #[test]
    fn session_create_requires_a_client_id_a_label_and_a_numeric_ttl() {
        assert!(session_command(&["create", "--label", "x"]).is_err());
        assert!(session_command(&["create", "--client-id", "claude-code"]).is_err());
        assert!(
            session_command(&[
                "create",
                "--client-id",
                "claude-code",
                "--label",
                "x",
                "--ttl-seconds",
                "soon",
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_session_list_and_revoke() {
        assert!(matches!(
            session_command(&["list"]).unwrap(),
            SessionCommand::List
        ));
        let SessionCommand::Revoke { id } =
            session_command(&["revoke", "0123456789abcdef"]).unwrap()
        else {
            panic!("expected revoke");
        };
        assert_eq!(id, "0123456789abcdef");
        assert!(session_command(&["revoke"]).is_err());
        assert!(session_command(&[]).is_err());
        assert!(session_command(&["show"]).is_err());
    }

    fn status_error(status: u16, body: &str) -> anyhow::Error {
        anyhow::Error::new(agentdesktop_client::StatusError {
            status,
            body: body.to_owned(),
        })
    }

    #[test]
    fn session_error_message_names_the_session_for_404() {
        assert_eq!(
            session_error_message(&status_error(404, "no session 0123456789abcdef")),
            "no session 0123456789abcdef"
        );
    }

    #[test]
    fn session_error_message_explains_429() {
        assert_eq!(
            session_error_message(&status_error(
                429,
                "too many sessions (64); revoke unused ones"
            )),
            "too many sessions (64); revoke unused ones"
        );
        // The message is the CLI's own, whatever body the daemon sent.
        assert_eq!(
            session_error_message(&status_error(429, "")),
            "too many sessions (64); revoke unused ones"
        );
    }

    #[test]
    fn session_error_message_reports_other_statuses_with_reason_and_body() {
        assert_eq!(
            session_error_message(&status_error(409, "the local LLM proxy is not running")),
            "daemon returned 409 Conflict: the local LLM proxy is not running"
        );
        assert_eq!(
            session_error_message(&status_error(500, "boom")),
            "daemon returned 500 Internal Server Error: boom"
        );
    }

    #[test]
    fn parses_claude_pre_tool_use_input_without_unrelated_fields() {
        let event = parse_claude_pre_tool_use(
            br#"{
                "session_id": "session-secret",
                "transcript_path": "/tmp/transcript.jsonl",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": "tool-1",
                "tool_input": {"command": "cargo test"}
            }"#,
            true,
        )
        .expect("valid Claude hook input");

        let serialized = serde_json::to_string(&event).expect("serialize telemetry");
        let TelemetryEventKind::ToolUse {
            client_id,
            tool_name,
            tool_use_id,
            tool_input,
        } = &event
        else {
            panic!("expected tool-use telemetry");
        };
        assert_eq!(client_id, "claude-code");
        assert_eq!(tool_name, "Bash");
        assert_eq!(tool_use_id.as_deref(), Some("tool-1"));
        assert_eq!(tool_input.as_ref().unwrap()["command"], "cargo test");
        assert!(!serialized.contains("session-secret"));
        assert!(!serialized.contains("transcript"));
    }
}

#[cfg(test)]
mod session_cli_tests {
    use super::{session_error_message, valid_session_id};

    #[test]
    fn a_session_id_is_sixteen_lowercase_hex_characters() {
        assert!(valid_session_id("0123456789abcdef"));
        for bad in [
            "0123456789ABCDEF",
            "0123456789abcde",
            "0123456789abcdef0",
            "a?b",
            "",
            "a b",
        ] {
            assert!(!valid_session_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn an_empty_404_means_an_older_daemon_without_the_session_api() {
        let error = anyhow::Error::new(agentdesktop_client::StatusError {
            status: 404,
            body: String::new(),
        });
        assert_eq!(
            session_error_message(&error),
            "this daemon has no session API (upgrade agentdesktop)"
        );
    }
}
