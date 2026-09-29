# Provider support

Features currently implemented by Agentdesktop.

GitHub Copilot CLI managed configuration requires user mode (the file is
the user's `providers.json`, pointed at the daemon's loopback LLM proxy; its
MCP and skills inventory under `~/.copilot` is read by the VS Code adapter).
Grok Build managed configuration requires system mode. Linux and macOS use
`/etc/grok/managed_config.toml`; Windows uses the system drive's
`\etc\grok\managed_config.toml`. `--user` rejects `programs.grok` because
Grok's own configuration sync can delete or replace the user-level managed
file.

✅ Implemented · ◯ Not implemented · — Not applicable

| Feature | [Claude Code](claude_code/) | [Claude Desktop](claude_desktop/) | [Codex](codex/) | [OpenCode](opencode/) | [VS Code](vscode/) | [Ollama](ollama/) | [Cursor](cursor/) | [Grok Build](grok/) | [GitHub Copilot CLI](copilot/) |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Installation and version discovery | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ |
| Local model discovery | — | — | — | — | — | ✅ | — | — | — |
| MCP server discovery | ✅ | ✅ | ✅ | ◯ | ✅ | — | ✅ | ✅ | — |
| Skill discovery | ✅ | ◯ | ✅ | ◯ | ✅ | — | ✅ | ✅ | — |
| Managed configuration | ✅ | ✅ | ✅ | ✅ | ◯ | ◯ | ◯ | ✅ | ✅ |
| LLM gateway routing | ✅ | ✅ | ✅ | ✅ | ◯ | — | ◯ | ✅ | ✅ |
| Gateway credentials | ✅ | ✅ | ✅ | ✅ | ◯ | — | ◯ | ✅ | ✅ |
| Sandbox configuration | ✅ | ◯ | ✅ | ◯ | ◯ | — | ◯ | ◯ | ◯ |
| Tool-use telemetry | ✅ | ◯ | ◯ | ◯ | ◯ | — | ◯ | ◯ | ◯ |
| Session-start telemetry | ✅ | ◯ | ◯ | ◯ | ◯ | — | ◯ | ◯ | ◯ |

- ◯ describes a gap in Agentdesktop; it does not mean the upstream provider
  cannot support the feature.
- Managed configuration includes dry runs and removal of Agentdesktop-owned
  settings (no dry run for the GitHub Copilot CLI providers file: its loopback
  proxy cannot run in one-shot mode). Claude Code also supports merging into user settings; Claude Desktop
  requires system-managed settings.
- Discovery is best effort; versions may be unavailable. Ollama discovers models
  through its running local API. Grok Build versions require its optional
  `version.json` update cache; fresh installs may have no discovered version.

See [provider integration tests](../../tests/README.md) for the Docker suite.
