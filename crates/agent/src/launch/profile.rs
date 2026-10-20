//! Profile data: lists and constants for the Claude Code profile.

/// The Claude Code profile.
pub(crate) struct ClaudeCodeProfile {
    /// Base environment variable names to copy from the host.
    pub base_env_keys: &'static [&'static str],
    /// Fixed environment variable key-value pairs.
    pub fixed_env: &'static [(&'static str, &'static str)],
    /// Runtime readonly paths (home-relative segments).
    pub runtime_readonly: &'static [&'static str],
    /// Home executable config paths.
    pub home_executable_config: &'static [&'static str],
    /// Workspace executable config paths.
    pub workspace_executable_config: &'static [&'static str],
    /// Workspace .claude entries.
    pub workspace_claude_entries: &'static [&'static str],
    /// Git executable config paths.
    pub git_executable_config: &'static [&'static str],
    /// Denied secrets (home-relative segments).
    pub denied_secrets: &'static [&'static str],
    /// Window title.
    pub window_title: &'static str,
}

pub(crate) const CLAUDE_CODE: ClaudeCodeProfile = ClaudeCodeProfile {
    base_env_keys: &[],
    fixed_env: &[],
    runtime_readonly: &[],
    home_executable_config: &[],
    workspace_executable_config: &[],
    workspace_claude_entries: &[],
    git_executable_config: &[],
    denied_secrets: &[],
    window_title: "agentdesktop: claude",
};
