//! Named pipe transport for ssh-agent proxy on Windows.

#[cfg(windows)]
pub use windows_impl::*;

#[cfg(not(windows))]
pub use stub_impl::*;

/// Windows OpenSSH agent pipe name.
pub const OPENSSH_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// Agentdesktop ssh-agent pipe name prefix.
pub const AGENT_PIPE_PREFIX: &str = r"\\.\pipe\agentdesktop-ssh-";

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use anyhow::Result;

    /// Create and bind the ssh-agent proxy pipe for a launch.
    pub(crate) async fn create_agent_pipe(
        _launch_id: &str,
        _box_ac_sid: &str,
        _daemon_sid: &str,
    ) -> Result<()> {
        todo!("PR 5: create_agent_pipe Windows implementation");
    }
}

#[cfg(not(windows))]
mod stub_impl {
    use anyhow::{bail, Result};

    pub(crate) async fn create_agent_pipe(
        _launch_id: &str,
        _box_ac_sid: &str,
        _daemon_sid: &str,
    ) -> Result<()> {
        bail!("ssh-agent proxy is only available on Windows")
    }
}
