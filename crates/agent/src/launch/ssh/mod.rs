//! SSH agent proxy for git over ssh in containment.

use std::collections::BTreeSet;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use anyhow::Result;

use crate::llm_proxy::sessions::SessionRegistry;

pub mod pipe;

/// Maximum agent message size (framing length): 256 KiB.
pub const MAX_AGENT_MESSAGE: usize = 256 * 1024;

/// Maximum concurrent pipe connections per launch.
pub const MAX_AGENT_CONNECTIONS: usize = 8;

/// Maximum concurrent connections per TCP leg.
pub const MAX_LEG_CONNECTIONS: usize = 8;

/// SSH agent protocol message types.
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Refused operation codes (add/remove, smartcard, lock/unlock, extensions).
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub const SSH_AGENTC_ADD_SMARTCARD_KEY: u8 = 20;
pub const SSH_AGENTC_REMOVE_SMARTCARD_KEY: u8 = 21;
pub const SSH_AGENTC_LOCK: u8 = 22;
pub const SSH_AGENTC_UNLOCK: u8 = 23;
pub const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
pub const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
pub const SSH_AGENTC_EXTENSION: u8 = 27;

/// Key filtering policy for the ssh-agent proxy.
#[derive(Debug, Clone)]
pub(crate) struct AgentPolicy {
    /// Allowed key fingerprints. None = all keys ("*"), Some(empty) = deny-by-default, Some(set) = filter to set.
    allowed_keys: Option<BTreeSet<String>>,
}

impl AgentPolicy {
    /// Create a policy from the config keys list.
    /// Empty keys → Some(∅) (deny all), ["*"] → None (all keys), otherwise Some(set).
    pub(crate) fn from_config_keys(keys: &[String]) -> Self {
        if keys.iter().any(|k| k == "*") {
            AgentPolicy {
                allowed_keys: None,
            }
        } else if keys.is_empty() {
            AgentPolicy {
                allowed_keys: Some(BTreeSet::new()),
            }
        } else {
            AgentPolicy {
                allowed_keys: Some(keys.iter().cloned().collect()),
            }
        }
    }

    fn allows_key(&self, fingerprint: &str) -> bool {
        match &self.allowed_keys {
            None => true, // All keys allowed
            Some(set) => set.contains(fingerprint),
        }
    }
}

/// Upstream ssh-agent connection.
#[async_trait]
pub(crate) trait AgentUpstream: Send + Sync {
    async fn round_trip(&self, request: &[u8]) -> Result<Vec<u8>>;
}

/// Broker a single agent connection between the box and the upstream agent.
pub(crate) async fn broker_connection<C>(
    _client: C,
    _upstream: &dyn AgentUpstream,
    _policy: &AgentPolicy,
    _sessions: &SessionRegistry,
    _session_id: &str,
    _launch_id: &str,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    todo!("PR 5: broker_connection implementation");
}

/// Compute SHA256 fingerprint of an ssh key blob.
pub(crate) fn key_fingerprint(_blob: &[u8]) -> String {
    todo!("PR 5: key_fingerprint implementation");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_policy_from_config_empty_keys_denies_all() {
        let policy = AgentPolicy::from_config_keys(&[]);
        assert!(!policy.allows_key("SHA256:abcd1234"));
        assert!(!policy.allows_key("SHA256:xyz789"));
    }

    #[test]
    fn agent_policy_from_config_wildcard_allows_all() {
        let policy = AgentPolicy::from_config_keys(&["*".to_owned()]);
        assert!(policy.allows_key("SHA256:abcd1234"));
        assert!(policy.allows_key("SHA256:xyz789"));
    }

    #[test]
    fn agent_policy_from_config_specific_keys_filters() {
        let policy = AgentPolicy::from_config_keys(&["SHA256:allowed1".to_owned(), "SHA256:allowed2".to_owned()]);
        assert!(policy.allows_key("SHA256:allowed1"));
        assert!(policy.allows_key("SHA256:allowed2"));
        assert!(!policy.allows_key("SHA256:denied"));
    }
}

// Additional broker protocol tests

#[cfg(test)]
mod broker_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::duplex;
    use tokio::time::{timeout, Duration};

    #[derive(Clone)]
    struct TestUpstream {
        calls: Arc<Mutex<usize>>,
    }

    impl TestUpstream {
        fn new() -> Self {
            TestUpstream {
                calls: Arc::new(Mutex::new(0)),
            }
        }

        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    #[async_trait]
    impl AgentUpstream for TestUpstream {
        async fn round_trip(&self, _request: &[u8]) -> Result<Vec<u8>> {
            *self.calls.lock().unwrap() += 1;
            Ok(vec![0, 0, 0, 1, SSH_AGENT_FAILURE])
        }
    }

    fn encode_msg(typ: u8, payload: &[u8]) -> Vec<u8> {
        let len = (1 + payload.len()) as u32;
        let mut msg = Vec::new();
        msg.extend_from_slice(&len.to_be_bytes());
        msg.push(typ);
        msg.extend_from_slice(payload);
        msg
    }

    // Op-code refused tests
    #[tokio::test]
    #[should_panic(expected = "PR 5")]
    async fn broker_refuses_add_identity() {
        let (client, _server) = duplex(1024);
        let upstream = TestUpstream::new();
        let sessions = SessionRegistry::default();
        let session = sessions.authorize("test", 0).unwrap();
        let policy = AgentPolicy::from_config_keys(&[]);
        
        broker_connection(client, &upstream, &policy, &sessions, &session.id, "test").await.ok();
    }

    #[tokio::test]
    #[should_panic(expected = "PR 5")]
    async fn broker_refuses_extension() {
        let (client, _server) = duplex(1024);
        let upstream = TestUpstream::new();
        let sessions = SessionRegistry::default();
        let session = sessions.authorize("test", 0).unwrap();
        let policy = AgentPolicy::from_config_keys(&[]);
        
        broker_connection(client, &upstream, &policy, &sessions, &session.id, "test").await.ok();
    }

    #[test]
    fn key_fingerprint_sha256_prefix() {
        let fp = key_fingerprint(b"test");
        assert!(fp.starts_with("SHA256:"));
    }
}
