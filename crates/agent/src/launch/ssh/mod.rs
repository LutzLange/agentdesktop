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

// Broker protocol tests (spec "Tests first": framing, op-code battery, key
// filter, D4 default, upstream failure, session death, log shape). Every test
// drives `broker_connection` over a tokio duplex against a scripted
// `AgentUpstream` stub; none touches a named pipe.

#[cfg(test)]
mod broker_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::sync::{Arc, Mutex};

    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use tokio::time::{Duration, Instant, timeout};

    const LAUNCH_ID: &str = "00c0ffee00c0ffee";
    /// Upper bound for one whole broker exchange.
    const EXCHANGE_LIMIT: Duration = Duration::from_secs(5);
    /// Revocation closes a connection within one `REVOCATION_POLL` (50 ms);
    /// the rest is slack for a loaded CI runner. A broker that waits for the
    /// upstream reply (2 s in the in-flight test) cannot meet it.
    const REVOKE_LIMIT: Duration = Duration::from_millis(1000);
    const FAILURE_FRAME: [u8; 5] = [0, 0, 0, 1, SSH_AGENT_FAILURE];

    /// A real ed25519 public key blob (generated with `ssh-keygen -t ed25519`,
    /// private half discarded) and the fingerprint `ssh-add -l` printed for it
    /// with the key loaded into an agent.
    const PINNED_KEY_B64: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIKP1Mc1BgIC0217LXJoMqtTVkkpFN2muVsKFZyX8aQxw";
    const PINNED_KEY_FINGERPRINT: &str = "SHA256:H+vC+HiEhnhnYOIN8MIx0q11irGkwU4QHzCmJQoFbSs";
    /// Synthetic ed25519 blobs (`key_a`: key bytes 0x01..=0x20, `key_b`:
    /// 0x21..=0x40) and the fingerprints `ssh-keygen -lf` prints for them.
    const KEY_A_FINGERPRINT: &str = "SHA256:mKqU+0K8OhKmA8bBQi9Rz0Q5l7/g160hIP+rJYSTNj4";
    const KEY_B_FINGERPRINT: &str = "SHA256:yLcHRnrl/YjyiSIWUGY7IPRLbf9VEWEyVnQKRyzhxKw";
    /// Embedded in every sign request's data; must never reach the log.
    const SIGN_PAYLOAD_MARKER: &str = "SIGN-PAYLOAD-MARKER-7f3a";

    // --- wire helpers

    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    fn msg(op: u8, body: &[u8]) -> Vec<u8> {
        let mut payload = vec![op];
        payload.extend_from_slice(body);
        frame(&payload)
    }

    fn ed25519_blob(first: u8) -> Vec<u8> {
        let key: Vec<u8> = (first..first + 32).collect();
        let mut blob = string(b"ssh-ed25519");
        blob.extend(string(&key));
        blob
    }

    fn key_a() -> Vec<u8> {
        ed25519_blob(0x01)
    }

    fn key_b() -> Vec<u8> {
        ed25519_blob(0x21)
    }

    fn request_identities() -> Vec<u8> {
        vec![SSH_AGENTC_REQUEST_IDENTITIES]
    }

    fn identities_answer(keys: &[(&[u8], &str)]) -> Vec<u8> {
        let mut payload = vec![SSH_AGENT_IDENTITIES_ANSWER];
        payload.extend_from_slice(&(keys.len() as u32).to_be_bytes());
        for (blob, comment) in keys {
            payload.extend(string(blob));
            payload.extend(string(comment.as_bytes()));
        }
        payload
    }

    fn both_keys_answer() -> Vec<u8> {
        identities_answer(&[(&key_a(), "allowed@test"), (&key_b(), "filtered@test")])
    }

    fn sign_request(blob: &[u8]) -> Vec<u8> {
        let mut data = b"session-id-and-userauth-request:".to_vec();
        data.extend_from_slice(SIGN_PAYLOAD_MARKER.as_bytes());
        let mut payload = vec![SSH_AGENTC_SIGN_REQUEST];
        payload.extend(string(blob));
        payload.extend(string(&data));
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload
    }

    fn sign_response() -> Vec<u8> {
        let mut signature = string(b"ssh-ed25519");
        signature.extend(string(&[0x5a; 64]));
        let mut payload = vec![SSH_AGENT_SIGN_RESPONSE];
        payload.extend(string(&signature));
        payload
    }

    // --- scripted upstream

    enum Reply {
        Answer(Vec<u8>),
        Fail,
        After(Duration, Vec<u8>),
    }

    /// Scripted `AgentUpstream`: records every request payload and answers
    /// from a queue. The contract leaves open whether `round_trip` carries the
    /// 4-byte length prefix; the stub mirrors whatever the broker sends
    /// (framed request, framed reply; bare payload, bare reply) and records
    /// the bare payload either way.
    #[derive(Clone, Default)]
    struct StubUpstream {
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        replies: Arc<Mutex<VecDeque<Reply>>>,
    }

    impl StubUpstream {
        fn replying(replies: Vec<Reply>) -> Self {
            Self {
                requests: Arc::default(),
                replies: Arc::new(Mutex::new(replies.into())),
            }
        }

        fn calls(&self) -> usize {
            self.requests.lock().unwrap().len()
        }

        fn requests(&self) -> Vec<Vec<u8>> {
            self.requests.lock().unwrap().clone()
        }
    }

    fn split_frame(request: &[u8]) -> (bool, Vec<u8>) {
        if request.len() >= 4 {
            let declared = u32::from_be_bytes([request[0], request[1], request[2], request[3]]);
            if declared as usize == request.len() - 4 {
                return (true, request[4..].to_vec());
            }
        }
        (false, request.to_vec())
    }

    #[async_trait]
    impl AgentUpstream for StubUpstream {
        async fn round_trip(&self, request: &[u8]) -> Result<Vec<u8>> {
            let (framed, payload) = split_frame(request);
            self.requests.lock().unwrap().push(payload);
            let next = self.replies.lock().unwrap().pop_front();
            let reply = match next {
                Some(Reply::Answer(payload)) => payload,
                Some(Reply::After(delay, payload)) => {
                    tokio::time::sleep(delay).await;
                    payload
                }
                Some(Reply::Fail) => anyhow::bail!("stub upstream: agent unreachable"),
                None => anyhow::bail!("stub upstream: no scripted reply"),
            };
            Ok(if framed { frame(&reply) } else { reply })
        }
    }

    // --- fixture and driver

    struct Fixture {
        sessions: SessionRegistry,
        session_id: String,
        upstream: StubUpstream,
        policy: AgentPolicy,
    }

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// A live session, a stub answering `replies` in order, and the policy
    /// config `keys` map to (D4).
    fn fixture(keys: &[&str], replies: Vec<Reply>) -> Fixture {
        let sessions = SessionRegistry::default();
        let session = sessions
            .register(
                "claude-code",
                "ssh broker test",
                Duration::from_secs(3600),
                now_unix(),
            )
            .unwrap_or_else(|error| panic!("register a session: {error:?}"));
        let keys: Vec<String> = keys.iter().map(|key| (*key).to_owned()).collect();
        Fixture {
            sessions,
            session_id: session.id,
            upstream: StubUpstream::replying(replies),
            policy: AgentPolicy::from_config_keys(&keys),
        }
    }

    /// Runs the broker on one end of a duplex and `script` on the other,
    /// concurrently in this task, until both finish.
    async fn run<F, Fut, T>(fx: &Fixture, script: F) -> (Result<()>, T)
    where
        F: FnOnce(DuplexStream) -> Fut,
        Fut: Future<Output = T>,
    {
        let (client, server) = duplex(1 << 20);
        let broker = broker_connection(
            server,
            &fx.upstream,
            &fx.policy,
            &fx.sessions,
            &fx.session_id,
            LAUNCH_ID,
        );
        timeout(EXCHANGE_LIMIT, async { tokio::join!(broker, script(client)) })
            .await
            .expect("broker and client finish within the exchange limit")
    }

    /// One whole frame, length prefix included; `None` on EOF before or
    /// inside it.
    async fn read_frame(client: &mut DuplexStream) -> Option<Vec<u8>> {
        let mut header = [0u8; 4];
        client.read_exact(&mut header).await.ok()?;
        let len = u32::from_be_bytes(header) as usize;
        let mut out = header.to_vec();
        out.resize(4 + len, 0);
        client.read_exact(&mut out[4..]).await.ok()?;
        Some(out)
    }

    /// Sends each request and reads one reply frame for it, then half-closes
    /// and returns whatever else arrives before the broker closes.
    async fn exchange(fx: &Fixture, requests: Vec<Vec<u8>>) -> (Vec<Option<Vec<u8>>>, Vec<u8>) {
        let (_result, out) = run(fx, |mut client| async move {
            let mut replies = Vec::new();
            for request in requests {
                if client.write_all(&request).await.is_err() {
                    replies.push(None);
                    continue;
                }
                replies.push(read_frame(&mut client).await);
            }
            let _ = client.shutdown().await;
            let mut trailing = Vec::new();
            let _ = client.read_to_end(&mut trailing).await;
            (replies, trailing)
        })
        .await;
        out
    }

    // --- log capture (the llm_proxy test idiom)

    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    struct LogWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = LogWriter;

        fn make_writer(&'a self) -> LogWriter {
            LogWriter(self.0.clone())
        }
    }

    impl LogCapture {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }

        /// Lines an operator sees (info and above).
        fn visible_lines(&self) -> Vec<String> {
            self.text()
                .lines()
                .filter(|line| {
                    line.contains(" INFO ") || line.contains(" WARN ") || line.contains(" ERROR ")
                })
                .map(str::to_owned)
                .collect()
        }

        /// The per-request agent lines (AC 8): the ones carrying `op_name`.
        fn agent_lines(&self) -> Vec<String> {
            self.text()
                .lines()
                .filter(|line| line.contains(" op_name="))
                .map(str::to_owned)
                .collect()
        }
    }

    fn capture_logs() -> (LogCapture, tracing::subscriber::DefaultGuard) {
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        (capture, tracing::subscriber::set_default(subscriber))
    }

    /// The value of `key=value` in a formatted event line, without quotes.
    fn log_field(line: &str, key: &str) -> String {
        let marker = format!(" {key}=");
        let start = line
            .find(&marker)
            .unwrap_or_else(|| panic!("no field {key} in {line}"))
            + marker.len();
        line[start..]
            .split(' ')
            .next()
            .unwrap()
            .trim_matches('"')
            .to_owned()
    }

    // --- Framing (Tests-first bullet 1)

    #[tokio::test]
    async fn framing_oversize_length_closes_connection() {
        let (logs, _guard) = capture_logs();
        let fx = fixture(&["*"], vec![Reply::Answer(both_keys_answer())]);
        let (_result, received) = run(&fx, |mut client| async move {
            let header = ((MAX_AGENT_MESSAGE + 1) as u32).to_be_bytes();
            client.write_all(&header).await.expect("write the length");
            // No payload follows and the client never half-closes: only the
            // broker closing ends this read.
            let mut received = Vec::new();
            let _ = client.read_to_end(&mut received).await;
            received
        })
        .await;
        assert!(received.is_empty(), "no reply to an oversize frame: {received:?}");
        assert_eq!(fx.upstream.calls(), 0);
        let visible = logs.visible_lines();
        assert_eq!(visible.len(), 1, "one log line for the close: {visible:?}");
    }

    #[tokio::test]
    async fn framing_zero_length_closes_connection() {
        let (logs, _guard) = capture_logs();
        let fx = fixture(&["*"], vec![Reply::Answer(both_keys_answer())]);
        let (_result, received) = run(&fx, |mut client| async move {
            client.write_all(&[0, 0, 0, 0]).await.expect("write the length");
            let mut received = Vec::new();
            let _ = client.read_to_end(&mut received).await;
            received
        })
        .await;
        assert!(received.is_empty(), "no reply to a zero-length frame: {received:?}");
        assert_eq!(fx.upstream.calls(), 0);
        let visible = logs.visible_lines();
        assert_eq!(visible.len(), 1, "one log line for the close: {visible:?}");
    }

    #[tokio::test]
    async fn framing_truncated_frame_is_eof() {
        let (logs, _guard) = capture_logs();
        let fx = fixture(&["*"], vec![Reply::Answer(both_keys_answer())]);
        let (_result, received) = run(&fx, |mut client| async move {
            // Declares 10 bytes, delivers 3, then EOF.
            client
                .write_all(&[0, 0, 0, 10, SSH_AGENTC_REQUEST_IDENTITIES, 1, 2])
                .await
                .expect("write the partial frame");
            client.shutdown().await.expect("half-close");
            let mut received = Vec::new();
            let _ = client.read_to_end(&mut received).await;
            received
        })
        .await;
        assert!(received.is_empty(), "no reply to a truncated frame: {received:?}");
        assert_eq!(fx.upstream.calls(), 0, "a partial request is never forwarded");
        let visible = logs.visible_lines();
        assert!(visible.is_empty(), "a truncated read closes silently: {visible:?}");
    }

    // --- Op-code battery (Tests-first bullet 2)

    /// `op` is answered `[0,0,0,1,5]` without an upstream call, and the
    /// connection stays usable: a following REQUEST_IDENTITIES is forwarded
    /// (policy `*`, so the key filter plays no part).
    async fn assert_refused_locally(op: u8) {
        let answer = identities_answer(&[(&key_a(), "a@test")]);
        let fx = fixture(&["*"], vec![Reply::Answer(answer.clone())]);
        let (replies, trailing) = exchange(
            &fx,
            vec![msg(op, b"\x00\x00\x00\x04body"), frame(&request_identities())],
        )
        .await;
        assert_eq!(
            replies,
            vec![Some(FAILURE_FRAME.to_vec()), Some(frame(&answer))],
            "op {op} is answered SSH_AGENT_FAILURE locally and the connection stays open"
        );
        assert!(trailing.is_empty(), "nothing else is sent: {trailing:?}");
        assert_eq!(
            fx.upstream.requests(),
            vec![request_identities()],
            "op {op} never reaches the user's agent"
        );
    }

    #[tokio::test]
    async fn policy_add_identity_refused() {
        assert_refused_locally(SSH_AGENTC_ADD_IDENTITY).await;
    }

    #[tokio::test]
    async fn policy_remove_identity_refused() {
        assert_refused_locally(SSH_AGENTC_REMOVE_IDENTITY).await;
    }

    #[tokio::test]
    async fn policy_remove_all_identities_refused() {
        assert_refused_locally(SSH_AGENTC_REMOVE_ALL_IDENTITIES).await;
    }

    #[tokio::test]
    async fn policy_add_smartcard_key_refused() {
        assert_refused_locally(SSH_AGENTC_ADD_SMARTCARD_KEY).await;
    }

    #[tokio::test]
    async fn policy_remove_smartcard_key_refused() {
        assert_refused_locally(SSH_AGENTC_REMOVE_SMARTCARD_KEY).await;
    }

    #[tokio::test]
    async fn policy_lock_refused() {
        assert_refused_locally(SSH_AGENTC_LOCK).await;
    }

    #[tokio::test]
    async fn policy_unlock_refused() {
        assert_refused_locally(SSH_AGENTC_UNLOCK).await;
    }

    #[tokio::test]
    async fn policy_add_id_constrained_refused() {
        assert_refused_locally(SSH_AGENTC_ADD_ID_CONSTRAINED).await;
    }

    #[tokio::test]
    async fn policy_add_smartcard_key_constrained_refused() {
        assert_refused_locally(SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED).await;
    }

    #[tokio::test]
    async fn policy_extension_refused() {
        assert_refused_locally(SSH_AGENTC_EXTENSION).await;
    }

    #[tokio::test]
    async fn policy_unknown_op_0_refused() {
        assert_refused_locally(0).await;
    }

    #[tokio::test]
    async fn policy_unknown_op_99_refused() {
        assert_refused_locally(99).await;
    }

    #[tokio::test]
    async fn policy_request_identities_forwarded() {
        let fx = fixture(&["*"], vec![Reply::Answer(both_keys_answer())]);
        let (replies, trailing) = exchange(&fx, vec![frame(&request_identities())]).await;
        assert_eq!(replies, vec![Some(frame(&both_keys_answer()))]);
        assert!(trailing.is_empty(), "{trailing:?}");
        assert_eq!(fx.upstream.requests(), vec![request_identities()]);
    }

    #[tokio::test]
    async fn policy_sign_request_forwarded() {
        let fx = fixture(&["*"], vec![Reply::Answer(sign_response())]);
        let (replies, trailing) = exchange(&fx, vec![frame(&sign_request(&key_a()))]).await;
        assert_eq!(replies, vec![Some(frame(&sign_response()))]);
        assert!(trailing.is_empty(), "{trailing:?}");
        assert_eq!(fx.upstream.requests(), vec![sign_request(&key_a())]);
    }

    // --- Key filter (Tests-first bullet 3)

    #[test]
    fn key_fingerprint_matches_ssh_add_l() {
        let blob = base64::engine::general_purpose::STANDARD
            .decode(PINNED_KEY_B64)
            .unwrap();
        assert_eq!(key_fingerprint(&blob), PINNED_KEY_FINGERPRINT);
        assert_eq!(key_fingerprint(&key_a()), KEY_A_FINGERPRINT);
        assert_eq!(key_fingerprint(&key_b()), KEY_B_FINGERPRINT);
    }

    #[tokio::test]
    async fn key_filter_identities_answer_re_encodes_to_allowed_only() {
        let fx = fixture(&[KEY_A_FINGERPRINT], vec![Reply::Answer(both_keys_answer())]);
        let (replies, trailing) = exchange(&fx, vec![frame(&request_identities())]).await;
        let expected = frame(&identities_answer(&[(&key_a(), "allowed@test")]));
        assert_eq!(replies, vec![Some(expected.clone())]);
        // The count field (bytes 5..9: after length and type) says 1.
        assert_eq!(&expected[5..9], &[0, 0, 0, 1]);
        assert!(trailing.is_empty(), "{trailing:?}");
    }

    #[tokio::test]
    async fn key_filter_sign_request_for_filtered_key_refused() {
        let fx = fixture(&[KEY_A_FINGERPRINT], vec![Reply::Answer(sign_response())]);
        let (replies, trailing) = exchange(&fx, vec![frame(&sign_request(&key_b()))]).await;
        assert_eq!(replies, vec![Some(FAILURE_FRAME.to_vec())]);
        assert!(trailing.is_empty(), "{trailing:?}");
        assert_eq!(fx.upstream.calls(), 0, "a filtered key's sign request stays local");
    }

    #[tokio::test]
    async fn key_filter_sign_request_for_allowed_key_forwarded() {
        let fx = fixture(&[KEY_A_FINGERPRINT], vec![Reply::Answer(sign_response())]);
        let (replies, trailing) = exchange(&fx, vec![frame(&sign_request(&key_a()))]).await;
        assert_eq!(replies, vec![Some(frame(&sign_response()))]);
        assert!(trailing.is_empty(), "{trailing:?}");
        assert_eq!(fx.upstream.requests(), vec![sign_request(&key_a())]);
    }

    // --- D4 default at the broker (Tests-first bullet 4).
    // (flips if Lutz changes D4)

    /// (flips if Lutz changes D4) `keys` empty: no identity is offered.
    #[tokio::test]
    async fn d4_default_keys_empty_identities_answer_re_encodes_to_zero() {
        let fx = fixture(&[], vec![Reply::Answer(both_keys_answer())]);
        let (replies, trailing) = exchange(&fx, vec![frame(&request_identities())]).await;
        assert_eq!(
            replies,
            vec![Some(vec![0, 0, 0, 5, SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0])]
        );
        assert!(trailing.is_empty(), "{trailing:?}");
    }

    /// (flips if Lutz changes D4) `keys` empty: every sign request is refused
    /// without reaching the user's agent.
    #[tokio::test]
    async fn d4_default_keys_empty_sign_request_refused_locally() {
        let fx = fixture(&[], vec![Reply::Answer(sign_response())]);
        let (replies, trailing) = exchange(&fx, vec![frame(&sign_request(&key_a()))]).await;
        assert_eq!(replies, vec![Some(FAILURE_FRAME.to_vec())]);
        assert!(trailing.is_empty(), "{trailing:?}");
        assert_eq!(fx.upstream.calls(), 0);
    }

    /// (flips if Lutz changes D4) `keys: ["*"]`: both ops pass through
    /// byte-identical.
    #[tokio::test]
    async fn d4_default_keys_wildcard_passes_through_unfiltered() {
        let fx = fixture(
            &["*"],
            vec![
                Reply::Answer(both_keys_answer()),
                Reply::Answer(sign_response()),
            ],
        );
        let (replies, trailing) = exchange(
            &fx,
            vec![frame(&request_identities()), frame(&sign_request(&key_b()))],
        )
        .await;
        assert_eq!(
            replies,
            vec![Some(frame(&both_keys_answer())), Some(frame(&sign_response()))]
        );
        assert!(trailing.is_empty(), "{trailing:?}");
        assert_eq!(
            fx.upstream.requests(),
            vec![request_identities(), sign_request(&key_b())]
        );
    }

    // --- Upstream failure (Tests-first bullet 5)

    #[tokio::test]
    async fn upstream_failure_returns_agent_failure() {
        let (logs, _guard) = capture_logs();
        let fx = fixture(&["*"], vec![Reply::Fail]);
        let (replies, trailing) = exchange(&fx, vec![frame(&request_identities())]).await;
        assert_eq!(replies, vec![Some(FAILURE_FRAME.to_vec())]);
        assert!(trailing.is_empty(), "{trailing:?}");
        assert_eq!(fx.upstream.calls(), 1);
        let lines = logs.agent_lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(log_field(&lines[0], "decision"), "upstream_unreachable", "{}", lines[0]);
    }

    // --- Session death (Tests-first bullet 6)

    #[tokio::test]
    async fn session_revocation_closes_an_idle_connection() {
        let answer = identities_answer(&[(&key_a(), "a@test")]);
        let fx = fixture(&["*"], vec![Reply::Answer(answer.clone())]);
        let fx_ref = &fx;
        let (_result, (first, elapsed, received)) = run(&fx, |mut client| async move {
            // The connection is live and serving before the revoke.
            client
                .write_all(&frame(&request_identities()))
                .await
                .expect("write request");
            let first = read_frame(&mut client).await;
            assert!(fx_ref.sessions.revoke(&fx_ref.session_id));
            let revoked_at = Instant::now();
            let mut received = Vec::new();
            let _ = client.read_to_end(&mut received).await;
            (first, revoked_at.elapsed(), received)
        })
        .await;
        assert_eq!(first, Some(frame(&answer)));
        assert!(received.is_empty(), "no bytes after the revoke: {received:?}");
        assert!(
            elapsed < REVOKE_LIMIT,
            "closed {elapsed:?} after the revoke (poll is 50 ms)"
        );
    }

    #[tokio::test]
    async fn session_revocation_closes_connection() {
        // In-flight: the upstream answers only after 2 s; the revoke lands
        // while the sign request is pending. The client gets EOF, never the
        // late answer.
        let (logs, _guard) = capture_logs();
        let fx = fixture(
            &["*"],
            vec![Reply::After(Duration::from_secs(2), sign_response())],
        );
        let fx_ref = &fx;
        let (_result, (elapsed, received)) = run(&fx, |mut client| async move {
            client
                .write_all(&frame(&sign_request(&key_a())))
                .await
                .expect("write request");
            let deadline = Instant::now() + Duration::from_secs(1);
            while fx_ref.upstream.calls() == 0 && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(fx_ref.upstream.calls(), 1, "the request is in flight upstream");
            assert!(fx_ref.sessions.revoke(&fx_ref.session_id));
            let revoked_at = Instant::now();
            let mut received = Vec::new();
            let _ = client.read_to_end(&mut received).await;
            (revoked_at.elapsed(), received)
        })
        .await;
        assert!(received.is_empty(), "no late reply after the revoke: {received:?}");
        assert!(
            elapsed < REVOKE_LIMIT,
            "closed {elapsed:?} after the revoke (poll is 50 ms)"
        );
        let lines = logs.agent_lines();
        assert_eq!(lines.len(), 1, "one line for the canceled request: {lines:?}");
        assert_eq!(log_field(&lines[0], "outcome"), "canceled", "{}", lines[0]);
    }

    #[tokio::test]
    async fn session_revoked_before_request_answers_nothing_and_never_reaches_upstream() {
        let fx = fixture(&["*"], vec![Reply::Answer(both_keys_answer())]);
        assert!(fx.sessions.revoke(&fx.session_id));
        let (_result, received) = run(&fx, |mut client| async move {
            let _ = client.write_all(&frame(&request_identities())).await;
            let mut received = Vec::new();
            let _ = client.read_to_end(&mut received).await;
            received
        })
        .await;
        assert!(received.is_empty(), "a dead session answers nothing: {received:?}");
        assert_eq!(fx.upstream.calls(), 0);
    }

    // --- Log shape per decision (Tests-first bullet 10)

    fn assert_common_shape(line: &str, session: &str, op: u8) {
        assert_eq!(log_field(line, "session"), session, "{line}");
        assert_eq!(log_field(line, "launch_id"), LAUNCH_ID, "{line}");
        assert_eq!(log_field(line, "op"), op.to_string(), "{line}");
        log_field(line, "duration_ms")
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("duration_ms is an integer: {line}"));
        // Not an HTTP surface: none of the PR 4 emit's HTTP fields.
        for http_field in ["client_id", "method", "path", "status", "code"] {
            assert!(
                !line.contains(&format!(" {http_field}=")),
                "{http_field} must not appear: {line}"
            );
        }
    }

    #[tokio::test]
    async fn log_shape_allow() {
        let (logs, _guard) = capture_logs();
        let fx = fixture(
            &[KEY_A_FINGERPRINT],
            vec![
                Reply::Answer(both_keys_answer()),
                Reply::Answer(sign_response()),
            ],
        );
        exchange(
            &fx,
            vec![frame(&request_identities()), frame(&sign_request(&key_a()))],
        )
        .await;
        let lines = logs.agent_lines();
        assert_eq!(lines.len(), 2, "one line per request: {lines:?}");
        let identities = &lines[0];
        assert_common_shape(identities, &fx.session_id, SSH_AGENTC_REQUEST_IDENTITIES);
        assert_eq!(log_field(identities, "op_name"), "request_identities", "{identities}");
        assert_eq!(log_field(identities, "decision"), "allow", "{identities}");
        assert_eq!(log_field(identities, "key"), "-", "{identities}");
        assert_eq!(log_field(identities, "outcome"), "complete", "{identities}");
        let sign = &lines[1];
        assert_common_shape(sign, &fx.session_id, SSH_AGENTC_SIGN_REQUEST);
        assert_eq!(log_field(sign, "op_name"), "sign_request", "{sign}");
        assert_eq!(log_field(sign, "decision"), "allow", "{sign}");
        assert_eq!(log_field(sign, "key"), KEY_A_FINGERPRINT, "{sign}");
        assert_eq!(log_field(sign, "outcome"), "complete", "{sign}");
        assert!(
            !logs.text().contains(SIGN_PAYLOAD_MARKER),
            "the sign payload never reaches the log"
        );
    }

    #[tokio::test]
    async fn log_shape_refuse() {
        let (logs, _guard) = capture_logs();
        let fx = fixture(&[KEY_A_FINGERPRINT], vec![]);
        exchange(
            &fx,
            vec![
                msg(SSH_AGENTC_ADD_IDENTITY, b"\x00\x00\x00\x04body"),
                frame(&sign_request(&key_b())),
            ],
        )
        .await;
        let lines = logs.agent_lines();
        assert_eq!(lines.len(), 2, "one line per request: {lines:?}");
        let refused_op = &lines[0];
        assert_common_shape(refused_op, &fx.session_id, SSH_AGENTC_ADD_IDENTITY);
        assert_eq!(log_field(refused_op, "op_name"), "refused:17", "{refused_op}");
        assert_eq!(log_field(refused_op, "decision"), "refuse", "{refused_op}");
        assert_eq!(log_field(refused_op, "key"), "-", "{refused_op}");
        assert_eq!(log_field(refused_op, "outcome"), "complete", "{refused_op}");
        // A sign request for a filtered key: refused, and the line names the
        // key that was asked for.
        let filtered = &lines[1];
        assert_common_shape(filtered, &fx.session_id, SSH_AGENTC_SIGN_REQUEST);
        assert_eq!(log_field(filtered, "decision"), "refuse", "{filtered}");
        assert_eq!(log_field(filtered, "key"), KEY_B_FINGERPRINT, "{filtered}");
        assert_eq!(log_field(filtered, "outcome"), "complete", "{filtered}");
        assert!(
            !logs.text().contains(SIGN_PAYLOAD_MARKER),
            "the sign payload never reaches the log"
        );
    }

    #[tokio::test]
    async fn log_shape_upstream_unreachable() {
        let (logs, _guard) = capture_logs();
        let fx = fixture(&["*"], vec![Reply::Fail]);
        exchange(&fx, vec![frame(&request_identities())]).await;
        let lines = logs.agent_lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        let line = &lines[0];
        assert_common_shape(line, &fx.session_id, SSH_AGENTC_REQUEST_IDENTITIES);
        assert_eq!(log_field(line, "op_name"), "request_identities", "{line}");
        assert_eq!(log_field(line, "decision"), "upstream_unreachable", "{line}");
        assert_eq!(log_field(line, "key"), "-", "{line}");
        assert_eq!(log_field(line, "outcome"), "complete", "{line}");
    }

    #[test]
    fn key_fingerprint_sha256_prefix() {
        let fp = key_fingerprint(b"test");
        assert!(fp.starts_with("SHA256:"));
    }
}
