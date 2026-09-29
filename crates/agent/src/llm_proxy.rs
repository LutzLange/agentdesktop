use std::{convert::Infallible, net::SocketAddr, path::Path, sync::Arc, time::Duration};

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode, Uri,
    body::Incoming,
    header::{AUTHORIZATION, CONNECTION, CONTENT_TYPE, HOST, HeaderValue, ORIGIN},
    service::service_fn,
};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use tokio::{net::TcpListener, task::JoinSet};

use agentdesktop_core::config::{GitHubTokenSource, LlmGatewayConfig};

use crate::api::{self, AppState};

type ProxyClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Incoming>;
type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Header that carries the per-device pairing value on every route.
pub(crate) const PAIRING_HEADER: &str = "x-agentdesktop-pairing";
/// File under the daemon state directory that holds the pairing value.
const PAIRING_FILE: &str = "llm-proxy-pairing";

/// How a route obtains the credential that goes upstream in `x-llm-token`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RouteCredential {
    /// Only the gateway identity is sent; any client credential is dropped.
    Gateway,
    /// The client's own bearer token is moved to `x-llm-token` and the gateway
    /// identity takes `Authorization` (the VS Code Copilot pass-through shape).
    Passthrough,
}

/// Which configured gateway base URL a route forwards to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Upstream {
    /// `llmGateway.url`, shared with the credential-helper programs.
    Url,
    /// `llmGateway.proxyUrl` when set, else `llmGateway.url`.
    ProxyUrl,
}

/// A fixed path prefix the proxy serves for one managed program.
///
/// The prefix is what a reconciler writes into that program's client file, so
/// the client id is decided by the file the daemon owns, never by request
/// headers. The prefix is stripped before forwarding.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProxyRoute {
    pub prefix: &'static str,
    pub client_id: &'static str,
    pub credential: RouteCredential,
    pub upstream: Upstream,
}

/// Routes for the Copilot programs. A prefix matches only at a `/` boundary, so
/// `/vscode-copilot-passthrough/...` never matches `/vscode-copilot`.
pub(crate) const ROUTES: &[ProxyRoute] = &[
    ProxyRoute {
        prefix: "/vscode-copilot-passthrough",
        client_id: "vscode-copilot",
        credential: RouteCredential::Passthrough,
        upstream: Upstream::ProxyUrl,
    },
    ProxyRoute {
        prefix: "/vscode-copilot",
        client_id: "vscode-copilot",
        credential: RouteCredential::Gateway,
        upstream: Upstream::Url,
    },
    ProxyRoute {
        prefix: "/copilot-cli",
        client_id: "copilot-cli",
        credential: RouteCredential::Gateway,
        upstream: Upstream::Url,
    },
];

/// Runtime settings of the proxy listener.
#[derive(Clone)]
pub(crate) struct ProxyConfig {
    /// Client id for requests that match no prefixed route (the original,
    /// hand-configured shape from the README).
    pub default_client_id: String,
    /// Pairing value required on every route.
    pub pairing: Arc<str>,
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("default_client_id", &self.default_client_id)
            .field("pairing", &"<redacted>")
            .finish()
    }
}

/// What a reconciler needs to point a client file at the proxy.
///
/// The pairing is a secret: write it only into files created owner-only (0600,
/// or under an owner-only directory; on Windows `secure_fs::atomic_write`
/// relies on the parent directory's ACL). A reconciler that sees `None` here
/// must remove or neutralise a pointer it wrote earlier, so a stale client file
/// never sends the pairing, or the user's own token, to a port the daemon no
/// longer owns.
#[derive(Clone)]
pub struct LlmProxyContext {
    pub address: SocketAddr,
    pub pairing: Arc<str>,
}

impl std::fmt::Debug for LlmProxyContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmProxyContext")
            .field("address", &self.address)
            .field("pairing", &"<redacted>")
            .finish()
    }
}

/// Read the pairing value from the state directory, creating it on first use.
///
/// The value is a bearer secret for the loopback listener, required on every
/// route: it stops other local users on a shared host and browser-origin
/// traffic from using the proxy. It does not, and cannot, stop the current
/// user's own processes, which can ask the daemon for a credential directly.
/// Kept across restarts so client files stay valid.
pub(crate) fn load_or_create_pairing(state_dir: &Path) -> anyhow::Result<Arc<str>> {
    let path = state_dir.join(PAIRING_FILE);
    let existing = std::fs::read_to_string(&path);
    match existing {
        Ok(contents) if contents.trim().len() >= 32 => Ok(Arc::from(contents.trim())),
        // Only a missing or unusable file (too short, not text) is replaced; any
        // other read error (permissions, I/O) is an error, so an existing pairing
        // is never silently rotated and every client file invalidated by a
        // transient fault.
        Err(error)
            if !matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidData
            ) =>
        {
            Err(anyhow::Error::from(error).context(format!("read {}", path.display())))
        }
        Ok(_) | Err(_) => {
            if !matches!(&existing, Err(error) if error.kind() == std::io::ErrorKind::NotFound) {
                tracing::warn!(path = %path.display(), "LLM proxy pairing file is unusable; regenerating (client files must be re-applied)");
            }
            let mut bytes = [0u8; 32];
            rand::fill(&mut bytes);
            let value = URL_SAFE_NO_PAD.encode(bytes);
            crate::secure_fs::ensure_private_dir(state_dir)?;
            crate::secure_fs::atomic_write(&path, value.as_bytes(), 0o600)
                .with_context(|| format!("write {}", path.display()))?;
            Ok(Arc::from(value.as_str()))
        }
    }
}

pub(crate) async fn serve(
    listener: TcpListener,
    state: AppState,
    config: ProxyConfig,
) -> anyhow::Result<()> {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(30)));
    let connector = HttpsConnectorBuilder::new()
        .with_provider_and_native_roots(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))?
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    let client = Client::builder(TokioExecutor::new()).build(connector);
    let config = Arc::new(config);
    // Dropping the server cancels active connections and their upstream streams.
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                // A per-connection accept error (EMFILE, ECONNABORTED, ENOBUFS)
                // must not end the proxy, let alone the daemon: log, pause briefly
                // so a persistent condition does not spin, and keep accepting.
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(%error, "LLM proxy accept failed; retrying");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let client = client.clone();
                let state = state.clone();
                let config = config.clone();
                connections.spawn(async move {
                    let service = service_fn(move |request| {
                        let client = client.clone();
                        let state = state.clone();
                        let config = config.clone();
                        async move {
                            let response = match forward(request, &client, &state, &config).await {
                                Ok(response) => response,
                                Err(error) => {
                                    tracing::warn!(status = %error.status, code = error.code, message = %error.message, "LLM proxy request failed");
                                    error.into_response()
                                }
                            };
                            Ok::<_, Infallible>(response)
                        }
                    });
                    if let Err(error) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service).await
                    {
                        tracing::debug!(%error, "LLM proxy connection closed");
                    }
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "LLM proxy connection task failed");
                }
            }
        }
    }
}

/// A refused or failed request, rendered as an OpenAI-style JSON error so the
/// LLM clients display the message instead of dropping the connection.
#[derive(Debug)]
pub(crate) struct ProxyError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ProxyError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn into_response(self) -> Response<ProxyBody> {
        let body = serde_json::json!({
            "error": {
                "message": self.message,
                "type": "agentdesktop_error",
                "code": self.code,
            }
        })
        .to_string();
        Response::builder()
            .status(self.status)
            .header(CONTENT_TYPE, "application/json")
            .body(
                Full::new(Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .expect("static response")
    }
}

impl ProxyError {
    /// A failure to obtain the gateway identity for this device: not enrolled,
    /// revoked, controller unreachable, OIDC refresh failed. The status comes
    /// from the credential path; the code tells the client what kind of problem
    /// it is so the message is actionable ("run agentdesktop login" and so on).
    fn credential((status, message): (StatusCode, String)) -> Self {
        Self::new(
            status,
            "agentdesktop_credential",
            format!("agentdesktop: no gateway credential for this device: {message}"),
        )
    }
}

/// Only loopback hosts: a page on another origin that resolves a name to
/// 127.0.0.1 (DNS rebinding) sends that name in `Host`. Accepts any loopback
/// IP (the listen validation allows all of 127.0.0.0/8 and ::1), bracketed or
/// bare IPv6, `localhost` in any case with an optional trailing dot, each with
/// or without a port. A request without `Host` (HTTP/1.0) is refused.
fn host_is_loopback(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(HOST).and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let host = host.trim();
    let name = if let Some(rest) = host.strip_prefix('[') {
        match rest.split_once(']') {
            Some((name, port)) if port.is_empty() || port.starts_with(':') => name,
            _ => return false,
        }
    } else if host.matches(':').count() > 1 {
        // Bare IPv6 without brackets cannot carry a port.
        host
    } else {
        host.rsplit_once(':').map_or(host, |(name, _)| name)
    };
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    name.trim_end_matches('.').eq_ignore_ascii_case("localhost")
}

/// Refuse `..` segments so a route cannot escape the upstream base it pins.
/// The check runs on a percent-decoded copy (the forwarded path stays as sent),
/// so `%2e%2e` and encoded separators are caught too; a malformed escape is
/// refused outright.
fn path_escapes_base(path: &str) -> bool {
    let Some(decoded) = percent_decode(path) else {
        return true;
    };
    decoded
        .split(|byte| *byte == b'/' || *byte == b'\\')
        .any(|segment| segment == b"..")
}

/// Decodes `%XX` escapes to bytes. Escapes that are not two hex digits are
/// malformed and yield `None`; the bytes are not required to be UTF-8, since
/// the check only looks for separators and dots.
fn percent_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            let value = u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
            out.push(value);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

/// Whether the first path segment looks like one of the managed route names
/// without matching one exactly (wrong case, extra suffix, doubled slash).
/// A gateway sub-path whose first segment starts with a route name (for
/// example `/vscode-copilot-proxy/...`) is refused on the prefix-less route
/// as well; the check is on the literal path, so an encoded near miss is not
/// caught and reaches the gateway on the prefix-less route.
fn resembles_route(path: &str) -> bool {
    let first = path
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    !first.is_empty()
        && ROUTES.iter().any(|route| {
            let name = &route.prefix[1..];
            first == name || first.starts_with(name) || name.starts_with(&first) && first.len() >= 8
        })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The route for a request path, and the path with the prefix removed.
fn match_route(path: &str) -> Option<(&'static ProxyRoute, &str)> {
    ROUTES.iter().find_map(|route| {
        let rest = path.strip_prefix(route.prefix)?;
        (rest.is_empty() || rest.starts_with('/'))
            .then_some((route, if rest.is_empty() { "/" } else { rest }))
    })
}

fn bearer_or_header(headers: &HeaderMap, header: &str) -> Option<String> {
    headers
        .get(header)
        .or_else(|| headers.get(AUTHORIZATION))
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .strip_prefix("Bearer ")
                .unwrap_or(value)
                .trim()
                .to_owned()
        })
        .filter(|value| !value.is_empty())
}

fn upstream_base(gateway: &LlmGatewayConfig, upstream: Upstream) -> &url::Url {
    match upstream {
        Upstream::Url => &gateway.url,
        Upstream::ProxyUrl => gateway.proxy_url.as_ref().unwrap_or(&gateway.url),
    }
}

async fn forward(
    mut request: Request<Incoming>,
    client: &ProxyClient,
    state: &AppState,
    config: &ProxyConfig,
) -> Result<Response<ProxyBody>, ProxyError> {
    if !host_is_loopback(request.headers()) {
        return Err(ProxyError::new(
            StatusCode::FORBIDDEN,
            "host_not_allowed",
            "agentdesktop proxy: Host must be a loopback address",
        ));
    }
    // This listener is for local native clients, not browser scripts or tunnels.
    if request.headers().contains_key(ORIGIN) || request.method() == Method::CONNECT {
        return Err(ProxyError::new(
            StatusCode::FORBIDDEN,
            "browser_not_allowed",
            "agentdesktop proxy: browser requests and CONNECT are not supported",
        ));
    }
    if request.method() == Method::OPTIONS {
        return Err(ProxyError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "agentdesktop proxy: OPTIONS is not supported",
        ));
    }
    // The pairing value is required on every route and travels only in its own
    // header: Authorization keeps one meaning (the client's own token, used by the
    // pass-through shapes) and the pairing is never mistaken for a credential.
    // Checked before anything that reads configuration, so an unpaired caller
    // learns nothing about this device and costs it no work.
    let offered = request
        .headers()
        .get(PAIRING_HEADER)
        .and_then(|value| value.to_str().ok());
    if !offered
        .is_some_and(|offered| constant_time_eq(offered.as_bytes(), config.pairing.as_bytes()))
    {
        return Err(ProxyError::new(
            StatusCode::FORBIDDEN,
            "pairing_invalid",
            "agentdesktop proxy: pairing value missing or wrong; re-apply the managed configuration",
        ));
    }
    // Pure string checks on the path run before any configuration is read.
    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str());
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path_and_query, None),
    };
    if path_escapes_base(path) {
        return Err(ProxyError::new(
            StatusCode::BAD_REQUEST,
            "path_invalid",
            "agentdesktop proxy: path must not contain '..' segments",
        ));
    }
    if match_route(path).is_none() && resembles_route(path) {
        // A first segment that looks like a route name but is not one (case,
        // suffix, doubled slash) is a mistyped client file, not a request for
        // the hand-configured route with its different identity and credential mode.
        return Err(ProxyError::new(
            StatusCode::NOT_FOUND,
            "route_unknown",
            "agentdesktop proxy: unknown route; the managed prefixes are /copilot-cli, /vscode-copilot and /vscode-copilot-passthrough",
        ));
    }
    let effective =
        api::load_effective_config(&state.config, &state.state_dir).map_err(|error| {
            tracing::warn!(
                error = %format!("{error:#}"),
                "LLM proxy could not read the applied configuration"
            );
            ProxyError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "agentdesktop_unavailable",
                "agentdesktop: could not read the applied configuration; see the daemon log",
            )
        })?;
    let gateway = effective.llm_gateway.as_ref().ok_or_else(|| {
        ProxyError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "agentdesktop_unavailable",
            "agentdesktop: no LLM gateway configured on this device yet",
        )
    })?;

    // Which route, which client id, which credential mode, which upstream.
    let (client_id, credential_mode, base, rest) = match match_route(path) {
        Some((route, rest)) => {
            if route.upstream == Upstream::ProxyUrl && gateway.proxy_url.is_none() {
                // The pass-through shape needs the gateway route that restores the
                // client token; sending x-llm-token to the plain LLM route would
                // fail in a way that looks like a gateway fault.
                return Err(ProxyError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "agentdesktop_unavailable",
                    "agentdesktop proxy: this route needs llmGateway.proxyUrl, which is not configured",
                ));
            }
            (
                route.client_id.to_owned(),
                Some(route.credential),
                upstream_base(gateway, route.upstream),
                rest,
            )
        }
        // No prefix: the original hand-configured shape. Credential mode comes
        // from llmGateway.githubOAuth, upstream from proxyUrl.
        None => (
            config.default_client_id.clone(),
            None,
            upstream_base(gateway, Upstream::ProxyUrl),
            path,
        ),
    };
    let uri: Uri = match query {
        Some(query) => format!("{}{rest}?{query}", base.as_str().trim_end_matches('/')),
        None => format!("{}{rest}", base.as_str().trim_end_matches('/')),
    }
    .parse()
    .map_err(|error: hyper::http::uri::InvalidUri| {
        ProxyError::new(
            StatusCode::BAD_GATEWAY,
            "gateway_unreachable",
            error.to_string(),
        )
    })?;

    // Capture the client's own credential before the headers are cleared. A
    // client such as VS Code Copilot has already done its provider handshake and
    // sends the resulting token; on a pass-through route (or with
    // `githubOAuth.source: request` on the default route) that token is what
    // goes upstream, and the daemon only adds the gateway identity.
    //
    // x-llm-token wins over Authorization so a caller can send both: its identity
    // in one and the provider credential in the other.
    // The pairing value is never a client credential, even if a client put it in
    // both places.
    let client_credential = bearer_or_header(request.headers(), "x-llm-token")
        .filter(|value| !constant_time_eq(value.as_bytes(), config.pairing.as_bytes()));

    strip_hop_headers(request.headers_mut());
    for header in [
        AUTHORIZATION.as_str(),
        "x-api-key",
        "api-key",
        "x-llm-token",
        PAIRING_HEADER,
    ] {
        request.headers_mut().remove(header);
    }
    // Both branches put a bare token in x-llm-token. The gateway is the one
    // that re-forms the header, with `"Bearer " + request.headers['x-llm-token']`,
    // so the prefix is added in exactly one place.
    let upstream_token = match credential_mode {
        Some(RouteCredential::Gateway) => None,
        Some(RouteCredential::Passthrough) => Some(client_credential.ok_or_else(|| {
            ProxyError::new(
                StatusCode::UNAUTHORIZED,
                "client_credential_missing",
                "agentdesktop proxy: no client credential to pass through; send it in Authorization or x-llm-token",
            )
        })?),
        None => match &gateway.github_oauth {
            None => None,
            Some(github) => Some(match github.source {
                GitHubTokenSource::DeviceFlow => {
                    let client_id = github.client_id.as_deref().ok_or_else(|| {
                        ProxyError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "agentdesktop_unavailable",
                            "githubOAuth.clientId is required for deviceFlow",
                        )
                    })?;
                    crate::github_oauth::credential(client_id, &state.state_dir, None)
                        .await
                        .map_err(|error| ProxyError::new(StatusCode::BAD_GATEWAY, "gateway_unreachable", format!("GitHub OAuth: {error:#}")))?
                        .credential
                }
                // Fail rather than forward a request that cannot succeed: without a
                // client credential the gateway would swap in an empty Authorization
                // and the provider would reject it with an error that looks like a
                // gateway fault.
                GitHubTokenSource::Request => client_credential.ok_or_else(|| {
                    ProxyError::new(
                        StatusCode::UNAUTHORIZED,
                        "client_credential_missing",
                        "no client credential to forward; send it in Authorization or x-llm-token",
                    )
                })?,
            }),
        },
    };
    if let Some(token) = upstream_token {
        let mut value = HeaderValue::from_str(&token).map_err(|_| {
            ProxyError::new(
                StatusCode::BAD_GATEWAY,
                "gateway_unreachable",
                "invalid client credential header",
            )
        })?;
        value.set_sensitive(true);
        request.headers_mut().insert("x-llm-token", value);
    }
    // Identity last: no controller or OIDC round trip for a request that was
    // going to be refused anyway.
    if gateway.authentication.is_some() {
        let credential = api::gateway_credential(state, &effective, &client_id, false)
            .await
            .map_err(ProxyError::credential)?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", credential.credential))
            .map_err(|_| {
                ProxyError::new(
                    StatusCode::BAD_GATEWAY,
                    "gateway_unreachable",
                    "invalid gateway credential header",
                )
            })?;
        authorization.set_sensitive(true);
        request.headers_mut().insert(AUTHORIZATION, authorization);
    }
    request.headers_mut().insert(
        HOST,
        HeaderValue::from_str(
            uri.authority()
                .map(|authority| authority.as_str())
                .unwrap_or(""),
        )
        .map_err(|_| {
            ProxyError::new(
                StatusCode::BAD_GATEWAY,
                "gateway_unreachable",
                "invalid gateway host",
            )
        })?,
    );
    *request.uri_mut() = uri;
    let mut response = client.request(request).await.map_err(|error| {
        ProxyError::new(
            StatusCode::BAD_GATEWAY,
            "gateway_unreachable",
            format!("agentdesktop proxy: gateway unreachable: {error}"),
        )
    })?;
    strip_hop_headers(response.headers_mut());
    Ok(response.map(BodyExt::boxed))
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let nominated: Vec<_> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_owned())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{enrollment::EnrollmentState, secret_store::SecretStore};
    use agentdesktop_core::{
        config::parse_daemon,
        model::{DaemonInfo, DaemonScope, Discovery},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use http_body_util::StreamBody;
    use hyper::body::Frame;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tokio::sync::{mpsc, oneshot, watch};
    use tokio_stream::wrappers::ReceiverStream;

    // Covers the real socket path, credential replacement/rotation, opaque bytes,
    // header forwarding, and delivery before the upstream response is complete.
    #[tokio::test]
    async fn streams_opaque_requests_with_current_credentials() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = upstream.local_addr().unwrap();
            let (release_tx, release_rx) = oneshot::channel();
            let release = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));
            let upstream_task = tokio::spawn(async move {
                let (socket, _) = upstream.accept().await.unwrap();
                hyper::server::conn::http1::Builder::new().serve_connection(
                    TokioIo::new(socket), service_fn(move |request: Request<Incoming>| {
                        let release = release.clone();
                        async move {
                            assert_eq!(request.uri(), "/gateway/v1/messages?value=%2F");
                            assert_eq!(request.headers()[HOST], address.to_string());
                            assert!(!request.headers().contains_key("x-api-key"));
                            assert!(!request.headers().contains_key("x-hop"));
                            assert!(!request.headers().contains_key(PAIRING_HEADER));
                            assert_eq!(request.headers()["x-llm-token"], "ghu_test");
                            assert_eq!(request.headers()["anthropic-version"], "2023-06-01");
                            let gate = release.lock().await.take();
                            assert_eq!(request.headers()[AUTHORIZATION],
                                if gate.is_some() { "Bearer first" } else { "Bearer second" });
                            assert_eq!(request.into_body().collect().await.unwrap().to_bytes(),
                                Bytes::from_static(b"\xffnot-json\x00"));
                            let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(2);
                            tokio::spawn(async move {
                                tx.send(Ok(Frame::data(Bytes::from_static(b"data: first\n\n")))).await.unwrap();
                                if let Some(gate) = gate { gate.await.unwrap(); }
                                let _ = tx.send(Ok(Frame::data(Bytes::from_static(b"data: last\n\n")))).await;
                            });
                            Ok::<_, Infallible>(Response::builder()
                                .header("content-type", "text/event-stream")
                                .header("connection", "x-upstream-hop")
                                .header("x-upstream-hop", "remove")
                                .body(StreamBody::new(ReceiverStream::new(rx))).unwrap())
                        }
                    })
                ).await.unwrap();
            });
            let dir = tempfile::tempdir().unwrap();
            let store = SecretStore::new(dir.path()).unwrap();
            let account = URL_SAFE_NO_PAD.encode(Sha256::digest(b"https://issuer.example/\0proxy-test"));
            let save_token = |token: &str| store.set("dev.agentdesktop.gateway-oidc", &account,
                &serde_json::json!({"accessToken": token, "refreshToken": null,
                    "expiresAtUnixSeconds": 4_000_000_000u64,
                    "tokenEndpoint": "https://issuer.example/token"}).to_string()).unwrap();
            save_token("first");
            store.set("dev.agentdesktop.github-oauth", "github-test", &serde_json::json!({
                "accessToken": "ghu_test", "expiresAt": 4_000_000_000u64,
                "refreshToken": null, "refreshExpiresAt": 0,
            }).to_string()).unwrap();
            let config = parse_daemon(&format!("llmGateway:\n  url: http://{address}/gateway\n  githubOAuth:\n    clientId: github-test\n  authentication:\n    type: oidc\n    issuer: https://issuer.example/\n    clientId: proxy-test\n")).unwrap();
            let (_, discovery) = watch::channel(Arc::new(Discovery { agents: vec![], model_runtimes: vec![] }));
            let state = AppState {
                config,
                daemon_info: DaemonInfo { version: "test".into(), scope: DaemonScope::User,
                    config_path: String::new(), state_directory: String::new(),
                    inventory_interval: Duration::from_secs(60), controller: None, llm_proxy: None },
                discovery, enrollment: EnrollmentState::new(false), state_dir: dir.path().to_owned(),
                oidc_callback_listen: None, telemetry: None, logout: None,
            };
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_address = listener.local_addr().unwrap();
            let proxy = tokio::spawn(serve(listener, state, default_config()));
            let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
            let mut release_tx = Some(release_tx);
            for _ in 0..2 {
                let request = Request::builder().method(Method::POST)
                    .uri(format!("http://{proxy_address}/v1/messages?value=%2F"))
                    .header(AUTHORIZATION, "Bearer must-not-forward")
                    .header("x-api-key", "must-not-forward")
                    .header("x-llm-token", "must-not-forward")
                    .header(PAIRING_HEADER, PAIRING)
                    .header(CONNECTION, "x-hop").header("x-hop", "remove")
                    .header("anthropic-version", "2023-06-01")
                    .body(Full::new(Bytes::from_static(b"\xffnot-json\x00"))).unwrap();
                let response = client.request(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.headers()["content-type"], "text/event-stream");
                assert!(!response.headers().contains_key("x-upstream-hop"));
                let mut body = response.into_body();
                let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
                if let Some(release) = release_tx.take() {
                    assert_eq!(first, "data: first\n\n");
                    release.send(()).unwrap();
                }
                let rest = body.collect().await.unwrap().to_bytes();
                assert_eq!([first.as_ref(), rest.as_ref()].concat(), b"data: first\n\ndata: last\n\n");
                save_token("second");
            }
            proxy.abort();
            let _ = proxy.await;
            drop(client);
            upstream_task.abort();
        }).await.unwrap();
    }

    // source: request. The client's own credential is what reaches the gateway
    // in x-llm-token, and the daemon contributes only the gateway identity.
    // This is the VS Code Copilot shape: Copilot has already exchanged its
    // GitHub session for a provider token and sends it in Authorization.
    #[tokio::test]
    async fn forwards_the_client_credential_when_source_is_request() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = upstream.local_addr().unwrap();
            let upstream_task = tokio::spawn(async move {
                let (socket, _) = upstream.accept().await.unwrap();
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(socket),
                        service_fn(move |request: Request<Incoming>| async move {
                            // The Bearer prefix is stripped here and re-added by the
                            // gateway, so the token travels bare.
                            assert_eq!(request.headers()["x-llm-token"], "tid=from-client");
                            assert_eq!(request.headers()[AUTHORIZATION], "Bearer identity");
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                        }),
                    )
                    .await
                    .unwrap();
            });
            let (dir, state) = request_source_state(address).await;
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_address = listener.local_addr().unwrap();
            let proxy = tokio::spawn(serve(listener, state, default_config()));
            let client: Client<HttpConnector, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build_http();
            let request = Request::builder()
                .method(Method::POST)
                .uri(format!("http://{proxy_address}/chat/completions"))
                .header(PAIRING_HEADER, PAIRING)
                .header(AUTHORIZATION, "Bearer tid=from-client")
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            let response = client.request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            proxy.abort();
            let _ = proxy.await;
            drop(client);
            upstream_task.abort();
            drop(dir);
        })
        .await
        .unwrap();
    }

    // Without a client credential the gateway would swap in an empty
    // Authorization and the provider would fail in a way that looks like a
    // gateway fault, so the proxy refuses instead of forwarding.
    #[tokio::test]
    async fn rejects_a_request_with_no_client_credential() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = upstream.local_addr().unwrap();
            let (dir, state) = request_source_state(address).await;
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_address = listener.local_addr().unwrap();
            let proxy = tokio::spawn(serve(listener, state, default_config()));
            let client: Client<HttpConnector, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build_http();
            let request = Request::builder()
                .method(Method::POST)
                .uri(format!("http://{proxy_address}/chat/completions"))
                .header(PAIRING_HEADER, PAIRING)
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            let response = client.request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            // The default route is paired too: without the header it is refused
            // before any credential work.
            let request = Request::builder()
                .method(Method::POST)
                .uri(format!("http://{proxy_address}/chat/completions"))
                .header(AUTHORIZATION, "Bearer tid=from-client")
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            assert_eq!(
                error_code(client.request(request).await.unwrap()).await,
                (StatusCode::FORBIDDEN, "pairing_invalid".to_owned())
            );
            proxy.abort();
            let _ = proxy.await;
            drop(client);
            drop(dir);
        })
        .await
        .unwrap();
    }

    const PAIRING: &str = "pairing-secret-value-0123456789abcdef";

    fn default_config() -> ProxyConfig {
        ProxyConfig {
            default_client_id: "vscode".into(),
            pairing: Arc::from(PAIRING),
        }
    }

    async fn error_code(response: Response<Incoming>) -> (StatusCode, String) {
        let status = response.status();
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (status, json["error"]["code"].as_str().unwrap().to_owned())
    }

    #[tokio::test]
    async fn refuses_non_loopback_hosts_and_options_with_json_errors() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (dir, state) = request_source_state(upstream.local_addr().unwrap()).await;
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_address = listener.local_addr().unwrap();
            let proxy = tokio::spawn(serve(listener, state, default_config()));
            let client: Client<HttpConnector, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build_http();
            let rebound = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{proxy_address}/copilot-cli/v1/chat/completions"
                ))
                .header(HOST, "attacker.example")
                .header(PAIRING_HEADER, "pairing-secret-value-0123456789abcdef")
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            assert_eq!(
                error_code(client.request(rebound).await.unwrap()).await,
                (StatusCode::FORBIDDEN, "host_not_allowed".to_owned())
            );
            let options = Request::builder()
                .method(Method::OPTIONS)
                .uri(format!(
                    "http://{proxy_address}/copilot-cli/v1/chat/completions"
                ))
                .body(Full::new(Bytes::new()))
                .unwrap();
            assert_eq!(
                error_code(client.request(options).await.unwrap()).await,
                (
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed".to_owned()
                )
            );
            proxy.abort();
            let _ = proxy.await;
            drop(client);
            drop(dir);
        })
        .await
        .unwrap();
    }

    // A prefixed route needs the pairing value, strips its prefix, sends only the
    // gateway identity (no client credential leaks through), and is refused with a
    // JSON error without the pairing.
    #[tokio::test]
    async fn prefixed_gateway_route_requires_pairing_and_strips_the_prefix() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = upstream.local_addr().unwrap();
            let upstream_task = tokio::spawn(async move {
                let (socket, _) = upstream.accept().await.unwrap();
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(socket),
                        service_fn(move |request: Request<Incoming>| async move {
                            assert_eq!(request.uri(), "/v1/chat/completions?stream=true");
                            assert_eq!(request.headers()[AUTHORIZATION], "Bearer identity");
                            assert!(!request.headers().contains_key("x-llm-token"));
                            assert!(!request.headers().contains_key(PAIRING_HEADER));
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                        }),
                    )
                    .await
                    .unwrap();
            });
            let (dir, state) = request_source_state(address).await;
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_address = listener.local_addr().unwrap();
            let proxy = tokio::spawn(serve(listener, state.clone(), default_config()));
            let client: Client<HttpConnector, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build_http();
            let unpaired = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{proxy_address}/copilot-cli/v1/chat/completions"
                ))
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            assert_eq!(
                error_code(client.request(unpaired).await.unwrap()).await,
                (StatusCode::FORBIDDEN, "pairing_invalid".to_owned())
            );
            // The pairing is only accepted in its own header, never as the bearer.
            let as_bearer = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{proxy_address}/copilot-cli/v1/chat/completions"
                ))
                .header(AUTHORIZATION, format!("Bearer {PAIRING}"))
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            assert_eq!(
                error_code(client.request(as_bearer).await.unwrap()).await,
                (StatusCode::FORBIDDEN, "pairing_invalid".to_owned())
            );
            let wrong = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{proxy_address}/copilot-cli/v1/chat/completions"
                ))
                .header(PAIRING_HEADER, "pairing-secret-value-0123456789abcdeX")
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            assert_eq!(
                error_code(client.request(wrong).await.unwrap()).await,
                (StatusCode::FORBIDDEN, "pairing_invalid".to_owned())
            );
            let paired = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{proxy_address}/copilot-cli/v1/chat/completions?stream=true"
                ))
                .header(PAIRING_HEADER, PAIRING)
                .header(AUTHORIZATION, "Bearer a-real-key-by-mistake")
                .header("x-llm-token", "must-not-forward")
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            let response = client.request(paired).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            proxy.abort();
            let _ = proxy.await;
            // A '..' segment cannot escape the upstream base the route pins.
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_address = listener.local_addr().unwrap();
            let proxy = tokio::spawn(serve(listener, state, default_config()));
            let request = Request::builder()
                .method(Method::POST)
                .uri(format!("http://{proxy_address}/copilot-cli/../admin"))
                .header(PAIRING_HEADER, PAIRING)
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            assert_eq!(
                error_code(client.request(request).await.unwrap()).await,
                (StatusCode::BAD_REQUEST, "path_invalid".to_owned())
            );
            proxy.abort();
            let _ = proxy.await;
            drop(client);
            upstream_task.abort();
            drop(dir);
        })
        .await
        .unwrap();
    }

    // The pass-through route moves the client's token to x-llm-token, keeps the
    // gateway identity in Authorization, forwards to proxyUrl, and refuses a
    // request without a client token. The pairing must come in its own header
    // here, because Authorization carries the client token.
    #[tokio::test]
    async fn passthrough_route_moves_the_client_token_and_uses_proxy_url() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = upstream.local_addr().unwrap();
            let upstream_task = tokio::spawn(async move {
                let (socket, _) = upstream.accept().await.unwrap();
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(socket),
                        service_fn(move |request: Request<Incoming>| async move {
                            assert_eq!(request.uri(), "/copilot-proxy/chat/completions");
                            assert_eq!(request.headers()["x-llm-token"], "tid=from-client");
                            assert_eq!(request.headers()[AUTHORIZATION], "Bearer identity");
                            assert!(!request.headers().contains_key(PAIRING_HEADER));
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                        }),
                    )
                    .await
                    .unwrap();
            });
            let (dir, mut state) = request_source_state(address).await;
            let client: Client<HttpConnector, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build_http();
            // Without proxyUrl the pass-through route is unavailable rather than
            // sending x-llm-token to the plain LLM route.
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_address = listener.local_addr().unwrap();
            let proxy = tokio::spawn(serve(listener, state.clone(), default_config()));
            let request = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{proxy_address}/vscode-copilot-passthrough/chat/completions"
                ))
                .header(PAIRING_HEADER, PAIRING)
                .header(AUTHORIZATION, "Bearer tid=from-client")
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            assert_eq!(
                error_code(client.request(request).await.unwrap()).await,
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "agentdesktop_unavailable".to_owned()
                )
            );
            proxy.abort();
            let _ = proxy.await;
            state.config.llm_gateway.as_mut().unwrap().proxy_url =
                Some(format!("http://{address}/copilot-proxy").parse().unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_address = listener.local_addr().unwrap();
            let proxy = tokio::spawn(serve(listener, state, default_config()));
            let no_token = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{proxy_address}/vscode-copilot-passthrough/chat/completions"
                ))
                .header(PAIRING_HEADER, "pairing-secret-value-0123456789abcdef")
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            assert_eq!(
                error_code(client.request(no_token).await.unwrap()).await,
                (
                    StatusCode::UNAUTHORIZED,
                    "client_credential_missing".to_owned()
                )
            );
            // The pairing in Authorization is not a client token: refused, never forwarded.
            let pairing_as_token = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{proxy_address}/vscode-copilot-passthrough/chat/completions"
                ))
                .header(PAIRING_HEADER, PAIRING)
                .header(AUTHORIZATION, format!("Bearer {PAIRING}"))
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            assert_eq!(
                error_code(client.request(pairing_as_token).await.unwrap()).await,
                (
                    StatusCode::UNAUTHORIZED,
                    "client_credential_missing".to_owned()
                )
            );
            let request = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{proxy_address}/vscode-copilot-passthrough/chat/completions"
                ))
                .header(PAIRING_HEADER, "pairing-secret-value-0123456789abcdef")
                .header(AUTHORIZATION, "Bearer tid=from-client")
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            let response = client.request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            proxy.abort();
            let _ = proxy.await;
            drop(client);
            upstream_task.abort();
            drop(dir);
        })
        .await
        .unwrap();
    }

    #[test]
    fn route_matching_prefers_the_longer_prefix_and_strips_it() {
        let (route, rest) = match_route("/vscode-copilot-passthrough/chat/completions").unwrap();
        assert_eq!(route.client_id, "vscode-copilot");
        assert_eq!(route.credential, RouteCredential::Passthrough);
        assert_eq!(rest, "/chat/completions");
        let (route, rest) = match_route("/vscode-copilot/v1/chat/completions").unwrap();
        assert_eq!(route.credential, RouteCredential::Gateway);
        assert_eq!(rest, "/v1/chat/completions");
        assert_eq!(match_route("/copilot-cli").unwrap().1, "/");
        assert!(match_route("/copilot-client/v1").is_none());
        assert!(match_route("/v1/chat/completions").is_none());
    }

    #[test]
    fn host_check_accepts_loopback_forms_only() {
        let mut headers = HeaderMap::new();
        let accepted = [
            "127.0.0.1:18095",
            "localhost:18095",
            "[::1]:18095",
            "localhost",
            "127.0.0.1",
            "127.0.0.2:1",
            "Localhost:18095",
            "LOCALHOST",
            "localhost.:18095",
            "[::1]",
            "::1",
        ];
        for ok in accepted {
            headers.insert(HOST, HeaderValue::from_static(ok));
            assert!(host_is_loopback(&headers), "{ok}");
        }
        let refused = [
            "attacker.example",
            "127.0.0.1.attacker.example:18095",
            "10.0.0.5:18095",
            "",
            "[::1",
            "[fe80::1]:18095",
            "localhost.attacker.example",
            "127.0.0.1:18095:1",
        ];
        for bad in refused {
            headers.insert(HOST, HeaderValue::from_static(bad));
            assert!(!host_is_loopback(&headers), "{bad}");
        }
        headers.remove(HOST);
        assert!(!host_is_loopback(&headers));
    }

    #[test]
    fn pairing_is_created_once_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_pairing(dir.path()).unwrap();
        let second = load_or_create_pairing(dir.path()).unwrap();
        assert_eq!(first, second);
        assert!(first.len() >= 43);
        let metadata = std::fs::metadata(dir.path().join(PAIRING_FILE)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
        let _ = metadata;
    }

    #[test]
    fn pairing_file_is_regenerated_only_when_unusable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PAIRING_FILE);
        // Too short: replaced.
        std::fs::write(&path, b"short").unwrap();
        let regenerated = load_or_create_pairing(dir.path()).unwrap();
        assert!(regenerated.len() >= 43);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), *regenerated);
        // Not text: replaced.
        std::fs::write(&path, [0xff, 0xfe, 0x00, 0x01]).unwrap();
        let again = load_or_create_pairing(dir.path()).unwrap();
        assert_ne!(again, regenerated);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), *again);
        // Any other read error is an error, and the value on disk is untouched.
        let other = tempfile::tempdir().unwrap();
        std::fs::create_dir(other.path().join(PAIRING_FILE)).unwrap();
        let error = load_or_create_pairing(other.path()).unwrap_err();
        assert!(format!("{error:#}").contains("read "), "{error:#}");
        assert!(other.path().join(PAIRING_FILE).is_dir());
        // An existing value that cannot be read (permissions) is kept as is.
        #[cfg(unix)]
        if !nix_is_root() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            let error = load_or_create_pairing(dir.path()).unwrap_err();
            assert!(format!("{error:#}").contains("read "), "{error:#}");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(*load_or_create_pairing(dir.path()).unwrap(), *again);
        }
        // A state directory that cannot be created is an error, not a pairing.
        let blocked = tempfile::tempdir().unwrap();
        let file = blocked.path().join("state");
        std::fs::write(&file, b"x").unwrap();
        assert!(load_or_create_pairing(&file.join("nested")).is_err());
    }

    #[cfg(unix)]
    fn nix_is_root() -> bool {
        std::fs::metadata("/proc/self")
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.uid() == 0
            })
            .unwrap_or(false)
    }

    #[test]
    fn route_table_maps_each_prefix_to_its_identity_mode_and_upstream() {
        let expected = [
            (
                "/copilot-cli/v1/x",
                "copilot-cli",
                RouteCredential::Gateway,
                Upstream::Url,
            ),
            (
                "/vscode-copilot/v1/x",
                "vscode-copilot",
                RouteCredential::Gateway,
                Upstream::Url,
            ),
            (
                "/vscode-copilot-passthrough/chat/completions",
                "vscode-copilot",
                RouteCredential::Passthrough,
                Upstream::ProxyUrl,
            ),
        ];
        for (path, client_id, credential, upstream) in expected {
            let (route, _) = match_route(path).unwrap_or_else(|| panic!("{path}"));
            assert_eq!(route.client_id, client_id, "{path}");
            assert_eq!(route.credential, credential, "{path}");
            assert_eq!(route.upstream, upstream, "{path}");
        }
        assert_eq!(ROUTES.len(), 3);
    }

    #[test]
    fn path_guard_catches_encoded_traversal_and_near_miss_routes() {
        for escaping in [
            "/copilot-cli/../admin",
            "/copilot-cli/%2e%2e/admin",
            "/copilot-cli/%2E%2E/admin",
            "/copilot-cli/%2e%2e%2fadmin",
            "/copilot-cli/..%5cadmin",
            "/copilot-cli/%zz",
            "/copilot-cli/%+f",
            "/copilot-cli/%2",
        ] {
            assert!(path_escapes_base(escaping), "{escaping}");
        }
        for fine in [
            "/copilot-cli/v1/chat/completions",
            "/v1/messages",
            "/copilot-cli/a.b/c%20d",
            "/copilot-cli/caf%e9",
            "/copilot-cli/%2e%2ex",
        ] {
            assert!(!path_escapes_base(fine), "{fine}");
        }
        for near in [
            "/copilot-cli2/v1",
            "/Copilot-cli/v1",
            "//copilot-cli/v1",
            "/vscode-copilotx/v1",
        ] {
            assert!(
                match_route(near).is_none() && resembles_route(near),
                "{near}"
            );
        }
        for other in ["/v1/chat/completions", "/chat/completions", "/models"] {
            assert!(!resembles_route(other), "{other}");
        }
    }

    // The pairing is checked before any configuration is read: an unpaired
    // caller gets 403 even when the applied configuration is unreadable, and a
    // paired caller gets a generic message without file detail.
    #[tokio::test]
    async fn pairing_is_checked_before_configuration_is_read() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("remote-config.yaml"),
                "llmGateway: [not: an: object",
            )
            .unwrap();
            let config = parse_daemon("controller:\n  address: https://127.0.0.1:1\n").unwrap();
            let (_, discovery) = watch::channel(Arc::new(Discovery {
                agents: vec![],
                model_runtimes: vec![],
            }));
            let state = AppState {
                config,
                daemon_info: DaemonInfo {
                    version: "test".into(),
                    scope: DaemonScope::User,
                    config_path: String::new(),
                    state_directory: String::new(),
                    inventory_interval: Duration::from_secs(60),
                    controller: None,
                    llm_proxy: None,
                },
                discovery,
                enrollment: EnrollmentState::new(true),
                state_dir: dir.path().to_owned(),
                oidc_callback_listen: None,
                telemetry: None,
                logout: None,
            };
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_address = listener.local_addr().unwrap();
            let proxy = tokio::spawn(serve(listener, state, default_config()));
            let client: Client<HttpConnector, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build_http();
            let unpaired = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{proxy_address}/copilot-cli/v1/chat/completions"
                ))
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            assert_eq!(
                error_code(client.request(unpaired).await.unwrap()).await,
                (StatusCode::FORBIDDEN, "pairing_invalid".to_owned())
            );
            // The path checks are pure string checks and run before the
            // configuration is read: a paired caller with a bad path gets the
            // path error, not the configuration error.
            for (bad_path, code) in [
                ("/copilot-cli/../admin", "path_invalid"),
                ("/Copilot-cli/v1/chat/completions", "route_unknown"),
            ] {
                let request = Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{proxy_address}{bad_path}"))
                    .header(PAIRING_HEADER, PAIRING)
                    .body(Full::new(Bytes::from_static(b"{}")))
                    .unwrap();
                let (_, got) = error_code(client.request(request).await.unwrap()).await;
                assert_eq!(got, code, "{bad_path}");
            }
            let paired = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{proxy_address}/copilot-cli/v1/chat/completions"
                ))
                .header(PAIRING_HEADER, PAIRING)
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            let response = client.request(paired).await.unwrap();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let message = json["error"]["message"].as_str().unwrap();
            assert!(
                !message.contains("remote-config")
                    && !message.contains(dir.path().to_str().unwrap()),
                "{message}"
            );
            proxy.abort();
            let _ = proxy.await;
            drop(client);
            drop(dir);
        })
        .await
        .unwrap();
    }

    async fn request_source_state(address: std::net::SocketAddr) -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::new(dir.path()).unwrap();
        let account =
            URL_SAFE_NO_PAD.encode(Sha256::digest(b"https://issuer.example/\0proxy-test"));
        store
            .set(
                "dev.agentdesktop.gateway-oidc",
                &account,
                &serde_json::json!({"accessToken": "identity", "refreshToken": null,
                "expiresAtUnixSeconds": 4_000_000_000u64,
                "tokenEndpoint": "https://issuer.example/token"})
                .to_string(),
            )
            .unwrap();
        let config = parse_daemon(&format!(
            "llmGateway:\n  url: http://{address}\n  githubOAuth:\n    source: request\n  authentication:\n    type: oidc\n    issuer: https://issuer.example/\n    clientId: proxy-test\n"
        )).unwrap();
        let (_, discovery) = watch::channel(Arc::new(Discovery {
            agents: vec![],
            model_runtimes: vec![],
        }));
        let state = AppState {
            config,
            daemon_info: DaemonInfo {
                version: "test".into(),
                scope: DaemonScope::User,
                config_path: String::new(),
                state_directory: String::new(),
                inventory_interval: Duration::from_secs(60),
                controller: None,
                llm_proxy: None,
            },
            discovery,
            enrollment: EnrollmentState::new(false),
            state_dir: dir.path().to_owned(),
            oidc_callback_listen: None,
            telemetry: None,
            logout: None,
        };
        (dir, state)
    }
}
