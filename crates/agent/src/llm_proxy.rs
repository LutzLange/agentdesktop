use std::{convert::Infallible, time::Duration};

use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode, Uri,
    body::Incoming,
    header::{AUTHORIZATION, CONNECTION, HOST, HeaderValue, ORIGIN},
    service::service_fn,
};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use tokio::{net::TcpListener, task::JoinSet};

use agentdesktop_core::config::GitHubTokenSource;

use crate::api::{self, AppState};

type ProxyClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Incoming>;
type ProxyBody = BoxBody<Bytes, hyper::Error>;

pub(crate) async fn serve(
    listener: TcpListener,
    state: AppState,
    client_id: String,
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
    // Dropping the server cancels active connections and their upstream streams.
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept LLM proxy connection")?;
                let client = client.clone();
                let state = state.clone();
                let client_id = client_id.clone();
                connections.spawn(async move {
                    let service = service_fn(move |request| {
                        let client = client.clone();
                        let state = state.clone();
                        let client_id = client_id.clone();
                        async move {
                            let response = match forward(request, &client, &state, &client_id).await {
                                Ok(response) => response,
                                Err((status, error)) => {
                                    tracing::warn!(%status, %error, "LLM proxy request failed");
                                    Response::builder().status(status)
                                        .body(Full::new(Bytes::from_static(b"LLM proxy request failed; see daemon logs\n"))
                                            .map_err(|never| match never {}).boxed()).unwrap()
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

async fn forward(
    mut request: Request<Incoming>,
    client: &ProxyClient,
    state: &AppState,
    client_id: &str,
) -> Result<Response<ProxyBody>, (StatusCode, String)> {
    // This listener is for local native clients, not browser scripts or tunnels.
    if request.headers().contains_key(ORIGIN) || request.method() == Method::CONNECT {
        return Err((
            StatusCode::FORBIDDEN,
            "browser requests and CONNECT are not supported".into(),
        ));
    }
    let effective = api::load_effective_config(&state.config, &state.state_dir)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let gateway = effective.llm_gateway.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "no llmGateway configured".into(),
    ))?;
    // proxyUrl wins when present, so the proxy and the credential-helper
    // programs can target different prefixes on the same gateway.
    let base = gateway.proxy_url.as_ref().unwrap_or(&gateway.url);
    let uri: Uri = format!(
        "{}{}",
        base.as_str().trim_end_matches('/'),
        request
            .uri()
            .path_and_query()
            .map_or("/", |path| path.as_str())
    )
    .parse()
    .map_err(|error: hyper::http::uri::InvalidUri| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    // Capture the client's own credential before the headers are cleared. A
    // client such as VS Code Copilot has already done its provider handshake and
    // sends the resulting token; with `githubOAuth.source: request` that token is
    // what goes upstream, and the daemon only adds the gateway identity.
    //
    // x-llm-token wins over Authorization so a caller can send both: its identity
    // in one and the provider credential in the other.
    let client_credential = request
        .headers()
        .get("x-llm-token")
        .or_else(|| request.headers().get(AUTHORIZATION))
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .strip_prefix("Bearer ")
                .unwrap_or(value)
                .trim()
                .to_owned()
        })
        .filter(|value| !value.is_empty());

    strip_hop_headers(request.headers_mut());
    request.headers_mut().remove(AUTHORIZATION);
    request.headers_mut().remove("x-api-key");
    request.headers_mut().remove("api-key");
    request.headers_mut().remove("x-llm-token");
    if gateway.authentication.is_some() {
        let credential = api::gateway_credential(state, &effective, client_id, false).await?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", credential.credential))
            .map_err(|_| {
                (
                    StatusCode::BAD_GATEWAY,
                    "invalid gateway credential header".into(),
                )
            })?;
        authorization.set_sensitive(true);
        request.headers_mut().insert(AUTHORIZATION, authorization);
    }
    if let Some(github) = &gateway.github_oauth {
        // Both branches put a bare token in x-llm-token. The gateway is the one
        // that re-forms the header, with `"Bearer " + request.headers['x-llm-token']`,
        // so the prefix is added in exactly one place.
        let credential = match github.source {
            GitHubTokenSource::DeviceFlow => {
                let client_id = github.client_id.as_deref().ok_or((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "githubOAuth.clientId is required for deviceFlow".to_string(),
                ))?;
                crate::github_oauth::credential(client_id, &state.state_dir, None)
                    .await
                    .map_err(|error| (StatusCode::BAD_GATEWAY, format!("GitHub OAuth: {error:#}")))?
                    .credential
            }
            // Fail rather than forward a request that cannot succeed: without a
            // client credential the gateway would swap in an empty Authorization
            // and the provider would reject it with an error that looks like a
            // gateway fault.
            GitHubTokenSource::Request => client_credential.clone().ok_or((
                StatusCode::UNAUTHORIZED,
                "no client credential to forward; send it in Authorization or x-llm-token"
                    .to_string(),
            ))?,
        };
        let mut value = HeaderValue::from_str(&credential).map_err(|_| {
            (
                StatusCode::BAD_GATEWAY,
                "invalid GitHub credential header".into(),
            )
        })?;
        value.set_sensitive(true);
        request.headers_mut().insert("x-llm-token", value);
    }
    request.headers_mut().insert(
        HOST,
        HeaderValue::from_str(uri.authority().unwrap().as_str())
            .map_err(|_| (StatusCode::BAD_GATEWAY, "invalid gateway host".into()))?,
    );
    *request.uri_mut() = uri;
    let mut response = client
        .request(request)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
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
                    inventory_interval: Duration::from_secs(60), controller: None },
                discovery, enrollment: EnrollmentState::new(false), state_dir: dir.path().to_owned(),
                oidc_callback_listen: None, telemetry: None, logout: None,
            };
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_address = listener.local_addr().unwrap();
            let proxy = tokio::spawn(serve(listener, state, "vscode".into()));
            let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
            let mut release_tx = Some(release_tx);
            for _ in 0..2 {
                let request = Request::builder().method(Method::POST)
                    .uri(format!("http://{proxy_address}/v1/messages?value=%2F"))
                    .header(AUTHORIZATION, "Bearer must-not-forward")
                    .header("x-api-key", "must-not-forward")
                    .header("x-llm-token", "must-not-forward")
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
            let proxy = tokio::spawn(serve(listener, state, "vscode".into()));
            let client: Client<HttpConnector, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build_http();
            let request = Request::builder()
                .method(Method::POST)
                .uri(format!("http://{proxy_address}/chat/completions"))
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
            let proxy = tokio::spawn(serve(listener, state, "vscode".into()));
            let client: Client<HttpConnector, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build_http();
            let request = Request::builder()
                .method(Method::POST)
                .uri(format!("http://{proxy_address}/chat/completions"))
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap();
            let response = client.request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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
