use crate::security::{AgentConnection, MESSAGE_LIMIT};
use crate::state::{unix_time_secs, AppState, IngestError};
use async_stream::stream;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, Response};
use axum::routing::{get, patch, post};
use axum::{Extension, Json, Router};
use futures_util::StreamExt;
use rprobe_common::{ClientMessage, Group, HostSnapshot, ServerMessage};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::time::Duration;
use tokio::time::{timeout, timeout_at, Instant};

#[derive(Clone)]
struct AgentIdentity(String);

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/overview", get(overview))
        .route("/api/events", get(events))
        .route("/api/groups", get(list_groups).post(create_group))
        .route("/api/hosts/{id}/group", patch(assign_group))
        .route("/api/report", post(http_ingest))
        .route("/ws/agent", get(websocket_upgrade))
        .layer(DefaultBodyLimit::max(MESSAGE_LIMIT))
        .layer(middleware::from_fn_with_state(state.clone(), protect))
        .with_state(state)
}

// Runs before body extraction so unauthenticated clients cannot trigger JSON work or state changes.
async fn protect(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let _permit = state.controls().request()?;
    let path = request.uri().path();
    if path == "/api/report" || path == "/ws/agent" {
        // Agents are native clients. Browser origins are never needed on this endpoint.
        if request.headers().contains_key(header::ORIGIN) {
            return Err(StatusCode::FORBIDDEN);
        }
        let id = single_header(request.headers(), "x-agent-id")
            .ok_or(StatusCode::UNAUTHORIZED)?
            .to_owned();
        let token = bearer_token(request.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
        state.authorize_agent(&id, token).await?;
        request.extensions_mut().insert(AgentIdentity(id));
    } else if path.starts_with("/api/") {
        require_admin(&state, request.headers())?;
    }
    let mut response = timeout(Duration::from_secs(10), next.run(request))
        .await
        .map_err(|_| StatusCode::REQUEST_TIMEOUT)?;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    Ok(response)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

#[derive(Serialize)]
struct Overview {
    hosts: Vec<HostSnapshot>,
    groups: Vec<Group>,
    generated_at: i64,
}

async fn overview(State(state): State<AppState>) -> Json<Overview> {
    let generated_at = unix_time_secs();
    let (hosts, groups) = state.overview(generated_at).await;
    Json(Overview {
        hosts,
        groups,
        generated_at,
    })
}

async fn list_groups(State(state): State<AppState>) -> Json<Vec<Group>> {
    Json(state.overview(unix_time_secs()).await.1)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateGroupRequest {
    id: Option<String>,
    name: String,
    parent_id: Option<String>,
    sort: Option<i32>,
    color: Option<String>,
}

async fn create_group(
    State(state): State<AppState>,
    Json(body): Json<CreateGroupRequest>,
) -> Result<StatusCode, StatusCode> {
    let name = body.name.trim();
    let id = body.id.unwrap_or_else(|| slug(name));
    if body.color.as_deref().is_some_and(|c| !valid_color(c)) {
        return Err(StatusCode::BAD_REQUEST);
    }
    state
        .create_group(Group {
            id,
            name: name.to_owned(),
            parent_id: body.parent_id,
            sort: body.sort.unwrap_or(0),
            color: body.color,
        })
        .await
        .map_err(ingest_status)?;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignGroupRequest {
    group_id: Option<String>,
}

async fn assign_group(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<AssignGroupRequest>,
) -> Result<StatusCode, StatusCode> {
    state
        .assign_group(&id, body.group_id)
        .await
        .map_err(|error| match error {
            IngestError::UnknownHost => StatusCode::NOT_FOUND,
            _ => ingest_status(error),
        })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn http_ingest(
    State(state): State<AppState>,
    Extension(AgentIdentity(id)): Extension<AgentIdentity>,
    Json(message): Json<ClientMessage>,
) -> Result<StatusCode, StatusCode> {
    state.controls().frame(&id)?;
    state
        .ingest(&id, message, unix_time_secs())
        .await
        .map_err(ingest_status)?;
    Ok(StatusCode::ACCEPTED)
}

async fn websocket_upgrade(
    State(state): State<AppState>,
    Extension(AgentIdentity(id)): Extension<AgentIdentity>,
    ws: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    let connection = state.controls().connection(&id)?;
    Ok(ws
        .max_frame_size(MESSAGE_LIMIT)
        .max_message_size(MESSAGE_LIMIT)
        .write_buffer_size(4096)
        .max_write_buffer_size(65536)
        .on_upgrade(move |socket| handle_socket(socket, state, id, connection)))
}

async fn handle_socket(
    mut socket: WebSocket,
    state: AppState,
    id: String,
    _connection: AgentConnection,
) {
    let config = ServerMessage::Config {
        interval_secs: state.report_interval_secs(),
    };
    let Ok(json) = serde_json::to_string(&config) else {
        return;
    };
    if !matches!(
        timeout(
            Duration::from_secs(5),
            socket.send(Message::Text(json.into()))
        )
        .await,
        Ok(Ok(()))
    ) {
        return;
    }
    let mut introduced = false;
    let mut deadline = Instant::now() + Duration::from_secs(10);
    while let Ok(Some(Ok(frame))) = timeout_at(deadline, socket.next()).await {
        if state.controls().frame(&id).is_err() {
            break;
        }
        match frame {
            Message::Text(text) => {
                let Ok(message) = serde_json::from_str::<ClientMessage>(text.as_str()) else {
                    break;
                };
                if !introduced && !matches!(&message, ClientMessage::Hello { .. }) {
                    break;
                }
                if state.ingest(&id, message, unix_time_secs()).await.is_err() {
                    break;
                }
                introduced = true;
                deadline = Instant::now() + Duration::from_secs(90);
            }
            Message::Ping(payload) if introduced => {
                if !matches!(
                    timeout(Duration::from_secs(5), socket.send(Message::Pong(payload))).await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
            Message::Pong(_) if introduced => {}
            _ => break,
        }
    }
    // Dropping the socket releases the per-agent slot. Do not wait for an untrusted close handshake.
}

async fn events(
    State(state): State<AppState>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let permit = state.controls().events()?;
    let mut receiver = state.subscribe();
    let stream = stream! {
        let _permit = permit;
        loop {
            // Periodic updates also recompute offline status when agents have stopped reporting.
            let _ = timeout(Duration::from_secs(5), receiver.recv()).await;
            yield Ok(Event::default().event("update").data("refresh"));
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };
    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    if bearer_token(headers).is_some_and(|t| state.authorize_admin(t)) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    single_header(headers, "authorization")?.strip_prefix("Bearer ")
}

fn ingest_status(error: IngestError) -> StatusCode {
    match error {
        IngestError::UnknownHost => StatusCode::CONFLICT,
        IngestError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        IngestError::InvalidMessage | IngestError::InvalidGroup => StatusCode::BAD_REQUEST,
    }
}

fn slug(name: &str) -> String {
    let normalized: String = name
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else if c.is_ascii_whitespace() || c == '-' || c == '_' {
                '-'
            } else {
                'x'
            }
        })
        .collect();
    let result = normalized.trim_matches('-');
    if result.is_empty() {
        "group".to_owned()
    } else {
        result.to_owned()
    }
}

fn valid_color(c: &str) -> bool {
    c.len() == 7 && c.starts_with('#') && c[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{test_hello, test_state};
    use axum::body::Body;
    use tower::ServiceExt;

    fn request(path: &str, token: Option<&str>, body: String) -> Request {
        let mut request = Request::builder()
            .uri(path)
            .method(if body.is_empty() { "GET" } else { "POST" })
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        request.body(Body::from(body)).unwrap()
    }

    #[tokio::test]
    async fn private_routes_require_admin_and_auth_precedes_json() {
        let app = router(test_state());
        for path in ["/api/overview", "/api/groups", "/api/events"] {
            assert_eq!(
                app.clone()
                    .oneshot(request(path, None, String::new()))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                app.clone()
                    .oneshot(request(
                        path,
                        Some("test-agent-credential-12345"),
                        String::new()
                    ))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            app.clone()
                .oneshot(request("/api/report", None, "invalid-json".to_owned()))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = app
            .oneshot(request(
                "/api/overview",
                Some("test-admin-credential-12345"),
                String::new(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn rejects_large_bodies_cross_agent_ids_and_browser_agent_origins() {
        let state = test_state();
        let app = router(state.clone());
        let response = app
            .clone()
            .oneshot(request(
                "/api/groups",
                Some("test-admin-credential-12345"),
                "x".repeat(MESSAGE_LIMIT + 1),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let mut req = request(
            "/api/report",
            Some("test-agent-credential-12345"),
            serde_json::to_string(&test_hello()).unwrap(),
        );
        req.headers_mut()
            .insert("x-agent-id", HeaderValue::from_static("node-b"));
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let mut req = request(
            "/api/report",
            Some("test-agent-credential-12345"),
            serde_json::to_string(&test_hello()).unwrap(),
        );
        req.headers_mut()
            .insert("x-agent-id", HeaderValue::from_static("node-a"));
        req.headers_mut().insert(
            header::ORIGIN,
            HeaderValue::from_static("https://untrusted.example"),
        );
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert!(state.overview(unix_time_secs()).await.0.is_empty());
    }

    #[test]
    fn rejects_ambiguous_credentials() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer first"),
        );
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer second"),
        );
        assert!(bearer_token(&headers).is_none());
        assert!(valid_color("#12aBef"));
        assert!(!valid_color("#12xyef"));
        assert_eq!(slug("Free VPS"), "free-vps");
    }
}
