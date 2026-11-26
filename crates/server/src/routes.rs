use crate::state::{unix_time_secs, AppState, IngestError};
use async_stream::stream;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use futures_util::StreamExt;
use rprobe_common::{ClientMessage, Group, HostSnapshot, ServerMessage};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::time::Duration;
use tracing::{debug, warn};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/overview", get(overview))
        .route("/api/events", get(events))
        .route("/api/groups", get(list_groups).post(create_group))
        .route("/api/hosts/{id}/group", patch(assign_group))
        .route("/api/report", post(http_ingest))
        .route("/ws/agent", get(websocket_upgrade))
        .with_state(state)
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

async fn overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Overview>, StatusCode> {
    require_admin(&state, &headers)?;
    let (hosts, groups) = state.overview(unix_time_secs()).await;
    Ok(Json(Overview {
        hosts,
        groups,
        generated_at: unix_time_secs(),
    }))
}

async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Group>>, StatusCode> {
    require_admin(&state, &headers)?;
    let (_, groups) = state.overview(unix_time_secs()).await;
    Ok(Json(groups))
}

#[derive(Deserialize)]
struct CreateGroupRequest {
    id: Option<String>,
    name: String,
    parent_id: Option<String>,
    sort: Option<i32>,
    color: Option<String>,
}

async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateGroupRequest>,
) -> Result<StatusCode, StatusCode> {
    require_admin(&state, &headers)?;
    let name = body.name.trim();
    let id = body.id.unwrap_or_else(|| slug(name));
    if body
        .color
        .as_deref()
        .is_some_and(|color| !valid_color(color))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let group = Group {
        id,
        name: name.to_owned(),
        parent_id: body.parent_id,
        sort: body.sort.unwrap_or(0),
        color: body.color,
    };
    state
        .create_group(group)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct AssignGroupRequest {
    group_id: Option<String>,
}

async fn assign_group(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<AssignGroupRequest>,
) -> Result<StatusCode, StatusCode> {
    require_admin(&state, &headers)?;
    state
        .assign_group(&id, body.group_id)
        .await
        .map_err(|error| match error {
            IngestError::UnknownHost => StatusCode::NOT_FOUND,
            _ => StatusCode::BAD_REQUEST,
        })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn http_ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(message): Json<ClientMessage>,
) -> Result<StatusCode, StatusCode> {
    let agent_id = headers
        .get("x-agent-id")
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    if !state.authorize_agent(agent_id, token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    state
        .ingest(agent_id, message, unix_time_secs())
        .await
        .map_err(ingest_status)?;
    Ok(StatusCode::ACCEPTED)
}

async fn websocket_upgrade(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    let agent_id = headers
        .get("x-agent-id")
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_owned();
    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    if !state.authorize_agent(&agent_id, token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state, agent_id)))
}

async fn handle_socket(mut socket: WebSocket, state: AppState, agent_id: String) {
    let config = ServerMessage::Config {
        interval_secs: state.report_interval_secs(),
    };
    if let Ok(json) = serde_json::to_string(&config) {
        if socket.send(Message::Text(json.into())).await.is_err() {
            return;
        }
    }
    while let Some(frame) = socket.next().await {
        match frame {
            Ok(Message::Text(text)) => match serde_json::from_str::<ClientMessage>(text.as_str()) {
                Ok(message) => {
                    if let Err(error) = state.ingest(&agent_id, message, unix_time_secs()).await {
                        warn!(agent_id, ?error, "discarding invalid agent message");
                    }
                }
                Err(error) => warn!(agent_id, %error, "invalid protocol JSON"),
            },
            Ok(Message::Ping(payload)) => {
                if socket.send(Message::Pong(payload)).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(Message::Binary(_)) | Ok(Message::Pong(_)) => {
                debug!(agent_id, "ignoring non-text agent frame");
            }
        }
    }
}

async fn events(
    State(state): State<AppState>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let mut receiver = state.subscribe();
    let stream = stream! {
        loop {
            match receiver.recv().await {
                Ok(()) => yield Ok(Event::default().event("update").data("refresh")),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    yield Ok(Event::default().event("update").data("refresh"));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let token = bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    if state.authorize_admin(token) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn ingest_status(error: IngestError) -> StatusCode {
    match error {
        IngestError::UnknownHost => StatusCode::CONFLICT,
        IngestError::InvalidMessage | IngestError::InvalidGroup => StatusCode::BAD_REQUEST,
    }
}

fn slug(name: &str) -> String {
    let normalized: String = name
        .trim()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else if character.is_ascii_whitespace() || character == '-' || character == '_' {
                '-'
            } else {
                'x'
            }
        })
        .collect();
    let slug = normalized.trim_matches('-');
    if slug.is_empty() {
        "group".to_owned()
    } else {
        slug.to_owned()
    }
}

fn valid_color(color: &str) -> bool {
    color.len() == 7
        && color.starts_with('#')
        && color[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::{slug, valid_color};

    #[test]
    fn normalizes_group_slugs() {
        assert_eq!(slug("Free VPS"), "free-vps");
        assert_eq!(slug("免费机"), "xxx");
    }

    #[test]
    fn only_accepts_hex_colors() {
        assert!(valid_color("#12aBef"));
        assert!(!valid_color("red"));
        assert!(!valid_color("#12xyef"));
    }
}
