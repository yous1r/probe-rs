use anyhow::{Context, Result};
use rprobe_common::ClientMessage;
use std::collections::VecDeque;
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};
use tungstenite::client::IntoClientRequest;
use tungstenite::http::header::{HeaderValue, AUTHORIZATION};
use tungstenite::{connect, Message, WebSocket};

use crate::collector::Collector;

pub struct AgentConfig {
    pub server: String,
    pub agent_id: String,
    pub token: String,
    pub group: Option<String>,
    pub interval: Duration,
}

pub fn run(config: AgentConfig) -> Result<()> {
    let hello = Collector::hello(&config.agent_id, config.group.clone());
    let mut collector = Collector::default();
    let mut socket: Option<WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>> = None;
    let mut pending = VecDeque::<(i64, ClientMessage)>::new();
    let mut reconnect_delay = Duration::from_secs(1);
    let mut next_connect = Instant::now();
    let mut http_hello_sent = false;

    loop {
        if socket.is_none() && Instant::now() >= next_connect {
            match open_socket(&config) {
                Ok(mut connected) => {
                    if send_message(
                        &mut connected,
                        &ClientMessage::Hello {
                            hello: hello.clone(),
                        },
                    )
                    .is_ok()
                    {
                        socket = Some(connected);
                        http_hello_sent = false;
                        reconnect_delay = Duration::from_secs(1);
                    }
                }
                Err(error) => {
                    eprintln!("rprobe-agent: websocket unavailable: {error:#}");
                }
            }
            if socket.is_none() {
                next_connect = Instant::now() + reconnect_delay;
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(60));
            }
        }

        let report = collector.collect();
        let collected_at = report.collected_at;
        pending.push_back((
            collected_at,
            ClientMessage::Report {
                report: report.clone(),
            },
        ));
        trim_pending(&mut pending, collected_at);

        if let Some(connected) = socket.as_mut() {
            let mut failed = false;
            while let Some((_, message)) = pending.front() {
                if send_message(connected, message).is_err() {
                    failed = true;
                    break;
                }
                pending.pop_front();
            }
            if failed {
                socket = None;
                next_connect = Instant::now() + reconnect_delay;
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(60));
            }
        }

        if socket.is_none() {
            if !http_hello_sent {
                http_hello_sent = post_message(
                    &config,
                    &ClientMessage::Hello {
                        hello: hello.clone(),
                    },
                )
                .is_ok();
            }
            let _ = post_message(&config, &ClientMessage::Report { report });
        }

        thread::sleep(config.interval);
    }
}

fn trim_pending(pending: &mut VecDeque<(i64, ClientMessage)>, collected_at: i64) {
    while pending
        .front()
        .is_some_and(|(timestamp, _)| collected_at.saturating_sub(*timestamp) > 300)
    {
        pending.pop_front();
    }
    // The CLI permits a one-second interval: five minutes need up to 301 samples.
    while pending.len() > 301 {
        pending.pop_front();
    }
}

fn open_socket(config: &AgentConfig) -> Result<WebSocket<tungite_stream::TlsTcpStream>> {
    let url = websocket_url(&config.server);
    let mut request = url.into_client_request().context("invalid websocket URL")?;
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", config.token))
            .context("invalid token header")?,
    );
    request.headers_mut().insert(
        "x-agent-id",
        HeaderValue::from_str(&config.agent_id).context("invalid agent ID header")?,
    );
    let (socket, _) = connect(request).context("websocket connection failed")?;
    Ok(socket)
}

fn send_message(
    socket: &mut WebSocket<tungite_stream::TlsTcpStream>,
    message: &ClientMessage,
) -> Result<()> {
    let json = serde_json::to_string(message).context("serialize protocol message")?;
    socket
        .send(Message::Text(json.into()))
        .context("send websocket message")
}

fn post_message(config: &AgentConfig, message: &ClientMessage) -> Result<()> {
    let body = serde_json::to_value(message).context("serialize HTTP message")?;
    let response = ureq::post(&format!("{}/api/report", config.server))
        .set("Authorization", &format!("Bearer {}", config.token))
        .set("X-Agent-Id", &config.agent_id)
        .send_json(body)
        .context("HTTP report fallback failed")?;
    if response.status() >= 400 {
        anyhow::bail!("HTTP report returned status {}", response.status());
    }
    Ok(())
}

fn websocket_url(server: &str) -> String {
    let scheme = if server.starts_with("https://") {
        "wss://"
    } else {
        "ws://"
    };
    let host_and_path = server
        .strip_prefix("https://")
        .or_else(|| server.strip_prefix("http://"))
        .unwrap_or(server);
    format!("{scheme}{host_and_path}/ws/agent")
}

mod tungite_stream {
    use std::net::TcpStream;
    pub type TlsTcpStream = tungstenite::stream::MaybeTlsStream<TcpStream>;
}

#[cfg(test)]
mod tests {
    use super::websocket_url;

    #[test]
    fn uses_tls_websocket_for_https_server() {
        assert_eq!(
            websocket_url("https://monitor.example"),
            "wss://monitor.example/ws/agent"
        );
    }

    #[test]
    fn keeps_plain_http_for_local_development() {
        assert_eq!(
            websocket_url("http://127.0.0.1:8080"),
            "ws://127.0.0.1:8080/ws/agent"
        );
    }
    #[test]
    fn retains_five_minutes_at_one_second_intervals() {
        use super::trim_pending;
        use crate::collector::Collector;
        use rprobe_common::ClientMessage;
        use std::collections::VecDeque;
        let message = ClientMessage::Hello {
            hello: Collector::hello("test", None),
        };
        let mut pending = VecDeque::new();
        for timestamp in 0..=360 {
            pending.push_back((timestamp, message.clone()));
            trim_pending(&mut pending, timestamp);
        }
        assert_eq!(pending.len(), 301);
        assert_eq!(pending.front().unwrap().0, 60);
        assert_eq!(pending.back().unwrap().0, 360);
    }
}
