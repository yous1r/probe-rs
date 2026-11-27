use anyhow::{bail, Context, Result};
use rprobe_common::{ClientMessage, ServerMessage};
use std::collections::VecDeque;
use std::net::{TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};
use tungstenite::client::IntoClientRequest;
use tungstenite::http::header::{HeaderValue, AUTHORIZATION};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{client_tls_with_config, Message, WebSocket};

use crate::collector::Collector;
type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

pub struct AgentConfig {
    pub server: String,
    pub agent_id: String,
    pub token: String,
    pub group: Option<String>,
    pub interval: Duration,
}

pub fn run(config: AgentConfig) -> Result<()> {
    let hello = ClientMessage::Hello {
        hello: Collector::hello(&config.agent_id, config.group.clone()),
    };
    let mut collector = Collector::default();
    let mut socket: Option<Socket> = None;
    let mut pending = VecDeque::<(i64, ClientMessage)>::new();
    let mut reconnect_delay = Duration::from_secs(1);
    let mut next_connect = Instant::now();
    let mut http_hello_sent = false;
    let http = http_client();

    loop {
        if socket.is_none() && Instant::now() >= next_connect {
            if let Ok(mut connected) = open_socket(&config) {
                if send_message(&mut connected, &hello).is_ok() {
                    socket = Some(connected);
                    http_hello_sent = false;
                    reconnect_delay = Duration::from_secs(1);
                }
            }
            if socket.is_none() {
                // Never log credentials, remote response bodies, or request headers.
                eprintln!("rprobe-agent: websocket unavailable; trying HTTP fallback");
                next_connect = Instant::now() + reconnect_delay;
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(60));
            }
        }

        let report = collector.collect();
        let collected_at = report.collected_at;
        pending.push_back((collected_at, ClientMessage::Report { report }));
        trim_pending(&mut pending, collected_at);

        if let Some(connected) = socket.as_mut() {
            let mut failed = read_control_frames(connected).is_err();
            if !failed {
                while let Some((_, message)) = pending.front() {
                    if send_message(connected, message).is_err() {
                        failed = true;
                        break;
                    }
                    pending.pop_front();
                }
            }
            if failed {
                socket = None;
                http_hello_sent = false;
                next_connect = Instant::now() + reconnect_delay;
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(60));
            }
        }

        if socket.is_none() {
            if !http_hello_sent {
                http_hello_sent = post_message(&http, &config, &hello).is_ok();
            }
            if http_hello_sent {
                // Bounded batch: do not monopolize collection while recovering through POST.
                for _ in 0..4 {
                    let Some((_, message)) = pending.front() else {
                        break;
                    };
                    match post_message(&http, &config, message) {
                        Ok(()) => {
                            pending.pop_front();
                        }
                        Err(409) => {
                            http_hello_sent = false;
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }
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
    while pending.len() > 301 {
        pending.pop_front();
    }
}

fn open_socket(config: &AgentConfig) -> Result<Socket> {
    let url = websocket_url(&config.server);
    let endpoint = url::Url::parse(&url).context("invalid endpoint")?;
    let host = match endpoint.host().context("missing endpoint host")? {
        url::Host::Domain(name) => name.to_owned(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    };
    let port = endpoint
        .port_or_known_default()
        .context("missing endpoint port")?;
    let addresses = (host.as_str(), port)
        .to_socket_addrs()
        .context("resolve endpoint")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = None;
    for address in addresses.take(8) {
        let budget = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(2));
        if budget.is_zero() {
            break;
        }
        if let Ok(connected) = TcpStream::connect_timeout(&address, budget) {
            stream = Some(connected);
            break;
        }
    }
    let stream = stream.context("connect endpoint")?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut request = url.into_client_request()?;
    let mut authorization = HeaderValue::from_str(&format!("Bearer {}", config.token))
        .context("invalid credential header")?;
    authorization.set_sensitive(true);
    request.headers_mut().insert(AUTHORIZATION, authorization);
    request
        .headers_mut()
        .insert("x-agent-id", HeaderValue::from_str(&config.agent_id)?);
    let limits = WebSocketConfig::default()
        .read_buffer_size(4096)
        .write_buffer_size(0)
        .max_write_buffer_size(65536)
        .max_message_size(Some(16384))
        .max_frame_size(Some(16384));
    // Direct handshake: no automatic redirect can forward credentials to another destination.
    let (socket, _) = client_tls_with_config(request, stream, Some(limits), None)
        .map_err(|_| anyhow::anyhow!("TLS/WebSocket handshake failed"))?;
    tcp_stream(&socket)?.set_read_timeout(Some(Duration::from_millis(20)))?;
    Ok(socket)
}

fn tcp_stream(socket: &Socket) -> Result<&TcpStream> {
    match socket.get_ref() {
        MaybeTlsStream::Plain(stream) => Ok(stream),
        MaybeTlsStream::Rustls(stream) => Ok(&stream.sock),
        _ => bail!("unsupported TLS transport"),
    }
}

fn read_control_frames(socket: &mut Socket) -> Result<()> {
    for _ in 0..16 {
        match socket.read() {
            Ok(Message::Text(text)) => {
                let ServerMessage::Config { interval_secs } = serde_json::from_str(text.as_str())?;
                if !(1..=60).contains(&interval_secs) {
                    bail!("invalid server interval");
                }
                // Local interval remains the operator's override. Only Config is understood; no commands.
            }
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {
                socket.flush()?;
            }
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(())
            }
            _ => bail!("connection closed or invalid control frame"),
        }
    }
    bail!("too many server control frames")
}

fn send_message(socket: &mut Socket, message: &ClientMessage) -> Result<()> {
    let json = serde_json::to_string(message)?;
    if json.len() > 16384 {
        bail!("report exceeds message limit");
    }
    socket
        .send(Message::Text(json.into()))
        .context("send report")
}

fn http_client() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(Duration::from_secs(3))
        .timeout_read(Duration::from_secs(5))
        .timeout_write(Duration::from_secs(5))
        .timeout(Duration::from_secs(5))
        .build()
}

fn post_message(
    http: &ureq::Agent,
    config: &AgentConfig,
    message: &ClientMessage,
) -> Result<(), u16> {
    let body = serde_json::to_value(message).map_err(|_| 0_u16)?;
    let response = http
        .post(&format!("{}/api/report", config.server))
        .set("Authorization", &format!("Bearer {}", config.token))
        .set("X-Agent-Id", &config.agent_id)
        .send_json(body)
        .map_err(|error| match error {
            ureq::Error::Status(code, _) => code,
            ureq::Error::Transport(_) => 0,
        })?;
    if !(200..300).contains(&response.status()) {
        return Err(response.status());
    }
    Ok(())
}

fn websocket_url(server: &str) -> String {
    let scheme = if server.starts_with("https://") {
        "wss://"
    } else {
        "ws://"
    };
    let host = server
        .strip_prefix("https://")
        .or_else(|| server.strip_prefix("http://"))
        .unwrap_or(server);
    format!("{scheme}{host}/ws/agent")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn uses_matching_transport_scheme() {
        assert_eq!(
            websocket_url("https://monitor.example"),
            "wss://monitor.example/ws/agent"
        );
        assert_eq!(
            websocket_url("http://127.0.0.1:8080"),
            "ws://127.0.0.1:8080/ws/agent"
        );
    }

    #[test]
    fn retains_five_minutes_at_one_second_intervals() {
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
    }

    #[test]
    fn neither_transport_follows_redirects() {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let redirect = format!("HTTP/1.1 302 Found\r\nLocation: http://{}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", destination.local_addr().unwrap());
        for websocket in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let response = redirect.clone();
            let thread = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = [0; 4096];
                let _ = stream.read(&mut bytes).unwrap();
                stream.write_all(response.as_bytes()).unwrap();
            });
            let config = AgentConfig {
                server: format!("http://{address}"),
                agent_id: "test".to_owned(),
                token: "test-credential-12345".to_owned(),
                group: None,
                interval: Duration::from_secs(5),
            };
            if websocket {
                assert!(open_socket(&config).is_err());
            } else {
                assert!(post_message(
                    &http_client(),
                    &config,
                    &ClientMessage::Hello {
                        hello: Collector::hello("test", None)
                    }
                )
                .is_err());
            }
            thread.join().unwrap();
            assert!(
                matches!(destination.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
            );
        }
    }
}
