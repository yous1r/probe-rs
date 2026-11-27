use crate::security::Controls;
use anyhow::{anyhow, bail, Context, Result};
use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::http::StatusCode;
use rand_core::OsRng;
use rprobe_common::secret::{read_secret_file, valid_token};
use rprobe_common::{AgentHello, ClientMessage, Group, HostSnapshot, MetricsReport};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, RwLock};

const MAX_GROUPS: usize = 500;
const MAX_AGENTS: usize = 1000;
const MAX_REPORT_AGE_SECS: i64 = 360;
const MAX_REPORT_FUTURE_SECS: i64 = 60;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    data: RwLock<ServerData>,
    agent_hashes: HashMap<String, String>,
    admin_token: String,
    offline_after_secs: u64,
    report_interval_secs: u64,
    events: broadcast::Sender<()>,
    controls: Controls,
}

#[derive(Default)]
struct ServerData {
    hosts: HashMap<String, HostRecord>,
    groups: BTreeMap<String, Group>,
}

struct HostRecord {
    hello: AgentHello,
    report: Option<MetricsReport>,
    last_seen_at: i64,
    group_id: Option<String>,
    clock_skew_secs: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IngestError {
    InvalidMessage,
    UnknownHost,
    InvalidGroup,
    RateLimited,
}

impl AppState {
    pub fn from_env() -> Result<Self> {
        let credentials = credential_setting("RPROBE_AGENT_TOKENS", 400_000)?;
        let admin = credential_setting("RPROBE_ADMIN_TOKEN", 1024)?;
        let offline = env_u64("RPROBE_OFFLINE_AFTER_SECS", 30)?;
        let interval = env_u64("RPROBE_REPORT_INTERVAL_SECS", 5)?;
        Self::new(&credentials, admin.trim().to_owned(), offline, interval)
    }

    pub(crate) fn new(
        credentials: &str,
        admin_token: String,
        offline: u64,
        interval: u64,
    ) -> Result<Self> {
        if !valid_token(&admin_token) {
            bail!("admin token must contain 16-256 visible ASCII characters");
        }
        if !(1..=3600).contains(&offline) || !(1..=60).contains(&interval) {
            bail!("offline threshold must be 1-3600 seconds; report interval must be 1-60 seconds");
        }
        let mut agent_hashes = HashMap::new();
        let mut unique_tokens = HashSet::new();
        for entry in credentials
            .split([',', '\n'])
            .map(str::trim)
            .filter(|e| !e.is_empty())
        {
            let (id, token) = entry
                .split_once('=')
                .ok_or_else(|| anyhow!("agent credentials require id=token"))?;
            let token = token.trim();
            if !valid_agent_id(id) || !valid_token(token) {
                bail!("invalid agent ID or token format");
            }
            if agent_hashes.len() >= MAX_AGENTS
                || agent_hashes.contains_key(id)
                || token == admin_token
                || !unique_tokens.insert(token)
            {
                bail!("agent IDs and tokens must be unique, distinct from admin credentials, with at most 1000 agents");
            }
            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
                .hash_password(token.as_bytes(), &salt)
                .map_err(|_| anyhow!("cannot hash agent credential"))?
                .to_string();
            agent_hashes.insert(id.to_owned(), hash);
        }
        if agent_hashes.is_empty() {
            bail!("configure at least one agent credential");
        }
        let controls = Controls::new(agent_hashes.keys().cloned());
        let (events, _) = broadcast::channel(256);
        Ok(Self(Arc::new(Inner {
            data: RwLock::new(ServerData::default()),
            agent_hashes,
            admin_token,
            offline_after_secs: offline,
            report_interval_secs: interval,
            events,
            controls,
        })))
    }

    pub fn controls(&self) -> &Controls {
        &self.0.controls
    }

    pub async fn authorize_agent(&self, agent_id: &str, token: &str) -> Result<(), StatusCode> {
        if !valid_agent_id(agent_id) || !valid_token(token) {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let hash = self
            .0
            .agent_hashes
            .get(agent_id)
            .ok_or(StatusCode::UNAUTHORIZED)?
            .clone();
        self.controls().authentication(agent_id)?;
        let permit = self
            .controls()
            .auth_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
        let token = token.to_owned();
        // CPU-heavy verification never blocks Tokio's I/O workers; the permit lives in this job.
        let valid = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            PasswordHash::new(&hash).is_ok_and(|parsed| {
                Argon2::default()
                    .verify_password(token.as_bytes(), &parsed)
                    .is_ok()
            })
        })
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if valid {
            Ok(())
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }

    pub fn authorize_admin(&self, token: &str) -> bool {
        valid_token(token) && bool::from(self.0.admin_token.as_bytes().ct_eq(token.as_bytes()))
    }

    pub fn report_interval_secs(&self) -> u64 {
        self.0.report_interval_secs
    }
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.0.events.subscribe()
    }

    pub async fn ingest(
        &self,
        agent_id: &str,
        message: ClientMessage,
        received_at: i64,
    ) -> Result<(), IngestError> {
        if !self.0.agent_hashes.contains_key(agent_id) {
            return Err(IngestError::UnknownHost);
        }
        let mut data = self.0.data.write().await;
        match message {
            ClientMessage::Hello { hello } => {
                if hello.agent_id != agent_id || !valid_hello(&hello) {
                    return Err(IngestError::InvalidMessage);
                }
                self.controls()
                    .hello(agent_id)
                    .map_err(|_| IngestError::RateLimited)?;
                if let Some(host) = data.hosts.get_mut(agent_id) {
                    // Preserve manual assignment, including an explicit move to 'ungrouped'.
                    host.hello = hello;
                } else {
                    let group_id = hello
                        .group
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned);
                    if let Some(id) = &group_id {
                        if !data.groups.contains_key(id) {
                            if data.groups.len() >= MAX_GROUPS {
                                return Err(IngestError::InvalidGroup);
                            }
                            data.groups.insert(
                                id.clone(),
                                Group {
                                    id: id.clone(),
                                    name: id.clone(),
                                    parent_id: None,
                                    sort: 0,
                                    color: None,
                                },
                            );
                        }
                    }
                    data.hosts.insert(
                        agent_id.to_owned(),
                        HostRecord {
                            hello,
                            report: None,
                            last_seen_at: received_at,
                            group_id,
                            clock_skew_secs: None,
                        },
                    );
                }
            }
            ClientMessage::Report { report } => {
                if !valid_report(&report)
                    || report.collected_at < received_at.saturating_sub(MAX_REPORT_AGE_SECS)
                    || report.collected_at > received_at.saturating_add(MAX_REPORT_FUTURE_SECS)
                {
                    return Err(IngestError::InvalidMessage);
                }
                let host = data
                    .hosts
                    .get_mut(agent_id)
                    .ok_or(IngestError::UnknownHost)?;
                if host
                    .report
                    .as_ref()
                    .is_some_and(|current| report.collected_at <= current.collected_at)
                {
                    // HTTP-delivered records may be replayed over WS; idempotent, without extending liveness.
                    return Ok(());
                }
                host.clock_skew_secs = Some(received_at.saturating_sub(report.collected_at));
                host.report = Some(report);
                host.last_seen_at = received_at;
            }
        }
        drop(data);
        let _ = self.0.events.send(());
        Ok(())
    }

    pub async fn overview(&self, now: i64) -> (Vec<HostSnapshot>, Vec<Group>) {
        let data = self.0.data.read().await;
        let mut hosts: Vec<_> = data
            .hosts
            .values()
            .map(|host| HostSnapshot {
                hello: host.hello.clone(),
                report: host.report.clone(),
                last_seen_at: host.last_seen_at,
                online: now.saturating_sub(host.last_seen_at) <= self.0.offline_after_secs as i64,
                group_id: host.group_id.clone(),
                clock_skew_secs: host.clock_skew_secs,
            })
            .collect();
        hosts.sort_by(|a, b| a.hello.hostname.cmp(&b.hello.hostname));
        (hosts, data.groups.values().cloned().collect())
    }

    pub async fn create_group(&self, group: Group) -> Result<(), IngestError> {
        if !bounded_text(&group.id, 64, false)
            || !bounded_text(&group.name, 100, false)
            || group
                .parent_id
                .as_ref()
                .is_some_and(|p| !bounded_text(p, 64, false))
        {
            return Err(IngestError::InvalidGroup);
        }
        let mut data = self.0.data.write().await;
        if data.groups.len() >= MAX_GROUPS || data.groups.contains_key(&group.id) {
            return Err(IngestError::InvalidGroup);
        }
        if let Some(parent_id) = &group.parent_id {
            if parent_id == &group.id
                || !data
                    .groups
                    .get(parent_id)
                    .is_some_and(|p| p.parent_id.is_none())
            {
                return Err(IngestError::InvalidGroup);
            }
        }
        data.groups.insert(group.id.clone(), group);
        drop(data);
        let _ = self.0.events.send(());
        Ok(())
    }

    pub async fn assign_group(
        &self,
        agent_id: &str,
        group_id: Option<String>,
    ) -> Result<(), IngestError> {
        let mut data = self.0.data.write().await;
        if group_id
            .as_ref()
            .is_some_and(|id| !data.groups.contains_key(id))
        {
            return Err(IngestError::InvalidGroup);
        }
        data.hosts
            .get_mut(agent_id)
            .ok_or(IngestError::UnknownHost)?
            .group_id = group_id;
        drop(data);
        let _ = self.0.events.send(());
        Ok(())
    }
}

fn credential_setting(name: &str, max_bytes: u64) -> Result<String> {
    match (
        std::env::var(name).ok(),
        std::env::var(format!("{name}_FILE")).ok(),
    ) {
        (Some(_), Some(_)) => bail!("set only one of {name} or {name}_FILE"),
        (Some(value), None) if value.len() as u64 <= max_bytes => Ok(value),
        (None, Some(path)) => read_secret_file(Path::new(&path), max_bytes)
            .with_context(|| format!("read {name}_FILE")),
        _ => bail!("{name} or {name}_FILE is required and must fit the size limit"),
    }
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    std::env::var(name)
        .ok()
        .map(|s| {
            s.parse()
                .with_context(|| format!("{name} must be an integer"))
        })
        .unwrap_or(Ok(default))
}

fn valid_agent_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn bounded_text(s: &str, maximum: usize, empty: bool) -> bool {
    s.len() <= maximum && (empty || !s.trim().is_empty()) && !s.chars().any(char::is_control)
}

fn valid_hello(hello: &AgentHello) -> bool {
    hello.protocol_version == rprobe_common::PROTOCOL_VERSION
        && bounded_text(&hello.hostname, 255, false)
        && bounded_text(&hello.agent_version, 64, false)
        && bounded_text(&hello.os, 64, false)
        && bounded_text(&hello.kernel, 255, false)
        && bounded_text(&hello.cpu_model, 512, false)
        && bounded_text(&hello.virtualization, 64, false)
        && (1..=65536).contains(&hello.cpu_cores)
        && hello.memory_total_bytes < (1 << 62)
        && hello
            .cgroup_memory_limit_bytes
            .is_none_or(|n| n > 0 && n < (1 << 62))
        && hello
            .cgroup_cpu_limit_cores
            .is_none_or(|n| n.is_finite() && n > 0.0 && n <= 65536.0)
        && hello
            .group
            .as_ref()
            .is_none_or(|s| bounded_text(s, 64, true))
}

fn valid_report(report: &MetricsReport) -> bool {
    report.collected_at > 0
        && report.cpu_percent.is_finite()
        && (0.0..=100.0).contains(&report.cpu_percent)
        && [report.load1, report.load5, report.load15]
            .into_iter()
            .all(|n| n.is_finite() && (0.0..=1_000_000.0).contains(&n))
        && [
            report.memory_limit_bytes,
            report.memory_used_bytes,
            report.swap_total_bytes,
            report.swap_used_bytes,
            report.disk_total_bytes,
            report.disk_used_bytes,
        ]
        .into_iter()
        .all(|n| n < (1 << 62))
        && report.openvz_beancounters.len() <= 64
        && report.openvz_beancounters.keys().all(|s| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

pub fn unix_time_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
pub(crate) fn test_state() -> AppState {
    AppState::new(
        "node-a=test-agent-credential-12345,node-b=other-agent-credential-12345",
        "test-admin-credential-12345".to_owned(),
        30,
        5,
    )
    .unwrap()
}

#[cfg(test)]
pub(crate) fn test_hello() -> ClientMessage {
    ClientMessage::Hello {
        hello: AgentHello {
            agent_id: "node-a".to_owned(),
            agent_version: "0.1.0".to_owned(),
            protocol_version: 1,
            hostname: "test".to_owned(),
            os: "linux".to_owned(),
            kernel: "test".to_owned(),
            cpu_model: "test".to_owned(),
            cpu_cores: 1,
            memory_total_bytes: 1024,
            virtualization: "test".to_owned(),
            cgroup_memory_limit_bytes: None,
            cgroup_cpu_limit_cores: None,
            group: Some("initial".to_owned()),
        },
    }
}

#[cfg(test)]
pub(crate) fn test_report(timestamp: i64) -> ClientMessage {
    ClientMessage::Report {
        report: MetricsReport {
            collected_at: timestamp,
            cpu_percent: 1.0,
            memory_used_bytes: 1,
            memory_limit_bytes: 1024,
            swap_used_bytes: 0,
            swap_total_bytes: 0,
            disk_used_bytes: 1,
            disk_total_bytes: 10,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
            rx_bytes_per_sec: 0,
            tx_bytes_per_sec: 0,
            rx_bytes_total: 1,
            tx_bytes_total: 1,
            tcp_connections: 0,
            udp_connections: 0,
            process_count: 1,
            uptime_secs: 1,
            openvz_beancounters: BTreeMap::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn identity_replay_time_window_and_groups_are_bounded() {
        let state = test_state();
        assert_eq!(
            state.ingest("node-b", test_hello(), 1000).await,
            Err(IngestError::InvalidMessage)
        );
        state.ingest("node-a", test_hello(), 1000).await.unwrap();
        state
            .ingest("node-a", test_report(700), 1000)
            .await
            .unwrap(); // 5-minute replay
        state
            .ingest("node-a", test_report(1000), 1000)
            .await
            .unwrap();
        state
            .ingest("node-a", test_report(1000), 1040)
            .await
            .unwrap(); // duplicate cannot keep online
        assert!(!state.overview(1040).await.0[0].online);
        assert_eq!(
            state.ingest("node-a", test_report(1), 1040).await,
            Err(IngestError::InvalidMessage)
        );
        assert_eq!(
            state.ingest("node-a", test_report(i64::MAX), 1040).await,
            Err(IngestError::InvalidMessage)
        );
        state.assign_group("node-a", None).await.unwrap();
        let ClientMessage::Hello { mut hello } = test_hello() else {
            unreachable!()
        };
        hello.group = Some("arbitrary-new-group".to_owned());
        state
            .ingest("node-a", ClientMessage::Hello { hello }, 1040)
            .await
            .unwrap();
        let (hosts, groups) = state.overview(1040).await;
        assert!(hosts[0].group_id.is_none());
        assert_eq!(groups.len(), 1);
        assert!(!hosts[0].online);
    }

    #[test]
    fn rejects_control_strings_unbounded_maps_and_invalid_numbers() {
        let ClientMessage::Hello { mut hello } = test_hello() else {
            unreachable!()
        };
        hello.hostname = "line\nforge".to_owned();
        assert!(!valid_hello(&hello));
        let ClientMessage::Report { mut report } = test_report(100) else {
            unreachable!()
        };
        report.cpu_percent = f32::NAN;
        assert!(!valid_report(&report));
        report.cpu_percent = 100.1;
        assert!(!valid_report(&report));
        report.cpu_percent = 1.0;
        report.load1 = -1.0;
        assert!(!valid_report(&report));
        assert!(!valid_agent_id("../admin"));
    }

    #[tokio::test]
    async fn rejects_wrong_or_cross_agent_credentials() {
        let state = test_state();
        assert!(state
            .authorize_agent("node-a", "test-agent-credential-12345")
            .await
            .is_ok());
        assert_eq!(
            state
                .authorize_agent("node-b", "test-agent-credential-12345")
                .await,
            Err(StatusCode::UNAUTHORIZED)
        );
        assert!(!state.authorize_admin("test-agent-credential-12345"));
        assert!(AppState::new(
            "a=test-admin-credential-12345",
            "test-admin-credential-12345".to_owned(),
            30,
            5
        )
        .is_err());
    }
}
