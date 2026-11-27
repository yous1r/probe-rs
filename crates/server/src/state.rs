use crate::security::Controls;
use crate::storage::{LoadedState, Storage};
use anyhow::{anyhow, bail, Context, Result};
use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::http::StatusCode;
use rand_core::OsRng;
use rprobe_common::secret::{read_secret_file, valid_token};
use rprobe_common::{AgentHello, ClientMessage, Group, HostSnapshot, MetricsReport};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, RwLock, Semaphore};

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
    storage: Storage,
    mutations: Arc<Semaphore>,
}

#[derive(Default)]
struct ServerData {
    hosts: HashMap<String, HostRecord>,
    groups: BTreeMap<String, Group>,
}

#[derive(Clone)]
struct HostRecord {
    hello: AgentHello,
    report: Option<MetricsReport>,
    last_seen_at: i64,
    group_id: Option<String>,
    clock_skew_secs: Option<i64>,
    received_in_session: bool,
}

impl HostRecord {
    fn snapshot(&self, now: i64, offline_after_secs: u64) -> HostSnapshot {
        HostSnapshot {
            hello: self.hello.clone(),
            report: self.report.clone(),
            last_seen_at: self.last_seen_at,
            group_id: self.group_id.clone(),
            clock_skew_secs: self.clock_skew_secs,
            online: self.received_in_session
                && now.saturating_sub(self.last_seen_at) <= offline_after_secs as i64,
        }
    }
}

impl ServerData {
    fn restore(saved: LoadedState) -> Result<Self> {
        let groups: BTreeMap<_, _> = saved
            .groups
            .into_iter()
            .map(|g| (g.id.clone(), g))
            .collect();
        for group in groups.values() {
            if !bounded_text(&group.id, 64, false)
                || !bounded_text(&group.name, 100, false)
                || group.parent_id.as_ref().is_some_and(|parent| {
                    parent == &group.id
                        || !groups.get(parent).is_some_and(|g| g.parent_id.is_none())
                })
            {
                bail!("invalid saved group; refusing to start with an inconsistent registry");
            }
        }
        let mut hosts = HashMap::new();
        for host in saved.hosts {
            if !valid_agent_id(&host.hello.agent_id)
                || !valid_hello(&host.hello)
                || host.report.as_ref().is_some_and(|r| !valid_report(r))
                || host
                    .group_id
                    .as_ref()
                    .is_some_and(|id| !groups.contains_key(id))
            {
                bail!("invalid saved host; refusing to discard existing records");
            }
            hosts.insert(
                host.hello.agent_id.clone(),
                HostRecord {
                    hello: host.hello,
                    report: host.report,
                    last_seen_at: host.last_seen_at,
                    group_id: host.group_id,
                    clock_skew_secs: host.clock_skew_secs,
                    received_in_session: false,
                },
            );
        }
        Ok(Self { hosts, groups })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum IngestError {
    InvalidMessage,
    UnknownHost,
    InvalidGroup,
    RateLimited,
    StorageUnavailable,
}

impl AppState {
    pub async fn from_env() -> Result<Self> {
        let credentials = credential_setting("RPROBE_AGENT_TOKENS", 400_000)?;
        let admin = credential_setting("RPROBE_ADMIN_TOKEN", 1024)?;
        let offline = env_u64("RPROBE_OFFLINE_AFTER_SECS", 30)?;
        let interval = env_u64("RPROBE_REPORT_INTERVAL_SECS", 5)?;
        let path = match std::env::var("RPROBE_DB_PATH") {
            Ok(path) => path,
            Err(std::env::VarError::NotPresent) => "rprobe.sqlite".to_owned(),
            Err(error) => return Err(error).context("RPROBE_DB_PATH must be valid UTF-8"),
        };
        let storage = Storage::open(Path::new(&path)).await?;
        Self::new(
            &credentials,
            admin.trim().to_owned(),
            offline,
            interval,
            storage,
        )
        .await
    }

    pub(crate) async fn new(
        credentials: &str,
        admin_token: String,
        offline: u64,
        interval: u64,
        storage: Storage,
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
        let data = ServerData::restore(storage.load().await?)?;
        let controls = Controls::new(agent_hashes.keys().cloned());
        let (events, _) = broadcast::channel(256);
        Ok(Self(Arc::new(Inner {
            data: RwLock::new(data),
            agent_hashes,
            admin_token,
            offline_after_secs: offline,
            report_interval_secs: interval,
            events,
            controls,
            storage,
            mutations: Arc::new(Semaphore::new(64)),
        })))
    }

    // Once admitted, a write completes commit + cache publication even if its HTTP/WS caller leaves.
    async fn mutate<F>(
        &self,
        operation: impl FnOnce(Self) -> F + Send + 'static,
    ) -> Result<(), IngestError>
    where
        F: Future<Output = Result<(), IngestError>> + Send + 'static,
    {
        let permit = self
            .0
            .mutations
            .clone()
            .try_acquire_owned()
            .map_err(|_| IngestError::RateLimited)?;
        let state = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            operation(state).await
        })
        .await
        .map_err(|_| IngestError::StorageUnavailable)?
    }

    pub async fn close(&self) {
        self.0.storage.close().await;
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
        let id = agent_id.to_owned();
        self.mutate(
            move |state| async move { state.ingest_committed(&id, message, received_at).await },
        )
        .await
    }

    async fn ingest_committed(
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
                let mut new_group = None;
                let updated = if let Some(host) = data.hosts.get(agent_id) {
                    let mut updated = host.clone();
                    updated.hello = hello;
                    updated
                } else {
                    if data.hosts.len() >= MAX_AGENTS {
                        return Err(IngestError::RateLimited);
                    }
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
                            new_group = Some(Group {
                                id: id.clone(),
                                name: id.clone(),
                                parent_id: None,
                                sort: 0,
                                color: None,
                            });
                        }
                    }
                    HostRecord {
                        hello,
                        report: None,
                        last_seen_at: received_at,
                        group_id,
                        clock_skew_secs: None,
                        received_in_session: false,
                    }
                };
                self.0
                    .storage
                    .save_host(
                        &updated.snapshot(received_at, self.0.offline_after_secs),
                        new_group.as_ref(),
                    )
                    .await
                    .map_err(storage_error)?;
                if let Some(group) = new_group {
                    data.groups.insert(group.id.clone(), group);
                }
                data.hosts.insert(agent_id.to_owned(), updated);
            }
            ClientMessage::Report { report } => {
                if !valid_report(&report)
                    || report.collected_at < received_at.saturating_sub(MAX_REPORT_AGE_SECS)
                    || report.collected_at > received_at.saturating_add(MAX_REPORT_FUTURE_SECS)
                {
                    return Err(IngestError::InvalidMessage);
                }
                let host = data.hosts.get(agent_id).ok_or(IngestError::UnknownHost)?;
                if host
                    .report
                    .as_ref()
                    .is_some_and(|current| report.collected_at <= current.collected_at)
                {
                    return Ok(()); // Durable high-water timestamp prevents duplicate liveness after restart too.
                }
                let mut updated = host.clone();
                updated.clock_skew_secs = Some(received_at.saturating_sub(report.collected_at));
                updated.report = Some(report);
                updated.last_seen_at = received_at;
                updated.received_in_session = true;
                self.0
                    .storage
                    .save_host(
                        &updated.snapshot(received_at, self.0.offline_after_secs),
                        None,
                    )
                    .await
                    .map_err(storage_error)?;
                data.hosts.insert(agent_id.to_owned(), updated);
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
            .map(|host| host.snapshot(now, self.0.offline_after_secs))
            .collect();
        hosts.sort_by(|a, b| a.hello.hostname.cmp(&b.hello.hostname));
        (hosts, data.groups.values().cloned().collect())
    }

    pub async fn create_group(&self, group: Group) -> Result<(), IngestError> {
        self.mutate(move |state| async move { state.create_group_committed(group).await })
            .await
    }

    async fn create_group_committed(&self, group: Group) -> Result<(), IngestError> {
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
        self.0
            .storage
            .create_group(&group)
            .await
            .map_err(storage_error)?;
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
        let id = agent_id.to_owned();
        self.mutate(move |state| async move { state.assign_group_committed(&id, group_id).await })
            .await
    }

    async fn assign_group_committed(
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
        let host = data
            .hosts
            .get_mut(agent_id)
            .ok_or(IngestError::UnknownHost)?;
        self.0
            .storage
            .assign_group(agent_id, group_id.as_deref())
            .await
            .map_err(storage_error)?;
        host.group_id = group_id;
        drop(data);
        let _ = self.0.events.send(());
        Ok(())
    }
}

fn storage_error(error: anyhow::Error) -> IngestError {
    tracing::error!(%error, "failed to persist registry update");
    IngestError::StorageUnavailable
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
pub(crate) async fn test_state() -> AppState {
    AppState::new(
        "node-a=test-agent-credential-12345,node-b=other-agent-credential-12345",
        "test-admin-credential-12345".to_owned(),
        30,
        5,
        Storage::for_test().await,
    )
    .await
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
        let state = test_state().await;
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
        let state = test_state().await;
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
            5,
            Storage::for_test().await,
        )
        .await
        .is_err());
    }
}

#[cfg(test)]
#[path = "state_persistence_tests.rs"]
mod persistence_tests;
