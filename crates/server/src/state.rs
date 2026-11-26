use anyhow::{anyhow, Context, Result};
use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use rand_core::OsRng;
use rprobe_common::{AgentHello, ClientMessage, Group, HostSnapshot, MetricsReport};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, RwLock};

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    data: RwLock<ServerData>,
    agent_hashes: HashMap<String, String>,
    admin_token: String,
    offline_after_secs: u64,
    report_interval_secs: u64,
    events: broadcast::Sender<()>,
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

#[derive(Debug)]
pub enum IngestError {
    InvalidMessage,
    UnknownHost,
    InvalidGroup,
}

impl AppState {
    pub fn from_env() -> Result<Self> {
        let credentials = std::env::var("RPROBE_AGENT_TOKENS")
            .context("RPROBE_AGENT_TOKENS is required (format: id=token,id2=token2)")?;
        let mut agent_hashes = HashMap::new();
        for entry in credentials
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let (id, token) = entry
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid agent credential; expected id=token"))?;
            if !valid_agent_id(id) || token.trim().len() < 16 {
                return Err(anyhow!("agent IDs must use letters, numbers, '.', '_' or '-'; tokens must be at least 16 characters"));
            }
            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
                .hash_password(token.trim().as_bytes(), &salt)
                .map_err(|error| anyhow!("hash agent token: {error}"))?
                .to_string();
            agent_hashes.insert(id.to_owned(), hash);
        }
        if agent_hashes.is_empty() {
            return Err(anyhow!(
                "RPROBE_AGENT_TOKENS must configure at least one agent"
            ));
        }
        let admin_token =
            std::env::var("RPROBE_ADMIN_TOKEN").context("RPROBE_ADMIN_TOKEN is required")?;
        if admin_token.len() < 16 {
            return Err(anyhow!("RPROBE_ADMIN_TOKEN must be at least 16 characters"));
        }
        let offline_after_secs = env_u64("RPROBE_OFFLINE_AFTER_SECS", 30)?;
        if offline_after_secs == 0 {
            return Err(anyhow!(
                "RPROBE_OFFLINE_AFTER_SECS must be greater than zero"
            ));
        }
        let report_interval_secs = env_u64("RPROBE_REPORT_INTERVAL_SECS", 5)?.max(1);
        let (events, _) = broadcast::channel(256);
        Ok(Self(Arc::new(Inner {
            data: RwLock::new(ServerData::default()),
            agent_hashes,
            admin_token,
            offline_after_secs,
            report_interval_secs,
            events,
        })))
    }

    pub fn authorize_agent(&self, agent_id: &str, token: &str) -> bool {
        let Some(hash) = self.0.agent_hashes.get(agent_id) else {
            return false;
        };
        let Ok(parsed) = PasswordHash::new(hash) else {
            return false;
        };
        Argon2::default()
            .verify_password(token.as_bytes(), &parsed)
            .is_ok()
    }

    pub fn authorize_admin(&self, token: &str) -> bool {
        self.0.admin_token.as_bytes().ct_eq(token.as_bytes()).into()
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
        let mut data = self.0.data.write().await;
        match message {
            ClientMessage::Hello { hello } => {
                if hello.agent_id != agent_id
                    || hello.protocol_version != rprobe_common::PROTOCOL_VERSION
                    || hello.hostname.len() > 255
                {
                    return Err(IngestError::InvalidMessage);
                }
                let group_id = hello
                    .group
                    .as_deref()
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(|name| {
                        let id = name.to_owned();
                        data.groups.entry(id.clone()).or_insert_with(|| Group {
                            id: id.clone(),
                            name: name.to_owned(),
                            parent_id: None,
                            sort: 0,
                            color: None,
                        });
                        id
                    });
                let previous = data.hosts.remove(agent_id);
                let previous_report = previous.as_ref().and_then(|host| host.report.clone());
                let previous_group = previous.as_ref().and_then(|host| host.group_id.clone());
                let previous_clock_skew = previous.and_then(|host| host.clock_skew_secs);
                let record = HostRecord {
                    hello,
                    report: previous_report,
                    last_seen_at: received_at,
                    group_id: previous_group.or(group_id),
                    clock_skew_secs: previous_clock_skew,
                };
                data.hosts.insert(agent_id.to_owned(), record);
            }
            ClientMessage::Report { report } => {
                if !valid_report(&report) {
                    return Err(IngestError::InvalidMessage);
                }
                let host = data
                    .hosts
                    .get_mut(agent_id)
                    .ok_or(IngestError::UnknownHost)?;
                if host
                    .report
                    .as_ref()
                    .is_none_or(|current| report.collected_at >= current.collected_at)
                {
                    host.report = Some(report.clone());
                    host.clock_skew_secs = Some(received_at.saturating_sub(report.collected_at));
                }
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
        let groups = data.groups.values().cloned().collect();
        (hosts, groups)
    }

    pub async fn create_group(&self, group: Group) -> Result<(), IngestError> {
        if group.id.trim().is_empty()
            || group.id.len() > 64
            || group.name.trim().is_empty()
            || group.name.len() > 100
        {
            return Err(IngestError::InvalidGroup);
        }
        let mut data = self.0.data.write().await;
        if data.groups.contains_key(&group.id) {
            return Err(IngestError::InvalidGroup);
        }
        if let Some(parent_id) = group.parent_id.as_deref() {
            if parent_id == group.id
                || !data
                    .groups
                    .get(parent_id)
                    .is_some_and(|parent| parent.parent_id.is_none())
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
        let host = data
            .hosts
            .get_mut(agent_id)
            .ok_or(IngestError::UnknownHost)?;
        host.group_id = group_id;
        drop(data);
        let _ = self.0.events.send(());
        Ok(())
    }
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse()
                .with_context(|| format!("{name} must be an integer"))
        })
        .unwrap_or(Ok(default))
}

fn valid_agent_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_report(report: &MetricsReport) -> bool {
    report.cpu_percent.is_finite()
        && (0.0..=100.0).contains(&report.cpu_percent)
        && report.load1.is_finite()
        && report.load5.is_finite()
        && report.load15.is_finite()
        && report.memory_limit_bytes < (1_u64 << 62)
}

pub fn unix_time_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::{valid_agent_id, valid_report};
    use rprobe_common::MetricsReport;
    use std::collections::BTreeMap;

    #[test]
    fn agent_ids_are_safe_for_header_and_route_use() {
        assert!(valid_agent_id("node-1.example"));
        assert!(!valid_agent_id("../admin"));
        assert!(!valid_agent_id(""));
    }

    #[test]
    fn rejects_nan_and_out_of_range_cpu_metrics() {
        let mut report = MetricsReport {
            collected_at: 1,
            cpu_percent: f32::NAN,
            memory_used_bytes: 0,
            memory_limit_bytes: 1,
            swap_used_bytes: 0,
            swap_total_bytes: 0,
            disk_used_bytes: 0,
            disk_total_bytes: 0,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
            rx_bytes_per_sec: 0,
            tx_bytes_per_sec: 0,
            rx_bytes_total: 0,
            tx_bytes_total: 0,
            tcp_connections: 0,
            udp_connections: 0,
            process_count: 0,
            uptime_secs: 0,
            openvz_beancounters: BTreeMap::new(),
        };
        assert!(!valid_report(&report));
        report.cpu_percent = 101.0;
        assert!(!valid_report(&report));
        report.cpu_percent = 1.0;
        assert!(valid_report(&report));
    }
}
