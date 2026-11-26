use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PROTOCOL_VERSION: u16 = 1;
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentHello {
    pub agent_id: String,
    pub agent_version: String,
    pub protocol_version: u16,
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub memory_total_bytes: u64,
    pub virtualization: String,
    pub cgroup_memory_limit_bytes: Option<u64>,
    pub cgroup_cpu_limit_cores: Option<f64>,
    pub group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricsReport {
    pub collected_at: i64,
    pub cpu_percent: f32,
    pub memory_used_bytes: u64,
    pub memory_limit_bytes: u64,
    pub swap_used_bytes: u64,
    pub swap_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    pub tcp_connections: u32,
    pub udp_connections: u32,
    pub process_count: u32,
    pub uptime_secs: u64,
    #[serde(default)]
    pub openvz_beancounters: BTreeMap<String, BeancounterStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeancounterStat {
    pub held: u64,
    pub limit: u64,
    pub failcnt: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Hello { hello: AgentHello },
    Report { report: MetricsReport },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Config { interval_secs: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub sort: i32,
    pub color: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostSnapshot {
    pub hello: AgentHello,
    pub report: Option<MetricsReport>,
    pub last_seen_at: i64,
    pub online: bool,
    pub group_id: Option<String>,
    pub clock_skew_secs: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_messages_round_trip_as_tagged_json() {
        let message = ClientMessage::Report {
            report: MetricsReport {
                collected_at: 1_700_000_000,
                cpu_percent: 12.5,
                memory_used_bytes: 100,
                memory_limit_bytes: 200,
                swap_used_bytes: 0,
                swap_total_bytes: 0,
                disk_used_bytes: 300,
                disk_total_bytes: 500,
                load1: 0.1,
                load5: 0.2,
                load15: 0.3,
                rx_bytes_per_sec: 4,
                tx_bytes_per_sec: 5,
                rx_bytes_total: 6,
                tx_bytes_total: 7,
                tcp_connections: 8,
                udp_connections: 9,
                process_count: 10,
                uptime_secs: 11,
                openvz_beancounters: BTreeMap::new(),
            },
        };

        let encoded = serde_json::to_string(&message).unwrap();
        assert!(encoded.contains("\"type\":\"report\""));
        assert_eq!(
            serde_json::from_str::<ClientMessage>(&encoded).unwrap(),
            message
        );
    }
}
