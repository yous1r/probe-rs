#[cfg(test)]
use crate::cgroup::parse_memory_limit as parse_cgroup_memory_limit;
use crate::cgroup::{
    cpu_limit as cgroup_cpu_limit, cpu_usage_usec as cgroup_cpu_usage_usec,
    memory_limit as cgroup_memory_limit, memory_usage as cgroup_memory_usage,
};
use anyhow::{anyhow, Result};
use rprobe_common::{AgentHello, BeancounterStat, MetricsReport, AGENT_VERSION, PROTOCOL_VERSION};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Default)]
pub struct Collector {
    previous_cpu: Option<(u64, u64)>,
    previous_cgroup_cpu_usec: Option<u64>,
    previous_network: Option<(u64, u64)>,
    previous_sample: Option<Instant>,
}

impl Collector {
    pub fn hello(agent_id: &str, group: Option<String>) -> AgentHello {
        let (memory_total, _, _, _) = memory_info();
        let cpu = cpu_info();
        let cgroup_memory_limit = cgroup_memory_limit().filter(|limit| *limit > 0);
        let cgroup_cpu_limit = cgroup_cpu_limit();
        AgentHello {
            agent_id: agent_id.to_owned(),
            agent_version: AGENT_VERSION.to_owned(),
            protocol_version: PROTOCOL_VERSION,
            hostname: hostname(),
            os: std::env::consts::OS.to_owned(),
            kernel: read_trimmed("/proc/sys/kernel/osrelease")
                .unwrap_or_else(|| "unknown".to_owned()),
            cpu_model: cpu.0,
            cpu_cores: cpu.1,
            memory_total_bytes: memory_total,
            virtualization: virtualization_type(),
            cgroup_memory_limit_bytes: cgroup_memory_limit,
            cgroup_cpu_limit_cores: cgroup_cpu_limit,
            group,
        }
    }

    pub fn collect(&mut self) -> MetricsReport {
        let now = Instant::now();
        let elapsed = self
            .previous_sample
            .replace(now)
            .map(|previous| now.duration_since(previous).as_secs_f64())
            .filter(|elapsed| *elapsed > 0.0)
            .unwrap_or(1.0);

        let (memory_total, memory_available, swap_total, swap_free) = memory_info();
        let cgroup_limit = cgroup_memory_limit().filter(|limit| *limit > 0);
        let memory_used =
            cgroup_memory_usage().unwrap_or_else(|| memory_total.saturating_sub(memory_available));
        let memory_limit = cgroup_limit.unwrap_or(memory_total);

        let cpu_percent = self.cpu_percent(elapsed);
        let (rx_total, tx_total) = network_totals();
        let (rx_rate, tx_rate) = self.network_rates(rx_total, tx_total, elapsed);
        let (disk_used, disk_total) = disk_usage();
        let (load1, load5, load15) = load_average();
        let (tcp, udp) = connection_counts();
        let counters = read_beancounters();

        MetricsReport {
            collected_at: unix_time_secs(),
            cpu_percent,
            memory_used_bytes: memory_used,
            memory_limit_bytes: memory_limit,
            swap_used_bytes: swap_total.saturating_sub(swap_free),
            swap_total_bytes: swap_total,
            disk_used_bytes: disk_used,
            disk_total_bytes: disk_total,
            load1,
            load5,
            load15,
            rx_bytes_per_sec: rx_rate,
            tx_bytes_per_sec: tx_rate,
            rx_bytes_total: rx_total,
            tx_bytes_total: tx_total,
            tcp_connections: tcp,
            udp_connections: udp,
            process_count: process_count(),
            uptime_secs: uptime_secs(),
            openvz_beancounters: counters,
        }
    }

    fn cpu_percent(&mut self, elapsed_secs: f64) -> f32 {
        if let Some(current_usage) = cgroup_cpu_usage_usec() {
            if let Some(previous) = self.previous_cgroup_cpu_usec.replace(current_usage) {
                if let Some(quota_cores) = cgroup_cpu_limit().filter(|quota| *quota > 0.0) {
                    return cgroup_cpu_percent(current_usage, previous, elapsed_secs, quota_cores);
                }
            }
        }

        let Some((total, idle)) = cpu_counters() else {
            return 0.0;
        };
        if let Some((previous_total, previous_idle)) = self.previous_cpu.replace((total, idle)) {
            let total_delta = total.saturating_sub(previous_total);
            let idle_delta = idle.saturating_sub(previous_idle);
            if total_delta > 0 {
                return ((total_delta.saturating_sub(idle_delta) as f64 / total_delta as f64)
                    * 100.0) as f32;
            }
        }
        0.0
    }

    fn network_rates(&mut self, rx: u64, tx: u64, elapsed: f64) -> (u64, u64) {
        let previous = self.previous_network.replace((rx, tx));
        previous
            .map(|(previous_rx, previous_tx)| {
                (
                    (rx.saturating_sub(previous_rx) as f64 / elapsed) as u64,
                    (tx.saturating_sub(previous_tx) as f64 / elapsed) as u64,
                )
            })
            .unwrap_or((0, 0))
    }
}

fn cgroup_cpu_percent(current: u64, previous: u64, elapsed_secs: f64, quota_cores: f64) -> f32 {
    if !elapsed_secs.is_finite()
        || !quota_cores.is_finite()
        || elapsed_secs <= 0.0
        || quota_cores <= 0.0
    {
        return 0.0;
    }
    let elapsed_usec = elapsed_secs * 1_000_000.0;
    let used_usec = current.saturating_sub(previous) as f64;
    ((used_usec / elapsed_usec / quota_cores) * 100.0).clamp(0.0, 100.0) as f32
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| read_trimmed("/etc/hostname"))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn cpu_info() -> (String, u32) {
    let text = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let model = text
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(key, value)| {
                matches!(key.trim(), "model name" | "Hardware" | "Processor")
                    .then(|| value.trim().to_owned())
            })
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let count = text
        .lines()
        .filter(|line| line.starts_with("processor\t") || line.starts_with("processor "))
        .count();
    let cores = if count == 0 {
        std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1)
    } else {
        count
    };
    (model, cores.min(u32::MAX as usize) as u32)
}

fn memory_info() -> (u64, u64, u64, u64) {
    let mut total_kb = 0;
    let mut available_kb = 0;
    let mut free_kb = 0;
    let mut swap_total_kb = 0;
    let mut swap_free_kb = 0;
    if let Ok(text) = fs::read_to_string("/proc/meminfo") {
        for line in text.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let number = value
                .split_whitespace()
                .next()
                .and_then(|part| part.parse::<u64>().ok())
                .unwrap_or(0);
            match key {
                "MemTotal" => total_kb = number,
                "MemAvailable" => available_kb = number,
                "MemFree" => free_kb = number,
                "SwapTotal" => swap_total_kb = number,
                "SwapFree" => swap_free_kb = number,
                _ => {}
            }
        }
    }
    if available_kb == 0 {
        available_kb = free_kb;
    }
    (
        total_kb.saturating_mul(1024),
        available_kb.saturating_mul(1024),
        swap_total_kb.saturating_mul(1024),
        swap_free_kb.saturating_mul(1024),
    )
}

fn cpu_counters() -> Option<(u64, u64)> {
    let line = fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .next()?
        .to_owned();
    let mut values = line.split_whitespace();
    if values.next()? != "cpu" {
        return None;
    }
    let counters: Vec<u64> = values.filter_map(|value| value.parse().ok()).collect();
    if counters.len() < 4 {
        return None;
    }
    let total = counters.iter().copied().sum();
    let idle = counters[3].saturating_add(counters.get(4).copied().unwrap_or(0));
    Some((total, idle))
}

fn network_totals() -> (u64, u64) {
    fs::read_to_string("/proc/net/dev")
        .map(|text| parse_network_totals(&text))
        .unwrap_or((0, 0))
}

fn parse_network_totals(text: &str) -> (u64, u64) {
    text.lines()
        .skip(2)
        .filter_map(|line| {
            let (interface, counters) = line.rsplit_once(':')?;
            let interface = interface.trim();
            if interface == "lo" || interface.contains(':') {
                return None;
            }
            let values: Vec<u64> = counters
                .split_whitespace()
                .filter_map(|value| value.parse().ok())
                .collect();
            (values.len() >= 9).then(|| (values[0], values[8]))
        })
        .fold((0_u64, 0_u64), |total, next| {
            (
                total.0.saturating_add(next.0),
                total.1.saturating_add(next.1),
            )
        })
}

fn disk_usage() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        let path = CString::new("/").expect("static path has no NUL");
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: statvfs initializes the supplied structure on success and path is NUL-terminated.
        let result = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
        if result == 0 {
            // SAFETY: the successful statvfs call initialized the structure.
            let stats = unsafe { stats.assume_init() };
            let block_size = stats.f_frsize;
            let total = stats.f_blocks.saturating_mul(block_size);
            let available = stats.f_bavail.saturating_mul(block_size);
            return (total.saturating_sub(available), total);
        }
    }
    (0, 0)
}

fn load_average() -> (f64, f64, f64) {
    let values: Vec<f64> = read_trimmed("/proc/loadavg")
        .unwrap_or_default()
        .split_whitespace()
        .take(3)
        .filter_map(|value| value.parse().ok())
        .collect();
    (
        values.first().copied().unwrap_or(0.0),
        values.get(1).copied().unwrap_or(0.0),
        values.get(2).copied().unwrap_or(0.0),
    )
}

fn count_proc_table(path: &str) -> u32 {
    fs::read_to_string(path)
        .map(|text| text.lines().skip(1).count().min(u32::MAX as usize) as u32)
        .unwrap_or(0)
}

fn connection_counts() -> (u32, u32) {
    (
        count_proc_table("/proc/net/tcp") + count_proc_table("/proc/net/tcp6"),
        count_proc_table("/proc/net/udp") + count_proc_table("/proc/net/udp6"),
    )
}

fn process_count() -> u32 {
    fs::read_dir("/proc")
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry.file_name().to_str().is_some_and(|name| {
                        !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit())
                    })
                })
                .count()
                .min(u32::MAX as usize) as u32
        })
        .unwrap_or(0)
}

fn uptime_secs() -> u64 {
    read_trimmed("/proc/uptime")
        .and_then(|value| value.split_whitespace().next()?.parse::<f64>().ok())
        .map(|value| value.max(0.0) as u64)
        .unwrap_or(0)
}

fn read_beancounters() -> BTreeMap<String, BeancounterStat> {
    fs::read_to_string("/proc/user_beancounters")
        .map(|text| parse_beancounters(&text))
        .unwrap_or_default()
}

fn parse_beancounters(text: &str) -> BTreeMap<String, BeancounterStat> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _container_id = fields.next()?;
            let resource = fields.next()?;
            if resource == "resource" || resource.is_empty() {
                return None;
            }
            let values: Vec<u64> = fields.filter_map(|field| field.parse().ok()).collect();
            (values.len() >= 5).then(|| {
                (
                    resource.to_owned(),
                    BeancounterStat {
                        held: values[0],
                        limit: values[3],
                        failcnt: values[4],
                    },
                )
            })
        })
        .collect()
}

fn virtualization_type() -> String {
    if Path::new("/proc/vz").exists() && !Path::new("/proc/bc").exists() {
        let version = read_trimmed("/proc/version").unwrap_or_default();
        if version.contains("2.6.32") {
            "openvz6".to_owned()
        } else {
            "openvz7".to_owned()
        }
    } else if Path::new("/sys/fs/cgroup").exists() {
        "container_or_vm".to_owned()
    } else {
        "unknown".to_owned()
    }
}

fn unix_time_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

pub fn require_procfs() -> Result<()> {
    if cfg!(target_os = "linux") && Path::new("/proc/stat").exists() {
        Ok(())
    } else {
        Err(anyhow!("rprobe-agent collection requires Linux procfs"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_beancounter_rows_and_skips_header() {
        let input =
            "uid  resource held maxheld barrier limit failcnt\n  0: kmemsize 1024 2048 0 4096 3\n";
        let parsed = parse_beancounters(input);
        assert_eq!(parsed["kmemsize"].held, 1024);
        assert_eq!(parsed["kmemsize"].limit, 4096);
        assert_eq!(parsed["kmemsize"].failcnt, 3);
    }

    #[test]
    fn cgroup_cpu_percent_uses_quota_and_caps_at_100() {
        assert_eq!(cgroup_cpu_percent(5_000_000, 0, 1.0, 0.5), 100.0);
        assert_eq!(cgroup_cpu_percent(250_000, 0, 1.0, 0.5), 50.0);
    }

    #[test]
    fn cgroup_memory_limit_ignores_unlimited_sentinels() {
        assert_eq!(parse_cgroup_memory_limit("max"), None);
        assert_eq!(parse_cgroup_memory_limit("1024"), Some(1024));
        assert_eq!(
            parse_cgroup_memory_limit(&((1_u64 << 60) + 1).to_string()),
            None
        );
    }

    #[test]
    fn network_totals_skip_loopback_and_venet_aliases() {
        let input = "header\nheader\nlo: 100 0 0 0 0 0 0 0 100\nvenet0: 1000 0 0 0 0 0 0 0 3000\nvenet0:0: 1000 0 0 0 0 0 0 0 3000\neth0: 2000 0 0 0 0 0 0 0 5000\n";
        assert_eq!(parse_network_totals(input), (3000, 8000));
    }
}
