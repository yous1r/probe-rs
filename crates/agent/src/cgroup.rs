//! Locate this process's cgroup, including namespaced and systemd-managed layouts.
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug)]
struct Hierarchy {
    directory: PathBuf,
    mount: PathBuf,
    unified: bool,
}

impl Hierarchy {
    fn read(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.directory.join(name)).ok()
    }

    fn minimum_limit(&self, read: impl Fn(&Path) -> Option<f64>) -> Option<f64> {
        let mut limit: Option<f64> = None;
        for directory in self.directory.ancestors() {
            if !directory.starts_with(&self.mount) {
                break;
            }
            if let Some(value) = read(directory).filter(|v| v.is_finite() && *v > 0.0) {
                limit = Some(limit.map_or(value, |current| current.min(value)));
            }
        }
        limit
    }
}

#[derive(Default)]
struct Cgroups {
    memory: Option<Hierarchy>,
    cpu: Option<Hierarchy>,
    cpuacct: Option<Hierarchy>,
}

fn current() -> &'static Cgroups {
    static GROUPS: OnceLock<Cgroups> = OnceLock::new();
    GROUPS.get_or_init(|| {
        let membership = fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        Cgroups {
            memory: locate(&membership, &mounts, "memory"),
            cpu: locate(&membership, &mounts, "cpu"),
            cpuacct: locate(&membership, &mounts, "cpuacct"),
        }
    })
}

fn mount_path(value: &str) -> PathBuf {
    PathBuf::from(
        value
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\134", "\\"),
    )
}

fn locate(membership: &str, mounts: &str, controller: &str) -> Option<Hierarchy> {
    for line in membership.lines() {
        let mut fields = line.splitn(3, ':');
        let id = fields.next()?;
        let controllers = fields.next()?;
        let group = Path::new(fields.next()?);
        let unified = id == "0" && controllers.is_empty();
        if !unified && !controllers.split(',').any(|name| name == controller) {
            continue;
        }
        for mount in mounts.lines() {
            let Some((before, after)) = mount.split_once(" - ") else {
                continue;
            };
            let head: Vec<_> = before.split_whitespace().collect();
            let tail: Vec<_> = after.split_whitespace().collect();
            if head.len() < 5 || tail.len() < 3 {
                continue;
            }
            if (unified && tail[0] != "cgroup2")
                || (!unified
                    && (tail[0] != "cgroup" || !tail[2].split(',').any(|name| name == controller)))
            {
                continue;
            }
            let root = mount_path(head[3]);
            let mount = mount_path(head[4]);
            // With a private cgroup namespace membership may already be relative to the mount root.
            let relative = group
                .strip_prefix(&root)
                .or_else(|_| group.strip_prefix("/"))
                .ok()?;
            if relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
            {
                return None;
            }
            return Some(Hierarchy {
                directory: mount.join(relative),
                mount,
                unified,
            });
        }
    }
    None
}

pub fn memory_limit() -> Option<u64> {
    let hierarchy = current().memory.as_ref()?;
    let filename = if hierarchy.unified {
        "memory.max"
    } else {
        "memory.limit_in_bytes"
    };
    hierarchy
        .minimum_limit(|directory| {
            parse_memory_limit(&fs::read_to_string(directory.join(filename)).ok()?)
                .map(|n| n as f64)
        })
        .map(|n| n as u64)
}

pub fn parse_memory_limit(value: &str) -> Option<u64> {
    let value = value.trim().parse::<u64>().ok()?;
    (value > 0 && value < (1_u64 << 60)).then_some(value)
}

pub fn memory_usage() -> Option<u64> {
    let hierarchy = current().memory.as_ref()?;
    hierarchy
        .read(if hierarchy.unified {
            "memory.current"
        } else {
            "memory.usage_in_bytes"
        })?
        .trim()
        .parse()
        .ok()
}

fn quota(quota: &str, period: &str) -> Option<f64> {
    let quota = quota.trim().parse::<f64>().ok()?;
    let period = period.trim().parse::<f64>().ok()?;
    (quota.is_finite() && period.is_finite() && quota > 0.0 && period > 0.0)
        .then_some(quota / period)
}

pub fn cpu_limit() -> Option<f64> {
    let hierarchy = current().cpu.as_ref()?;
    hierarchy.minimum_limit(|directory| {
        if hierarchy.unified {
            let text = fs::read_to_string(directory.join("cpu.max")).ok()?;
            let mut fields = text.split_whitespace();
            quota(fields.next()?, fields.next()?)
        } else {
            quota(
                &fs::read_to_string(directory.join("cpu.cfs_quota_us")).ok()?,
                &fs::read_to_string(directory.join("cpu.cfs_period_us")).ok()?,
            )
        }
    })
}

pub fn cpu_usage_usec() -> Option<u64> {
    let hierarchy = current().cpuacct.as_ref()?;
    if hierarchy.unified {
        hierarchy.read("cpu.stat")?.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == "usage_usec")
                .then(|| fields.next()?.parse().ok())
                .flatten()
        })
    } else {
        hierarchy
            .read("cpuacct.usage")?
            .trim()
            .parse::<u64>()
            .ok()
            .map(|n| n / 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_systemd_child_in_combined_v1_mount() {
        let membership =
            "9:cpuacct,cpu:/system.slice/rprobe.service\n2:memory:/system.slice/rprobe.service";
        let mounts = "29 23 0:27 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct\n30 23 0:28 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory";
        assert_eq!(
            locate(membership, mounts, "cpu").unwrap().directory,
            Path::new("/sys/fs/cgroup/cpu,cpuacct/system.slice/rprobe.service")
        );
        assert_eq!(
            locate(membership, mounts, "memory").unwrap().directory,
            Path::new("/sys/fs/cgroup/memory/system.slice/rprobe.service")
        );
    }

    #[test]
    fn resolves_v2_mount_root_and_namespaced_membership() {
        let mounts = "29 23 0:27 /docker/container /sys/fs/cgroup rw - cgroup2 cgroup rw";
        for membership in ["0::/docker/container/worker", "0::/worker"] {
            let group = locate(membership, mounts, "cpu").unwrap();
            assert!(group.unified);
            assert_eq!(group.directory, Path::new("/sys/fs/cgroup/worker"));
        }
    }

    #[test]
    fn applies_strictest_parent_limit_without_leaving_mount() {
        let group = Hierarchy {
            directory: PathBuf::from("/cgroup/parent/child"),
            mount: PathBuf::from("/cgroup"),
            unified: true,
        };
        let limit = group.minimum_limit(|directory| match directory.to_str().unwrap() {
            "/cgroup/parent/child" => Some(1.0),
            "/cgroup/parent" => Some(0.1),
            "/cgroup" => Some(2.0),
            _ => panic!("walked outside cgroup mount"),
        });
        assert_eq!(limit, Some(0.1));
        assert_eq!(quota("max", "100000"), None);
        assert_eq!(quota("-1", "100000"), None);
        assert_eq!(quota("10000", "100000"), Some(0.1));
    }
}
