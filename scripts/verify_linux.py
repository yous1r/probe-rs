#!/usr/bin/env python3
"""Run end-to-end Linux checks against existing rprobe binaries (never builds)."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import platform
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable


AGENT_ID = "validation"
AGENT_GROUP = "smoke"
REPORT_FIELDS = {
    "collected_at",
    "cpu_percent",
    "memory_used_bytes",
    "memory_limit_bytes",
    "swap_used_bytes",
    "swap_total_bytes",
    "disk_used_bytes",
    "disk_total_bytes",
    "load1",
    "load5",
    "load15",
    "rx_bytes_per_sec",
    "tx_bytes_per_sec",
    "rx_bytes_total",
    "tx_bytes_total",
    "tcp_connections",
    "udp_connections",
    "process_count",
    "uptime_secs",
    "openvz_beancounters",
}
HELLO_FIELDS = {
    "agent_id",
    "agent_version",
    "protocol_version",
    "hostname",
    "os",
    "kernel",
    "cpu_model",
    "cpu_cores",
    "memory_total_bytes",
    "virtualization",
    "cgroup_memory_limit_bytes",
    "cgroup_cpu_limit_cores",
    "group",
}
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def iso_from_epoch(timestamp: float | int) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def parse_json(body: bytes, context: str) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{context}: invalid JSON response") from error


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def http_exchange(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    payload: Any | None = None,
    timeout: float = 2.0,
) -> tuple[int, bytes]:
    request_headers = dict(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(
        url, data=data, headers=request_headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        try:
            return error.code, error.read()
        finally:
            error.close()


def read_text(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None


def meminfo_bytes() -> dict[str, int]:
    values: dict[str, int] = {}
    text = read_text("/proc/meminfo")
    if text is None:
        return values
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        parts = value.split()
        if not parts:
            continue
        try:
            number = int(parts[0])
        except ValueError:
            continue
        values[key] = number * (1024 if len(parts) > 1 and parts[1] == "kB" else 1)
    return values


def proc_cpu_ticks(path: str = "/proc/stat") -> dict[str, int] | None:
    text = read_text(path)
    if not text:
        return None
    line = text.splitlines()[0].split()
    if not line or line[0] != "cpu":
        return None
    try:
        values = [int(value) for value in line[1:]]
    except ValueError:
        return None
    return {"total": sum(values), "idle": values[3] if len(values) > 3 else 0, "raw": values}


def parse_cgroup_memory_limit(raw: str | None) -> int | None:
    if raw is None or raw.strip() in {"", "max"}:
        return None
    try:
        value = int(raw.strip())
    except ValueError:
        return None
    return value if 0 < value < (1 << 60) else None


def cgroup_snapshot() -> dict[str, Any]:
    paths = {
        "memory_max_v2": "/sys/fs/cgroup/memory.max",
        "memory_current_v2": "/sys/fs/cgroup/memory.current",
        "memory_limit_v1": "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        "memory_usage_v1": "/sys/fs/cgroup/memory/memory.usage_in_bytes",
        "cpu_max_v2": "/sys/fs/cgroup/cpu.max",
        "cpu_stat_v2": "/sys/fs/cgroup/cpu.stat",
        "cpu_quota_v1": "/sys/fs/cgroup/cpu/cpu.cfs_quota_us",
        "cpu_period_v1": "/sys/fs/cgroup/cpu/cpu.cfs_period_us",
        "cpu_usage_v1": "/sys/fs/cgroup/cpuacct/cpuacct.usage",
    }
    raw = {name: read_text(path) for name, path in paths.items()}
    memory_limit_raw = raw["memory_max_v2"]
    memory_limit = parse_cgroup_memory_limit(memory_limit_raw)
    memory_source = "cgroup v2 memory.max" if memory_limit is not None else None
    if memory_limit is None:
        memory_limit_raw = raw["memory_limit_v1"]
        memory_limit = parse_cgroup_memory_limit(memory_limit_raw)
        memory_source = "cgroup v1 memory.limit_in_bytes" if memory_limit is not None else None
    memory_current_raw = raw["memory_current_v2"]
    if memory_current_raw is None:
        memory_current_raw = raw["memory_usage_v1"]
    try:
        memory_current = int(memory_current_raw) if memory_current_raw is not None else None
    except ValueError:
        memory_current = None

    cpu_quota_cores: float | None = None
    cpu_source = "unavailable"
    cpu_max = raw["cpu_max_v2"]
    if cpu_max:
        parts = cpu_max.split()
        if len(parts) >= 2 and parts[0] != "max":
            try:
                quota, period = int(parts[0]), int(parts[1])
                if quota > 0 and period > 0:
                    cpu_quota_cores = quota / period
                    cpu_source = "cgroup v2 cpu.max"
            except ValueError:
                pass
    if cpu_quota_cores is None:
        try:
            quota = int(raw["cpu_quota_v1"] or "")
            period = int(raw["cpu_period_v1"] or "")
            if quota > 0 and period > 0:
                cpu_quota_cores = quota / period
                cpu_source = "cgroup v1 cpu quota/period"
        except ValueError:
            pass

    return {
        "raw_files": raw,
        "memory_limit_bytes": memory_limit,
        "memory_limit_source": memory_source,
        "memory_current_bytes": memory_current,
        "cpu_quota_cores": cpu_quota_cores,
        "cpu_quota_source": cpu_source,
    }


def collect_host_conditions() -> dict[str, Any]:
    meminfo = meminfo_bytes()
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "kernel_release": platform.release(),
        "machine": platform.machine(),
        "logical_cpu_count": os.cpu_count(),
        "proc_meminfo_bytes": {
            key: meminfo.get(key)
            for key in ("MemTotal", "MemAvailable", "MemFree", "SwapTotal", "SwapFree")
        },
        "proc_stat_cpu_ticks": proc_cpu_ticks(),
        "cgroup": cgroup_snapshot(),
        "interpretation": (
            "These are the actual host/container conditions observed by this run; "
            "they do not establish performance at 256 MB or 0.1 vCPU."
        ),
    }


def parse_proc_status(pid: int) -> dict[str, int]:
    text = read_text(f"/proc/{pid}/status")
    if text is None:
        raise VerificationError(f"cannot read /proc/{pid}/status")
    values: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^(VmRSS|VmHWM):\s+(\d+)\s+kB\s*$", line)
        if match:
            values[match.group(1)] = int(match.group(2))
    missing = {"VmRSS", "VmHWM"} - values.keys()
    if missing:
        raise VerificationError(f"/proc/{pid}/status lacks {', '.join(sorted(missing))}")
    return values


def parse_process_stat_ticks(pid: int) -> dict[str, int]:
    text = read_text(f"/proc/{pid}/stat")
    if text is None:
        raise VerificationError(f"cannot read /proc/{pid}/stat")
    close_paren = text.rfind(")")
    if close_paren < 0:
        raise VerificationError(f"malformed /proc/{pid}/stat")
    fields_after_comm = text[close_paren + 1 :].split()
    # The tail begins at field 3 (state); utime/stime are fields 14/15.
    try:
        utime = int(fields_after_comm[11])
        stime = int(fields_after_comm[12])
    except (IndexError, ValueError) as error:
        raise VerificationError(f"malformed CPU tick fields in /proc/{pid}/stat") from error
    return {"utime_ticks": utime, "stime_ticks": stime, "total_ticks": utime + stime}


def validate_hello(hello: Any, expected_id: str = AGENT_ID) -> dict[str, Any]:
    require(isinstance(hello, dict), "hello must be a JSON object")
    missing = sorted(HELLO_FIELDS - hello.keys())
    require(not missing, f"hello missing fields: {', '.join(missing)}")
    require(hello.get("agent_id") == expected_id, "hello agent_id mismatch")
    require(hello.get("protocol_version") == 1, "unexpected protocol_version")
    require(isinstance(hello.get("os"), str) and hello["os"].lower() == "linux", "agent did not report Linux")
    require(isinstance(hello.get("cpu_cores"), int) and hello["cpu_cores"] > 0, "cpu_cores is not positive")
    require(isinstance(hello.get("memory_total_bytes"), int) and hello["memory_total_bytes"] > 0, "memory_total_bytes is not positive")
    return hello


def validate_report(report: Any) -> dict[str, Any]:
    require(isinstance(report, dict), "report must be a JSON object")
    missing = sorted(REPORT_FIELDS - report.keys())
    require(not missing, f"report missing fields: {', '.join(missing)}")
    require(isinstance(report.get("collected_at"), int) and report["collected_at"] > 0, "collected_at is not a positive integer")
    cpu = report.get("cpu_percent")
    require(isinstance(cpu, (int, float)) and math.isfinite(float(cpu)) and 0 <= cpu <= 100, "cpu_percent is invalid")
    for field in ("memory_limit_bytes", "disk_total_bytes", "process_count", "uptime_secs"):
        require(isinstance(report.get(field), int) and report[field] > 0, f"{field} is not positive")
    require(isinstance(report.get("openvz_beancounters"), dict), "openvz_beancounters is not an object")
    return report


def snapshot_host(snapshot: dict[str, Any], expected_id: str = AGENT_ID) -> dict[str, Any]:
    hosts = snapshot.get("hosts")
    require(isinstance(hosts, list), "overview response has no hosts array")
    for host in hosts:
        if isinstance(host, dict) and isinstance(host.get("hello"), dict) and host["hello"].get("agent_id") == expected_id:
            return host
    raise VerificationError(f"host {expected_id} not present in overview")


def authorization_headers(admin_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {admin_token}"}


def api_json(
    base_url: str,
    path: str,
    method: str = "GET",
    payload: Any | None = None,
    admin_token: str | None = None,
    timeout: float = 2.0,
) -> tuple[int, bytes]:
    headers = authorization_headers(admin_token) if admin_token else {}
    return http_exchange(base_url + path, method, headers, payload, timeout)


def wait_for_server(base_url: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    last_error = "not responding"
    while time.monotonic() < deadline:
        try:
            status, _ = http_exchange(base_url + "/api/overview", timeout=0.6)
            if status == 401:
                return
            last_error = f"unauthenticated overview returned HTTP {status}, expected 401"
        except Exception as error:  # connection refusal while the child is starting
            last_error = f"{type(error).__name__}: {error}"
        time.sleep(0.2)
    raise VerificationError(f"server did not become ready: {last_error}")


def wait_for_host_report(
    base_url: str, admin_token: str, timeout: float = 35.0, expected_id: str = AGENT_ID
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_status: int | None = None
    while time.monotonic() < deadline:
        status, body = api_json(base_url, "/api/overview", admin_token=admin_token, timeout=1.0)
        last_status = status
        if status == 200:
            overview = parse_json(body, "overview")
            try:
                host = snapshot_host(overview, expected_id)
            except VerificationError:
                time.sleep(0.2)
                continue
            if isinstance(host.get("report"), dict):
                return host
        time.sleep(0.2)
    raise VerificationError(f"agent hello/report not visible before timeout (last HTTP {last_status})")


def wait_for_new_report(
    base_url: str,
    admin_token: str,
    after_collected_at: int,
    timeout: float = 35.0,
    expected_id: str = AGENT_ID,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        host = get_host_snapshot(base_url, admin_token, expected_id)
        report = host.get("report")
        if isinstance(report, dict) and report.get("collected_at", 0) > after_collected_at:
            return host
        time.sleep(0.2)
    raise VerificationError(
        f"no report newer than collected_at={after_collected_at} before timeout"
    )


def get_host_snapshot(base_url: str, admin_token: str, expected_id: str = AGENT_ID) -> dict[str, Any]:
    status, body = api_json(base_url, "/api/overview", admin_token=admin_token)
    require(status == 200, f"overview returned HTTP {status}")
    return snapshot_host(parse_json(body, "overview"), expected_id)


class CaseBook:
    def __init__(self, secrets_to_redact: list[str]):
        self.secrets = [value for value in secrets_to_redact if value]
        self.cases: list[dict[str, Any]] = []

    def redact(self, value: Any) -> Any:
        if isinstance(value, str):
            for secret in self.secrets:
                value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, tuple):
            return [self.redact(item) for item in value]
        if isinstance(value, dict):
            return {str(key): self.redact(item) for key, item in value.items()}
        return value

    def pass_case(self, name: str, details: Any = None) -> None:
        self.cases.append({"name": name, "status": "PASS", "details": self.redact(details)})

    def fail_case(self, name: str, details: Any) -> None:
        self.cases.append({"name": name, "status": "FAIL", "details": self.redact(details)})

    def run(self, name: str, operation: Callable[[], Any]) -> Any:
        try:
            value = operation()
        except Exception as error:
            self.fail_case(name, f"{type(error).__name__}: {error}")
            return None
        self.pass_case(name, value)
        return value

    def fail_prerequisite(self, names: list[str], reason: str) -> None:
        for name in names:
            self.fail_case(name, f"not executable: {reason}")


class OwnedProcesses:
    def __init__(self, output_dir: Path, agent_token: str, admin_token: str):
        self.output_dir = output_dir
        self.agent_token = agent_token
        self.secrets = [agent_token, admin_token]
        self.entries: list[dict[str, Any]] = []

    def spawn(
        self,
        name: str,
        binary: Path,
        args: list[str],
        env: dict[str, str],
    ) -> dict[str, Any]:
        log_path = self.output_dir / f"{name}.log"
        with log_path.open("ab") as log_file:
            process = subprocess.Popen(
                [str(binary), *args],
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env=env,
                close_fds=True,
            )
        entry = {"name": name, "process": process, "log_path": log_path, "stopped": False}
        self.entries.append(entry)
        return entry

    def start_server(self, binary: Path, port: int, admin_token: str) -> dict[str, Any]:
        env = os.environ.copy()
        env.update(
            {
                "RPROBE_LISTEN": f"127.0.0.1:{port}",
                "RPROBE_AGENT_TOKENS": f"{AGENT_ID}={self.agent_token}",
                "RPROBE_ADMIN_TOKEN": admin_token,
                "RPROBE_OFFLINE_AFTER_SECS": "3",
                "RPROBE_REPORT_INTERVAL_SECS": "1",
            }
        )
        return self.spawn("verify-linux-server", binary, [], env)

    def start_agent(self, binary: Path, name: str, url: str, interval: int = 1) -> dict[str, Any]:
        env = os.environ.copy()
        args = [
            "--server",
            url,
            "--id",
            AGENT_ID,
            "--token",
            self.agent_token,
            "--group",
            AGENT_GROUP,
            "--interval",
            str(interval),
        ]
        return self.spawn(name, binary, args, env)

    def stop(self, entry: dict[str, Any] | None, timeout: float = 3.0) -> None:
        if not entry or entry.get("stopped"):
            return
        process: subprocess.Popen[bytes] = entry["process"]
        if process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=timeout)
        entry["stopped"] = True

    def cleanup_all(self) -> None:
        for entry in reversed(self.entries):
            try:
                self.stop(entry)
            except Exception:
                pass

    def redact_logs(self) -> None:
        for entry in self.entries:
            path: Path = entry["log_path"]
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                for secret in self.secrets:
                    text = text.replace(secret, "[REDACTED]")
                path.write_text(text, encoding="utf-8")
            except OSError:
                continue


def wait_process_alive(entry: dict[str, Any], context: str) -> None:
    process: subprocess.Popen[bytes] = entry["process"]
    require(process.poll() is None, f"{context}: child process exited with status {process.returncode}")


def wait_agent_offline(base_url: str, admin_token: str, timeout: float = 12.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_host: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        try:
            last_host = get_host_snapshot(base_url, admin_token)
        except Exception:
            time.sleep(0.25)
            continue
        if last_host.get("online") is False:
            return last_host
        time.sleep(0.25)
    raise VerificationError(
        "host did not become offline after stopping our agent "
        f"(last online={last_host.get('online') if last_host else 'unknown'})"
    )


def post_group(
    base_url: str, admin_token: str, group_id: str, name: str, parent_id: str | None = None
) -> tuple[int, bytes]:
    payload: dict[str, Any] = {"id": group_id, "name": name}
    if parent_id is not None:
        payload["parent_id"] = parent_id
    return api_json(base_url, "/api/groups", "POST", payload, admin_token)


def validate_procfs_cgroup_comparison(host: dict[str, Any], conditions: dict[str, Any]) -> dict[str, Any]:
    hello = validate_hello(host.get("hello"))
    report = validate_report(host.get("report"))
    proc_mem_total = meminfo_bytes().get("MemTotal")
    live_cgroup = cgroup_snapshot()
    observed_limit = live_cgroup.get("memory_limit_bytes")
    agent_cgroup_limit = hello.get("cgroup_memory_limit_bytes")
    report_limit = report.get("memory_limit_bytes")
    require(proc_mem_total is not None and proc_mem_total > 0, "/proc/meminfo MemTotal unavailable")
    require(hello["memory_total_bytes"] > 0, "agent memory total is zero")
    if observed_limit is not None:
        require(
            agent_cgroup_limit == observed_limit,
            "agent hello cgroup memory limit differs from readable cgroup limit",
        )
        require(report_limit == observed_limit, "report memory_limit_bytes differs from cgroup limit")
    else:
        require(agent_cgroup_limit is None, "agent reported a cgroup limit while supported cgroup files are unavailable")
        require(report_limit == hello["memory_total_bytes"], "report limit differs from /proc-based memory total")
    proc_vs_agent_delta = hello["memory_total_bytes"] - proc_mem_total
    current = live_cgroup.get("memory_current_bytes")
    return {
        "proc_mem_total_bytes": proc_mem_total,
        "agent_hello_memory_total_bytes": hello["memory_total_bytes"],
        "agent_minus_proc_mem_total_bytes": proc_vs_agent_delta,
        "cgroup_memory_limit_bytes": observed_limit,
        "cgroup_memory_limit_source": live_cgroup.get("memory_limit_source"),
        "agent_hello_cgroup_memory_limit_bytes": agent_cgroup_limit,
        "report_memory_limit_bytes": report_limit,
        "cgroup_memory_current_bytes": current,
        "report_memory_used_bytes": report["memory_used_bytes"],
        "report_memory_used_minus_cgroup_current_bytes": (
            report["memory_used_bytes"] - current if current is not None else None
        ),
        "cgroup_cpu_quota_cores": live_cgroup.get("cpu_quota_cores"),
        "cgroup_cpu_quota_source": live_cgroup.get("cpu_quota_source"),
        "host_conditions_at_start": conditions,
        "comparison_note": (
            "memory.current/usage is sampled independently and can differ from the agent's "
            "collection instant; the raw values and delta are recorded, not treated as an exact race-free equality."
        ),
    }


def sample_agent_process(entry: dict[str, Any], sample_secs: int) -> dict[str, Any]:
    process: subprocess.Popen[bytes] = entry["process"]
    pid = process.pid
    require(platform.system() == "Linux", "process /proc sampling is Linux-only")
    status_before = parse_proc_status(pid)
    stat_before = parse_process_stat_ticks(pid)
    host_ticks_before = proc_cpu_ticks()
    cgroup_before = cgroup_snapshot()
    wall_start = time.time()
    monotonic_start = time.monotonic()
    deadline = monotonic_start + sample_secs
    while time.monotonic() < deadline:
        wait_process_alive(entry, "resource sample")
        time.sleep(min(0.5, max(0.01, deadline - time.monotonic())))
    monotonic_end = time.monotonic()
    wall_end = time.time()
    status_after = parse_proc_status(pid)
    stat_after = parse_process_stat_ticks(pid)
    host_ticks_after = proc_cpu_ticks()
    cgroup_after = cgroup_snapshot()
    elapsed = monotonic_end - monotonic_start
    ticks_per_second = os.sysconf("SC_CLK_TCK")
    delta_ticks = stat_after["total_ticks"] - stat_before["total_ticks"]
    cpu_percent_one_core = (delta_ticks / ticks_per_second / elapsed * 100.0) if elapsed > 0 else None
    host_delta = None
    if host_ticks_before and host_ticks_after:
        host_delta = host_ticks_after["total"] - host_ticks_before["total"]
    return {
        "pid": pid,
        "requested_sample_secs": sample_secs,
        "wall_start_epoch": wall_start,
        "wall_end_epoch": wall_end,
        "elapsed_wall_secs": elapsed,
        "reporting_interval_secs": 5,
        "proc_status_before_kb": status_before,
        "proc_status_after_kb": status_after,
        "proc_stat_before": stat_before,
        "proc_stat_after": stat_after,
        "proc_stat_delta_ticks": delta_ticks,
        "proc_stat_ticks_per_second": ticks_per_second,
        "estimated_agent_cpu_percent_of_one_logical_cpu": cpu_percent_one_core,
        "proc_stat_host_cpu_ticks_before": host_ticks_before,
        "proc_stat_host_cpu_ticks_after": host_ticks_after,
        "proc_stat_host_total_tick_delta": host_delta,
        "cgroup_before": cgroup_before,
        "cgroup_after": cgroup_after,
        "interpretation": (
            "Raw VmRSS/VmHWM and per-process /proc/<pid>/stat ticks over wall time only; "
            "this is not a claim about a 256 MB / 0.1-vCPU container or a quota-normalized benchmark."
        ),
    }


def phase1(ctx: dict[str, Any]) -> None:
    book: CaseBook = ctx["book"]
    processes: OwnedProcesses = ctx["processes"]
    server_bin: Path = ctx["server_bin"]
    agent_bin: Path = ctx["agent_bin"]
    admin_token: str = ctx["admin_token"]
    agent_token: str = ctx["agent_token"]
    conditions: dict[str, Any] = ctx["host_conditions"]
    if not ctx["server_ok"] or not ctx["agent_ok"]:
        missing = ", ".join(
            name for name, ok in (("rprobe-server", ctx["server_ok"]), ("rprobe-agent", ctx["agent_ok"])) if not ok
        )
        book.fail_prerequisite(
            [
                "stage1.server_ready",
                "stage1.unauthenticated_report_401",
                "stage1.agent_hello_report_online",
                "stage1.linux_metrics_nonzero",
                "stage1.procfs_cgroup_comparison",
                "stage1.create_group_level_1",
                "stage1.create_group_level_2",
                "stage1.reject_group_level_3",
                "stage1.assign_group",
                "stage1.reconnect_keeps_assignment",
                "stage1.proc_sample_5s_reporting_cycle",
                "stage1.agent_stops_offline",
            ],
            f"missing/non-executable binaries: {missing}",
        )
        return

    port = reserve_loopback_port()
    base_url = f"http://127.0.0.1:{port}"
    ctx["stage1_base_url"] = base_url
    server_entry: dict[str, Any] | None = None
    active_agent: dict[str, Any] | None = None
    try:
        try:
            server_entry = processes.start_server(server_bin, port, admin_token)
            ctx["stage1_server_entry"] = server_entry
        except Exception as error:
            book.fail_case("stage1.server_ready", f"could not spawn our server: {type(error).__name__}: {error}")
            book.fail_prerequisite(
                [
                    "stage1.unauthenticated_report_401",
                    "stage1.agent_hello_report_online",
                    "stage1.linux_metrics_nonzero",
                    "stage1.procfs_cgroup_comparison",
                    "stage1.create_group_level_1",
                    "stage1.create_group_level_2",
                    "stage1.reject_group_level_3",
                    "stage1.assign_group",
                    "stage1.reconnect_keeps_assignment",
                    "stage1.proc_sample_5s_reporting_cycle",
                    "stage1.agent_stops_offline",
                ],
                "server process did not start",
            )
            return

        ready = book.run("stage1.server_ready", lambda: _phase1_ready(server_entry, base_url))
        if ready is None:
            book.fail_prerequisite(
                [
                    "stage1.unauthenticated_report_401",
                    "stage1.agent_hello_report_online",
                    "stage1.linux_metrics_nonzero",
                    "stage1.procfs_cgroup_comparison",
                    "stage1.create_group_level_1",
                    "stage1.create_group_level_2",
                    "stage1.reject_group_level_3",
                    "stage1.assign_group",
                    "stage1.reconnect_keeps_assignment",
                    "stage1.proc_sample_5s_reporting_cycle",
                    "stage1.agent_stops_offline",
                ],
                "real server did not become ready",
            )
            return

        synthetic_hello = {
            "type": "hello",
            "hello": {
                "agent_id": AGENT_ID,
                "agent_version": "validation",
                "protocol_version": 1,
                "hostname": "unauthenticated-validation",
                "os": "linux",
                "kernel": "unknown",
                "cpu_model": "unknown",
                "cpu_cores": 1,
                "memory_total_bytes": 1,
                "virtualization": "unknown",
                "cgroup_memory_limit_bytes": None,
                "cgroup_cpu_limit_cores": None,
                "group": None,
            },
        }
        book.run(
            "stage1.unauthenticated_report_401",
            lambda: _expect_http_status(
                http_exchange(base_url + "/api/report", "POST", payload=synthetic_hello),
                401,
                "POST /api/report without credentials",
            ),
        )

        try:
            active_agent = processes.start_agent(agent_bin, "verify-linux-agent", base_url, 1)
        except Exception as error:
            book.fail_case("stage1.agent_hello_report_online", f"could not spawn agent: {type(error).__name__}: {error}")
            book.fail_prerequisite(
                ["stage1.linux_metrics_nonzero", "stage1.procfs_cgroup_comparison"],
                "initial agent process did not start",
            )
            # Group creation is independent of an online agent; attempt it below.
            initial_host = None
        else:
            def initial_host_operation() -> dict[str, Any]:
                wait_process_alive(active_agent, "initial agent")
                host = wait_for_host_report(base_url, admin_token)
                validate_hello(host.get("hello"))
                validate_report(host.get("report"))
                require(host.get("online") is True, "overview did not mark agent online")
                ctx["stage1_initial_host"] = host
                return {
                    "online": host.get("online"),
                    "agent_id": host["hello"]["agent_id"],
                    "protocol_version": host["hello"]["protocol_version"],
                    "report_collected_at": host["report"]["collected_at"],
                }

            initial_host_result = book.run("stage1.agent_hello_report_online", initial_host_operation)
            initial_host = ctx.get("stage1_initial_host") if initial_host_result is not None else None
            if initial_host is not None:
                book.run(
                    "stage1.linux_metrics_nonzero",
                    lambda: _check_nonzero_metrics(initial_host),
                )
                book.run(
                    "stage1.procfs_cgroup_comparison",
                    lambda: validate_procfs_cgroup_comparison(initial_host, conditions),
                )
            else:
                book.fail_prerequisite(
                    ["stage1.linux_metrics_nonzero", "stage1.procfs_cgroup_comparison"],
                    "agent hello/report did not arrive",
                )

        group_suffix = secrets.token_hex(4)
        root_id = f"verify-{group_suffix}-root"
        child_id = f"verify-{group_suffix}-child"
        third_id = f"verify-{group_suffix}-third"
        ctx["stage1_child_group_id"] = child_id
        root_response: dict[str, Any] = {}
        child_response: dict[str, Any] = {}

        def create_root() -> dict[str, Any]:
            status, body = post_group(base_url, admin_token, root_id, "Linux validation root")
            root_response.update(status=status, body_bytes=len(body))
            require(status == 201, f"root group returned HTTP {status}; expected 201")
            require(len(body) == 0, "POST /api/groups 201 response unexpectedly had a body")
            return root_response.copy()

        def create_child() -> dict[str, Any]:
            status, body = post_group(base_url, admin_token, child_id, "Linux validation child", root_id)
            child_response.update(status=status, body_bytes=len(body))
            require(status == 201, f"child group returned HTTP {status}; expected 201")
            require(len(body) == 0, "POST /api/groups 201 response unexpectedly had a body")
            return child_response.copy()

        def reject_third() -> dict[str, Any]:
            status, body = post_group(base_url, admin_token, third_id, "Linux validation third", child_id)
            require(status == 400, f"third-level group returned HTTP {status}; expected 400")
            require(len(body) == 0, "third-level rejection response body was not empty")
            return {"http_status": status, "response_body_bytes": len(body)}

        book.run("stage1.create_group_level_1", create_root)
        book.run("stage1.create_group_level_2", create_child)
        book.run("stage1.reject_group_level_3", reject_third)

        def assign_child() -> dict[str, Any]:
            status, body = api_json(
                base_url,
                f"/api/hosts/{AGENT_ID}/group",
                "PATCH",
                {"group_id": child_id},
                admin_token,
            )
            require(status == 204, f"assign group returned HTTP {status}; expected 204")
            require(len(body) == 0, "PATCH group 204 response unexpectedly had a body")
            host = get_host_snapshot(base_url, admin_token)
            require(host.get("group_id") == child_id, "overview did not reflect assigned group")
            return {"http_status": status, "group_id": host.get("group_id")}

        # Use the latest pre-reconnect report timestamp so a preserved stale report cannot
        # satisfy the reconnect check before the new agent has actually reported.
        previous_report_at = 0
        try:
            prior_host = get_host_snapshot(base_url, admin_token)
            prior_report = prior_host.get("report")
            if isinstance(prior_report, dict):
                previous_report_at = int(prior_report.get("collected_at", 0))
        except Exception:
            if initial_host is not None and isinstance(initial_host.get("report"), dict):
                previous_report_at = int(initial_host["report"].get("collected_at", 0))

        book.run("stage1.assign_group", assign_child)
        try:
            latest_before_reconnect = get_host_snapshot(base_url, admin_token)
            latest_report = latest_before_reconnect.get("report")
            if isinstance(latest_report, dict):
                previous_report_at = int(latest_report.get("collected_at", previous_report_at))
        except Exception:
            pass

        processes.stop(active_agent)
        active_agent = None
        restarted: dict[str, Any] | None = None
        try:
            restarted = processes.start_agent(agent_bin, "verify-linux-agent-restarted", base_url, 1)
            active_agent = restarted
        except Exception as error:
            book.fail_case("stage1.reconnect_keeps_assignment", f"could not spawn restarted agent: {type(error).__name__}: {error}")

        if restarted is not None:
            def verify_reconnect_assignment() -> dict[str, Any]:
                wait_process_alive(restarted, "restarted agent")
                host = wait_for_new_report(base_url, admin_token, previous_report_at)
                require(host.get("online") is True, "reconnected host is not online")
                require(host.get("group_id") == child_id, "assigned group did not survive hello/reconnect")
                return {
                    "online": host.get("online"),
                    "group_id": host.get("group_id"),
                    "report_collected_at": host["report"]["collected_at"],
                }

            book.run("stage1.reconnect_keeps_assignment", verify_reconnect_assignment)

        sample_after_report_at = previous_report_at
        try:
            current_host = get_host_snapshot(base_url, admin_token)
            current_report = current_host.get("report")
            if isinstance(current_report, dict):
                sample_after_report_at = int(current_report.get("collected_at", sample_after_report_at))
        except Exception:
            pass
        processes.stop(active_agent)
        active_agent = None
        sample_agent: dict[str, Any] | None = None
        try:
            sample_agent = processes.start_agent(agent_bin, "verify-linux-agent-sample-5s", base_url, 5)
            active_agent = sample_agent
        except Exception as error:
            book.fail_case("stage1.proc_sample_5s_reporting_cycle", f"could not spawn 5-second sampler: {type(error).__name__}: {error}")

        if sample_agent is not None:
            def run_stable_sample() -> dict[str, Any]:
                wait_process_alive(sample_agent, "5-second reporting sampler")
                host = wait_for_new_report(base_url, admin_token, sample_after_report_at)
                require(host.get("online") is True, "5-second sampler is not online")
                sample_start_report_at = int(host["report"]["collected_at"])
                sample = sample_agent_process(sample_agent, ctx["sample_secs"])
                # Confirm that the production reporting cadence advanced during sampling.
                later = wait_for_new_report(
                    base_url, admin_token, sample_start_report_at, timeout=8.0
                )
                sample["sample_start_report_collected_at"] = sample_start_report_at
                sample["latest_report_collected_at_after_sample"] = later["report"]["collected_at"]
                sample["report_timestamp_advance_secs"] = (
                    later["report"]["collected_at"] - sample_start_report_at
                )
                sample["reported_hello_group"] = host["hello"].get("group")
                ctx["stage1_resource_sample"] = sample
                return sample

            book.run("stage1.proc_sample_5s_reporting_cycle", run_stable_sample)

        processes.stop(active_agent)
        active_agent = None

        def verify_offline() -> dict[str, Any]:
            host = wait_agent_offline(base_url, admin_token)
            require(host.get("online") is False, "overview still reports host online")
            return {
                "online": host.get("online"),
                "last_seen_at": host.get("last_seen_at"),
                "offline_after_secs": 3,
            }

        book.run("stage1.agent_stops_offline", verify_offline)
    finally:
        processes.stop(active_agent)
        processes.stop(server_entry)


def _phase1_ready(server_entry: dict[str, Any], base_url: str) -> dict[str, Any]:
    wait_process_alive(server_entry, "rprobe-server")
    wait_for_server(base_url)
    return {"listening_url": base_url, "unauthenticated_overview_status": 401}


def _expect_http_status(
    response: tuple[int, bytes], expected: int, context: str
) -> dict[str, Any]:
    status, body = response
    require(status == expected, f"{context} returned HTTP {status}; expected {expected}")
    return {"http_status": status, "response_body_bytes": len(body)}


def _check_nonzero_metrics(host: dict[str, Any]) -> dict[str, Any]:
    hello = validate_hello(host.get("hello"))
    report = validate_report(host.get("report"))
    nonzero = {
        "cpu_cores": hello["cpu_cores"],
        "memory_total_bytes": hello["memory_total_bytes"],
        "memory_limit_bytes": report["memory_limit_bytes"],
        "disk_total_bytes": report["disk_total_bytes"],
        "process_count": report["process_count"],
        "uptime_secs": report["uptime_secs"],
    }
    require(all(value > 0 for value in nonzero.values()), "one or more Linux resource fields are zero")
    return {"nonzero_fields": nonzero, "cpu_percent_observed": report["cpu_percent"]}


class FakeHTTPState:
    def __init__(self, token: str):
        self.token = token
        self.lock = threading.Condition()
        self.messages: list[dict[str, Any]] = []
        self.upgrade_seen = False
        self.upgrade_rejected = False
        self.auth_header_ok = True
        self.id_header_ok = True

    def add_message(self, message: Any, headers: dict[str, str]) -> None:
        with self.lock:
            if headers.get("authorization") != f"Bearer {self.token}":
                self.auth_header_ok = False
            if headers.get("x-agent-id") != AGENT_ID:
                self.id_header_ok = False
            self.messages.append(
                {"message": message, "received_at_epoch": time.time(), "path": "/api/report"}
            )
            self.lock.notify_all()


class FakeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def phase2(ctx: dict[str, Any]) -> None:
    book: CaseBook = ctx["book"]
    processes: OwnedProcesses = ctx["processes"]
    agent_bin: Path = ctx["agent_bin"]
    if not ctx["agent_ok"]:
        book.fail_prerequisite(
            [
                "stage2.listener_ready",
                "stage2.reject_websocket_upgrade",
                "stage2.http_fallback_hello_report",
                "stage2.real_report_fields",
            ],
            "rprobe-agent binary is missing or not executable",
        )
        return

    state = FakeHTTPState(ctx["agent_token"])

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            if self.path == "/ws/agent":
                with state.lock:
                    state.upgrade_seen = True
                    state.upgrade_rejected = self.headers.get("Upgrade", "").lower() == "websocket"
                    state.lock.notify_all()
                self.send_response(426)
                self.send_header("Connection", "close")
                self.send_header("Content-Length", "0")
                self.end_headers()
                self.close_connection = True
                return
            self.send_error(404)

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            if self.path != "/api/report":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 1024 * 1024:
                    self.send_error(413)
                    return
                message = json.loads(self.rfile.read(length).decode("utf-8"))
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                self.send_error(400)
                return
            headers = {key.lower(): value for key, value in self.headers.items()}
            state.add_message(message, headers)
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = FakeHTTPServer(("127.0.0.1", 0), Handler)
    port = int(server.server_address[1])
    base_url = f"http://127.0.0.1:{port}"
    server_thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
    server_thread.start()
    agent: dict[str, Any] | None = None
    ctx["stage2_capture"] = state.messages
    try:
        book.run("stage2.listener_ready", lambda: _http_listener_ready(server, server_thread, base_url))
        try:
            agent = processes.start_agent(agent_bin, "verify-linux-agent-http", base_url, 1)
        except Exception as error:
            book.fail_case("stage2.reject_websocket_upgrade", f"could not spawn agent: {type(error).__name__}: {error}")
            book.fail_prerequisite(
                ["stage2.http_fallback_hello_report", "stage2.real_report_fields"],
                "agent process did not start",
            )
            return

        def wait_upgrade_rejected() -> dict[str, Any]:
            _wait_fake_http(state, lambda: state.upgrade_seen, 25.0)
            with state.lock:
                require(state.upgrade_rejected, "agent request did not contain Upgrade: websocket")
                return {"path": "/ws/agent", "upgrade_header_seen": state.upgrade_rejected, "response_status": 426}

        book.run("stage2.reject_websocket_upgrade", wait_upgrade_rejected)

        def wait_fallback_messages() -> dict[str, Any]:
            _wait_fake_http(
                state,
                lambda: {item.get("message", {}).get("type") for item in state.messages}
                >= {"hello", "report"},
                35.0,
            )
            with state.lock:
                messages = list(state.messages)
                require(state.auth_header_ok, "one or more HTTP fallback requests had incorrect Authorization")
                require(state.id_header_ok, "one or more HTTP fallback requests had incorrect X-Agent-Id")
            parsed = [item["message"] for item in messages]
            hello = next(item["hello"] for item in parsed if item.get("type") == "hello")
            report = next(item["report"] for item in parsed if item.get("type") == "report")
            validate_hello(hello)
            validate_report(report)
            ctx["stage2_capture"] = messages
            return {
                "message_types": sorted({item.get("type") for item in parsed}),
                "http_message_count": len(messages),
                "hello": hello,
                "report": report,
                "headers_verified_without_recording_token": True,
            }

        fallback = book.run("stage2.http_fallback_hello_report", wait_fallback_messages)

        def verify_report_fields() -> dict[str, Any]:
            require(fallback is not None, "HTTP fallback hello/report was not captured")
            report_record = next(
                item["message"]["report"]
                for item in ctx["stage2_capture"]
                if item.get("message", {}).get("type") == "report"
            )
            report = validate_report(report_record)
            return {
                "fields_present": sorted(report.keys()),
                "collected_at": report["collected_at"],
                "memory_used_bytes": report["memory_used_bytes"],
                "memory_limit_bytes": report["memory_limit_bytes"],
                "disk_total_bytes": report["disk_total_bytes"],
                "process_count": report["process_count"],
            }

        book.run("stage2.real_report_fields", verify_report_fields)
    finally:
        processes.stop(agent)
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=3.0)


def _http_listener_ready(
    server: FakeHTTPServer, thread: threading.Thread, base_url: str
) -> dict[str, Any]:
    require(thread.is_alive(), "HTTPServer serving thread is not alive")
    return {"listen_url": base_url, "server_class": "http.server.ThreadingHTTPServer"}


def _wait_fake_http(state: FakeHTTPState, predicate: Callable[[], bool], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    with state.lock:
        while not predicate():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VerificationError("timed out waiting for HTTP/WebSocket-fallback client request")
            state.lock.wait(timeout=min(0.5, remaining))


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        part = sock.recv(length - len(chunks))
        if not part:
            raise ConnectionError("peer closed during WebSocket frame")
        chunks.extend(part)
    return bytes(chunks)


def read_http_headers(sock: socket.socket, maximum: int = 65536) -> tuple[str, dict[str, str]]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        if len(data) >= maximum:
            raise VerificationError("WebSocket HTTP headers exceed size limit")
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("peer closed during WebSocket handshake")
        data.extend(chunk)
    header_bytes, _remainder = bytes(data).split(b"\r\n\r\n", 1)
    lines = header_bytes.decode("iso-8859-1").split("\r\n")
    if not lines:
        raise VerificationError("empty WebSocket handshake")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if separator:
            headers[name.strip().lower()] = value.strip()
    return lines[0], headers


def send_server_ws_text(sock: socket.socket, text: str) -> None:
    payload = text.encode("utf-8")
    prefix = bytearray([0x81])
    if len(payload) < 126:
        prefix.append(len(payload))
    elif len(payload) <= 0xFFFF:
        prefix.append(126)
        prefix.extend(struct.pack("!H", len(payload)))
    else:
        prefix.append(127)
        prefix.extend(struct.pack("!Q", len(payload)))
    sock.sendall(bytes(prefix) + payload)


def read_ws_text(sock: socket.socket, max_payload: int = 1024 * 1024) -> str | None:
    fragmented_opcode: int | None = None
    fragmented_payload = bytearray()
    while True:
        first, second = recv_exact(sock, 2)
        final = bool(first & 0x80)
        if first & 0x70:
            raise VerificationError("WebSocket frame uses unsupported RSV bits")
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", recv_exact(sock, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", recv_exact(sock, 8))[0]
        if length > max_payload:
            raise VerificationError(f"WebSocket frame payload exceeds {max_payload} bytes")
        if not masked:
            raise VerificationError("client WebSocket frames must be masked")
        mask = recv_exact(sock, 4)
        payload = bytearray(recv_exact(sock, length))
        if masked:
            for index in range(length):
                payload[index] ^= mask[index % 4]
        if opcode == 0x8:
            return None
        if opcode == 0x9:
            pong = bytearray([0x8A])
            if len(payload) < 126:
                pong.append(len(payload))
            elif len(payload) <= 0xFFFF:
                pong.append(126)
                pong.extend(struct.pack("!H", len(payload)))
            else:
                pong.append(127)
                pong.extend(struct.pack("!Q", len(payload)))
            sock.sendall(bytes(pong) + bytes(payload))
            continue
        if opcode == 0xA:
            continue
        if opcode in (0x1, 0x2):
            if fragmented_opcode is not None:
                raise VerificationError("new data frame started before fragmented frame completed")
            if final:
                if opcode != 0x1:
                    continue
                return bytes(payload).decode("utf-8")
            fragmented_opcode = opcode
            fragmented_payload.extend(payload)
            continue
        if opcode == 0x0:
            if fragmented_opcode is None:
                raise VerificationError("unexpected WebSocket continuation frame")
            fragmented_payload.extend(payload)
            if final:
                completed_opcode = fragmented_opcode
                complete = bytes(fragmented_payload)
                fragmented_opcode = None
                fragmented_payload.clear()
                if completed_opcode == 0x1:
                    return complete.decode("utf-8")
            continue
        raise VerificationError(f"unsupported WebSocket opcode {opcode}")


class OutageWebSocketReceiver(threading.Thread):
    def __init__(self, port: int, token: str, outage_secs: int):
        super().__init__(name="verify-linux-websocket-receiver", daemon=True)
        self.port = port
        self.token = token
        self.outage_secs = outage_secs
        self.stop_event = threading.Event()
        self.listening = threading.Event()
        self.outage_started = threading.Event()
        self.restored = threading.Event()
        self.condition = threading.Condition()
        self.error: str | None = None
        self.records: list[dict[str, Any]] = []
        self.handshakes: list[dict[str, Any]] = []
        self.initial_hello_seen = False
        self.initial_report_seen = False
        self.initial_hello: dict[str, Any] | None = None
        self.outage_start_epoch: float | None = None
        self.restored_epoch: float | None = None
        self.config_frames_sent = 0
        self.listener: socket.socket | None = None
        self.active_client: socket.socket | None = None

    def _new_listener(self) -> socket.socket:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.port))
        listener.listen(8)
        listener.settimeout(0.5)
        with self.condition:
            self.listener = listener
            self.condition.notify_all()
        return listener

    def run(self) -> None:
        listener: socket.socket | None = None
        try:
            listener = self._new_listener()
            self.listening.set()
            initial_complete = self._serve(listener, initial=True)
            if not initial_complete or self.stop_event.is_set():
                return
            self._close_socket(listener)
            listener = None
            self.outage_start_epoch = time.time()
            self.outage_started.set()
            with self.condition:
                self.condition.notify_all()
            if self.stop_event.wait(self.outage_secs):
                return
            listener = self._new_listener()
            self.restored_epoch = time.time()
            self.restored.set()
            with self.condition:
                self.condition.notify_all()
            self._serve(listener, initial=False)
        except Exception as error:
            if not self.stop_event.is_set():
                self.error = f"{type(error).__name__}: {error}"
                self.listening.set()
                self.outage_started.set()
                self.restored.set()
                with self.condition:
                    self.condition.notify_all()
        finally:
            self._close_socket(listener)
            with self.condition:
                current_listener = self.listener
                current_client = self.active_client
                self.listener = None
                self.active_client = None
            self._close_socket(current_client)
            self._close_socket(current_listener)

    def _serve(self, listener: socket.socket, initial: bool) -> bool:
        phase = "before_outage" if initial else "recovered"
        deadline = time.monotonic() + (40.0 if initial else 600.0)
        while not self.stop_event.is_set() and time.monotonic() < deadline:
            try:
                client, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop_event.is_set():
                    return False
                raise
            client.settimeout(4.0)
            with self.condition:
                self.active_client = client
            completed = False
            try:
                completed = self._handle_connection(client, phase, initial)
            except (OSError, ConnectionError, UnicodeDecodeError, json.JSONDecodeError, VerificationError):
                completed = False
            finally:
                self._close_socket(client)
                with self.condition:
                    if self.active_client is client:
                        self.active_client = None
            if initial and completed:
                return True
        if initial:
            raise VerificationError("did not receive both hello and report on initial WebSocket connection")
        return False

    def _handle_connection(self, client: socket.socket, phase: str, initial: bool) -> bool:
        request_line, headers = read_http_headers(client)
        parts = request_line.split()
        key = headers.get("sec-websocket-key", "")
        if len(parts) < 2 or parts[0] != "GET" or parts[1] != "/ws/agent":
            client.sendall(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            return False
        is_upgrade = headers.get("upgrade", "").lower() == "websocket"
        authorized = headers.get("authorization") == f"Bearer {self.token}"
        correct_id = headers.get("x-agent-id") == AGENT_ID
        if not is_upgrade or not key:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            return False
        accept = base64.b64encode(hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
        with self.condition:
            self.handshakes.append(
                {
                    "request_path": parts[1],
                    "upgrade_header_ok": is_upgrade,
                    "authorization_header_ok": authorized,
                    "agent_id_header_ok": correct_id,
                    "received_at_epoch": time.time(),
                }
            )
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        client.sendall(response.encode("ascii"))
        send_server_ws_text(client, json.dumps({"type": "config", "interval_secs": 1}, separators=(",", ":")))
        with self.condition:
            self.config_frames_sent += 1
            self.condition.notify_all()

        while not self.stop_event.is_set():
            raw_text = read_ws_text(client)
            if raw_text is None:
                return False
            message = json.loads(raw_text)
            message_type = message.get("type") if isinstance(message, dict) else None
            received_at = time.time()
            if message_type not in ("hello", "report"):
                continue
            if message_type == "hello":
                hello = message.get("hello")
                if isinstance(hello, dict):
                    validate_hello(hello)
                    if initial:
                        self.initial_hello_seen = True
                        self.initial_hello = hello
            elif message_type == "report":
                report = message.get("report")
                validate_report(report)
                if initial:
                    self.initial_report_seen = True
            record = {
                "phase": phase,
                "type": message_type,
                "received_at_epoch": received_at,
                "received_at_utc": iso_from_epoch(received_at),
                "message": message,
            }
            if message_type == "report":
                collected_at = message["report"]["collected_at"]
                record["collected_at"] = collected_at
                record["collected_at_utc"] = iso_from_epoch(collected_at)
                record["receipt_delay_secs"] = received_at - collected_at
            with self.condition:
                self.records.append(record)
                self.condition.notify_all()
            if initial and self.initial_hello_seen and self.initial_report_seen:
                # Deliberately drop both the WebSocket and listener to create the configured outage.
                return True
        return False

    def wait(self, event: threading.Event, timeout: float, what: str) -> None:
        if not event.wait(timeout):
            raise VerificationError(f"timed out waiting for WebSocket receiver {what}")
        if self.error:
            raise VerificationError(f"WebSocket receiver error: {self.error}")

    def snapshot(self) -> dict[str, Any]:
        with self.condition:
            return {
                "records": list(self.records),
                "handshakes": list(self.handshakes),
                "initial_hello_seen": self.initial_hello_seen,
                "initial_report_seen": self.initial_report_seen,
                "initial_hello": self.initial_hello,
                "outage_start_epoch": self.outage_start_epoch,
                "restored_epoch": self.restored_epoch,
                "config_frames_sent": self.config_frames_sent,
                "error": self.error,
            }

    def close(self) -> None:
        self.stop_event.set()
        with self.condition:
            listener = self.listener
            client = self.active_client
            self.listener = None
            self.active_client = None
        self._close_socket(client)
        self._close_socket(listener)

    @staticmethod
    def _close_socket(sock: socket.socket | None) -> None:
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


def phase3(ctx: dict[str, Any]) -> None:
    book: CaseBook = ctx["book"]
    processes: OwnedProcesses = ctx["processes"]
    agent_bin: Path = ctx["agent_bin"]
    if not ctx["agent_ok"]:
        book.fail_prerequisite(
            [
                "stage3.listener_ready",
                "stage3.initial_websocket_hello_report_and_disconnect",
                "stage3.outage_and_listener_restore",
                "stage3.agent_reconnect_and_replay",
                "stage3.collection_gap_continuity",
                "stage3.receive_time_interpretation",
            ],
            "rprobe-agent binary is missing or not executable",
        )
        return

    port = reserve_loopback_port()
    receiver = OutageWebSocketReceiver(port, ctx["agent_token"], ctx["outage_secs"])
    receiver.start()
    agent: dict[str, Any] | None = None
    ctx["stage3_receiver"] = receiver
    try:
        def wait_listener() -> dict[str, Any]:
            receiver.wait(receiver.listening, 5.0, "initial listener")
            require(receiver.error is None, receiver.error or "receiver error")
            return {"listen_url": f"ws://127.0.0.1:{port}/ws/agent", "implementation": "stdlib socket + manual RFC6455 handshake"}

        book.run("stage3.listener_ready", wait_listener)
        if receiver.error:
            book.fail_prerequisite(
                [
                    "stage3.initial_websocket_hello_report_and_disconnect",
                    "stage3.outage_and_listener_restore",
                    "stage3.agent_reconnect_and_replay",
                    "stage3.collection_gap_continuity",
                    "stage3.receive_time_interpretation",
                ],
                f"WebSocket receiver failed: {receiver.error}",
            )
            return
        try:
            agent = processes.start_agent(agent_bin, "verify-linux-agent-websocket-outage", f"http://127.0.0.1:{port}", 1)
        except Exception as error:
            book.fail_case("stage3.initial_websocket_hello_report_and_disconnect", f"could not spawn agent: {type(error).__name__}: {error}")
            book.fail_prerequisite(
                [
                    "stage3.outage_and_listener_restore",
                    "stage3.agent_reconnect_and_replay",
                    "stage3.collection_gap_continuity",
                    "stage3.receive_time_interpretation",
                ],
                "agent process did not start",
            )
            return

        def wait_initial_outage() -> dict[str, Any]:
            wait_process_alive(agent, "WebSocket outage agent")
            receiver.wait(receiver.outage_started, 45.0, "initial hello/report and forced disconnect")
            state = receiver.snapshot()
            require(state["initial_hello_seen"], "initial WebSocket hello was not received")
            require(state["initial_report_seen"], "initial WebSocket report was not received")
            require(bool(state["handshakes"]), "no WebSocket handshake was captured")
            require(state["handshakes"][0]["authorization_header_ok"], "WebSocket Authorization header did not match configured token")
            require(state["handshakes"][0]["agent_id_header_ok"], "WebSocket X-Agent-Id header mismatch")
            require(state["config_frames_sent"] >= 1, "server config was not sent on initial connection")
            return {
                "initial_hello_received": state["initial_hello_seen"],
                "initial_report_received": state["initial_report_seen"],
                "initial_connection_closed": True,
                "listener_closed_for_outage": True,
                "handshake": state["handshakes"][0],
                "config_frames_sent": state["config_frames_sent"],
                "outage_started_at_utc": iso_from_epoch(state["outage_start_epoch"]),
            }

        initial_ok = book.run("stage3.initial_websocket_hello_report_and_disconnect", wait_initial_outage)
        if initial_ok is None:
            book.fail_prerequisite(
                [
                    "stage3.outage_and_listener_restore",
                    "stage3.agent_reconnect_and_replay",
                    "stage3.collection_gap_continuity",
                    "stage3.receive_time_interpretation",
                ],
                "initial WebSocket connection did not deliver hello and report",
            )
            return

        def wait_restored() -> dict[str, Any]:
            timeout = ctx["outage_secs"] + 20.0
            receiver.wait(receiver.restored, timeout, "listener restoration after outage")
            state = receiver.snapshot()
            require(state["restored_epoch"] is not None and state["outage_start_epoch"] is not None, "outage timestamps unavailable")
            elapsed = state["restored_epoch"] - state["outage_start_epoch"]
            require(elapsed >= ctx["outage_secs"], f"outage lasted {elapsed:.3f}s, shorter than requested")
            return {
                "requested_outage_secs": ctx["outage_secs"],
                "actual_listener_downtime_secs": elapsed,
                "outage_started_at_utc": iso_from_epoch(state["outage_start_epoch"]),
                "listener_restored_at_utc": iso_from_epoch(state["restored_epoch"]),
            }

        book.run("stage3.outage_and_listener_restore", wait_restored)
        if receiver.error:
            book.fail_prerequisite(
                ["stage3.agent_reconnect_and_replay", "stage3.collection_gap_continuity", "stage3.receive_time_interpretation"],
                f"receiver failed during outage: {receiver.error}",
            )
            return

        def wait_replay_and_fresh() -> dict[str, Any]:
            deadline = time.monotonic() + max(180.0, ctx["outage_secs"] + 90.0)
            while time.monotonic() < deadline:
                wait_process_alive(agent, "WebSocket recovery agent")
                state = receiver.snapshot()
                recovered_reports = [
                    record for record in state["records"]
                    if record.get("phase") == "recovered" and record.get("type") == "report"
                ]
                replayed = [
                    record for record in recovered_reports
                    if state["outage_start_epoch"] <= record["collected_at"] <= state["restored_epoch"]
                ] if state["outage_start_epoch"] and state["restored_epoch"] else []
                fresh = [record for record in recovered_reports if record["collected_at"] > (state["restored_epoch"] or float("inf"))]
                if replayed and fresh:
                    ctx["stage3_replay_state"] = state
                    return {
                        "recovered_websocket_connections": len(state["handshakes"]) - 1,
                        "replayed_reports_collected_during_outage": len(replayed),
                        "fresh_reports_after_listener_restore": len(fresh),
                        "first_replayed_collected_at_utc": iso_from_epoch(replayed[0]["collected_at"]),
                        "first_replayed_received_at_utc": replayed[0]["received_at_utc"],
                        "first_fresh_collected_at_utc": iso_from_epoch(fresh[0]["collected_at"]),
                        "first_fresh_received_at_utc": fresh[0]["received_at_utc"],
                    }
                time.sleep(0.25)
            raise VerificationError("no outage-collected replay plus fresh report arrived after listener restoration")

        replay_result = book.run("stage3.agent_reconnect_and_replay", wait_replay_and_fresh)
        state = ctx.get("stage3_replay_state") or receiver.snapshot()
        reports = [record for record in state["records"] if record.get("type") == "report"]
        unique_collected = sorted({int(record["collected_at"]) for record in reports})
        gaps = [right - left for left, right in zip(unique_collected, unique_collected[1:])]
        max_gap = max(gaps) if gaps else None
        during = [
            record for record in reports
            if record.get("phase") == "recovered"
            and state.get("outage_start_epoch") is not None
            and state.get("restored_epoch") is not None
            and state["outage_start_epoch"] <= record["collected_at"] <= state["restored_epoch"]
        ]
        timing_details = {
            "all_websocket_report_count": len(reports),
            "unique_collected_timestamp_count": len(unique_collected),
            "collection_timestamp_gaps_secs": gaps,
            "maximum_collection_gap_secs": max_gap,
            "outage_reports_replayed_count": len(during),
            "replayed_receive_delay_secs": [round(record["receipt_delay_secs"], 3) for record in during],
            "replayed_received_after_listener_restore": all(
                record["received_at_epoch"] >= (state.get("restored_epoch") or 0) for record in during
            ),
            "explanation": (
                "A report is identified as replayed when its collected_at lies inside the listener outage "
                "but its received_at is after restoration. receipt_delay_secs is receive wall-clock minus "
                "collection time; compare the complete sorted collected_at sequence to see any lost interval."
            ),
        }
        ctx["stage3_report_timing"] = timing_details

        def check_collection_gap() -> dict[str, Any]:
            require(replay_result is not None, "reconnect/replay case did not complete")
            require(max_gap is not None, "not enough report timestamps to compute collection gap")
            allowed_gap_secs = 5
            require(
                max_gap <= allowed_gap_secs,
                f"maximum collection-time gap {max_gap}s exceeds {allowed_gap_secs}s continuity tolerance",
            )
            return {**timing_details, "continuity_tolerance_secs": allowed_gap_secs}

        book.run("stage3.collection_gap_continuity", check_collection_gap)

        def receipt_time_explanation() -> dict[str, Any]:
            require(replay_result is not None, "no report replay evidence was available")
            require(during, "no report collected during the outage was received after restoration")
            delays = [record["receipt_delay_secs"] for record in during]
            return {
                **timing_details,
                "minimum_replayed_receipt_delay_secs": min(delays),
                "maximum_replayed_receipt_delay_secs": max(delays),
                "meaning": "Positive delay of roughly the outage duration indicates deferred delivery; collection timestamps determine whether every interval was recovered.",
            }

        book.run("stage3.receive_time_interpretation", receipt_time_explanation)
        ctx["stage3_capture"] = state
    finally:
        processes.stop(agent)
        receiver.close()
        receiver.join(timeout=3.0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify existing Linux rprobe-agent/rprobe-server binaries using stdlib-only "
            "HTTP/WebSocket test receivers. This script never builds binaries."
        )
    )
    parser.add_argument("--bin-dir", required=True, type=Path, help="directory containing executable rprobe-agent and rprobe-server")
    parser.add_argument("--output-dir", required=True, type=Path, help="directory for verify_linux_results.json and logs")
    parser.add_argument("--sample-secs", type=int, default=30, help="stable 5-second-cycle process sampling duration (default: 30)")
    parser.add_argument("--outage-secs", type=int, default=120, help="WebSocket listener outage duration (default: 120)")
    return parser


def executable_binary(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def write_outputs(
    output_dir: Path,
    book: CaseBook,
    results: dict[str, Any],
    processes: OwnedProcesses,
) -> tuple[Path, Path]:
    processes.redact_logs()
    result_path = output_dir / "verify_linux_results.json"
    log_path = output_dir / "verify_linux.log"
    passed = sum(case["status"] == "PASS" for case in book.cases)
    failed = sum(case["status"] == "FAIL" for case in book.cases)
    results["cases"] = book.redact(book.cases)
    results["summary"] = {"status": "PASS" if failed == 0 else "FAIL", "passed": passed, "failed": failed, "exit_code": 0 if failed == 0 else 1}
    serialized = json.dumps(book.redact(results), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    result_path.write_text(serialized, encoding="utf-8")
    log_lines = [
        f"Started: {results.get('started_at_utc')}",
        f"Finished: {results.get('finished_at_utc')}",
    ]
    for case in book.cases:
        detail = case.get("details")
        suffix = f" — {json.dumps(book.redact(detail), ensure_ascii=False, sort_keys=True)}" if detail is not None else ""
        log_lines.append(f"{case['status']} {case['name']}{suffix}")
    log_lines.append(f"SUMMARY {results['summary']['status']} PASS={passed} FAIL={failed} EXIT={results['summary']['exit_code']}")
    log_path.write_text("\n".join(book.redact(log_lines)) + "\n", encoding="utf-8")
    return result_path, log_path


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.sample_secs <= 0:
        raise SystemExit("--sample-secs must be greater than zero")
    if args.outage_secs <= 0:
        raise SystemExit("--outage-secs must be greater than zero")
    try:
        args.output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise SystemExit(f"cannot create --output-dir: {error}") from error

    agent_token = secrets.token_urlsafe(32)
    admin_token = secrets.token_urlsafe(32)
    book = CaseBook([agent_token, admin_token])
    processes = OwnedProcesses(args.output_dir, agent_token, admin_token)
    agent_bin = args.bin_dir / "rprobe-agent"
    server_bin = args.bin_dir / "rprobe-server"
    host_conditions = collect_host_conditions()
    server_ok = executable_binary(server_bin)
    agent_ok = executable_binary(agent_bin)
    preflight_details = {
        "bin_dir": str(args.bin_dir),
        "rprobe_agent_exists_and_executable": agent_ok,
        "rprobe_server_exists_and_executable": server_ok,
        "linux_host": platform.system() == "Linux",
        "build_performed": False,
    }
    if server_ok and agent_ok and platform.system() == "Linux":
        book.pass_case("preflight.existing_binaries_linux", preflight_details)
    else:
        book.fail_case("preflight.existing_binaries_linux", preflight_details)

    results: dict[str, Any] = {
        "script": "scripts/verify_linux.py",
        "started_at_utc": utc_now(),
        "configuration": {
            "sample_secs": args.sample_secs,
            "outage_secs": args.outage_secs,
            "agent_interval_secs": 1,
            "resource_sample_reporting_interval_secs": 5,
            "offline_after_secs": 3,
            "token_generated_randomly": True,
            "token_written_to_results": False,
        },
        "host_conditions": host_conditions,
        "resource_sample_interpretation": (
            "No claim is made that measurements represent 256 MB or 0.1 vCPU. "
            "Raw values and observed host/cgroup limits are captured for context."
        ),
        "captures": {},
        "build_performed": False,
    }
    ctx = {
        "book": book,
        "processes": processes,
        "server_bin": server_bin,
        "agent_bin": agent_bin,
        "server_ok": server_ok,
        "agent_ok": agent_ok,
        "agent_token": agent_token,
        "admin_token": admin_token,
        "sample_secs": args.sample_secs,
        "outage_secs": args.outage_secs,
        "host_conditions": host_conditions,
    }
    try:
        if platform.system() != "Linux":
            book.fail_case("preflight.linux_platform", f"current platform is {platform.system()}, Linux is required")
        else:
            book.pass_case("preflight.linux_platform", {"system": platform.system(), "kernel": platform.release()})
        for phase_name, phase in (("stage1", phase1), ("stage2", phase2), ("stage3", phase3)):
            try:
                phase(ctx)
            except Exception as error:
                # Record the phase crash, but keep trying independent remaining phases.
                book.fail_case(f"{phase_name}.unhandled_error", f"{type(error).__name__}: {error}")
    except KeyboardInterrupt:
        book.fail_case("run.interrupted", "verification interrupted by user")
    except Exception as error:
        # A phase-level guard prevents one unexpected bug from hiding later independent phases.
        book.fail_case("run.unhandled_error", f"{type(error).__name__}: {error}")
    finally:
        processes.cleanup_all()
        processes.redact_logs()
        for key in ("stage1_resource_sample", "stage1_initial_host", "stage2_capture", "stage3_capture"):
            if key in ctx:
                results["captures"][key] = ctx[key]
        if "stage3_report_timing" in ctx:
            results["captures"]["stage3_report_timing"] = ctx["stage3_report_timing"]
        results["finished_at_utc"] = utc_now()
        try:
            result_path, log_path = write_outputs(args.output_dir, book, results, processes)
        except OSError as error:
            # Output errors cannot be serialized to the requested directory; still return failure.
            safe_error = book.redact(f"cannot write result/log files: {type(error).__name__}: {error}")
            print(f"FAIL {safe_error}", file=sys.stderr)
            return 1

    failed_cases = [case for case in book.cases if case["status"] == "FAIL"]
    for case in book.cases:
        print(f"{case['status']} {case['name']}")
        if case["status"] == "FAIL":
            print(f"  {book.redact(case.get('details'))}")
    passed = len(book.cases) - len(failed_cases)
    exit_code = 1 if failed_cases else 0
    print(f"SUMMARY {'PASS' if exit_code == 0 else 'FAIL'} PASS={passed} FAIL={len(failed_cases)} EXIT={exit_code}")
    print(f"Results: {result_path}")
    print(f"Log: {log_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
