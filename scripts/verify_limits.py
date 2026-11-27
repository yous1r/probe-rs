#!/usr/bin/env python3
"""Run existing binaries under a temporary systemd 256 MiB / 0.1 CPU limit.

Requires Linux systemd and passwordless sudo. Never builds or installs software.
Only the temporary service and subprocess created here are stopped on exit.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--sample-secs', type=int, default=60)
    args = parser.parse_args()
    if args.sample_secs < 10:
        parser.error('--sample-secs must be at least 10')
    args.output_dir.mkdir(parents=True, exist_ok=True)
    token, admin = secrets.token_hex(24), secrets.token_hex(24)
    token_file = (args.output_dir / ('.agent-token-' + secrets.token_hex(6))).resolve()
    token_fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(token_fd, 'w') as token_stream:
        token_stream.write(token + '\n')
    unit = 'rprobe-verify-' + secrets.token_hex(6)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    base_url = f'http://127.0.0.1:{port}'
    env = {**os.environ, 'RPROBE_LISTEN': f'127.0.0.1:{port}',
           'RPROBE_AGENT_TOKENS': f'limited={token}', 'RPROBE_ADMIN_TOKEN': admin}
    server = agent = None
    result = {'status': 'FAIL', 'build_performed': False,
              'expected_memory_limit_bytes': 268435456, 'expected_cpu_limit_cores': 0.1,
              'report_interval_secs': 5, 'requested_sample_secs': args.sample_secs}
    try:
        with (args.output_dir / 'server.log').open('w') as log:
            server = subprocess.Popen([str(args.bin_dir.resolve() / 'rprobe-server')],
                                      env=env, stdout=log, stderr=log)
        deadline = time.monotonic() + 20
        while True:
            try:
                urllib.request.urlopen(base_url + '/', timeout=1).close()
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError('Server failed to start')
                time.sleep(.2)
        with (args.output_dir / 'agent.log').open('w') as log:
            agent = subprocess.Popen([
                'sudo', '-n', 'systemd-run', '--quiet', '--wait', '--collect', '--unit=' + unit,
                '--property=CPUQuota=10%', '--property=MemoryMax=256M',
                '--property=User=' + str(os.getuid()),
                str(args.bin_dir.resolve() / 'rprobe-agent'), '--server', base_url,
                '--id', 'limited', '--token-file', str(token_file), '--interval', '5'],
                stdout=log, stderr=log)
        request = urllib.request.Request(base_url + '/api/overview',
                                         headers={'Authorization': 'Bearer ' + admin})
        host = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with urllib.request.urlopen(request, timeout=2) as response:
                data = json.load(response)
            if data['hosts'] and data['hosts'][0]['report']:
                host = data['hosts'][0]
                break
            time.sleep(.25)
        if not host:
            raise RuntimeError('No report received from agent in constrained cgroup')
        result.update(observed_memory_limit_bytes=host['report']['memory_limit_bytes'],
                      observed_cpu_limit_cores=host['hello']['cgroup_cpu_limit_cores'])
        pid = int(subprocess.check_output(['systemctl', 'show', unit, '-p', 'MainPID', '--value'], text=True))
        proc = Path('/proc') / str(pid)
        result['agent_cgroup_membership'] = (proc / 'cgroup').read_text()
        def sample():
            fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
            status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
            return {'ticks': int(fields[11]) + int(fields[12]),
                    'rss_kib': int(status['VmRSS'].split()[0]),
                    'hwm_kib': int(status['VmHWM'].split()[0]), 'time': time.monotonic()}
        first = sample()
        peak = first['rss_kib']
        deadline = first['time'] + args.sample_secs
        while time.monotonic() < deadline:
            time.sleep(min(.5, max(.01, deadline - time.monotonic())))
            last = sample()
            peak = max(peak, last['rss_kib'])
        elapsed = last['time'] - first['time']
        ticks = last['ticks'] - first['ticks']
        cpu = ticks / os.sysconf('SC_CLK_TCK') / elapsed * 100
        with urllib.request.urlopen(request, timeout=2) as response:
            latest = json.load(response)['hosts'][0]
        result.update(elapsed_secs=elapsed, cpu_delta_ticks=ticks,
                      cpu_percent_of_one_core=cpu, cpu_percent_of_0_1_core_quota=cpu / 0.1,
                      peak_rss_kib=peak, high_water_kib=last['hwm_kib'],
                      first_report_timestamp=host['report']['collected_at'],
                      last_report_timestamp=latest['report']['collected_at'])
        checks = {
            'memory_quota': result['observed_memory_limit_bytes'] == 268435456,
            'cpu_quota': result['observed_cpu_limit_cores'] == 0.1,
            'rss_under_6_mb': peak * 1024 < 6000000,
            'cpu_under_1_percent_of_one_core': cpu < 1,
            'reports_continue': latest['report']['collected_at'] > host['report']['collected_at'],
        }
        result['checks'] = checks
        result['status'] = 'PASS' if all(checks.values()) else 'FAIL'
    except Exception as error:
        result['error'] = str(error).replace(token, '[REDACTED]').replace(admin, '[REDACTED]')
    finally:
        subprocess.run(['sudo', '-n', 'systemctl', 'stop', unit],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for process in [agent, server]:
            if process is None:
                continue
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        token_file.unlink(missing_ok=True)
        (args.output_dir / 'verify_limits_results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
