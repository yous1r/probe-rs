#!/usr/bin/env python3
"""Verify durable SQLite state using existing rprobe-server; never build or run an agent.

Requires POSIX for SIGKILL. Credentials and databases live in a temporary directory;
only a JSON summary and bounded, redacted server logs are retained in --output-dir.
"""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


TIMEOUT = 5
STARTUP_TIMEOUT = 30
LOG_LIMIT = 1024 * 1024


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Verification:
    def __init__(self, binary, output, root, result):
        self.binary, self.output, self.root, self.result = binary, output, root, result
        self.database = root / 'rprobe.sqlite'
        self.token, self.admin = secrets.token_hex(24), secrets.token_hex(24)
        self.process, self.logs = None, []
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.env = {k: v for k, v in os.environ.items() if not k.upper().startswith('RPROBE_')}

    def redact(self, value):
        for token in (self.token, self.admin):
            value = value.replace(token, '[REDACTED]')
        return value

    def credential(self, name, value):
        path = self.root / 'credentials' / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(value + '\n')
        require(path.stat().st_mode & 0o777 == 0o600, 'credential file must have mode 0600')
        return str(path)

    def spawn(self, label, database):
        require(self.process is None, 'previous child was not reaped')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.base = f'http://127.0.0.1:{port}'
        env = dict(self.env, RPROBE_LISTEN=f'127.0.0.1:{port}', RPROBE_DB_PATH=str(database))
        log = self.root / (label + '.log')
        self.logs.append(log)
        self.result['phase'] = label
        with log.open('wb') as stream:
            self.process = subprocess.Popen([str(self.binary)], cwd=self.root, env=env,
                                            stdin=subprocess.DEVNULL, stdout=stream,
                                            stderr=subprocess.STDOUT)

    def stop(self):
        if self.process is None:
            return None
        if self.process.poll() is None:
            self.process.kill()
        code = self.process.wait(timeout=TIMEOUT)
        self.process = None
        return code

    def crash(self):
        require(self.process is not None and self.process.poll() is None,
                'server exited before the forced crash')
        require(self.stop() == -signal.SIGKILL, 'server was not terminated by SIGKILL')

    def start(self, label):
        self.spawn(label, self.database)
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            require(self.process.poll() is None, label + ': server exited; see server log')
            try:
                self.request('GET', '/', timeout=min(1, deadline - time.monotonic()))
                return
            except (OSError, AssertionError):
                time.sleep(min(.2, max(0, deadline - time.monotonic())))
        raise RuntimeError(label + ': readiness exceeded 30 seconds')

    def request(self, method, path, payload=None, agent=False, expected=200, timeout=TIMEOUT):
        headers = {'Authorization': 'Bearer ' + (self.token if agent else self.admin)}
        body = None
        if agent:
            headers['X-Agent-Id'] = 'a'
        if payload is not None:
            body = json.dumps(payload).encode()
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=max(.001, timeout))
        except urllib.error.HTTPError as error:
            response = error
        with response:
            content = response.read(LOG_LIMIT + 1)
            require(response.code == expected,
                    f'{method} {path}: expected HTTP {expected}, got {response.code}')
            require(len(content) <= LOG_LIMIT, path + ': oversized response')
            return content

    def snapshot(self, label):
        data = json.loads(self.request('GET', '/api/overview'))
        require(len(data['hosts']) == 1 and data['hosts'][0]['hello']['agent_id'] == 'a',
                label + ': missing host or duplicate hosts')
        self.result['snapshots'][label] = data
        return data

    def compare(self, actual, expected, online, label):
        host = dict(expected['hosts'][0], online=online)
        require(actual['hosts'] == [host], label + ': host details, report, liveness or assignment changed')
        order = lambda group: group['id']
        require(sorted(actual['groups'], key=order) == sorted(expected['groups'], key=order),
                label + ': group hierarchy, colors, sort order or group count changed')

    def check_database(self, snapshot):
        with closing(sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True,
                                     timeout=TIMEOUT)) as connection:
            connection.row_factory = sqlite3.Row
            require(connection.execute('PRAGMA journal_mode').fetchone()[0].lower() == 'wal',
                    'SQLite journal_mode is not WAL')
            require(connection.execute('PRAGMA user_version').fetchone()[0] == 1,
                    'SQLite schema version is not 1')
            columns = {'hosts': {'id', 'hello_json', 'report_json', 'last_seen_at', 'group_id',
                                 'clock_skew_secs'},
                       'groups': {'id', 'parent_id', 'name', 'sort', 'color'}}
            for table, names in columns.items():
                actual = {row['name'] for row in connection.execute(f'PRAGMA table_info({table})')}
                require(actual == names, table + ': unexpected SQLite columns')
            hosts = [dict(row) for row in connection.execute('SELECT * FROM hosts')]
            require(len(hosts) == 1, 'SQLite must contain exactly one host')
            host = snapshot['hosts'][0]
            row = hosts[0]
            row['hello_json'], row['report_json'] = json.loads(row['hello_json']), json.loads(row['report_json'])
            expected = dict(id='a', hello_json=host['hello'], report_json=host['report'],
                            last_seen_at=host['last_seen_at'], group_id=host['group_id'],
                            clock_skew_secs=host['clock_skew_secs'])
            require(row == expected, 'SQLite host row differs from acknowledged API state')
            groups = [dict(row) for row in connection.execute('SELECT * FROM groups ORDER BY id')]
            require(groups == sorted(snapshot['groups'], key=lambda group: group['id']),
                    'SQLite groups differ from acknowledged API state')

    def passed(self, name):
        self.result['checks'].append({'name': name, 'status': 'PASS'})

    def rejected_startup(self, label, database):
        self.spawn(label, database)
        try:
            code = self.process.wait(timeout=STARTUP_TIMEOUT)
            require(code > 0, label + ': startup must fail with a nonzero exit, without crashing')
            self.result['startup_exit_codes'][label] = code
        except subprocess.TimeoutExpired:
            raise AssertionError(label + ': server did not reject the database within 30 seconds') from None
        finally:
            self.stop()

    def preserve_logs(self):
        for source in self.logs:
            with source.open('rb') as stream:
                content = stream.read(LOG_LIMIT + 256).decode('utf-8', errors='replace')
            content = self.redact(content)
            if len(content) > LOG_LIMIT:
                content = content[:LOG_LIMIT] + '\n[log truncated]\n'
            (self.output / source.name).write_text(content, encoding='utf-8')

    def run(self):
        require(self.binary.is_file(), 'existing rprobe-server binary not found: ' + str(self.binary))
        require(os.name == 'posix', 'crash verification requires POSIX SIGKILL')
        (self.root / 'credentials').mkdir(mode=0o700)
        self.env.update(RPROBE_AGENT_TOKENS_FILE=self.credential('agents', 'a=' + self.token),
                        RPROBE_ADMIN_TOKEN_FILE=self.credential('admin', self.admin),
                        RPROBE_OFFLINE_AFTER_SECS='3600')
        hello = {'agent_id': 'a', 'agent_version': '0.1.0', 'protocol_version': 1,
                 'hostname': 'persistence-validation', 'os': 'linux', 'kernel': 'test',
                 'cpu_model': 'test', 'cpu_cores': 2, 'memory_total_bytes': 4096,
                 'virtualization': 'test', 'cgroup_memory_limit_bytes': 2048,
                 'cgroup_cpu_limit_cores': 1.5, 'group': 'auto'}
        self.start('initial')
        before = int(time.time())
        self.request('POST', '/api/report', {'type': 'hello', 'hello': hello}, agent=True, expected=202)
        report = {'collected_at': int(time.time()), 'cpu_percent': 12.5,
                  'memory_used_bytes': 512, 'memory_limit_bytes': 2048,
                  'swap_used_bytes': 0, 'swap_total_bytes': 0, 'disk_used_bytes': 1024,
                  'disk_total_bytes': 8192, 'load1': .25, 'load5': .5, 'load15': .75,
                  'rx_bytes_per_sec': 10, 'tx_bytes_per_sec': 20, 'rx_bytes_total': 100,
                  'tx_bytes_total': 200, 'tcp_connections': 2, 'udp_connections': 1,
                  'process_count': 3, 'uptime_secs': 42, 'openvz_beancounters': {}}
        self.request('POST', '/api/report', {'type': 'report', 'report': report}, agent=True, expected=202)
        groups = [{'id': 'auto', 'parent_id': None, 'name': 'auto', 'sort': 0, 'color': None},
                  {'id': 'root', 'parent_id': None, 'name': 'Root group', 'sort': 7, 'color': '#123456'},
                  {'id': 'child', 'parent_id': 'root', 'name': 'Child group', 'sort': -3, 'color': '#abcdef'}]
        for group in groups[1:]:
            require(self.request('POST', '/api/groups', group, expected=201) == b'',
                    'group creation must return an empty 201 response')
        require(self.request('PATCH', '/api/hosts/a/group', {'group_id': 'child'}, expected=204) == b'',
                'group assignment must return an empty 204 response')
        initial = self.snapshot('initial')
        host = initial['hosts'][0]
        require(before <= host['last_seen_at'] <= int(time.time()), 'invalid initial last_seen_at')
        expected = {'hosts': [dict(hello=hello, report=report, last_seen_at=host['last_seen_at'],
                                  online=True, group_id='child',
                                  clock_skew_secs=host['last_seen_at'] - report['collected_at'])],
                    'groups': groups}
        self.compare(initial, expected, True, 'initial')
        self.check_database(initial)
        self.passed('initial_rows_schema_v1_wal_and_hierarchy')

        self.crash()
        self.start('restart-manual')
        restored = self.snapshot('restored_manual')
        self.compare(restored, initial, False, 'restored manual assignment')
        self.check_database(restored)
        self.passed('sigkill_retains_host_report_last_seen_groups_and_assignment_offline')
        self.request('POST', '/api/report', {'type': 'report', 'report': report}, agent=True, expected=202)
        duplicate = self.snapshot('duplicate_after_restart')
        self.compare(duplicate, restored, False, 'duplicate report after restart')
        self.check_database(duplicate)
        self.passed('duplicate_report_after_restart_does_not_refresh_liveness')
        changed_hello = dict(hello, group='must-not-be-created', hostname='reconnected-validation')
        self.request('POST', '/api/report', {'type': 'hello', 'hello': changed_hello}, agent=True, expected=202)
        expected = {'hosts': [dict(host, hello=changed_hello)], 'groups': groups}
        changed = self.snapshot('hello_preserves_manual')
        self.compare(changed, expected, False, 'Hello with a different group')
        self.check_database(changed)
        self.passed('hello_preserves_manual_assignment_without_creating_group')

        deadline = time.monotonic() + TIMEOUT
        while int(time.time()) <= max(host['last_seen_at'], report['collected_at']):
            require(time.monotonic() < deadline, 'clock did not advance for a newer report')
            time.sleep(.1)
        newer_report = dict(report, collected_at=int(time.time()), cpu_percent=37.5,
                            rx_bytes_total=321, uptime_secs=84)
        self.request('POST', '/api/report', {'type': 'report', 'report': newer_report}, agent=True, expected=202)
        updated = self.snapshot('newer_report_online')
        new_host = updated['hosts'][0]
        require(host['last_seen_at'] < new_host['last_seen_at'] <= int(time.time()),
                'new report did not advance last_seen_at')
        expected['hosts'] = [dict(expected['hosts'][0], report=newer_report,
                                  last_seen_at=new_host['last_seen_at'],
                                  clock_skew_secs=new_host['last_seen_at'] - newer_report['collected_at'])]
        self.compare(updated, expected, True, 'newer report')
        self.check_database(updated)
        self.passed('newer_report_refreshes_online_status_and_database')
        self.request('PATCH', '/api/hosts/a/group', {'group_id': None}, expected=204)
        ungrouped = self.snapshot('explicit_ungroup')
        expected['hosts'] = [dict(new_host, group_id=None)]
        self.compare(ungrouped, expected, True, 'explicit ungroup')
        self.check_database(ungrouped)
        self.crash()
        self.start('restart-ungrouped')
        restored = self.snapshot('restored_ungrouped')
        self.compare(restored, ungrouped, False, 'restored explicit ungroup')
        self.check_database(restored)
        self.passed('explicit_null_assignment_survives_sigkill')
        for replay in (newer_report, report):
            self.request('POST', '/api/report', {'type': 'report', 'report': replay}, agent=True, expected=202)
        duplicate = self.snapshot('duplicate_and_older_after_restart')
        self.compare(duplicate, restored, False, 'duplicate and older reports')
        self.check_database(duplicate)
        self.passed('duplicate_and_older_reports_preserve_last_seen_and_offline')
        self.request('POST', '/api/report', {'type': 'hello', 'hello': hello}, agent=True, expected=202)
        expected['hosts'] = [dict(restored['hosts'][0], hello=hello)]
        final = self.snapshot('hello_preserves_ungrouped')
        self.compare(final, expected, False, 'Hello after explicit ungroup')
        self.check_database(final)
        self.passed('hello_initial_group_preserves_null_without_duplicate_host')
        self.crash()
        self.check_database(final)

        corrupt = self.root / 'corrupt.sqlite'
        original = b'not a SQLite database\x00' + secrets.token_bytes(256)
        corrupt.write_bytes(original)
        corrupt.chmod(0o600)  # Reach SQLite corruption validation, not just the permission guard.
        self.rejected_startup('corrupt-db', corrupt)
        require(corrupt.read_bytes() == original, 'corrupt database was replaced or modified')
        self.passed('corrupt_database_rejected_without_replacement')
        self.rejected_startup('memory-db', ':memory:')
        self.passed('memory_database_rejected')
        directory = self.root / 'database-is-directory'
        directory.mkdir()
        self.rejected_startup('directory-db', directory)
        require(directory.is_dir(), 'database directory was replaced')
        self.passed('unwritable_directory_database_rejected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    result = {'status': 'FAIL', 'build_performed': False, 'checks': [],
              'snapshots': {}, 'startup_exit_codes': {}}
    verifier = None
    try:
        with tempfile.TemporaryDirectory(prefix='rprobe-persistence-') as temporary:
            verifier = Verification(args.bin_dir.resolve() / 'rprobe-server', output,
                                    Path(temporary).resolve(), result)
            try:
                verifier.run()
                result['status'] = 'PASS'
            finally:
                try:
                    verifier.stop()
                finally:
                    verifier.preserve_logs()
    except (Exception, KeyboardInterrupt) as error:
        result['status'] = 'FAIL'
        message = type(error).__name__ + ': ' + str(error)
        result['error'] = verifier.redact(message) if verifier else message
    text = json.dumps(result, indent=2) + '\n'
    (output / 'verify_persistence_results.json').write_text(text, encoding='utf-8')
    print(text, end='')
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
