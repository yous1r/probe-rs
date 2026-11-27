#!/usr/bin/env python3
"""Bounded security regression checks against existing binaries; no build step."""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def frame(payload, opcode=1):
    payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    mask = os.urandom(4)
    length = len(payload)
    header = bytes([0x80 | opcode, 0x80 | length]) if length < 126 else bytes([0x80 | opcode, 0xfe]) + struct.pack('!H', length)
    return header + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(payload))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    agent_bin = args.bin_dir.resolve() / 'rprobe-agent'
    server_bin = args.bin_dir.resolve() / 'rprobe-server'
    token, other, admin = (secrets.token_hex(24) for _ in range(3))
    cases, sockets, children = [], [], []
    server_port = port()
    base = f'http://127.0.0.1:{server_port}'
    hello = {'type': 'hello', 'hello': {'agent_id': 'a', 'agent_version': '0.1.0', 'protocol_version': 1,
        'hostname': 'validation', 'os': 'linux', 'kernel': 'test', 'cpu_model': 'test', 'cpu_cores': 1,
        'memory_total_bytes': 1024, 'virtualization': 'test', 'cgroup_memory_limit_bytes': None,
        'cgroup_cpu_limit_cores': None, 'group': None}}
    now = int(time.time())
    report = {'type': 'report', 'report': {'collected_at': now, 'cpu_percent': 1,
        'memory_used_bytes': 1, 'memory_limit_bytes': 1024, 'swap_used_bytes': 0, 'swap_total_bytes': 0,
        'disk_used_bytes': 1, 'disk_total_bytes': 1024, 'load1': 0, 'load5': 0, 'load15': 0,
        'rx_bytes_per_sec': 0, 'tx_bytes_per_sec': 0, 'rx_bytes_total': 1, 'tx_bytes_total': 1,
        'tcp_connections': 0, 'udp_connections': 0, 'process_count': 1, 'uptime_secs': 1,
        'openvz_beancounters': {}}}

    def check(name, operation):
        try:
            detail = operation()
            cases.append({'name': name, 'status': 'PASS', 'detail': detail})
            print('PASS', name, flush=True)
        except Exception as error:
            message = str(error)
            for credential in (token, other, admin):
                message = message.replace(credential, '[REDACTED]')
            cases.append({'name': name, 'status': 'FAIL', 'detail': message})
            print('FAIL', name, message, flush=True)

    def require(condition, message):
        if not condition:
            raise AssertionError(message)

    def api(path, credential=None, identity=None, payload=None):
        headers = {}
        if credential:
            headers['Authorization'] = 'Bearer ' + credential
        if identity:
            headers['X-Agent-Id'] = identity
        body = None
        if payload is not None:
            body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(base + path, data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def ws(identity='a', credential=token, extra=''):
        sock = socket.create_connection(('127.0.0.1', server_port), timeout=5)
        sockets.append(sock)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (f'GET /ws/agent HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nUpgrade: websocket\r\n'
                   f'Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n'
                   f'Authorization: Bearer {credential}\r\nX-Agent-Id: {identity}\r\n{extra}\r\n')
        sock.sendall(request.encode())
        headers = b''
        while not headers.endswith(b'\r\n\r\n'):
            chunk = sock.recv(1)
            require(bool(chunk), 'EOF during handshake')
            headers += chunk
            require(len(headers) < 16384, 'oversized response headers')
        return sock, int(headers.split(b' ')[1])

    def wait_closed(sock):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                if not sock.recv(65536):
                    return
            except (ConnectionResetError, BrokenPipeError):
                return
            except socket.timeout:
                continue
        raise AssertionError('connection was not closed within the test deadline')

    with tempfile.TemporaryDirectory(prefix='rprobe-security-') as credential_dir:
        credential_dir = Path(credential_dir)
        def secret_file(name, value):
            path = credential_dir / name
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(value)
            return path
        token_path = secret_file('agent', token)
        tokens_path = secret_file('agents', f'a={token}\nb={other}\n')
        admin_path = secret_file('admin', admin)
        env = {k: v for k, v in os.environ.items() if not k.startswith('RPROBE_')}
        env.update(RPROBE_LISTEN=f'127.0.0.1:{server_port}', RPROBE_AGENT_TOKENS_FILE=str(tokens_path),
                   RPROBE_ADMIN_TOKEN_FILE=str(admin_path), RPROBE_OFFLINE_AFTER_SECS='2')
        env['RPROBE_DB_PATH'] = str(credential_dir / 'registry.sqlite')
        try:
            with (args.output_dir / 'server.log').open('w') as log:
                server = subprocess.Popen([str(server_bin)], env=env, stdout=log, stderr=log)
            children.append(server)
            deadline = time.monotonic() + 30
            while True:
                try:
                    if api('/')[0] == 200:
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError('test server failed to start')
                    time.sleep(.2)

            def auth_checks():
                for path in ('/api/overview', '/api/groups', '/api/events'):
                    require(api(path)[0] == 401, path + ' permitted anonymous access')
                    require(api(path, token)[0] == 401, path + ' permitted agent access')
                require(api('/api/report', token, 'b', hello)[0] == 401, 'cross-agent token accepted')
                require(api('/api/report', payload=b'{')[0] == 401, 'parsed unauthenticated body')
                require(api('/api/groups', admin, payload=b'x' * 16385)[0] == 413, 'oversized body accepted')
            check('http_identity_and_size_boundaries', auth_checks)

            def report_checks():
                require(api('/api/report', token, 'a', hello)[0] == 202, 'valid Hello rejected')
                require(api('/api/report', token, 'a', report)[0] == 202, 'valid Report rejected')
                first = json.loads(api('/api/overview', admin)[1])['hosts'][0]['last_seen_at']
                time.sleep(3)
                require(api('/api/report', token, 'a', report)[0] == 202, 'duplicate not idempotent')
                host = json.loads(api('/api/overview', admin)[1])['hosts'][0]
                require(host['last_seen_at'] == first and not host['online'], 'duplicate refreshed online status')
                invalid = json.loads(json.dumps(report))
                invalid['report']['collected_at'] = int(time.time()) + 3600
                require(api('/api/report', token, 'a', invalid)[0] == 400, 'future timestamp accepted')
                invalid['report']['collected_at'] = 1
                require(api('/api/report', token, 'a', invalid)[0] == 400, 'ancient timestamp accepted')
                invalid_hello = json.loads(json.dumps(hello))
                invalid_hello['hello']['hostname'] = 'x' * 256
                require(api('/api/report', token, 'a', invalid_hello)[0] == 400, 'oversized hostname accepted')
            check('report_replay_and_field_validation', report_checks)

            def websocket_checks():
                rejected, status = ws(extra='Origin: https://untrusted.example\r\n')
                require(status == 403, 'browser-origin upgrade accepted'); rejected.close()
                first, status = ws(); require(status == 101, 'first WS rejected')
                first.sendall(frame(hello))
                second, status = ws(); require(status == 409, 'duplicate WS accepted'); second.close()
                first.sendall(frame(b'x' * 16385)); wait_closed(first); first.close()
                time.sleep(.2)
                fresh, status = ws(); require(status == 101, 'slot not released')
                fresh.sendall(frame(hello))
                fresh.sendall(frame(b'', 9) * 700)
                wait_closed(fresh); fresh.close()
            check('websocket_origin_size_connection_and_rate_limits', websocket_checks)

            def sse_checks():
                streams = []
                request = urllib.request.Request(base + '/api/events', headers={'Authorization': 'Bearer ' + admin})
                try:
                    for _ in range(16):
                        response = urllib.request.urlopen(request, timeout=7)
                        streams.append(response)
                        require('text/event-stream' in response.headers.get('Content-Type', ''), 'invalid SSE content type')
                    require(api('/api/events', admin)[0] == 429, 'event stream limit not enforced')
                finally:
                    for response in streams:
                        response.close()
            check('authenticated_event_stream_limit', sse_checks)

            def cli_checks():
                command = [str(agent_bin), '--server', base, '--id', 'a', '--token-file', str(token_path)]
                token_path.chmod(0o644)
                denied = subprocess.run(command, capture_output=True, timeout=5)
                token_path.chmod(0o600)
                require(denied.returncode != 0, 'world-readable credential accepted')
                denied = subprocess.run([str(agent_bin), '--server', 'http://localhost:80@untrusted.example',
                    '--id', 'a', '--token-file', str(token_path)], capture_output=True, timeout=5)
                require(denied.returncode != 0, 'HTTP URL userinfo bypass accepted')
                require(token.encode() not in denied.stderr, 'error exposed token')
            check('credential_file_permissions_and_url_validation', cli_checks)

            def tls_checks():
                cert, key = credential_dir / 'certificate.pem', credential_dir / 'key.pem'
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                    '-out', str(cert), '-days', '1', '-subj', '/CN=localhost'], check=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
                listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(4); listener.settimeout(.3)
                tls_port = listener.getsockname()[1]
                stop = threading.Event(); observations = {'rejected_handshakes': 0, 'application_requests': 0}
                def accept_tls():
                    while not stop.is_set():
                        try: client, _ = listener.accept()
                        except socket.timeout: continue
                        except OSError: break
                        try:
                            client.settimeout(2)
                            with context.wrap_socket(client, server_side=True) as secure:
                                if secure.recv(16384): observations['application_requests'] += 1
                        except ssl.SSLError: observations['rejected_handshakes'] += 1
                        except OSError: pass
                        finally: client.close()
                worker = threading.Thread(target=accept_tls, daemon=True); worker.start()
                with (args.output_dir / 'tls-agent.log').open('w') as log:
                    agent = subprocess.Popen([str(agent_bin), '--server', f'https://localhost:{tls_port}', '--id', 'a',
                        '--token-file', str(token_path), '--interval', '1'], stdout=log, stderr=log)
                children.append(agent)
                try:
                    deadline = time.monotonic() + 12
                    while time.monotonic() < deadline and observations['rejected_handshakes'] < 2: time.sleep(.2)
                    require(observations['rejected_handshakes'] >= 2, 'did not observe both WS and HTTP TLS rejection')
                    require(observations['application_requests'] == 0, 'credentials sent before trusting certificate')
                    return observations
                finally:
                    agent.terminate(); agent.wait(timeout=5); stop.set(); listener.close(); worker.join(timeout=3)
            check('untrusted_tls_certificate_rejected_before_credentials', tls_checks)
        finally:
            for sock in sockets: sock.close()
            for process in reversed(children):
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
    result = {'status': 'PASS' if cases and all(c['status'] == 'PASS' for c in cases) else 'FAIL',
              'build_performed': False, 'cases': cases}
    (args.output_dir / 'security-results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(result['status'], flush=True)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
