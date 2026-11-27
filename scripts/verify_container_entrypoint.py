#!/usr/bin/env python3
"""Docker regression tests for the optional agent entrypoint. Never build Rust."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
import zipfile


MOCK_CURL = '''#!/usr/local/bin/python3
import os,pathlib,shutil,sys,time,json
state=pathlib.Path('/state'); args=sys.argv[1:]
os.umask(0o022)
with (state/'downloads').open('a') as f: f.write('download\\n')
(state/'curl-args.json').write_text(json.dumps(args))
mode=os.environ.get('TEST_DOWNLOAD_MODE','ok')
if mode=='slow':
 while not (state/'release-download').exists(): time.sleep(.05)
if mode=='fail': sys.exit(22)
out=pathlib.Path(args[args.index('--output')+1])
if mode=='bad': out.write_bytes(b'not-the-expected-agent')
else: shutil.copyfile('/fixtures/'+os.environ.get('TEST_PACKAGE','agent.bin'),out)
'''
MOCK_AGENT = '''#!/usr/local/bin/python3
import json,os,pathlib,signal,sys,time
state=pathlib.Path('/state'); args=sys.argv[1:]
token=pathlib.Path(args[args.index('--token-file')+1])
os.umask(0o022)
assert token.stat().st_mode & 0o777 == 0o600
assert len(token.read_bytes()) >= 16
assert token.read_text().strip() not in '\\0'.join(args)
with (state/'agents').open('a') as f: f.write(str(os.getpid())+'\\n')
(state/'agent-args.json').write_text(json.dumps(args))
(state/'private-token-path').write_text(str(token))
(state/'agent-started').write_text('yes')
if os.environ.get('TEST_AGENT_CRASH')=='1': sys.exit(23)
signal.signal(signal.SIGTERM,lambda *_: sys.exit(0))
while True: time.sleep(.1)
'''
APPLICATION = '''#!/usr/local/bin/python3
import json,os,pathlib,signal,sys,time
state=pathlib.Path('/state')
(state/'app.json').write_text(json.dumps({'pid':os.getpid(),'ppid':os.getppid(),'args':sys.argv[1:]}))
def stop(*_):
 (state/'term').write_text('received')
 sys.exit(37)
signal.signal(signal.SIGTERM,stop)
if '--exit' in sys.argv: sys.exit(int(sys.argv[sys.argv.index('--exit')+1]))
while True: time.sleep(.1)
'''
HTTP_RECEIVER = '''#!/usr/local/bin/python3
import http.server,json,pathlib,threading
state=pathlib.Path('/state')
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_GET(self): self.send_error(503)
 def do_POST(self):
  n=int(self.headers.get('Content-Length','0')); assert n<16384
  data=json.loads(self.rfile.read(n))
  assert self.headers.get('X-Agent-Id')=='container-test'
  assert self.headers.get('Authorization')=='Bearer '+pathlib.Path('/run/secrets/agent').read_text().strip()
  (state/('real-'+data['type']+'.json')).write_text(json.dumps(data))
  self.send_response(202);self.send_header('Content-Length','0');self.end_headers()
srv=http.server.ThreadingHTTPServer(('127.0.0.1',18080),Handler)
threading.Thread(target=srv.serve_forever,daemon=True).start()
exec(compile(pathlib.Path('/fixtures/app.py').read_text(),'/fixtures/app.py','exec'))
'''


def execute(*command, timeout=60, check=True):
    return subprocess.run(command, capture_output=True, text=True, check=check, timeout=timeout)


def require(value, message):
    if not value:
        raise AssertionError(message)


def wait_for(predicate, message, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.05)
    raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-binary', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    entrypoint = Path('deploy/rprobe-entrypoint.sh').resolve()
    require(args.agent_binary.is_file(), 'CI-built agent binary is required')
    image = 'rprobe-entrypoint-check:' + secrets.token_hex(6)
    owned = []
    result = {'checks': [], 'rust_build_performed': False, 'real_container_engine': 'Docker'}
    with tempfile.TemporaryDirectory(prefix='rprobe-entrypoint-', dir=os.environ.get('PI_SCRATCH_DIR') or os.environ.get('RUNNER_TEMP')) as temporary:
        root = Path(temporary)
        context = root / 'context'; context.mkdir()
        fixtures = context / 'fixtures'; fixtures.mkdir()
        shutil.copy2(entrypoint, context / 'rprobe-entrypoint.sh')
        for name, text in [('curl', MOCK_CURL), ('agent.bin', MOCK_AGENT), ('app.py', APPLICATION), ('receiver.py', HTTP_RECEIVER)]:
            (fixtures / name).write_text(text, encoding='utf-8')
            (fixtures / name).chmod(0o755)
        shutil.copy2(args.agent_binary, fixtures / 'real-agent')
        agent_hash = hashlib.sha256((fixtures / 'agent.bin').read_bytes()).hexdigest()
        real_hash = hashlib.sha256((fixtures / 'real-agent').read_bytes()).hexdigest()
        tar_data = io.BytesIO()
        with tarfile.open(fileobj=tar_data, mode='w:gz') as tar:
            member = tarfile.TarInfo('rprobe-agent'); member.mode = 0o755
            data = (fixtures / 'agent.bin').read_bytes(); member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
            # Archive traversal names must never be extracted by the production script.
            member = tarfile.TarInfo('../unexpected-file'); member.size = 4
            tar.addfile(member, io.BytesIO(b'evil'))
        (fixtures / 'agent.tar.gz').write_bytes(tar_data.getvalue())
        with zipfile.ZipFile(fixtures / 'agent.zip', 'w') as archive:
            archive.writestr('rprobe-agent-x86_64-unknown-linux-musl.tar.gz', tar_data.getvalue())
        (context / 'Dockerfile').write_text('''FROM python:3.12-slim-bookworm
RUN apt-get update -qq && apt-get install -y --no-install-recommends ca-certificates curl unzip util-linux coreutils tar && rm -rf /var/lib/apt/lists/*
COPY rprobe-entrypoint.sh /rprobe-entrypoint.sh
COPY fixtures /fixtures
RUN chmod 755 /rprobe-entrypoint.sh /fixtures/curl /fixtures/agent.bin /fixtures/real-agent && mkdir /testbin && ln -s /fixtures/curl /testbin/curl
ENV PATH=/testbin:/usr/local/bin:/usr/bin:/bin
ENTRYPOINT ["/bin/sh", "/rprobe-entrypoint.sh"]
CMD ["python3", "/fixtures/app.py"]
''', encoding='utf-8')
        def create(name, updates=None, app=None, cache=None, user=None, readonly=False, raw=False, init=False):
            state = root / (name + '-state'); state.mkdir(); state.chmod(0o777)
            cache = cache or root / (name + '-cache')
            if not cache.exists(): cache.mkdir(mode=0o700)
            if user is None and os.geteuid() != 0:
                execute('sudo', '-n', 'chown', '0:0', str(cache))
            token = root / (name + '-token'); token.write_text(secrets.token_hex(24)); token.chmod(0o444)
            env = {'RPROBE_SERVER': 'https://monitor.example', 'RPROBE_AGENT_ID': 'container-test',
                   'RPROBE_TOKEN_FILE': '/run/secrets/agent', 'RPROBE_AGENT_DIR': '/cache',
                   'RPROBE_AGENT_URL': 'https://downloads.example/agent', 'RPROBE_AGENT_SHA256': agent_hash,
                   'RPROBE_AGENT_FORMAT': 'binary', 'TEST_PACKAGE': 'agent.bin'}
            env.update(updates or {})
            command = ['docker', 'run', '-d', '--name', name + '-' + secrets.token_hex(3),
                       '-v', str(state) + ':/state', '-v', str(cache) + ':/cache' + (':ro' if readonly else ''),
                       '-v', str(token) + ':/run/secrets/agent:ro']
            if user: command += ['--user', user]
            if raw: command += ['--entrypoint', '/bin/sh']
            if init: command += ['--init']
            for key, value in env.items(): command += ['-e', key + '=' + value]
            command += [image] + (app or [])
            started = time.monotonic()
            container = execute(*command).stdout.strip(); owned.append(container)
            wait_for(lambda: (state / 'app.json').exists(), name + ': main app did not start promptly', 5)
            require(time.monotonic() - started < 5, 'startup stalled')
            app_info = json.loads((state / 'app.json').read_text())
            require(app_info['ppid'] == 1 if init else app_info['pid'] == 1, 'main exec semantics lost')
            return container, state, cache, token

        def stop(container):
            execute('docker', 'stop', '-t', '5', container, timeout=10)
            info = json.loads(execute('docker', 'inspect', container).stdout)[0]
            require(info['State']['ExitCode'] == 37, 'application SIGTERM/exit status changed')

        def passed(name):
            result['checks'].append({'name': name, 'status': 'PASS'})
            print('PASS', name, flush=True)

        try:
            build = execute('docker', 'build', '-t', image, str(context), timeout=300)
            (output / 'docker-build.log').write_text(build.stdout + build.stderr, encoding='utf-8')
            container, state, cache, token = create('slow', {'TEST_DOWNLOAD_MODE': 'slow'}, ['python3', '/fixtures/app.py', 'spaces intact', 'literal;argument'])
            wait_for(lambda: (state / 'downloads').exists(), 'background download did not start')
            require(not (state / 'agent-started').exists(), 'slow download unexpectedly finished')
            require(json.loads((state / 'app.json').read_text())['args'] == ['spaces intact', 'literal;argument'], 'argument quoting lost')
            (state / 'release-download').touch()
            wait_for(lambda: (state / 'agent-started').exists(), 'agent did not start after download')
            require(execute('docker', 'exec', container, 'sha256sum', '/cache/rprobe-agent').stdout.split()[0] == agent_hash, 'installed hash mismatch')
            private = (state / 'private-token-path').read_text()
            require(private.startswith('/dev/shm/rprobe-runtime.'), 'token copy not on private tmpfs')
            require(token.stat().st_mode & 0o777 == 0o444, 'mounted secret permissions changed')
            require(token.read_text() not in execute('docker', 'logs', container).stdout, 'token leaked to logs')
            require(execute('docker', 'exec', container, 'test', '!', '-e', '/cache/unexpected-file', check=False).returncode == 0, 'archive path escaped')
            stop(container); require((state / 'term').exists(), 'main app did not receive SIGTERM')
            passed('slow_download_does_not_block_main_exec_signals_arguments_or_secret_protection')

            container, state, _, _ = create('reuse', {'TEST_DOWNLOAD_MODE': 'fail'}, cache=cache)
            wait_for(lambda: (state / 'agent-started').exists(), 'verified cached binary not reused')
            require(not (state / 'downloads').exists(), 'cache triggered download')
            execute('docker', 'exec', container, 'sh', '/rprobe-entrypoint.sh', '--start-only')
            time.sleep(.3)
            require(len((state / 'agents').read_text().splitlines()) == 1, 'duplicate agent started')
            stop(container); passed('verified_cache_reused_and_concurrent_start_is_singleton')

            for mode in ['bad', 'fail']:
                container, state, cache, _ = create(mode, {'TEST_DOWNLOAD_MODE': mode})
                wait_for(lambda: (state / 'downloads').exists(), 'download mock not reached')
                time.sleep(.3)
                require(not (state / 'agent-started').exists(), 'unverified binary executed')
                require(execute('docker', 'exec', container, 'test', '!', '-e', '/cache/rprobe-agent', check=False).returncode == 0, 'partial install published')
                stop(container); passed(mode + '_download_never_blocks_or_executes_unverified_agent')

            for fmt, package in [('tar.gz', 'agent.tar.gz'), ('zip', 'agent.zip')]:
                container, state, cache, _ = create('archive-' + fmt.replace('.', '-'), {'RPROBE_AGENT_FORMAT': fmt, 'TEST_PACKAGE': package})
                wait_for(lambda: (state / 'agent-started').exists(), 'archive install failed')
                require(execute('docker', 'exec', container, 'test', '!', '-e', '/unexpected-file', check=False).returncode == 0, 'unsafe archive member extracted')
                stop(container); passed(fmt + '_only_expected_member_installed')

            container, state, _, _ = create('crash', {'TEST_AGENT_CRASH': '1'})
            wait_for(lambda: (state / 'agent-started').exists(), 'crash fixture never started')
            time.sleep(.3); stop(container); passed('agent_failure_does_not_terminate_application')

            for name, env in [('disabled', {'RPROBE_ENABLED':'0'}), ('missing-config', {'RPROBE_SERVER':''}), ('bad-source', {'RPROBE_AGENT_URL':'http://untrusted.example'})]:
                container, state, _, _ = create(name, env)
                time.sleep(.2); require(not (state / 'downloads').exists(), 'invalid config downloaded agent')
                stop(container); passed(name + '_leaves_main_application_running')

            container, state, _, _ = create('exit-status', {'RPROBE_ENABLED':'0'}, ['python3', '/fixtures/app.py', '--exit', '42'])
            require(execute('docker', 'wait', container, timeout=5).stdout.strip() == '42', 'main exit code changed')
            passed('main_nonzero_exit_status_is_preserved')

            nonroot_cache = root / 'nonroot-cache'; nonroot_cache.mkdir(mode=0o700)
            if os.geteuid() == 0: os.chown(nonroot_cache, 65534, 65534)
            else: execute('sudo', '-n', 'chown', '65534:65534', str(nonroot_cache))
            container, state, _, _ = create('nonroot', cache=nonroot_cache, user='65534:65534')
            wait_for(lambda: (state / 'agent-started').exists(), 'nonroot installation failed')
            stop(container); passed('nonroot_installation_with_writable_private_cache')

            container, state, _, _ = create('readonly-cache', readonly=True)
            time.sleep(.3); require(not (state / 'agent-started').exists(), 'read-only cache unexpectedly installed')
            stop(container); passed('read_only_cache_failure_is_isolated')

            # Both installers are invoked by the existing entrypoint, which then execs the app.
            container, state, _, _ = create('start-only', {}, ['-c', '/bin/sh /rprobe-entrypoint.sh --start-only | cat; /bin/sh /rprobe-entrypoint.sh --start-only; exec python3 /fixtures/app.py'], raw=True)
            wait_for(lambda: (state / 'agent-started').exists(), 'existing-entrypoint integration failed')
            require(len((state / 'agents').read_text().splitlines()) == 1, 'start-only duplicated agent')
            stop(container); passed('existing_entrypoint_start_only_keeps_exec_and_singleton')

            container, state, _, _ = create('nonroot-init', {}, ['-c', '/bin/sh /rprobe-entrypoint.sh --start-only; exec python3 /fixtures/app.py'], cache=nonroot_cache, user='65534:65534', raw=True, init=True)
            wait_for(lambda: (state / 'agent-started').exists(), 'nonroot --start-only under --init failed')
            stop(container); passed('nonroot_start_only_under_docker_init_preserves_start_and_stop')

            directory_cache = root / 'directory-target-cache'; directory_cache.mkdir(mode=0o700)
            (directory_cache / 'rprobe-agent').mkdir()
            container, state, _, _ = create('directory-target', cache=directory_cache)
            time.sleep(.3); require(not (state / 'downloads').exists(), 'directory install target was not rejected')
            stop(container); passed('directory_install_target_is_rejected_without_affecting_main')

            container, state, _, _ = create('real-agent', {'RPROBE_AGENT_SHA256':real_hash, 'TEST_PACKAGE':'real-agent', 'RPROBE_SERVER':'http://127.0.0.1:18080', 'RPROBE_INTERVAL':'1'}, ['python3','/fixtures/receiver.py'])
            wait_for(lambda: (state / 'real-report.json').exists(), 'real agent did not report from container', 20)
            report = json.loads((state / 'real-report.json').read_text())['report']
            require(report['process_count'] > 0 and report['memory_limit_bytes'] > 0, 'invalid real container metrics')
            stop(container); passed('ci_built_real_agent_installs_and_reports_inside_docker')
            result['status'] = 'PASS'
        except Exception as error:
            result['status'] = 'FAIL'
            result['error'] = type(error).__name__ + ': ' + str(error)
            for i, container in enumerate(owned):
                log = execute('docker', 'logs', container, check=False)
                (output / f'container-{i}.log').write_text(log.stdout + log.stderr, encoding='utf-8')
            if isinstance(error, subprocess.CalledProcessError):
                (output / 'failed-command.log').write_text((error.stdout or '') + (error.stderr or ''), encoding='utf-8')
            print(result['error'], flush=True)
        finally:
            for container in reversed(owned): execute('docker', 'rm', '-f', container, check=False)
            execute('docker', 'image', 'rm', '-f', image, check=False)
            # Containers can create root-owned files; remove task-owned fixture dirs with a helper if needed.
            for directory in root.glob('*-cache'):
                try: shutil.rmtree(directory)
                except PermissionError:
                    execute('sudo', '-n', 'rm', '-rf', '--', str(directory), check=False)
    (output / 'entrypoint-results.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return 0 if result.get('status') == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
