#!/usr/bin/env python3
"""Bounded Linux process park; no namespaces, containers, external network or dependencies."""
import argparse
import asyncio
import concurrent.futures
import contextlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import threading
import tempfile
import time
import traceback


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def exact(sock, count):
    result = b''
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise EOFError(f'EOF after {len(result)}/{count} bytes')
        result += part
    return result


def eventually(fn, timeout=8):
    end = time.monotonic() + timeout
    while True:
        try:
            result = fn()
            if result:
                return result
        except (OSError, AssertionError, EOFError, http.client.HTTPException):
            pass
        if time.monotonic() >= end:
            raise AssertionError(f'condition not met in {timeout}s: {fn}')
        time.sleep(.05)


async def backend(spec):
    identity = spec['identity'].encode() + b'|'
    writers = set()

    async def tcp(reader, writer):
        writers.add(writer)
        try:
            writer.write(identity)
            await writer.drain()
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
            writer.write_eof()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            writers.discard(writer)

    async def http(reader, writer):
        writers.add(writer)
        try:
            head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
            path = head.split(b' ', 2)[1]
            body = identity + path
            writer.write(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
            await writer.drain()
        except (ConnectionError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            writers.discard(writer)

    class UDP(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            self.transport.sendto(identity + data, addr)

    servers = [await asyncio.start_server(tcp, spec['ip'], spec['tcp'], backlog=512),
               await asyncio.start_server(http, spec['ip'], spec['http'], backlog=512)]
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(UDP, local_addr=(spec['ip'], spec['udp']))
    print('ready', flush=True)
    try:
        await asyncio.Future()
    finally:
        transport.close()
        for server in servers:
            server.close()
        for writer in list(writers):
            writer.close()


def children_of(pid):
    children = set()
    for path in Path(f'/proc/{pid}/task').glob('*/children'):
        with contextlib.suppress(FileNotFoundError):
            children.update(int(value) for value in path.read_text().split())
    return sorted(children)


class Park:
    def __init__(self, args):
        self.args = args
        self.start = time.monotonic()
        self.root = Path(args.work_dir or f'test-results/virtual-park-{time.time_ns()}').resolve()
        self.root.mkdir(parents=True, exist_ok=False)
        os.chmod(self.root, 0o700)
        self.short_root = Path(tempfile.mkdtemp(prefix="np-park-"))
        (self.short_root / "artifacts").symlink_to(self.root, target_is_directory=True)
        self.processes, self.logs, self.sockets, self.instances = [], [], [], []
        self.used_ports = set()
        self.report = {'topology': 'Linux host processes on distinct 127.0.0.0/8 IPs; no VMs or containers',
                       'parameters': vars(args), 'artifacts': str(self.root), 'scenarios': [], 'resources': [],
                       'observations': [], 'passed': False}

    def port(self, ip='127.0.0.1'):
        while True:
            with socket.socket() as sock:
                sock.bind((ip, 0))
                port = sock.getsockname()[1]
            if port not in self.used_ports:
                self.used_ports.add(port)
                return port

    def spawn(self, command, name, env=None):
        log = open(self.root / (name + '.log'), 'ab', buffering=0)
        self.logs.append(log)
        proc = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True, env=env)
        self.processes.append(proc)
        return proc

    def api(self, inst, method='GET', path='/api/config', body=None, status=200):
        conn = http.client.HTTPConnection(inst['ip'], inst['panel'], timeout=12)
        headers = {'Content-Type': 'application/json', 'Origin': f"http://{inst['ip']}:{inst['panel']}"}
        if inst.get('cookie'):
            headers['Cookie'] = inst['cookie']
        try:
            conn.request(method, path, None if body is None else json.dumps(body), headers)
            resp = conn.getresponse()
            data = resp.read()
            check(resp.status == status, f'{method} {path}: {resp.status} expected {status}: {data[:500]!r}')
            if resp.getheader('Set-Cookie'):
                inst['cookie'] = resp.getheader('Set-Cookie').split(';')[0]
            return json.loads(data)
        finally:
            conn.close()

    def stage(self, name, fn):
        entry = {'name': name, 'start_s': time.monotonic() - self.start}
        self.report['scenarios'].append(entry)
        print(f'RUN {name}', flush=True)
        try:
            entry['details'] = fn()
            entry['passed'] = True
        except BaseException as exc:
            entry['passed'] = False
            entry['error'] = f'{type(exc).__name__}: {exc}'
            raise
        finally:
            entry['duration_s'] = time.monotonic() - self.start - entry['start_s']

    def launch(self, inst):
        inst['proc'] = self.spawn([self.args.binary, '--caddy', self.args.caddy, '--data', str(inst['dir'] / 'data'),
                                  '--runtime', str(self.short_root / 'artifacts' / f"instance-{inst['index']}" / 'run'), '--ui', str(Path('web/dist').resolve()),
                                  '--panel', f"{inst['ip']}:{inst['panel']}", '--http-port', str(inst['http']),
                                  '--https-port', str(inst['https']), '--max-tcp', str(self.args.clients), '--max-udp', '8'],
                                 f"instance-{inst['index']}-{len(self.processes)}", env={**os.environ, 'GOMAXPROCS': '2'})
        eventually(lambda: self.api(inst, path='/api/auth'), 15)

    def setup(self):
        for index in range(self.args.instances):
            ip = f'127.77.{index // 250}.{index % 250 + 1}'
            inst = {'index': index, 'ip': ip, 'dir': self.root / f'instance-{index}',
                    **{key: self.port() for key in ('panel', 'http', 'https', 'tcp', 'udp')}}
            inst['dir'].mkdir()
            inst['backends'] = []
            for label in ('A', 'B'):
                spec = {'ip': ip, 'identity': f'tenant{index}-{label}', **{key: self.port(ip) for key in ('tcp', 'udp', 'http')}}
                spec['proc'] = self.spawn([sys.executable, __file__, '--backend', json.dumps(spec)], f'backend-{index}-{label}')
                inst['backends'].append(spec)
                eventually(lambda s=spec: self.backend_ready(s))
            self.instances.append(inst)
            self.launch(inst)
            self.api(inst, 'POST', '/api/setup', {'password': secrets.token_urlsafe(24)})
            a = inst['backends'][0]
            inst['tr'] = self.rule(inst, 'tcp', inst['tcp'], a['tcp'])
            inst['ur'] = self.rule(inst, 'udp', inst['udp'], a['udp'])
            inst['plain'] = self.route(inst, 'off', a['http'])
            inst['secure'] = self.route(inst, 'internal', a['http'])
        return [{'ip': i['ip'], 'niceproxy_pid': i['proc'].pid, 'caddy_pids': children_of(i['proc'].pid), 'backend_pids': [b['proc'].pid for b in i['backends']],
                 'ports': {k: i[k] for k in ('panel', 'http', 'https', 'tcp', 'udp')}} for i in self.instances]

    @staticmethod
    def backend_ready(spec):
        with socket.create_connection((spec['ip'], spec['tcp']), timeout=.3) as sock:
            return exact(sock, len(spec['identity']) + 1) == spec['identity'].encode() + b'|'

    def rule(self, inst, protocol, port, target):
        return self.api(inst, 'POST', '/api/direct-rules', {'protocol': protocol, 'listenHost': inst['ip'],
                        'listenPort': port, 'targetHost': inst['ip'], 'targetPort': target, 'enabled': True})

    def route(self, inst, tls, target):
        return self.api(inst, 'POST', '/api/http-routes', {'host': f"{tls}-{inst['index']}.park.test", 'path': '/tenant',
                        'stripPrefix': True, 'tls': tls, 'target': f"http://{inst['ip']}:{target}", 'enabled': True})

    def connect(self, inst, backend=0, port=None):
        sock = socket.create_connection((inst['ip'], port or inst['tcp']), timeout=2)
        self.sockets.append(sock)
        prefix = inst['backends'][backend]['identity'].encode() + b'|'
        check(exact(sock, len(prefix)) == prefix, 'server-first backend identity / cross-tenant leakage')
        return sock

    @staticmethod
    def echo(sock):
        payload = secrets.token_bytes(8193)
        sock.sendall(payload)
        check(exact(sock, len(payload)) == payload, 'TCP nonce corruption')

    def http(self, inst, secure=False, path='/tenant/probe', host=None, expected_status=None):
        route = inst['secure' if secure else 'plain']
        sock = socket.create_connection((inst['ip'], inst['https' if secure else 'http']), timeout=2)
        try:
            if secure:
                ca = next((inst['dir'] / 'data').rglob('root.crt'))
                ctx = ssl.create_default_context(cafile=str(ca))
                sock = ctx.wrap_socket(sock, server_hostname=route['host'])
            requested_host = host or route['host']
            sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {requested_host}\r\nConnection: close\r\n\r\n".encode())
            response = http.client.HTTPResponse(sock)
            response.begin()
            body = response.read()
            statuses = expected_status or (200 if path.startswith('/tenant/') else 404,)
            if isinstance(statuses, int):
                statuses = (statuses,)
            check(response.status in statuses, f'HTTP route status {response.status}; expected {statuses}')
            if host is not None and host != route['host']:
                check(response.status != 200 and not body.startswith(inst['backends'][0]['identity'].encode() + b'|'), 'foreign Host reached tenant backend')
            if response.status == 200:
                check(body == inst['backends'][0]['identity'].encode() + b'|' + path[len('/tenant'):].encode(), f'HTTP path/identity: {body!r}')
            return True
        finally:
            sock.close()

    def functional(self):
        held = []
        try:
            for inst in self.instances:
                self.http(inst)
                self.http(inst, path='/tenant-other')
                eventually(lambda: self.http(inst, True), 10)
                for secure in (False, True):
                    other = self.instances[(inst['index'] + 1) % len(self.instances)]
                    foreign = other['secure' if secure else 'plain']['host']
                    if foreign == inst['secure' if secure else 'plain']['host']:
                        foreign = 'other.park.test'
                    for foreign_host in (foreign, 'unknown.park.test'):
                        self.http(inst, secure, host=foreign_host, expected_status=(404, 421))
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(2)
                    payload = secrets.token_bytes(113)
                    udp.sendto(payload, (inst['ip'], inst['udp']))
                    check(udp.recv(1024) == inst['backends'][0]['identity'].encode() + b'|' + payload, 'UDP identity/nonce leak')
                # Keep every tenant's sockets open until the complete fleet is
                # populated, rather than testing one tenant at a time.
                held.extend(self.connect(inst) for _ in range(self.args.clients))
            for inst in self.instances:
                check(self.stats(inst, inst['tr'])['active'] == self.args.clients, 'fleet did not reach requested concurrency')
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                list(pool.map(self.echo, held))
            for sock in held:
                sock.shutdown(socket.SHUT_WR)
                check(sock.recv(1) == b'', 'half-close did not propagate EOF')
            return {'clients_per_instance': self.args.clients,
                    'simultaneous_tcp_clients': len(held),
                    'tls': 'private CA + hostname verified, no trust-store modification',
                    'foreign_host_checks': 'foreign tenant and unknown Host rejected on HTTP and verified HTTPS (valid current SNI)',
                    'tcp': 'all tenants held concurrently; server-first, idle-no-send, parallel nonce echo, half-close EOF',
                    'udp_expiry_started_s': time.monotonic() - self.start}
        finally:
            for sock in held:
                sock.close()

    def stats(self, inst, rule):
        return next(r for r in self.api(inst)['directRules'] if r['id'] == rule['id'])['stats']

    def churn(self):
        observations = []
        for inst in self.instances:
            held = self.connect(inst)
            stop = threading.Event()
            results = {'old': 0, 'new': 0, 'errors': 0, 'invariant_errors': []}
            def traffic():
                while not stop.is_set():
                    try:
                        with socket.create_connection((inst['ip'], inst['tcp']), timeout=.5) as s:
                            prefix = exact(s, len(inst['backends'][0]['identity']) + 1)
                            which = 'old' if prefix == inst['backends'][0]['identity'].encode() + b'|' else 'new'
                            check(prefix == inst['backends'][0 if which == 'old' else 1]['identity'].encode() + b'|', 'unknown tenant')
                            self.echo(s)
                            results[which] += 1
                    except AssertionError as exc:
                        results['invariant_errors'].append(str(exc))
                        break
                    except (OSError, EOFError):
                        results['errors'] += 1
                    stop.wait(.005)
            thread = threading.Thread(target=traffic)
            thread.start()
            try:
                for cycle in range(self.args.cycles):
                    target = cycle % 2 ^ 1
                    self.api(inst, 'PATCH', '/api/direct-rules/' + inst['tr']['id'], {'targetPort': inst['backends'][target]['tcp']})
                    self.echo(held)
                    with self.connect(inst, target) as new:
                        self.echo(new)
                    if cycle in (self.args.cycles // 2, self.args.cycles - 1):
                        self.snapshot('churn', inst)
                self.api(inst, 'PATCH', '/api/direct-rules/' + inst['tr']['id'], {'targetPort': inst['backends'][0]['tcp']})
            finally:
                stop.set()
                thread.join(3)
                held.close()
            check(results['errors'] == 0 and not results['invariant_errors'], f'hot retarget connect failures: {results}')
            observations.append(results)
        return observations

    def conflicts(self):
        for inst in self.instances:
            revision = self.api(inst)['revision']
            original = {k: inst['tr'][k] for k in ('protocol', 'listenHost', 'listenPort', 'targetHost', 'targetPort', 'enabled')}
            self.api(inst, 'POST', '/api/direct-rules', original, 409)
            self.api(inst, 'PATCH', '/api/port-owners', {'http': 'direct'}, 409)
            check(self.api(inst)['revision'] == revision, '409 modified revision')
            occupied = socket.socket()
            occupied.bind((inst['ip'], self.port(inst['ip'])))
            occupied.listen()
            try:
                failed = self.rule(inst, 'tcp', occupied.getsockname()[1], inst['backends'][0]['tcp'])
                health = self.api(inst, path='/api/health')
                check(health['caddy'] and health['appliedRevision'] == -1 and health.get('error'), 'partial apply not reported honestly')
                check(failed['status'] != 'healthy', 'occupied port reported healthy')
            finally:
                occupied.close()
            self.api(inst, 'POST', '/api/reconcile', {})
            self.api(inst, 'DELETE', '/api/direct-rules/' + failed['id'])
        return 'duplicate listener + ownership 409 preserve revision; external bind failure leaves authenticated panel alive and reconcile recovers'

    def ownership(self):
        inst = self.instances[0]
        samples, boundaries, probe_errors = [], [], []
        stop = threading.Event()
        def probe():
            while not stop.is_set():
                start = time.monotonic() - self.start
                try:
                    with socket.create_connection((inst['ip'], inst['http']), timeout=.25) as sock:
                        sock.sendall(f"GET /tenant/probe HTTP/1.1\r\nHost: {inst['plain']['host']}\r\nConnection: close\r\n\r\n".encode())
                        first = exact(sock, 4)
                        kind = 'caddy' if first == b'HTTP' else 'direct' if first + exact(sock, len(b'tenant0-A|') - 4) == b'tenant0-A|' else 'unexpected'
                        check(kind != 'unexpected', f'ownership probe unexpected response {first!r}')
                        samples.append({'t_s': start, 'result': kind})
                except AssertionError as exc:
                    probe_errors.append(str(exc))
                    break
                except (OSError, EOFError) as exc:
                    samples.append({'t_s': start, 'result': 'failure', 'error': type(exc).__name__})
                stop.wait(.005)
        def operation(label, method, path, body):
            begin = time.monotonic() - self.start
            result = self.api(inst, method, path, body)
            boundaries.append({'operation': label, 'start_s': begin, 'end_s': time.monotonic() - self.start})
            if self.args.handover_pause_ms:
                time.sleep(self.args.handover_pause_ms / 1000)
            return result
        thread = threading.Thread(target=probe)
        thread.start()
        held = None
        try:
            time.sleep(.1)
            operation('disable HTTP route', 'PATCH', '/api/http-routes/' + inst['plain']['id'], {'enabled': False})
            operation('Caddy to direct owner', 'PATCH', '/api/port-owners', {'http': 'direct'})
            rule = operation('create direct listener', 'POST', '/api/direct-rules', {'protocol': 'tcp', 'listenHost': inst['ip'], 'listenPort': inst['http'], 'targetHost': inst['ip'], 'targetPort': inst['backends'][0]['tcp'], 'enabled': True})
            held = self.connect(inst, port=inst['http'])
            self.echo(held)
            time.sleep(.04)  # Observe the now-live direct stage, not a bind gap.
            revision = self.api(inst)['revision']
            self.api(inst, 'PATCH', '/api/port-owners', {'http': 'caddy'}, 409)
            check(self.api(inst)['revision'] == revision, 'owner dependency conflict changed revision')
            operation('disable direct / Retire', 'PATCH', '/api/direct-rules/' + rule['id'], {'enabled': False})
            self.echo(held)
            operation('direct to Caddy owner', 'PATCH', '/api/port-owners', {'http': 'caddy'})
            self.echo(held)
            operation('enable HTTP route', 'PATCH', '/api/http-routes/' + inst['plain']['id'], {'enabled': True})
            self.http(inst)
            self.echo(held)
            # Second Caddy -> direct handover while the retired direct stream remains held.
            operation('disable HTTP route again', 'PATCH', '/api/http-routes/' + inst['plain']['id'], {'enabled': False})
            operation('Caddy to direct owner again', 'PATCH', '/api/port-owners', {'http': 'direct'})
            operation('enable direct again', 'PATCH', '/api/direct-rules/' + rule['id'], {'enabled': True})
            self.echo(held)
            with self.connect(inst, port=inst['http']) as new:
                self.echo(new)
            operation('disable direct finally', 'PATCH', '/api/direct-rules/' + rule['id'], {'enabled': False})
            operation('restore Caddy owner', 'PATCH', '/api/port-owners', {'http': 'caddy'})
            operation('restore HTTP route', 'PATCH', '/api/http-routes/' + inst['plain']['id'], {'enabled': True})
            self.echo(held)
            time.sleep(.1)
        finally:
            stop.set()
            thread.join(3)
            if held:
                held.close()
        check(not probe_errors, f'ownership probe invariants: {probe_errors}')
        check(any(s['result'] == 'caddy' for s in samples) and any(s['result'] == 'direct' for s in samples), 'continuous probe missed owner stages')
        failures = [s['t_s'] for s in samples if s['result'] == 'failure']
        return {'boundaries': boundaries, 'samples': samples, 'failure_count': len(failures),
                'first_failure_s': min(failures) if failures else None, 'last_failure_s': max(failures) if failures else None,
                'probe_interval_s': .005, 'probe_timeout_s': .25,
                'window_label': 'multi-API user operation gap included; sampled failures, not exact outage duration',
                'held_stream': 'nonce verified after Retire and each owner handover in both directions'}

    def recovery(self):
        inst = self.instances[0]
        backend = inst['backends'][0]
        backend['proc'].kill()
        backend['proc'].wait(3)
        with socket.create_connection((inst['ip'], inst['tcp']), timeout=2) as sock:
            check(sock.recv(1) == b'', 'dead backend unexpectedly served payload')
        spec = {k: v for k, v in backend.items() if k != 'proc'}
        backend['proc'] = self.spawn([sys.executable, __file__, '--backend', json.dumps(spec)], 'backend-restarted')
        eventually(lambda: self.backend_ready(backend))
        with self.connect(inst) as sock:
            self.echo(sock)
        self.http(inst)
        before = self.api(inst)['revision']
        parent = inst['proc'].pid
        children = children_of(parent)
        check(children, 'no Caddy child found')
        inst['proc'].kill()
        inst['proc'].wait(3)
        def dead(pid):
            try:
                return Path(f'/proc/{pid}/stat').read_text().split()[2] == 'Z'
            except FileNotFoundError:
                return True
        eventually(lambda: all(dead(pid) for pid in children), 5)
        stale = (inst['dir'] / 'run/control.sock').exists()
        self.launch(inst)
        check(self.api(inst)['revision'] == before, 'persisted config or session not restored')
        with self.connect(inst) as sock:
            self.echo(sock)
        self.http(inst, True)
        self.snapshot('restarted_warmup', inst)
        return {'killed_pid': parent, 'caddy_children': children, 'caddy_exited_after_parent_SIGKILL': True,
                'stale_control_socket_before_restart': stale, 'same_DB_runtime_session_revision_restored': before}

    def limits(self):
        inst = self.instances[-1]
        held = [self.connect(inst) for _ in range(self.args.clients)]
        before = self.stats(inst, inst['tr'])['rejects']
        for _ in range(12):
            with socket.create_connection((inst['ip'], inst['tcp']), timeout=2) as sock:
                try:
                    check(sock.recv(1) == b'', 'over-limit TCP admitted')
                except ConnectionResetError:
                    pass
        after = self.stats(inst, inst['tr'])
        check(after['rejects'] >= before + 12 and after['active'] <= self.args.clients, 'TCP rejection counters/limit')
        for sock in held:
            sock.close()
        senders = []
        try:
            # This instance may have one earlier association; allow expiry first.
            eventually(lambda: self.stats(inst, inst['ur'])['active'] == 0, 70)
            for _ in range(8):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                senders.append(sock)
                nonce = secrets.token_bytes(32)
                sock.sendto(nonce, (inst['ip'], inst['udp']))
                check(sock.recv(1024) == inst['backends'][0]['identity'].encode() + b'|' + nonce, 'UDP admitted payload')
            before_udp = self.stats(inst, inst['ur'])['rejects']
            for _ in range(4):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(b'over-limit', (inst['ip'], inst['udp']))
            eventually(lambda: self.stats(inst, inst['ur'])['rejects'] >= before_udp + 4)
            udp = self.stats(inst, inst['ur'])
            check(udp['active'] <= 8, 'UDP cap exceeded')
        finally:
            for sock in senders:
                sock.close()
        return {'tcp': after, 'udp': udp, 'udp_idle_expiry_seconds': 60}

    def snapshot(self, label, inst):
        for role, pid in [('niceproxy', inst['proc'].pid)] + [('caddy', p) for p in children_of(inst['proc'].pid)]:
            status = Path(f'/proc/{pid}/status').read_text().splitlines()
            fields = {line.split(':')[0]: line.split(':')[1].strip() for line in status if ':' in line}
            self.report['resources'].append({'stage': label, 'instance': inst['index'], 'role': role, 'pid': pid,
                                           'rss_kib': int(fields['VmRSS'].split()[0]), 'threads': int(fields['Threads']),
                                           'fds': len(list(Path(f'/proc/{pid}/fd').iterdir())), 't_s': time.monotonic() - self.start})

    def cleanup_idle(self):
        # UDP associations are intentionally retained for 60s; never call them leaks early.
        end = time.monotonic() + 72
        while True:
            states = [(i, r, self.stats(i, r)) for i in self.instances for r in (i['tr'], i['ur'])]
            if all(s['active'] == 0 for _, _, s in states):
                break
            check(time.monotonic() < end, f'active associations after expiry: {[s for _, _, s in states]}')
            time.sleep(.5)
        for _, rule, stats in states:
            check(stats['closed'] <= stats['accepted'], f'closed > accepted {rule["id"]}')
            check(stats['accepted'] == stats['closed'], f'unfinished lifecycles {stats}')
        for inst in self.instances:
            self.snapshot('idle', inst)
        # Compare equivalent post-warmup samples with generous documented runtime tolerances.
        for inst in self.instances:
            rows = [r for r in self.report['resources'] if r['instance'] == inst['index'] and r['role'] == 'niceproxy' and r['stage'] == 'churn']
            check(len(rows) == 2, 'missing plateau samples')
            check(rows[-1]['rss_kib'] <= rows[0]['rss_kib'] + 32768, 'RSS grew >32MiB in second half of churn')
            check(rows[-1]['fds'] <= rows[0]['fds'] + 32, 'FD growth >32 after warmup')
            check(rows[-1]['threads'] <= rows[0]['threads'] + 16, 'thread growth >16 after warmup')
        for row in [r for r in self.report['resources'] if r['stage'] == 'idle']:
            earlier = [r for r in self.report['resources'] if r['pid'] == row['pid'] and r['stage'] != 'idle']
            check(row['fds'] <= self.args.clients * 4 + 512 and row['threads'] <= 128,
                  f'idle process exceeded absolute FD/thread bounds: {row}')
            if earlier:
                check(row['rss_kib'] <= earlier[0]['rss_kib'] + 32768, f'idle RSS growth >32MiB: {row}')
                check(row['fds'] <= earlier[0]['fds'] + 32, f'idle FD growth >32: {row}')
                check(row['threads'] <= earlier[0]['threads'] + 16, f'idle thread growth >16: {row}')
        return {'active': 0, 'accepted_equals_closed': True,
                'final_rule_stats': [{'instance': i['index'], 'rule_id': r['id'], 'protocol': r['protocol'], 'stats': s}
                                     for i, r, s in states], 'plateau_tolerances': {'rss_kib': 32768, 'fds': 32, 'threads': 16},
                'scope': 'bounded-run growth guard, not proof of long-term absence of leaks'}

    def cleanup(self):
        for sock in self.sockets:
            with contextlib.suppress(OSError):
                sock.close()
        # Every child has its own session; Caddy inherits niceproxy's group.
        # Kill groups even if their leader already exited, to cover Caddy orphans.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            for proc in reversed(self.processes):
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, sig)
            deadline = time.monotonic() + 2
            for proc in self.processes:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(max(.01, deadline - time.monotonic()))
        for log in self.logs:
            log.close()
        (self.short_root / "artifacts").unlink()
        self.short_root.rmdir()

    def run(self):
        try:
            scenarios = [('topology_startup', self.setup), ('tenant_HTTP_HTTPS_TCP_UDP', self.functional),
                             ('hot_retarget_and_churn', self.churn), ('conflicts_partial_apply', self.conflicts),
                             ('ownership_continuous_accepts', self.ownership), ('backend_and_process_recovery', self.recovery),
                             ('admission_limits', self.limits), ('idle_expiry_and_resource_bounds', self.cleanup_idle)]
            if self.args.functional_only:
                scenarios = scenarios[:2]
            self.report['suite'] = 'functional' if self.args.functional_only else 'full'
            for name, fn in scenarios:
                self.stage(name, fn)
            self.report['passed'] = True
        except BaseException as exc:
            self.report['error'] = f'{type(exc).__name__}: {exc}'
            self.report['traceback'] = traceback.format_exc()
            print(self.report['traceback'], file=sys.stderr)
        finally:
            signal.alarm(0)
            self.cleanup()
            self.report['duration_s'] = time.monotonic() - self.start
            output = Path(self.args.output).resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(self.report, indent=2) + '\n')
            summary = f"{'PASS' if self.report['passed'] else 'FAIL'}: {sum(s.get('passed', False) for s in self.report['scenarios'])}/{len(self.report['scenarios'])} scenarios; {self.report['duration_s']:.2f}s; report {output}; artifacts {self.root}"
            (self.root / 'summary.txt').write_text(summary + '\n')
            print(summary, flush=True)
        return 0 if self.report['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='bin/niceproxy')
    parser.add_argument('--caddy', required='--backend' not in sys.argv)
    parser.add_argument('--instances', type=int, default=3)
    parser.add_argument('--clients', type=int, default=64)
    parser.add_argument('--cycles', type=int, default=20)
    parser.add_argument('--handover-pause-ms', type=float, default=0, help='optional observation pause between API mutations; default none')
    parser.add_argument('--output', default='test-results/virtual-park.json')
    parser.add_argument('--work-dir')
    parser.add_argument('--functional-only', action='store_true', help='only topology and routing/isolation/concurrent clients; no failure/expiry scenarios')
    parser.add_argument('--quick', action='store_true', help='reduce client/churn counts; still waits for real UDP idle expiry')
    parser.add_argument('--backend', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.backend:
        asyncio.run(backend(json.loads(args.backend)))
        return 0
    check(sys.platform == 'linux', 'Linux required')
    if args.quick:
        args.clients, args.cycles = min(args.clients, 8), min(args.cycles, 4)
    check(1 <= args.instances <= 8 and 2 <= args.clients <= 128 and 2 <= args.cycles <= 50, 'bounds: instances 1..8, clients 2..128, cycles 2..50')
    check(0 <= args.handover_pause_ms <= 100, 'handover pause must be 0..100ms')
    for key in ('binary', 'caddy'):
        setattr(args, key, str(Path(getattr(args, key)).resolve()))
        check(os.access(getattr(args, key), os.X_OK), f'{key} not executable')
    version = subprocess.check_output([args.caddy, 'version'], text=True, timeout=5).strip()
    check(version.startswith('v2.10.2 ' ) or version == 'v2.10.2', f'Caddy 2.10.2 required, got {version}')
    def interrupt(signum, frame):
        raise TimeoutError(f'park interrupted by signal {signum}')
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(sig, interrupt)
    park = Park(args)
    park.report['caddy_version'] = version
    signal.alarm(175)
    return park.run()


if __name__ == '__main__':
    sys.exit(main())
