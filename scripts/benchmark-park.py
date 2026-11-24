#!/usr/bin/env python3
"""Closed-loop local measurements against an echo/HTTP backend and niceproxy.

This measures shared-host application behavior, not WAN capacity or a maximum
sustainable arrival rate. Build scripts/parkload into bin/parkload before use.
"""
import argparse
import contextlib
import hashlib
import http.cookiejar
import json
import math
import os
from pathlib import Path
import platform
import secrets
import select
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


HTTP_BODY = 'bench-backend /'
CASES = [('http_keepalive','http','reused',0), ('tcp_256_reused','tcp','reused',256),
         ('udp_256_reused','udp','reused',256), ('tcp_256_new','tcp','new',256),
         ('tcp_65536_reused','tcp','reused',65536), ('https_keepalive','https','reused',0)]


def assess_targets(rows, targets, levels, repeats):
    """A case qualifies at a level only if every expected proxy repeat qualifies."""
    assessments = {}
    for case, target in targets.items():
        by_level = {}
        for level in levels:
            runs = [r for r in rows if r.get('case') == case and
                    r.get('variant') == 'proxy' and r.get('concurrency') == level]
            complete = (len(runs) == repeats and
                        sorted(r.get('repeat', 0) for r in runs) == list(range(1, repeats + 1)))
            clean = True
            for row in runs:
                try:
                    validate_result(row)
                except AssertionError:
                    clean = False
            by_level[str(level)] = {'complete': complete, 'passed': complete and clean and
                all(math.isfinite(r.get('requestsPerSecond', 0)) and
                    r.get('requestsPerSecond', 0) >= target for r in runs),
                'requestsPerSecond': [r.get('requestsPerSecond') for r in runs]}
        assessments[case] = {'targetRequestsPerSecond': target, 'concurrency': by_level,
                             'passed': any(v['passed'] for v in by_level.values())}
    return assessments


def proc_cpu(pid):
    # comm can contain spaces and parentheses; fields after its last ')' start at field 3.
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK')


def cpu_measurement(seconds, wall, affinity):
    return {'cpuSeconds': seconds, 'measurementWallSeconds': wall,
            'meanCores': seconds / wall, 'affinityCPUs': affinity}


def cpu_snapshot(pid):
    start = time.monotonic()
    seconds = proc_cpu(pid)
    end = time.monotonic()
    return {'cpuSeconds': seconds, 'sampleMonotonicSeconds': (start + end) / 2,
            'readDurationSeconds': end - start}


def cgroup_cpu():
    """Record unified hierarchy constraints and throttling without changing them."""
    rows = []
    try:
        entry = next(line for line in Path('/proc/self/cgroup').read_text().splitlines()
                     if line.startswith('0::'))
        base = Path('/sys/fs/cgroup')
        path = (base / entry.split('::', 1)[1].lstrip('/')).resolve()
        while path == base or base in path.parents:
            values = {'path': str(path)}
            for field in ('cpu.max', 'cpu.stat', 'cpuset.cpus.effective'):
                try:
                    values[field] = (path / field).read_text().strip()
                except OSError:
                    values[field] = None
            rows.append(values)
            path = path.parent
    except (OSError, StopIteration) as e:
        return {'unavailable': str(e)}
    return rows


def validate_result(row):
    """Reject a client-only success when proxy or infrastructure evidence failed."""
    if row.get('exitCode') != 0 or row.get('errors') != 0 or row.get('succeeded', 0) <= 0:
        raise AssertionError('load client did not complete cleanly')
    if row.get('protocol') in ('http', 'https') or row.get('case') in ('http_keepalive', 'https_keepalive'):
        if row.get('receivedBytes') != row['succeeded'] * len(HTTP_BODY.encode()):
            raise AssertionError('HTTP received byte count differs from full expected body')
    for field in ('conntrackBefore', 'conntrackAfter'):
        value = row.get(field)
        if not isinstance(value, dict) or value.get('max', 0) <= 0 or value.get('count', -1) < 0:
            raise AssertionError('required conntrack accounting unavailable: '+field)
    stats = row.get('ruleStatsAfter')
    if row.get('statsReadError') or not isinstance(stats, list) or len(stats) != 2:
        raise AssertionError('required proxy statistics unavailable')
    for rule in stats:
        counters = rule.get('stats')
        if rule.get('status') != 'healthy' or not isinstance(counters, dict):
            raise AssertionError('proxy rule was not healthy or lacked statistics')
        if counters.get('errors') != 0 or counters.get('rejects') != 0:
            raise AssertionError('proxy error/reject counters were nonzero')
        if rule.get('protocol') == 'tcp' and counters.get('active') != 0:
            raise AssertionError('proxy TCP work had not quiesced')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='bin/niceproxy')
    parser.add_argument('--load-binary', default='bin/parkload')
    parser.add_argument('--caddy', required=True)
    parser.add_argument('--seconds', type=float, default=3)
    parser.add_argument('--repeats', type=int, default=2)
    parser.add_argument('--new-connection-seconds', type=float, default=1, help='shorter window for TCP churn to bound shared-host conntrack pressure')
    parser.add_argument('--concurrency', default='1,16,64')
    parser.add_argument('--cases', default='', help='comma-separated cases; default all: http_keepalive,tcp_256_reused,udp_256_reused,tcp_256_new,tcp_65536_reused,https_keepalive')
    for role in ('backend', 'client', 'app'):
        parser.add_argument('--'+role+'-gomaxprocs', type=int, default=4,
                            help='Go CPU budget (app is inherited by bundled Caddy; default 4)')
    parser.add_argument('--proxy-only', action='store_true', help='skip direct backend variants')
    parser.add_argument('--tcp-on-http-port', action='store_true',
                        help='assign the configured public HTTP port to direct TCP instead of Caddy; excludes HTTP cases')
    parser.add_argument('--targets', default='', help='proxy RPS targets, e.g. tcp_256_reused=70000,http_keepalive=80000,https_keepalive=40000')
    parser.add_argument('--output', default='test-results/park/benchmark.json')
    args = parser.parse_args()
    started = time.monotonic()
    try:
        levels = list(dict.fromkeys(int(x) for x in args.concurrency.split(',')))
        targets = {}
        for item in filter(None, args.targets.split(',')):
            name, value = item.split('=')
            if name not in {c[0] for c in CASES} or name in targets:
                raise ValueError('unknown or duplicate target case: '+name)
            targets[name] = float(value)
            if not math.isfinite(targets[name]) or targets[name] <= 0:
                raise ValueError('targets must be finite positive RPS')
    except ValueError as e:
        parser.error(str(e))
    selected = set(args.cases.split(',')) if args.cases else {case[0] for case in CASES}
    if selected - {case[0] for case in CASES}:
        parser.error('unknown benchmark cases: '+','.join(sorted(selected - {case[0] for case in CASES})))
    if args.tcp_on_http_port and 'http_keepalive' in selected:
        parser.error('--tcp-on-http-port cannot share its listener with an HTTP case')
    if min(args.backend_gomaxprocs, args.client_gomaxprocs, args.app_gomaxprocs) < 1:
        parser.error('per-role GOMAXPROCS must be positive')
    if not (0 < args.new_connection_seconds <= 1 and 0 < args.seconds <= 30 and 1 <= args.repeats <= 5 and levels and all(1 <= n <= 512 for n in levels)):
        parser.error('new-connection-seconds <=1, seconds <=30, repeats <=5, concurrency <=512 required')
    args.binary, args.load_binary, args.caddy = [str(Path(p).resolve()) for p in (args.binary,args.load_binary,args.caddy)]
    out = Path(args.output).resolve();out.parent.mkdir(parents=True,exist_ok=True)
    artifacts = out.parent/('benchmark-artifacts-'+str(time.time_ns()));artifacts.mkdir(mode=0o700)
    temporary = tempfile.TemporaryDirectory(prefix='np-bench-')
    root = Path(temporary.name)
    processes=[];logs=[];used=set();stop_sample=threading.Event();samples=[];sampler=None
    def interrupted(signum, frame):
        raise KeyboardInterrupt('benchmark interrupted by signal '+str(signum))
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    report={'passed':False,'topology':'shared-host loopback backend + niceproxy + bundled Caddy + Go closed-loop clients',
            'hardware':{'cpuCount':os.cpu_count(),'kernel':platform.release(),'machine':platform.machine(),
                        'memTotal':next(x for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemTotal:'))},
            'parameters':vars(args),'GOMAXPROCS':{'backend':args.backend_gomaxprocs, 'client':args.client_gomaxprocs,
                'niceproxy':args.app_gomaxprocs, 'caddy':args.app_gomaxprocs},'results':[],
            'artifacts':str(artifacts),'limitations':['single machine and kernel; generator/backend/proxy share resources',
            'closed-loop throughput is not an independently controlled offered arrival rate',
            'explicit TCP source uses Linux IP_BIND_ADDRESS_NO_PORT; fresh loopback source subnet per run',
            'new TCP cases use shorter windows and pre-run conntrack headroom; no sysctls or conntrack flushes',
            'HTTP/1.1 clients, keep-alive unless new specified; HTTPS verifies generated CA',
            'latency histogram includes failed attempts; 1% approximate buckets',
            'TCP/UDP throughput counts successful verified request/reply exchanges; HTTP counts verified responses',
            'no nginx comparison, no WAN/NAT emulation, no claim of 100k requests/s capacity']}
    envs={role:{**os.environ,'GOMAXPROCS':str(getattr(args, role+'_gomaxprocs'))}
          for role in ('backend','client','app')}
    report['hardware']['affinityCPUs']=sorted(os.sched_getaffinity(0))
    report['hardware']['cgroupCPU']=cgroup_cpu()
    report['runtimeEnvironment']={role:{key:env.get(key, 'Go default')
        for key in ('GOMAXPROCS','GOGC','GOMEMLIMIT','GODEBUG','GOEXPERIMENT')}
        for role,env in envs.items()}
    report['cpuAccounting']='approximate per-process CPU ticks / midpoint-to-midpoint sampling wall time; client wait4 covers startup, load and teardown; distinct from client RPS interval'
    report['cpuTickSeconds']=1/os.sysconf('SC_CLK_TCK')
    report['binarySHA256']={role:hashlib.sha256(Path(path).read_bytes()).hexdigest()
                           for role,path in [('niceproxy',args.binary),('parkload',args.load_binary),('caddy',args.caddy)]}
    source_subnet='127.96.'+str(secrets.randbelow(256))
    report['sourceSubnet']=source_subnet+'.0/24'
    report['conntrackObservations']=[]
    def conntrack():
        try:
            base=Path('/proc/sys/net/netfilter')
            return {'count':int((base/'nf_conntrack_count').read_text()),'max':int((base/'nf_conntrack_max').read_text())}
        except OSError:
            return None
    def wait_capacity(reserve):
        started_wait=time.monotonic()
        announced=False
        while True:
            state=conntrack()
            if state is None:raise RuntimeError('conntrack accounting unavailable; refusing an unguarded shared-host benchmark')
            if state['count']+reserve <= state['max']*.8:
                report['conntrackObservations'].append({'stage':'before','waitSeconds':time.monotonic()-started_wait,**state})
                return state
            if not announced:
                print(f"WAIT conntrack {state['count']}/{state['max']}; reserve {reserve}; waiting for natural expiry",flush=True)
                announced=True
            if time.monotonic()-started_wait > 150:
                raise RuntimeError('shared host conntrack remains above the test safety budget')
            time.sleep(2)
    def spawn(command,name,pipe=False,role='app'):
        log=(artifacts/(name+'.log')).open('w');logs.append(log)
        p=subprocess.Popen(command,stdout=subprocess.PIPE if pipe else log,stderr=log,stdin=subprocess.DEVNULL,
                           env=envs[role],start_new_session=True,text=True)
        processes.append(p);return p
    def free_port():
        # Keep listeners outside the host's ephemeral client port range so an
        # outgoing test connection cannot take a reserved candidate before bind.
        low,high=map(int,Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split())
        for _ in range(1000):
            port=20000+secrets.randbelow(10000)
            if low <= port <= high or port in used:
                continue
            try:
                with socket.socket() as sock:
                    sock.bind(('0.0.0.0',port))
            except OSError:
                continue
            used.add(port);return port
        raise RuntimeError('no free listener port outside ephemeral range')
    def resources(pid):
        try:
            fields={a:b.strip() for a,b in (line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)}
            return {'pid':pid,'rssKiB':int(fields['VmRSS'].split()[0]),'threads':int(fields['Threads']),
                    'fds':len(list(Path(f'/proc/{pid}/fd').iterdir()))}
        except (OSError,KeyError):return None
    def db_fingerprint():
        return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'data').glob('niceproxy.db*') if not p.name.endswith('-shm')}
    def cleanup():
        stop_sample.set()
        if sampler is not None:
            sampler.join(3)
        for sig in (signal.SIGTERM,signal.SIGKILL):
            for p in reversed(processes):
                with contextlib.suppress(ProcessLookupError):os.killpg(p.pid,sig)
            for p in processes:
                with contextlib.suppress(subprocess.TimeoutExpired):p.wait(timeout=3)
        for log in logs:log.close()
        temporary.cleanup()
    try:
        wait_capacity(65536)
        backend=spawn([args.load_binary,'serve','--listen-host','127.88.0.10','--id','bench-backend'],'backend',True,role='backend')
        if not select.select([backend.stdout],[],[],10)[0]:raise TimeoutError('backend readiness')
        endpoints=json.loads(backend.stdout.readline());report['backend']=endpoints
        panel,hp,sp,tp,up=[free_port() for _ in range(5)]
        base=f'http://127.88.0.2:{panel}'
        app=spawn([args.binary,'--caddy',args.caddy,'--data',str(root/'data'),'--runtime',str(root/'run'),
                   '--ui',str(Path('web/dist').resolve()),'--panel',f'127.88.0.2:{panel}',
                   '--http-port',str(hp),'--https-port',str(sp),'--max-tcp','1024','--max-udp','1024'],'niceproxy')
        client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        def api(path,body=None,method=None):
            req=urllib.request.Request(base+'/api/'+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Content-Type':'application/json'})
            with client.open(req,timeout=15) as r:return json.load(r)
        for _ in range(150):
            try:api('auth');break
            except (OSError,urllib.error.URLError):
                if app.poll() is not None:raise RuntimeError('niceproxy startup failed')
                time.sleep(.05)
        else:raise TimeoutError('panel readiness')
        api('setup',{'password':secrets.token_urlsafe(24)})
        http_routes=[('bench.park.test','off'),('secure-bench.park.test','internal')]
        if args.tcp_on_http_port:
            api('port-owners',{'http':'direct'},'PATCH')
            tp=hp
            http_routes=[('secure-bench.park.test','internal')]
        report['listeners']={'httpPort':hp,'httpsPort':sp,'tcpPort':tp,'udpPort':up,
                             'httpOwner':'direct' if args.tcp_on_http_port else 'caddy'}
        for host,tls in http_routes:
            r=api('http-routes',{'host':host,'target':'http://'+endpoints['http'],'tls':tls,'enabled':True})
            if r['status']!='healthy':raise AssertionError(r)
        for proto,port in [('tcp',tp),('udp',up)]:
            host,target_port=endpoints[proto].rsplit(':',1)
            r=api('direct-rules',{'protocol':proto,'listenHost':'127.88.0.2','listenPort':port,
                                'targetHost':host,'targetPort':int(target_port),'enabled':True})
            if r['status']!='healthy':raise AssertionError(r)
        ca=root/'data/caddy/pki/authorities/local/root.crt'
        for _ in range(100):
            if ca.exists():break
            time.sleep(.05)
        configs=CASES
        if args.cases:
            selected=set(args.cases.split(','))
            unknown=selected-{case[0] for case in configs}
            if unknown:raise ValueError('unknown benchmark cases: '+','.join(sorted(unknown)))
            configs=[case for case in configs if case[0] in selected]
        target_proxy={'http':f'127.88.0.2:{hp}','https':f'127.88.0.2:{sp}', 'tcp':f'127.88.0.2:{tp}','udp':f'127.88.0.2:{up}'}
        before=db_fingerprint();report['dbBefore']=before
        monitored=[('niceproxy',app.pid),('backend',backend.pid)]
        # Include the bundled Caddy process; Linux lists each thread's children.
        caddy_pids=set()
        for children in Path(f'/proc/{app.pid}/task').glob('*/children'):
            caddy_pids.update(map(int,children.read_text().split()))
        if not caddy_pids:raise RuntimeError('bundled Caddy PID unavailable')
        monitored += [('caddy',pid) for pid in sorted(caddy_pids)]
        report['processes']=[{'role':role,'pid':pid,'affinityCPUs':sorted(os.sched_getaffinity(pid))}
                             for role,pid in monitored]
        def sample():
            while not stop_sample.is_set():
                for role,pid in monitored:
                    row=resources(pid)
                    if row:samples.append({'role':role,'t':time.monotonic(),**row})
                stop_sample.wait(.5)
        sampler=threading.Thread(target=sample,daemon=True);sampler.start()
        sequence=0
        for name,protocol,connections,payload in configs:
            for concurrency in levels:
                for repeat in range(args.repeats):
                    variants=['proxy'] if args.proxy_only or protocol=='https' else (['direct','proxy'] if repeat%2==0 else ['proxy','direct'])
                    for variant in variants:
                        sequence+=1
                        ct_before=wait_capacity(65536 if connections=='new' else 4096)
                        case_seconds=args.new_connection_seconds if connections=='new' else args.seconds
                        command=[args.load_binary,'load','--protocol',protocol,'--target',target_proxy[protocol] if variant=='proxy' else endpoints[protocol],
                                 '--duration',str(case_seconds)+'s','--concurrency',str(concurrency),'--connections',connections,
                                 '--source-host',f'{source_subnet}.{sequence%250+1}']
                        if payload:command+=['--payload-size',str(payload)]
                        if protocol in ('http','https'):
                            command+=['--host','secure-bench.park.test' if protocol=='https' else 'bench.park.test','--expect-prefix',HTTP_BODY]
                        if protocol=='https':command+=['--ca',str(ca)]
                        print(f'RUN {name} {variant} workers={concurrency} repeat={repeat+1}',flush=True)
                        cgroup_before=cgroup_cpu()
                        cpu_before={pid:cpu_snapshot(pid) for _,pid in monitored}
                        affinities={pid:sorted(os.sched_getaffinity(pid)) for _,pid in monitored}
                        measurement_started=time.monotonic()
                        # Files avoid pipe backpressure; wait4 supplies this child's own CPU usage.
                        with tempfile.TemporaryFile(mode='w+') as stdout_file, tempfile.TemporaryFile(mode='w+') as stderr_file:
                            p=subprocess.Popen(command,stdout=stdout_file,stderr=stderr_file,
                                               env=envs['client'],start_new_session=True)
                            processes.append(p)
                            client_affinity=sorted(os.sched_getaffinity(p.pid))
                            while True:
                                waited,status,usage=os.wait4(p.pid,os.WNOHANG)
                                if waited:break
                                if time.monotonic()-measurement_started > case_seconds+20:
                                    raise TimeoutError('load client timed out')
                                time.sleep(.01)
                            p.returncode=os.waitstatus_to_exitcode(status)
                            processes.remove(p)
                            cpu_after={pid:cpu_snapshot(pid) for _,pid in monitored}
                            wall=time.monotonic()-measurement_started
                            cpu=[{'role':role,'pid':pid,
                                  'before':cpu_before[pid],'after':cpu_after[pid],
                                  **cpu_measurement(cpu_after[pid]['cpuSeconds']-cpu_before[pid]['cpuSeconds'],
                                      cpu_after[pid]['sampleMonotonicSeconds']-cpu_before[pid]['sampleMonotonicSeconds'],affinities[pid])}
                                 for role,pid in monitored]
                            cpu.append({'role':'client','pid':p.pid,**cpu_measurement(usage.ru_utime+usage.ru_stime,wall,client_affinity)})
                            stdout_file.seek(0);stdout=stdout_file.read()
                            stderr_file.seek(0);stderr=stderr_file.read()
                        try:row=json.loads(stdout)
                        except json.JSONDecodeError:raise RuntimeError(stderr[:1500] or stdout[:1500])
                        row.update({'case':name,'variant':variant,'repeat':repeat+1,'exitCode':p.returncode,
                                    'cpu':cpu,'cgroupCPUBefore':cgroup_before,'cgroupCPUAfter':cgroup_cpu(),
                                    'command':command,'loadAverage':os.getloadavg(),'conntrackBefore':ct_before,'conntrackAfter':conntrack()})
                        try:
                            settle_started=time.monotonic()
                            while True:
                                row['ruleStatsAfter']=[{'protocol':r['protocol'],'listenPort':r['listenPort'],'stats':r.get('stats'),'status':r.get('status')} for r in api('config')['directRules']]
                                if not any(r['protocol']=='tcp' and r.get('stats',{}).get('active',0) for r in row['ruleStatsAfter']):
                                    break
                                if time.monotonic()-settle_started >= 2:
                                    break
                                time.sleep(.02)
                            row['statsSettleSeconds']=time.monotonic()-settle_started
                        except Exception as e:
                            row['statsReadError']=str(e)
                        report['results'].append(row)
                        (artifacts/f'{sequence:03d}-{name}-{variant}.json').write_text(json.dumps(row,indent=2))
                        out.write_text(json.dumps(report,indent=2))
                        try:
                            validate_result(row)
                        except AssertionError as e:
                            raise AssertionError(f'load failed: {name} {variant}: {e}; {row.get("errorSamples")} {stderr[:1000]}')
        stop_sample.set();sampler.join(3)
        report['dbAfter']=db_fingerprint()
        if before!=report['dbAfter']:raise AssertionError('SQLite DB/WAL changed during data-plane-only load')
        report['sqliteUnchangedDuringTraffic']=True
        report['resources']=samples
        health=api('health');report['healthAfter']=health
        if health['status']!='healthy' or health['revision']!=health['appliedRevision']:raise AssertionError(health)
        report['passed']=True
    except BaseException as e:
        report['error']=f'{type(e).__name__}: {e}'
        print(report['error'],file=__import__('sys').stderr)
    finally:
        cleanup()
        report['resources']=samples
        report['targetAssessment']=assess_targets(report['results'],targets,levels,args.repeats)
        report['targetPassed']=report['passed'] and all(a['passed'] for a in report['targetAssessment'].values()) if targets else None
        report['totalDurationSeconds']=time.monotonic()-started
        out.write_text(json.dumps(report,indent=2)+'\n')
    print(('PASS' if report['passed'] else 'FAIL')+': benchmark report '+str(out),flush=True)
    if targets:print('Targets: '+('PASS' if report['targetPassed'] else 'FAIL'),flush=True)
    return 0 if report['passed'] and report['targetPassed'] is not False else 1


if __name__=='__main__':
    raise SystemExit(main())
