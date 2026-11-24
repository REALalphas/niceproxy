#!/usr/bin/env python3
"""Verify real QUIC HTTP/3 with TLS trust while raw TCP owns the same port number."""
import argparse
import importlib.util
import json
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='bin/niceproxy')
    parser.add_argument('--caddy', required=True)
    parser.add_argument('--output', default='test-results/park/http3.json')
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise TimeoutError('HTTP3 test interrupted by signal '+str(signum))
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    version = subprocess.check_output(['curl','--version'],text=True,timeout=5)
    if 'HTTP3' not in version:
        parser.error('curl built with HTTP3 support is required; no insecure/bind-only substitute')
    module_spec = importlib.util.spec_from_file_location('virtual_park',Path(__file__).with_name('virtual-park.py'))
    module = importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(module)
    settings = argparse.Namespace(binary=str(Path(args.binary).resolve()),caddy=str(Path(args.caddy).resolve()),
        instances=1,clients=4,cycles=2,output=args.output,work_dir=None,quick=False,
        backend=None,handover_pause_ms=0,functional_only=True)
    park = module.Park(settings)
    report={'passed':False,'curl':version.splitlines()[0],'artifacts':str(park.root),'checks':[]}
    try:
        park.setup();inst=park.instances[0]
        secure=inst['secure'];backend=inst['backends'][0]
        ca=next((inst['dir']/'data').rglob('root.crt'))
        def curl(protocol,host=None):
            command=['curl','--silent','--show-error','--noproxy','*','--max-time','5',protocol,
                '--cacert',str(ca),'--resolve',f"{secure['host']}:{inst['https']}:{inst['ip']}",
                '--write-out','\n%{http_version} %{http_code}',
                f"https://{secure['host']}:{inst['https']}/tenant/probe"]
            if host:command+=['--header','Host: '+host]
            result=subprocess.run(command,capture_output=True,text=True,timeout=8)
            if result.returncode:raise AssertionError(result.stderr)
            body,metrics=result.stdout.rsplit('\n',1);version,status=metrics.split()
            return body,version,int(status)
        park.api(inst,'PATCH','/api/port-owners',{'https':'direct'})
        raw=park.rule(inst,'tcp',inst['https'],backend['tcp'])
        with park.connect(inst,port=inst['https']) as sock:park.echo(sock)
        body,protocol,status=curl('--http3-only')
        if (body,protocol,status)!=(backend['identity']+'|/probe','3',200):raise AssertionError((body,protocol,status))
        report['checks'].append({'name':'verified QUIC HTTP3 and raw TCP on same port number','passed':True,'httpVersion':protocol})
        for foreign in ['foreign.park.test','unknown.park.test']:
            body,protocol,status=curl('--http3-only',foreign)
            if status not in (404,421) or body.startswith(backend['identity']+'|'):raise AssertionError((foreign,status,body))
        report['checks'].append({'name':'HTTP3 rejects foreign Host while validating original SNI certificate','passed':True})
        park.api(inst,'PATCH','/api/direct-rules/'+raw['id'],{'enabled':False})
        park.api(inst,'PATCH','/api/port-owners',{'https':'caddy','http3':'direct'})
        park.rule(inst,'udp',inst['https'],backend['udp'])
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(3);nonce=secrets.token_bytes(64)
            sock.sendto(nonce,(inst['ip'],inst['https']))
            if sock.recv(1024)!=backend['identity'].encode()+b'|'+nonce:raise AssertionError('raw UDP corruption')
        body,protocol,status=curl('--http2')
        if body!=backend['identity']+'|/probe' or status!=200 or protocol not in ('2','1.1'):raise AssertionError((body,protocol,status))
        report['checks'].append({'name':'verified HTTPS TCP and raw UDP after ownership change','passed':True,'httpVersion':protocol})
        health=park.api(inst,path='/api/health')
        if health['status']!='healthy' or health['revision']!=health['appliedRevision']:raise AssertionError(health)
        report['passed']=True
    except Exception as e:
        report['error']=f'{type(e).__name__}: {e}'
    finally:
        park.cleanup();report['durationSeconds']=time.monotonic()-park.start
        out=Path(args.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
