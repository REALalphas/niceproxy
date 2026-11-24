#!/usr/bin/env python3
"""Build/run a rootless test runtime, independently of registry and production bootstrap.

Build: python3 scripts/park-container.py --build --caddy /path/to/caddy
Run: use this executable as --binary for smoke.py or ownership-smoke.py.
This scratch runtime checks the actual Go/Caddy binaries and kernel/container
restrictions; it deliberately does not validate the production Node bootstrap.
"""
import argparse
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get('NICEPROXY_PARK_IMAGE', 'localhost/niceproxy-park:runtime')


def build():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', action='store_true')
    parser.add_argument('--caddy', required=True)
    args = parser.parse_args()
    if not (ROOT/'web/dist/index.html').is_file():
        parser.error('build web/dist first')
    with tempfile.TemporaryDirectory(prefix='niceproxy-container-build-') as tmp:
        context = Path(tmp)
        subprocess.run(['go','build','-trimpath','-o',str(context/'niceproxy'),'./cmd/niceproxy'],
            cwd=ROOT, env={**os.environ,'CGO_ENABLED':'0'}, check=True, timeout=120)
        shutil.copyfile(args.caddy, context/'caddy')
        (context/'caddy').chmod(0o755)
        shutil.copytree(ROOT/'web/dist',context/'ui')
        cafile = ssl.get_default_verify_paths().cafile
        if not cafile:
            raise RuntimeError('system CA bundle not found')
        shutil.copyfile(cafile, context/'ca-certificates.crt')
        (context/'Containerfile').write_text('''FROM scratch
COPY niceproxy /niceproxy
COPY caddy /caddy
COPY ui /app/web/dist
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
WORKDIR /app
ENV HOME=/data
ENTRYPOINT ["/niceproxy"]
''')
        subprocess.run(['podman','build','--pull=never','-t',IMAGE,str(context)], check=True, timeout=120)
    print('Rootless test runtime image:',IMAGE)


def run():
    forwarded = sys.argv[1:]
    def value(flag):
        try:
            return forwarded[forwarded.index(flag)+1]
        except (ValueError, IndexError):
            raise SystemExit('smoke wrapper requires '+flag)
    data = Path(value('--data')).resolve()
    runtime = Path(value('--runtime')).resolve()
    # Mount only the test's temporary root, never all /tmp or the workspace.
    root = data.parent
    if not root.name.startswith(('niceproxy-e2e-','niceproxy-ownership-')) or root != runtime.parent:
        raise SystemExit('refusing a mount outside an isolated smoke temporary root')
    root.mkdir(parents=True,exist_ok=True)
    if '--caddy' in forwarded:
        forwarded[forwarded.index('--caddy')+1]='/caddy'
    name='niceproxy-park-'+uuid.uuid4().hex[:12]
    command=['podman','run','--rm','--name',name,'--label','niceproxy.park=runtime',
        '--network=host','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--stop-timeout=8','--pids-limit=512','--memory=512m','--ulimit=nofile=262144:262144',
        '--volume',str(root)+':'+str(root)+':rw',
        '--env','NICEPROXY_RUNTIME_DIR='+str(runtime),
        IMAGE,*forwarded]
    os.execvp(command[0],command)


if __name__ == '__main__':
    if '--build' in sys.argv:
        build()
    else:
        run()
