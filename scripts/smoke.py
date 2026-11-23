#!/usr/bin/env python3
"""End-to-end smoke test using a real bundled/pinned Caddy binary."""
import argparse
import http.client
import http.cookiejar
import http.server
import json
import os
import pathlib
import re
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("path backend " + self.path).encode() if getattr(self.server, "path_backend", False) else b"niceproxy upstream"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--caddy", required=True)
    parser.add_argument("--binary", default="bin/niceproxy")
    args = parser.parse_args()
    servers = [http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTP),
               socketserver.ThreadingTCPServer(("127.0.0.1", 0), TCP),
               socketserver.ThreadingUDPServer(("127.0.0.1", 0), UDP),
               http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTP)]
    servers[3].path_backend = True
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    http_port, https_port, panel = free_port(), free_port(), free_port()
    tcp_port, udp_port = free_port(), free_port(socket.SOCK_DGRAM)
    base = f"http://127.0.0.1:{panel}"
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def api(path, body=None, method=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(base + "/api/" + path, data=data,
            method=method, headers={"Content-Type": "application/json"})
        with client.open(request, timeout=15) as response:
            return json.load(response)

    with tempfile.TemporaryDirectory(prefix="niceproxy-e2e-") as tmp:
        data, runtime = pathlib.Path(tmp) / "data", pathlib.Path(tmp) / "run"
        command = [str(pathlib.Path(args.binary).resolve()), "--caddy", str(pathlib.Path(args.caddy).resolve()),
                   "--data", str(data), "--runtime", str(runtime), "--panel", f"127.0.0.1:{panel}",
                   "--http-port", str(http_port), "--https-port", str(https_port)]
        process = None
        def start():
            nonlocal process
            process = subprocess.Popen(command)
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("niceproxy exited during startup")
                try:
                    return api("auth")
                except (OSError, urllib.error.URLError):
                    time.sleep(.05)
            raise TimeoutError("panel did not become ready")
        def stop():
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise
        try:
            assert start() == {"configured": False, "authenticated": False}
            subprocess.run([command[0], "healthcheck"], check=True, timeout=5,
                           env={**os.environ, "NICEPROXY_RUNTIME_DIR": str(runtime)})
            with client.open(base + "/", timeout=5) as response:
                page = response.read()
                assert response.headers.get_content_type() == "text/html"
            module = re.search(rb'<script\b[^>]*\bsrc="(\.?/assets/[^"/]+\.js)"', page)
            assert module, "panel HTML did not reference a built JavaScript bundle"
            with client.open(urllib.parse.urljoin(base + "/", module[1].decode()), timeout=5) as response:
                assert response.headers.get_content_type() in {"text/javascript", "application/javascript"}
                assert response.read(), "panel JavaScript bundle was empty"

            api("setup", {"password": "temporary-smoke-password-123"})
            for host, tls in [("plain.test", "off"), ("secure.test", "internal")]:
                route = api("http-routes", {"host": host, "target": f"http://127.0.0.1:{servers[0].server_port}", "tls": tls, "enabled": True})
                assert route["status"] == "healthy", route
                for path,strip in [("/api",False),("/api/v1",True),("/API",True)]:
                    route = api("http-routes", {"host":host,"path":path,"stripPrefix":strip,"target":f"http://127.0.0.1:{servers[3].server_port}","tls":tls,"enabled":True})
                    assert route["status"] == "healthy", route
            route = api("http-routes", {"host":"prefix-only.test","path":"/api","target":f"http://127.0.0.1:{servers[3].server_port}","tls":"off","enabled":True})
            assert route["status"] == "healthy", route
            request = urllib.request.Request(f"http://127.0.0.1:{http_port}/", headers={"Host": "plain.test"})
            assert urllib.request.urlopen(request, timeout=5).read() == b"niceproxy upstream"
            # Trust the generated local CA; no insecure TLS verification bypass.
            ca = data / "caddy/pki/authorities/local/root.crt"
            for _ in range(100):
                try:
                    context = ssl.create_default_context(cafile=str(ca))
                    with socket.create_connection(("127.0.0.1", https_port), timeout=2) as raw:
                        with context.wrap_socket(raw, server_hostname="secure.test") as secure:
                            secure.sendall(b"GET / HTTP/1.1\r\nHost: secure.test\r\nConnection: close\r\n\r\n")
                            response = http.client.HTTPResponse(secure)
                            response.begin()
                            assert response.status == 200
                            assert response.read() == b"niceproxy upstream"
                    break
                except (OSError, ssl.SSLError):
                    time.sleep(.05)
            else:
                raise TimeoutError("internal HTTPS certificate not ready")
            def proxy_request(host,path,tls=False):
                with socket.create_connection(("127.0.0.1",https_port if tls else http_port),timeout=5) as raw:
                    connection=context.wrap_socket(raw,server_hostname=host) if tls else raw
                    try:
                        connection.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                        response=http.client.HTTPResponse(connection)
                        response.begin()
                        return response.status,response.read()
                    finally:
                        if tls:connection.close()
            for host,tls in [("plain.test",False),("secure.test",True)]:
                for path,want in [("/",b"niceproxy upstream"),("/apix",b"niceproxy upstream"),
                    ("/api?x=one&y=two",b"path backend /api?x=one&y=two"),
                    ("/api/users?q=1",b"path backend /api/users?q=1"),
                    ("/API/users?q=1",b"path backend /users?q=1"),
                    ("/Api/users",b"niceproxy upstream"),
                    ("/api/v1/items?q=1",b"path backend /items?q=1"),
                    ("/api/v1?x=1",b"path backend /?x=1"),
                    ("/api/v1%2Fitems?q=1",b"path backend /items?q=1"),
                    ("/api/v1%2fitems%3Fpart?q=1",b"path backend /items%3Fpart?q=1"),
                    ("/api%2Fv1/items?q=1",b"path backend /items?q=1")]:
                    actual=proxy_request(host,path,tls)
                    assert actual==(200,want),(host,path,actual,want)
            assert proxy_request("prefix-only.test","/apix")[0]==404
            rules = []
            for protocol, listen, server in [("tcp", tcp_port, servers[1]), ("udp", udp_port, servers[2])]:
                r = api("direct-rules", {"protocol": protocol, "listenHost": "127.0.0.1", "listenPort": listen,
                    "targetHost": "127.0.0.1", "targetPort": server.server_address[1], "enabled": True})
                assert r["status"] == "healthy", r
                rules.append(r)
            payload = b"splice-remapping-test" * 65536
            with socket.create_connection(("127.0.0.1", tcp_port), timeout=5) as s:
                s.sendall(payload)
                s.shutdown(socket.SHUT_WR)
                chunks = []
                while chunk := s.recv(65536):
                    chunks.append(chunk)
                assert b"".join(chunks) == payload
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(5)
                s.sendto(b"udp-remapping-test", ("127.0.0.1", udp_port))
                assert s.recv(1024) == b"udp-remapping-test"
            assert api("health")["revision"] == api("health")["appliedRevision"]
            stop()
            assert start()["authenticated"]  # session and config survive restart
            assert len(api("config")["directRules"]) == 2
            assert api("health")["status"] == "healthy"
            assert proxy_request("plain.test","/api/v1/restarted")== (200,b"path backend /restarted")
            # A conflicting public port must not prevent management/recovery.
            stop()
            with socket.socket() as occupied:
                occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                occupied.bind(("0.0.0.0", http_port))
                occupied.listen()
                assert start()["authenticated"]
                assert api("health")["status"] == "error"
                assert api("health")["appliedRevision"] == -1
            api("reconcile", method="POST")
            assert api("health")["status"] == "healthy"
            api("direct-rules/" + rules[0]["id"], {"enabled": False}, "PATCH")
            with socket.socket() as s:
                s.settimeout(1)
                assert s.connect_ex(("127.0.0.1", tcp_port)) != 0
            for r in rules:
                api("direct-rules/" + r["id"], method="DELETE")
            api("logout", method="POST")
            assert not api("auth")["authenticated"]
            print("PASS: panel assets, healthcheck, setup/session, HTTP/HTTPS path priority and segment boundaries, strip-prefix/query, TCP/UDP remapping, restart persistence, occupied-port recovery, disable/delete/logout")
        finally:
            stop()
            for server in servers:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
