#!/usr/bin/env python3
"""Exercise explicit port ownership against the real Go process and bundled Caddy."""
import argparse
import http.cookiejar
import http.server
import json
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

from smoke import HTTP, UDP, free_port


class Greeting(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"server-ready\n")
        while data := self.request.recv(65536):
            self.request.sendall(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="bin/niceproxy")
    parser.add_argument("--caddy", required=True)
    args = parser.parse_args()
    servers = [http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTP),
               socketserver.ThreadingTCPServer(("127.0.0.1", 0), Greeting),
               socketserver.ThreadingUDPServer(("127.0.0.1", 0), UDP)]
    for server in servers:
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
    panel, http_port, https_port = free_port(), free_port(), free_port()
    base = f"http://127.0.0.1:{panel}"
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    process = None
    held = None

    def api(path, body=None, method=None, status=200):
        req = urllib.request.Request(base + "/api/" + path,
            data=None if body is None else json.dumps(body).encode(), method=method,
            headers={"Content-Type": "application/json"})
        try:
            response = client.open(req, timeout=15)
        except urllib.error.HTTPError as e:
            response = e
        with response:
            value = json.load(response)
            assert response.status == status, (path, response.status, value, status)
            return value

    def rule(protocol, port, server, enabled=True):
        return {"protocol": protocol, "listenHost": "127.0.0.1", "listenPort": port,
                "targetHost": "127.0.0.1", "targetPort": server.server_address[1], "enabled": enabled}

    def greet(port):
        conn = socket.create_connection(("127.0.0.1", port), timeout=3)
        assert conn.recv(128) == b"server-ready\n", "Server-first traffic must not wait for classification"
        return conn

    def health():
        h = api("health")
        assert h["status"] == "healthy" and h["revision"] == h["appliedRevision"], h
        return h

    def conflict(path, data):
        revision = api("config")["revision"]
        api(path, data, "PATCH" if path == "port-owners" else None, status=409)
        assert api("config")["revision"] == revision, "409 must not write desired config"

    def udp_echo():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(b"ownership-udp", ("127.0.0.1", https_port))
            assert s.recv(1024) == b"ownership-udp"

    try:
        with tempfile.TemporaryDirectory(prefix="niceproxy-ownership-") as tmp:
            root = Path(tmp)
            data, runtime = root / "data", root / "run"
            log = (root / "process.log").open("w+")
            command = [str(Path(args.binary).resolve()), "--caddy", str(Path(args.caddy).resolve()),
                       "--data", str(data), "--runtime", str(runtime),
                       "--panel", f"127.0.0.1:{panel}", "--http-port", str(http_port),
                       "--https-port", str(https_port), "--max-tcp", "2"]

            def stop():
                nonlocal process
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise

            def start():
                nonlocal process
                process = subprocess.Popen(command, stdout=log, stderr=log)
                for _ in range(150):
                    if process.poll() is not None:
                        log.flush(); log.seek(0)
                        raise RuntimeError("Startup exited: " + log.read()[-6000:])
                    try:
                        return api("auth")
                    except (OSError, urllib.error.URLError):
                        time.sleep(.05)
                raise TimeoutError("Panel not ready")

            try:
                assert start()["configured"] is False
                api("setup", {"password": "isolated-ownership-smoke-password"})
                settings = api("port-owners")
                assert settings == {"httpPort": http_port, "httpsPort": https_port,
                                    "owners": {"http": "caddy", "https": "caddy", "http3": "caddy"}}, settings
                conflict("direct-rules", rule("tcp", http_port, servers[1]))
                conflict("direct-rules", rule("udp", https_port, servers[2]))
                plain = api("http-routes", {"host": "ownership.test", "target": f"http://127.0.0.1:{servers[0].server_port}", "tls": "off", "enabled": True})
                conflict("port-owners", {"http": "direct"})
                api("http-routes/" + plain["id"], {"enabled": False}, "PATCH")
                api("port-owners", {"http": "direct", "https": "direct", "http3": "direct"}, "PATCH")
                direct = api("direct-rules", rule("tcp", http_port, servers[1]))
                assert direct["status"] == "healthy", direct
                held = greet(http_port)
                held.sendall(b"before"); assert held.recv(32) == b"before"
                time.sleep(.03)
                snapshot = next(r for r in api("config")["directRules"] if r["id"] == direct["id"])
                assert snapshot["stats"]["active"] == 1 and snapshot["stats"]["accepted"] == 1, snapshot
                second = greet(http_port)
                third = socket.create_connection(("127.0.0.1", http_port), timeout=3)
                assert third.recv(128) == b"", "Excess connection should be closed"
                third.close(); second.close()
                for _ in range(50):
                    snapshot = next(r for r in api("config")["directRules"] if r["id"] == direct["id"])
                    if snapshot["stats"]["rejects"] >= 1 and snapshot["stats"]["active"] == 1:
                        break
                    time.sleep(.02)
                assert snapshot["stats"]["rejects"] >= 1, snapshot
                conflict("port-owners", {"http": "caddy"})
                begun = time.perf_counter()
                api("direct-rules/" + direct["id"], {"enabled": False}, "PATCH")
                retired_ms = (time.perf_counter() - begun) * 1000
                assert retired_ms < 900, ("Handover waited for an open stream", retired_ms)
                api("port-owners", {"http": "caddy"}, "PATCH")
                api("http-routes/" + plain["id"], {"enabled": True}, "PATCH")
                req = urllib.request.Request(f"http://127.0.0.1:{http_port}/", headers={"Host": "ownership.test"})
                with urllib.request.urlopen(req, timeout=3) as response:
                    assert response.read() == b"niceproxy upstream"
                held.sendall(b"after-handover"); assert held.recv(128) == b"after-handover"
                snapshot = next(r for r in api("config")["directRules"] if r["id"] == direct["id"])
                assert snapshot["stats"]["active"] == 1, snapshot
                held.close(); held = None
                print(f"PASS: Caddy/direct ownership409, server-first, admission counters, preserved TCP after handover (retire {retired_ms:.2f}ms)", flush=True)

                udp = api("direct-rules", rule("udp", https_port, servers[2]))
                assert udp["status"] == "healthy", udp
                udp_echo()
                conflict("port-owners", {"http3": "caddy"})
                api("port-owners", {"https": "caddy"}, "PATCH")
                secure = api("http-routes", {"host": "secure-ownership.test", "target": f"http://127.0.0.1:{servers[0].server_port}", "tls": "internal", "enabled": True})
                assert secure["status"] == "healthy", secure
                caddy_config = json.loads((runtime / "caddy.json").read_text())
                assert "h3" not in caddy_config["apps"]["http"]["servers"]["public_https"]["protocols"]
                udp_echo()
                health()
                print("PASS: direct UDP and Caddy HTTPS share port number with independent transports; no Caddy UDP bind", flush=True)

                api("http-routes/" + secure["id"], {"enabled": False}, "PATCH")
                api("direct-rules/" + udp["id"], {"enabled": False}, "PATCH")
                api("port-owners", {"https": "direct", "http3": "caddy"}, "PATCH")
                tls_direct = api("direct-rules", rule("tcp", https_port, servers[1]))
                api("http-routes/" + secure["id"], {"enabled": True}, "PATCH")
                with greet(https_port) as conn:
                    conn.sendall(b"raw-not-https"); assert conn.recv(128) == b"raw-not-https"
                h3_config = json.loads((runtime / "caddy.json").read_text())
                assert h3_config["apps"]["http"]["servers"]["public_https"]["protocols"] == ["h3"]
                health()
                stop()
                assert start()["authenticated"], "Session must survive restart"
                health()
                with greet(https_port) as conn:
                    conn.sendall(b"restored"); assert conn.recv(128) == b"restored"
                print("PASS: HTTP/3-only Caddy and raw TCP same port number; ownership/rules/session restored after restart", flush=True)

                with socket.socket() as occupied:
                    occupied.bind(("127.0.0.1", 0)); occupied.listen()
                    bad = api("direct-rules", rule("tcp", occupied.getsockname()[1], servers[1]))
                    assert bad["status"] == "error", bad
                    assert api("health")["appliedRevision"] == -1
                    api("direct-rules/" + bad["id"], method="DELETE")
                health()
                print("PASS: external occupied port reports partial apply; panel stays alive and recovers", flush=True)
            finally:
                if held:
                    held.close(); held = None
                stop()
                log.close()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
