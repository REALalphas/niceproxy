# niceproxy

Linux-only self-hosted proxy. Implementation agents: Sol Medium. Independent reviewers: Terra Medium.

- Read `web/ALPHA_UI_AGENT_RULES.md` before editing the UI. Use Alpha UI public components and layout tokens.
- HTTP(S) belongs to the bundled Caddy. Direct TCP/UDP belongs to `internal/proxy`.
- Preserve concrete `*net.TCPConn` on the TCP copy path so Linux splice remains available. Verify it with strace.
- No Docker socket, privileged container, NET_ADMIN, iptables or remote tunnel dependency.
- Keep mutations serialized and report desired versus applied state honestly. Database writes never belong on the traffic path.
- Tests: `go test -race ./...`, `go vet ./...`, frontend typecheck/build and integration smoke tests.
