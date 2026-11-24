# niceproxy

Linux-only self-hosted proxy.

- Read `web/ALPHA_UI_AGENT_RULES.md` before editing the UI. Use Alpha UI public components and layout tokens.
- HTTP(S) belongs to the bundled Caddy. Direct TCP/UDP belongs to `internal/proxy`.
- Preserve concrete `*net.TCPConn` on the TCP copy path so Linux splice remains available. Verify it with strace.
- No Docker socket, privileged container, NET_ADMIN, iptables or remote tunnel dependency.
- Keep mutations serialized and report desired versus applied state honestly. Database writes never belong on the traffic path.
- Tests: `go test -race ./...`, `go vet ./...`, frontend typecheck/build and integration smoke tests.

## Subagents

- Subagents are applicable to separate technical subtasks: local changes, research into a specific question, and independent verification. Use them when a subtask can be clearly separated from the main work.
- Model priority: **6.2 Sol (Low) > Gemini 3.8 Flash (High) > Luna (Max)**. Select the first available model in that order; Low, High, and Max are the reasoning effort settings for 6.2 Sol, Gemini 3.8 Flash, and Luna respectively. Explicit user settings take precedence.
- Subagents **MUST receive small, precise tasks**: one bounded objective, necessary context, specific files or scope, constraints, expected output, and verification criteria. Do not delegate the entire user request or all project work. The primary agent performs a substantial part of the work and owns decomposition, decisions, integration, and final verification. Assign file ownership before parallel edits.
- If a work result is factually verifiable, **launch an independent counter-agent** with a narrow critical review task. Provide requirements, the result or diff, and acceptance criteria. The counter-agent looks for errors and counterexamples, runs relevant available checks, and supplies evidence: a file and line, reproduction, or check output. It explicitly reports unavailable checks and does not present preferences or speculation as factual defects.
- Validate the counter-agent's findings. When factual problems are confirmed, fix them and **launch a new independent agent** to re-check the corrected result, providing the original task, findings, fixes, and remaining objections. Repeat until confirmed problems are resolved; if verification is blocked, report the limitation and do not claim full verification. The primary agent handles small fixes directly; a separate implementer is only needed for a bounded subtask.
- Counter-agents receive equally small, precise tasks and follow the same model priority. Do not ask subagents to spawn further agents: the primary agent coordinates implementers and fresh independent reviews. Delegation does not expand permissions to modify or deploy; these rules apply to active technical work and do not authorize reviving archived projects.
