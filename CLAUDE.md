# CLAUDE.md

The StatusTick private-location agent in Rust, its Docker image, the browser sandbox and the Helm chart. Do not describe features in CLAUDE.md.

## Commands

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
STATUSTICK_TOKEN=… cargo run -p statustick-agent          # `-- doctor` checks the setup
(cd sandbox && npm ci --ignore-scripts && npm run typecheck && npm test)
docker build -t statustick-agent:dev .
```

- `UPDATE_DOCS=1 cargo test -p statustick-agent docs` rewrites the generated tables in `docs/agent.md` and the chart README; `cargo test` fails while they are out of date.
- `CONTRACT_DATABASES=postgres=…,redis=…,mongodb=…` adds real database servers to the contract tests (`crates/agent/tests/contract.rs`).
- `scripts/agent-budget.sh <image>` checks the image budget (size, user, no port, idle CPU and memory); `scripts/agent-zombies.sh <image>` fails on zombie processes after browser runs; `scripts/agent-isolation.sh <image>` checks browser-run isolation with the install command's capabilities.
- Chart: `helm lint --strict charts/statustick-agent --set existingSecret.name=statustick-agent`.

## Architecture

- Cargo workspace: `crates/agent` (the binary), `crates/checks` (check engine and target rules), `crates/browser` (one browser run). The crates stay self-contained (no workspace inheritance): StatusTick's drones vendor `crates/checks`, `crates/browser` and `sandbox/`.
- `crates/agent/src/`: `agent/` (long-poll loop, protocol v1 in `docs/agent-protocol.md`, `client.rs`), `jobs.rs`, `schema.rs` (job schema, result fields), `database/`, `browser/`, `buffer.rs`, `relay.rs`, `kubernetes.rs`, `metrics.rs`, `doctor.rs`, `settings.rs` (the only reader of `STATUSTICK_*`). Threat model: `docs/agent-security.md`.
- `crates/checks/src/targets.rs` is the SSRF guard: push-mode regions refuse internal and metadata addresses (`ALLOWED_INTERNAL_HOSTS` only for local test stacks). The agent sets its own policy at start.
- `sandbox/` is the Playwright process of each browser run (`run.mts`, `guard.cts`, `proxy.mts`, `vitals.cts`); the image copies it to `/runner`. Its `package.json` pins Playwright and names the Chromium version (`crates/browser/build.rs` reads both).
- `charts/statustick-agent/`: Helm chart, one agent per release. Probes use `STATUSTICK_HEALTH_PORT`.

## Rules

Customer scripts and checks:
- Never give a browser script the agent's environment. `sandbox/run.mts` builds it from scratch: `PATH`, `HOME`, `TMPDIR`, the run's own variables and a few `ST_*` settings.
- Never widen what a browser run may read, write, connect to or start. Its network goes only through the run's proxy; no listening, UDP, DNS or extra processes.

Agent:
- Outbound only: HTTPS to `agent.statustick.com` and the checks it is given. No port unless `STATUSTICK_HEALTH_PORT` or `STATUSTICK_RELAY_PORT` is set. Never expose the relay to the internet.
- Jobs are data: a field outside `schema.rs` is dropped and no field runs as code or a shell command.
- Shared agent health leaves the network only while the customer shares it, and only the names in `SHARED_METRICS` (`metrics.rs`); a new one goes into `SHARED_METRICS`, `docs/agent-security.md` and StatusTick's accepted names (`docs/agent-protocol.md`), with labels from fixed sets only.
- Only the result fields in `schema.rs` leave the network. Never a response body, header value, cookie, query result, MCP tool description or schema, or server text. A new result field goes into `schema.rs` and `docs/agent-security.md`.
- Database passwords come from `STATUSTICK_SECRET_*` variables only. Never write them or an MCP `authHeaderValue` to `jobs.json`, logs or results.
- Change `crates/checks/src/targets.rs` only in a change of its own.
- This repository is public: no internal hosts, infrastructure, tracker links, ticket ids or service internals in its files or commit messages.

## Gotchas

- The agent version is `version.txt`; release-please sets it and `appVersion` in `Chart.yaml` (`x-release-please-version`). `crates/agent/build.rs` compiles it in.
- Playwright is pinned in `sandbox/package.json` (with the `chromium` field); the image installs that Chromium. No busybox in the image: CI and scripts use `node -e` instead of `wget`.

## Workflow

- Pull requests are squash-merged; the title is a Conventional Commit (`feat(checks): …`, `fix: …`), checked by CI, and becomes one changelog line. Never a ticket id. See CONTRIBUTING.md.
- Releases only through release-please (`.github/workflows/release.yml`). Never push tags (`agent-v*`, `chart-v*`) or edit versions and changelogs by hand.
- No secrets in the repo.
