# StatusTick agent

The StatusTick agent checks services inside your network for [StatusTick](https://statustick.com) private locations: HTTP(S), TCP, ping, DNS, TLS certificates, gRPC health, SMTP, IMAP, MCP servers, PostgreSQL, MySQL, Redis and MongoDB, and Playwright browser checks. One image runs them all: browser checks need no extra install. It only makes outbound HTTPS calls to `agent.statustick.com`, opens no port (unless you turn on the health port for Kubernetes probes or the internal heartbeat relay), and sends back check results and relayed heartbeat pings only.

- Metrics, and sharing agent health with StatusTick: "Metrics" in [docs/agent.md](docs/agent.md)
- Install, settings, updates and troubleshooting: [docs/agent.md](docs/agent.md) and [statustick.com/docs/private-agents](https://statustick.com/docs/private-agents)
- Threat model and what leaves your network: [docs/agent-security.md](docs/agent-security.md)
- Kubernetes: the Helm chart in [charts/statustick-agent](charts/statustick-agent/README.md)
- Releases: [CHANGELOG.md](CHANGELOG.md)

## Run it

```bash
docker run -d --name statustick-agent --restart unless-stopped --shm-size 512m \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  -e STATUSTICK_TOKEN="<your agent token>" \
  -e STATUSTICK_INSTALL=docker \
  ghcr.io/statustick/agent:1
```

The image (`linux/amd64`, `linux/arm64`) has Chromium and the pinned Playwright runner: about 330 MB to download and 1.2 GB on disk. Chromium runs only while a browser check runs.

Without browser checks, the agent is one static binary. Download `statustick-agent-linux-<arch>.tar.gz` from a [release](https://github.com/statustick/agent/releases), check it against `SHA256SUMS`, and run it:

```bash
STATUSTICK_TOKEN="<your agent token>" ./statustick-agent
./statustick-agent doctor   # checks the token, DNS and the connection to StatusTick
```

## Verify the image

Images are signed with cosign (keyless) by this repository's `Release` workflow on `main`, and carry an SBOM and build provenance:

```bash
cosign verify ghcr.io/statustick/agent:X.Y.Z \
  --certificate-identity 'https://github.com/statustick/agent/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Layout

- `crates/agent/` (`statustick-agent`): the agent. `agent/` is the long-poll loop, `client.rs` agent protocol v1 ([docs/agent-protocol.md](docs/agent-protocol.md)), `schema.rs` the fixed job schema and the result fields that may leave the network, `jobs.rs` runs a leased job, `settings.rs` reads the `STATUSTICK_*` settings.
- `crates/checks/` (`statustick-checks`): the check engine (HTTP, TCP, ping, DNS, certificates, gRPC, mail, MCP) and the target rules (`targets.rs`). StatusTick's public check regions run the same crate, so a check gives the same result from a region and from an agent.
- `crates/browser/` (`statustick-browser`): one browser run: the script rules, the sandbox process and the result.
- `sandbox/`: the Playwright process of each browser run, its guard and its egress proxy, copied into the image's `/runner`. The only JavaScript in the repository.
- `charts/statustick-agent/`: the Helm chart. Has its own README.
- `docs/`: [agent.md](docs/agent.md) (install, settings, troubleshooting), [agent-protocol.md](docs/agent-protocol.md), [agent-security.md](docs/agent-security.md) (threat model) and [maintainers.md](docs/maintainers.md).
- `scripts/`: image checks for CI: resource budget, browser-run isolation, zombie processes.
- `Dockerfile`: the agent image; `--target binary-export` builds the static binaries.

## Build and test

Rust stable, Node 24 for the sandbox, Docker for the image.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
(cd sandbox && npm ci --ignore-scripts && npm run typecheck && npm test)
STATUSTICK_TOKEN=<agent token> cargo run -p statustick-agent
docker build -t statustick-agent:dev . && scripts/agent-budget.sh statustick-agent:dev
```

The other `STATUSTICK_*` settings are in [docs/agent.md](docs/agent.md).

## Release

Releases are made by [release-please](https://github.com/googleapis/release-please) from the [Conventional Commits](CONTRIBUTING.md#commits) on `main`; nobody sets versions or pushes tags by hand. Two components have their own version, tag and changelog:

| Component | Tag | Published |
| -- | -- | -- |
| The agent (everything outside `charts/`) | `agent-vX.Y.Z` | `ghcr.io/statustick/agent` (`X.Y.Z`, `X.Y`, `X`, `latest`) for amd64 and arm64 with an SBOM, provenance and a cosign signature; static binaries and `SHA256SUMS` on the GitHub release |
| The Helm chart | `chart-vX.Y.Z` | `oci://ghcr.io/statustick/charts/statustick-agent` |

On every push to `main` the `Release` workflow keeps one release pull request open with the next versions and the changelog. Merging it tags the releases, creates the GitHub releases with the same notes as `CHANGELOG.md`, and publishes them. An agent release also sets `appVersion` in `Chart.yaml`.

The agent talks to StatusTick only through agent protocol v1. StatusTick itself is not open source.

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
