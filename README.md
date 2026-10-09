# StatusTick agent

The agent runs checks inside your network for [StatusTick](https://statustick.com) private locations: HTTP, TCP, ping, DNS, TLS certificates, gRPC, SMTP, IMAP, MCP servers, PostgreSQL, MySQL, Redis, MongoDB and Playwright browser checks.

It only connects out, over HTTPS to `agent.statustick.com`. It opens no port unless you turn one on, and it sends back check results, not response bodies or page content.

- Install, settings and troubleshooting: [docs/agent.md](docs/agent.md)
- What leaves your network: [docs/agent-security.md](docs/agent-security.md)
- Kubernetes: [the Helm chart](charts/statustick-agent/README.md)
- Changes: [CHANGELOG.md](CHANGELOG.md)

## Run it

Add an agent to a private location in StatusTick, then run the command it gives you:

```bash
docker run -d --name statustick-agent --restart unless-stopped --shm-size 512m \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  -e STATUSTICK_TOKEN="<your agent token>" \
  -e STATUSTICK_INSTALL=docker \
  ghcr.io/statustick/agent:1
```

The image is built for `linux/amd64` and `linux/arm64` and includes Chromium for browser checks.

If you don't need browser checks, you can run the static binary instead. Download it from a [release](https://github.com/statustick/agent/releases) and check it against `SHA256SUMS`:

```bash
STATUSTICK_TOKEN="<your agent token>" ./statustick-agent
./statustick-agent doctor
```

## Verify the image

Images are signed with cosign by the `Release` workflow and come with an SBOM and build provenance:

```bash
cosign verify ghcr.io/statustick/agent:X.Y.Z \
  --certificate-identity 'https://github.com/statustick/agent/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Layout

- `crates/agent`: the agent binary.
- `crates/checks`: the check engine and the rules for which targets a check may reach. StatusTick's public locations use the same crate.
- `crates/browser`: one browser check run.
- `sandbox/`: the Playwright process that runs a browser script. The only JavaScript in the repository.
- `charts/statustick-agent`: the Helm chart.
- `scripts/`: image checks that CI runs.

## Build and test

You need Rust stable, Node 24 for the sandbox, and Docker for the image.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
(cd sandbox && npm ci --ignore-scripts && npm run typecheck && npm test)
docker build -t statustick-agent:dev .
```

## Releases

Releases are made by [release-please](https://github.com/googleapis/release-please) from the pull request titles on `main` (see [CONTRIBUTING.md](CONTRIBUTING.md)). The agent and the chart have their own versions:

| Tag | What is published |
| -- | -- |
| `agent-vX.Y.Z` | `ghcr.io/statustick/agent` with tags `X.Y.Z`, `X.Y`, `X` and `latest`; static binaries on the GitHub release |
| `chart-vX.Y.Z` | `oci://ghcr.io/statustick/charts/statustick-agent` |

The agent talks to StatusTick through [agent protocol v1](docs/agent-protocol.md). StatusTick itself is not open source.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
