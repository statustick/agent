# StatusTick agent

Runs checks inside your network for [StatusTick](https://statustick.com) private locations: HTTP, TCP, ping, DNS,
TLS certificates, gRPC, SMTP, IMAP, MCP, PostgreSQL, MySQL, Redis, MongoDB and Playwright browser checks. It only
connects out, over HTTPS to `agent.statustick.com`, and sends back results, never response bodies or page content.

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

Without browser checks, the static binary from a [release](https://github.com/statustick/agent/releases) works too
(check it against `SHA256SUMS`):

```bash
STATUSTICK_TOKEN="<your agent token>" ./statustick-agent
./statustick-agent doctor
```

## Verify the image

Images are signed with cosign by the `Release` workflow:

```bash
cosign verify ghcr.io/statustick/agent:X.Y.Z \
  --certificate-identity 'https://github.com/statustick/agent/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Layout

| Path | |
| -- | -- |
| `crates/agent` | The agent binary |
| `crates/checks` | Check engine and target rules, shared with StatusTick's public locations |
| `crates/browser` | One browser check run |
| `sandbox/` | The Playwright process for a browser script; the only JavaScript here |
| `charts/statustick-agent` | Helm chart |
| `scripts/` | Image checks run in CI |

## Build and test

Rust stable, Node 24 for the sandbox, Docker for the image.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
(cd sandbox && npm ci --ignore-scripts && npm run typecheck && npm test)
docker build -t statustick-agent:dev .
```

## Releases

release-please builds the changelog from pull request titles on `main` ([CONTRIBUTING.md](CONTRIBUTING.md)) and keeps
a release pull request open. Merging it tags and publishes:

| Tag | Published |
| -- | -- |
| `agent-vX.Y.Z` | `ghcr.io/statustick/agent` (`X.Y.Z`, `X.Y`, `X`, `latest`) for amd64 and arm64, scanned with Trivy, signed, with SBOM and provenance; static binaries and `SHA256SUMS` on the release |
| `chart-vX.Y.Z` | `oci://ghcr.io/statustick/charts/statustick-agent` |

Release pull requests get no CI run; maintainers merge them with the admin bypass. To republish a released image,
run the `Release` workflow by hand with its version.

The agent talks to StatusTick through [agent protocol v1](docs/agent-protocol.md). StatusTick itself is not open source.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
