# Maintainer notes

For people who build and release the agent. What customers need is in [agent.md](agent.md).

## Publish a release

Releases are made by release-please (see "Release" in the README); nobody pushes a tag by hand. When the release pull request is merged, the `Release` workflow tags `agent-vX.Y.Z` and, in the same run:

- scans the image with Trivy (any critical finding stops the release), then publishes `X.Y.Z`, `X.Y`, `X` and `latest` for both architectures to `ghcr.io/statustick/agent` (repository variable `AGENT_IMAGE` to change it), with an SBOM and provenance, and signs them with cosign;
- builds the static binaries and attaches `statustick-agent-linux-amd64.tar.gz`, `statustick-agent-linux-arm64.tar.gz` and `SHA256SUMS` to the GitHub release;
- for a chart release (`chart-vX.Y.Z`), pushes the chart to `oci://ghcr.io/statustick/charts` (repository variable `CHART_REGISTRY`).

## Heartbeat relay: platform contract (agent protocol v1)

What StatusTick implements for the relay (the whole protocol: [agent-protocol.md](agent-protocol.md)):

1. **Capability.** An agent with the relay on sends `capabilities.relay: true` in `POST /v1/connect`.
2. **Ping list.** The connect answer to such an agent carries `relay: {version, pingHashes}`: `pingHashes` is the lowercase hex SHA-256 of the UTF-8 ping token (the `<token>` in `/v1/ping/<token>`) of every heartbeat monitor of the token's organization, paused ones included (so their jobs do not get `404`), at most 20,000; `version` is an opaque string of at most 128 characters that changes whenever the set changes. An empty `pingHashes` is a valid list (the relay answers `404` to every ping). Until a list arrives the relay answers `503`.
3. **Changes.** While the relay is on, the agent adds `relay=<version>` to `GET /v1/jobs` (an empty value before it has a list). The lease answer carries `relay: {version, pingHashes}` only when the organization's current version differs; otherwise it leaves `relay` out. The agent keeps its list across disconnects and restarts (with `STATUSTICK_BUFFER_DIR`) and replaces it only with a list of another version.
4. **Upload.** `POST /v1/heartbeats/relay` with the agent's usual headers (`Authorization: Bearer <agent token>`, `Agent-Id`, `Agent-Version`), same rate limit and body limit as `POST /v1/results/late`:

   ```json
   {
     "pings": [
       { "pingId": "<token>", "kind": "start", "at": "2026-10-01T12:00:00.000Z", "run": "nightly-42" },
       { "pingId": "<token>", "kind": "ping", "at": "2026-10-01T12:03:12.512Z", "run": "nightly-42" }
     ],
     "dropped": 0
   }
   ```

   At most 500 pings, oldest first. `pingId` is the token as the job sent it; `kind` is `ping` (`/ping/<token>`, the public URL's success), `start` or `fail`; `at` is when the ping arrived at the agent (ISO-8601); `run` (only when the job sent one) is the ping URL's `run` query parameter, 1 to 64 of `[A-Za-z0-9_-]`, checked by the relay. `dropped` counts pings the full buffer dropped since it was last empty. There is no exit code or body: the public URL has neither.
5. **Answer.** `200` with each ping by its index: `{"accepted": [0, 1], "rejected": [{"index": 2, "reason": "ping.unknown"}]}`. Reasons: `ping.unknown` (no heartbeat monitor of the token's organization has this token; never forward it as a public ping), `ping.invalid` (bad `kind`, `at` or `run`), `ping.too_old` (`at` older than the platform accepts, suggested 2 hours like late results; `at` up to a minute ahead is clamped to now). An accepted ping counts like a public one, at `at`. Pings missing from both lists are sent again later. `401`, `429` and `5xx` make the agent retry with backoff; any other error status stops uploads until the agent connects again, and the pings stay buffered.
