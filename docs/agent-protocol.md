# Agent protocol v1

The agent calls `https://agent.statustick.com`; StatusTick never calls the agent. Bodies are JSON unless noted,
times are ISO-8601, durations milliseconds. `GET /health` answers `200 ok` without headers.

| Header | Value |
| -- | -- |
| `Authorization` | `Bearer sta_live_…` |
| `Agent-Version` | For example `1.0.1` |
| `Agent-Id`, `Agent-Session` | From connect; on every later call |

## Errors

`{"error": "<code>", "message": "…"}`:

| Status | `error` | Agent action |
| -- | -- | -- |
| 401 | `token.unauthorized`, `token.rotated`, `token.revoked` | Log, retry with backoff |
| 401 | `agent.unauthorized` | Connect again |
| 409 | `agent.replaced` | Stop; don't reconnect on its own |
| 426 | `agent.update_required` | Stop polling (`minimumVersion` in the body) |
| 429 | `rate_limited` | Wait `Retry-After` |
| 413 | `payload_too_large` | Over 256 KB (20 MB for an artifact) |
| 503 | `unavailable` | Retry with backoff |

## Connect

`POST /v1/connect` at start and after `agent.unauthorized`. All fields optional: `hostName`, `os`, `arch`,
`startedAt`, `installType`, `memoryLimitBytes`, `memoryLimited`, `shmBytes`, `cpuCount`, `chromium`,
`capabilities` (`browser: {playwright, chromium, concurrency}` to get browser jobs, `relay: true`), `envSettings`
(names set on the machine), `applied` (values in use), `buffering` (`{count, since}` of late results to upload).

The answer has `agentId`, `sessionId`, `location {id, name}`, `config {leaseSeconds, maxJobs, pollWaitSeconds,
heartbeatSeconds}`, `minimumVersion`, `recommendedVersion`, `upcomingMinimum {version, from}`, `shareMetrics`,
`settings` and, for relay agents, `relay`. A second connect with the same token ends the older session with
`409 agent.replaced`.

`settings` (also in every jobs answer): `browserRuns` (0–8), `maxChecks` (1–50), `paused`, `shareHealth`. A
variable on the machine wins. `GET /v1/settings` (only `Authorization` and `Agent-Version`) returns them without
connecting.

## Jobs

`GET /v1/jobs?wait=25&max=10` long-polls up to `wait` (max 30) seconds for at most `max` (20) jobs; relay agents add
`relay=<version>`. Each job has `leaseId`, `expiresAt` (60 s, 180 s for browser), `type`, `check` and `schedule
{monitorId, intervalSeconds}` (not for browser and `ssl`), used while offline.

| `type` | `check` fields |
| -- | -- |
| `http` | `url`, `method`, `timeout`, `expectedStatus`, `expectedText`, `textMode`, `caseSensitive`, `headers`, `body`, `bodyType`, `followRedirects`, `ipVersion`, `expectedHeaders`, `json`, `assets` |
| `tcp`, `ping` | `host`, `port` / `count`, `timeout`, `ipVersion` |
| `dns` | `hostname`, `recordType`, `timeout`, `expectedIP`, `expectedValue` |
| `ssl` | `host`, `port`, `timeout` |
| `mcp` | `url`, `timeout`, `authHeaderName`, `authHeaderValue` |
| `grpc` | `host`, `port`, `timeout`, `service`, `tlsMode`, `tlsVerify`, `ipVersion` |
| `smtp`, `imap` | `host`, `port`, `timeout`, `tlsMode`, `tlsVerify`, `requireStartTLS`, `ipVersion` |
| `postgres`, `mysql`, `redis`, `mongodb` | `host`, `port`, `database`, `user`, `password`, `userEnv`, `passwordEnv`, `tls`, `tlsVerify`, `query`, `expectedValue`, `timeout` |
| `browser` | `script`, `language`, `variables`, `allowedHosts` |

Other fields are dropped. `userEnv` and `passwordEnv` must name `STATUSTICK_SECRET_*` variables. Secrets arrive over
TLS and are never written to disk or logs.

## Results

Browser artifacts first: `PUT /v1/leases/{leaseId}/artifacts/{screenshot.png|trace.zip}`, raw body up to 20 MB,
`204`. A failed upload doesn't block the result.

`POST /v1/results` with up to 20 `{leaseId, result}`. The answer lists `accepted` lease ids and `rejected`
`{leaseId, reason}` (`lease.expired`, `lease.unknown`, `result.invalid`); rejected results are not resent.

A result has `status` (`up`, `down`, `blocked`, `error`), `responseTime` (0–600000) and optional `error` (2000
chars), `errorCode`, `details`. Per type:

| `type` | Fields |
| -- | -- |
| `http` | `httpStatus`, `errorType`; `details.textMatch`, `headerMismatch`, `assets`, `legacyTLS`, `tlsVersion`, `weakKey` |
| `ping` | `packetLoss`; `details.alive`, `min`, `max`, `avg`, `stddev`, `method`, `note` |
| `dns` | `records`, `recordCount`, `errorCode` |
| `ssl` | `errorCode`, `legacyTLS`, `tlsVersion`, `weakKey`, `certificate` |
| `mcp` | `details.protocolVersion`, `serverName`, `serverVersion`, `toolCount`, `toolsHash`, `initializeTime`, `toolsListTime` |
| `grpc`, `smtp`, `imap` | `details.servingStatus`, `grpcStatus`, `greetingCode`, `startTLSOffered`, `tlsVersion`, `certificateExpiresAt`, `certificateDaysLeft` |
| databases | `details.connectTime`, `authTime`, `queryTime`, `value` (only with `expectedValue`) |
| `browser` | `browser`: `status`, `durationMs`, `failedStep`, `error`, `tests`, `webVitals`, `playwright`, `artifacts` |

Bodies and header values are never sent. The agent compares `expectedHeaders` itself: `headerMismatch` is null or
`{name, reason: "missing" | "different"}`, and a mismatch makes the check `down`. JSON assertions run on the agent
too.

## Late results

While StatusTick is unreachable the agent repeats each `schedule` for up to an hour, then sends results oldest first
with `POST /v1/results/late` (up to 500): `{results: [{monitorId, checkedAt, result}], dropped, bufferedSince}`. The
answer refers to results by index: `accepted`, `rejected [{index, reason}]` with `monitor.unknown`,
`result.too_old` (over 2 hours) or `result.invalid`. Duplicates are stored once.

## Heartbeat relay

Connect answers for relay agents include `relay {version, pingHashes}`: lower-case hex SHA-256 of the organization's
heartbeat ping tokens (up to 20,000). Jobs answers include `relay` only when `version` changed.

`POST /v1/heartbeats/relay` with up to 500 `{pingId, kind: "ping" | "start" | "fail", at, run}`, oldest first, plus
`dropped`. Answer by index like late results; reasons `ping.unknown`, `ping.invalid`, `ping.too_old`.

## Kubernetes discovery

`PUT /v1/discovery/kubernetes` sends the whole set (up to 500, sorted by `key`) after a change and every 5 minutes:
`{monitors: [{key: "<namespace>/<service>", type: "http" | "tcp", target, name, intervalSeconds}]}`. The target must
be the key's own Service; interval 30–86400. The answer lists `created`, `updated`, `paused`, `resumed`, `skipped
[{key, reason, message}]` (`discovery.limit_reached`, `plan.limit_reached`, `monitor.invalid`), `limit` and `busy`
(another agent was sending; retry after 15 seconds).

## Heartbeat and goodbye

`POST /v1/heartbeat` (no body) after `heartbeatSeconds` without another call; `{"chromium": "off" | "starting" |
"ready" | "failed"}` when Chromium changes. A location is offline when no agent called for 3 minutes.
`POST /v1/goodbye` with `{"reason": "stopping" | "updating"}` ends the session; none after `agent.replaced` or a
refused token.

## Metrics

With sharing on, `POST /v1/agent/metrics` every 60 seconds: Prometheus text, at most 64 KB. Answer
`{"kept", "dropped"}`, or `403` when sharing is off. StatusTick keeps only the names in
[the agent guide](agent.md#metrics) and the process CPU and memory metrics.

## Versions and limits

Older than `minimumVersion`: `426` on every call. Older than `recommendedVersion`: works, shows "Update available".
`upcomingMinimum` applies from its `from`. 120 requests a minute per token, 600 per client address, one metrics push
per token every 30 seconds.
