# Agent protocol v1

How an agent gets checks from StatusTick and sends back results. The agent makes HTTPS calls to `https://agent.statustick.com`. StatusTick never calls the agent.

All bodies are JSON unless stated otherwise. Times are ISO-8601 instants and durations are milliseconds.

## Requests

| Header | Value |
| -- | -- |
| `Authorization` | `Bearer sta_live_…`, the agent's own token |
| `Agent-Version` | The agent's version, for example `1.0.1` |
| `Agent-Id` | The `agentId` from connect. On every call except connect |
| `Agent-Session` | The `sessionId` from the latest connect. On every call except connect |

`GET /health` needs no headers and answers `200 ok`. Use it to test the network path without a token.

## Errors

Errors look like `{"error": "<code>", "message": "…"}`. `message` is optional.

| Status | `error` | What the agent should do |
| -- | -- | -- |
| 401 | `token.unauthorized` | The token is wrong or its agent was removed. Retry with backoff |
| 401 | `token.rotated` | The token was rotated and its 60 minutes ran out. Log `message`, retry with backoff |
| 401 | `token.revoked` | The token was revoked. Log `message`, retry with backoff |
| 401 | `agent.unauthorized` | Unknown `Agent-Id` or ended session. Connect again |
| 409 | `agent.replaced` | Another machine connected with the same token. Stop, and do not connect again on your own |
| 426 | `agent.update_required` | The version is too old. The body has `minimumVersion`. Stop polling |
| 429 | `rate_limited` | Wait `Retry-After` seconds |
| 413 | `payload_too_large` | The body is over 256 KB, or over 20 MB for an artifact |
| 503 | `unavailable` | Retry with backoff |

## Connect

`POST /v1/connect` at start, and again after `agent.unauthorized`.

```json
{
  "hostName": "office-pi", "os": "linux", "arch": "arm64",
  "startedAt": "2026-10-03T10:00:00.000Z", "installType": "docker",
  "memoryLimitBytes": 2147483648, "memoryLimited": true, "shmBytes": 536870912, "cpuCount": 2,
  "chromium": "off",
  "capabilities": {"browser": {"playwright": "1.63.0", "chromium": "153.0.8010.12", "concurrency": 2}, "relay": true},
  "envSettings": ["STATUSTICK_CONCURRENCY"],
  "applied": {"browserConcurrency": 2, "concurrency": 10, "shareMetrics": false},
  "buffering": {"count": 120, "since": "2026-09-29T11:20:00Z"}
}
```

Every field is optional.

- `capabilities.browser` says the agent can run browser checks. Without it, the agent gets no browser jobs.
- `capabilities.relay` says the heartbeat relay is on.
- `envSettings` names the settings that are set on the machine. `applied` holds the values the agent runs with.
- `buffering` says the agent has results from a time StatusTick was unreachable and will upload them now.
- `shareMetrics` is `true` or `false` when `STATUSTICK_SHARE_METRICS` is set.

Answer:

```json
{
  "agentId": "agt_4Q1bX9mVZp0cN7sYh2kLtE",
  "sessionId": "0199a0b0-6c1e-7a3b-9f2d-4e5c6b7a8d90",
  "location": {"id": "loc_2hF8sKq0VnB5xR1mPz7dWc", "name": "Office"},
  "config": {"leaseSeconds": 60, "maxJobs": 20, "pollWaitSeconds": 25, "heartbeatSeconds": 30},
  "minimumVersion": "1.0.0",
  "recommendedVersion": "1.2.0",
  "upcomingMinimum": {"version": "1.1.0", "from": "2026-12-01T00:00:00Z"},
  "shareMetrics": false,
  "settings": {"browserRuns": 1, "maxChecks": 10, "paused": false, "shareHealth": false}
}
```

- Each connect starts a new session. If a second connect arrives with the same token, the older session gets `409 agent.replaced`.
- `recommendedVersion` and `upcomingMinimum` may be missing or null. The agent logs a notice when it is older than either.
- `relay` is added when the agent reported `capabilities.relay` (see [Heartbeat relay](#heartbeat-relay)).

### Settings

`settings` is in every connect and `GET /v1/jobs` answer, so changes in the dashboard reach the agent within one poll.

| Field | Values | Variable on the machine |
| -- | -- | -- |
| `browserRuns` | 0 (off) to 8, default 1 | `BROWSER_CONCURRENCY` |
| `maxChecks` | 1 to 50, default 5 | `STATUSTICK_CONCURRENCY` |
| `paused` | `true`: stay connected, get no jobs | none |
| `shareHealth` | `true`: push metrics | `STATUSTICK_SHARE_METRICS` |

A variable set on the machine wins. For those settings the answer repeats the value from `applied`.

`GET /v1/settings`, with only `Authorization` and `Agent-Version`, returns `{"agentId": "…", "settings": {…}}` without connecting. `doctor` uses it.

## Get jobs

`GET /v1/jobs?wait=25&max=10` is a long-poll. It answers as soon as a job is due, or after `wait` seconds (at most 30) with no jobs. `max` is at most 20. With the relay on, the agent adds `relay=<version>`.

```json
{
  "jobs": [
    {
      "leaseId": "0192f3a1-7c2e-7b0a-9d41-5e8f1c2b3a4d",
      "expiresAt": "2026-09-29T12:01:00Z",
      "type": "http",
      "schedule": {"monitorId": "mnt_7Qk2…", "intervalSeconds": 60},
      "check": {
        "url": "https://intranet.example.com/health", "method": "GET", "timeout": 10000,
        "expectedStatus": null, "expectedText": "ok", "textMode": "contains", "caseSensitive": true,
        "headers": {}, "body": null, "bodyType": "RAW", "followRedirects": true, "ipVersion": null,
        "expectedHeaders": {"content-type": "application/json"},
        "json": [{"path": "$.status", "equals": "ok"}]
      }
    }
  ],
  "shareMetrics": false,
  "settings": {"browserRuns": 1, "maxChecks": 10, "paused": false, "shareHealth": false}
}
```

A lease lasts 60 seconds, or 180 seconds for a browser job. `schedule` is what the agent repeats while StatusTick is unreachable. It is missing for browser and `ssl` jobs.

| `type` | `check` fields |
| -- | -- |
| `http` | as above, plus `assets` (`{"ignoreHosts": [...]}`) |
| `tcp` | `host`, `port`, `timeout`, `ipVersion` |
| `ping` | `host`, `timeout`, `count`, `ipVersion` |
| `dns` | `hostname`, `recordType` (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`), `timeout`, `expectedIP`, `expectedValue` |
| `ssl` | `host`, `port`, `timeout` |
| `mcp` | `url`, `timeout`, `authHeaderName`, `authHeaderValue` |
| `grpc` | `host`, `port`, `timeout`, `service`, `tlsMode` (`NONE` or `TLS`), `tlsVerify`, `ipVersion` |
| `smtp`, `imap` | `host`, `port`, `timeout`, `tlsMode` (`NONE`, `STARTTLS` or `TLS`), `tlsVerify`, `requireStartTLS`, `ipVersion` |
| `postgres`, `mysql`, `redis`, `mongodb` | `host`, `port`, `database`, `user`, `password`, `userEnv`, `passwordEnv`, `tls`, `tlsVerify`, `query`, `expectedValue`, `timeout` |
| `browser` | `script`, `language` (`typescript` or `javascript`), `variables`, `allowedHosts` |

`ipVersion` is `"4"`, `"6"` or null. Fields not in this table are dropped by the agent.

- `userEnv` and `passwordEnv` name variables on the agent. Only names that start with `STATUSTICK_SECRET_` are allowed.
- `authHeaderValue`, `password` and browser `variables` are sent in clear text over TLS. The agent never writes them to disk or logs.
- A browser job only goes to an agent that reported `capabilities.browser`, and never more at once than its `concurrency`.

## Upload browser artifacts

Before posting a browser result, the agent uploads the run's files with `PUT /v1/leases/{leaseId}/artifacts/{name}`. `name` is `screenshot.png` (`image/png`) or `trace.zip` (`application/zip`). The body is the raw file, at most 20 MB. The answer is `204`. A failed upload does not block the result.

## Post results

`POST /v1/results` with up to 20 results:

```json
{
  "results": [
    {"leaseId": "0192f3a1-…", "result": {"status": "up", "responseTime": 84, "httpStatus": 200, "details": {"textMatch": true, "headerMismatch": null}}}
  ]
}
```

Answer:

```json
{"accepted": ["0192f3a1-…"], "rejected": [{"leaseId": "0192f3a0-…", "reason": "lease.expired"}]}
```

`reason` is `lease.expired`, `lease.unknown` or `result.invalid`. Rejected results are not sent again.

Every result has `status` (`up`, `down`, `blocked` or `error`), `responseTime` (0 to 600000), and optionally `error` (at most 2000 characters), `errorCode` and `details`. Other fields by type:

| `type` | Fields |
| -- | -- |
| `http` | `httpStatus`, `errorType`; `details.textMatch`, `details.headerMismatch`, `details.assets`, `details.legacyTLS`, `details.tlsVersion`, `details.weakKey` |
| `tcp` | `errorCode` |
| `ping` | `packetLoss`; `details.alive`, `min`, `max`, `avg`, `stddev`, and `method`, `note` when a TCP connection stood in for ICMP |
| `dns` | `records`, `recordCount`, `errorCode` |
| `ssl` | `errorCode`, `legacyTLS`, `tlsVersion`, `weakKey`, and `certificate`: `valid`, `error`, `validFrom`, `validTo`, `daysLeft`, `lifetimeDays`, `issuer`, `subject` |
| `mcp` | `details.protocolVersion`, `serverName`, `serverVersion`, `toolCount`, `toolsHash`, `initializeTime`, `toolsListTime` |
| `grpc`, `smtp`, `imap` | `details.servingStatus`, `grpcStatus`, `greetingCode`, `startTLSOffered`, `tlsVersion`, `certificateExpiresAt`, `certificateDaysLeft` |
| databases | `details.connectTime`, `authTime`, `queryTime`, and `value` when the job has `expectedValue` |
| `browser` | `browser`: `status`, `durationMs`, `failedStep`, `error`, `tests`, `webVitals`, `playwright`, `artifacts` |

Response bodies and header values are never sent. The agent compares `expectedHeaders` itself: `headerMismatch` is null when all match, otherwise `{"name": "…", "reason": "missing" | "different"}`, and the check is `down`. JSON assertions also run on the agent. A failed one is `down` with an error that names the path, not the value.

## Late results

If StatusTick was unreachable, the agent repeats each monitor's last job on its `schedule` for up to an hour and keeps the results. After it connects again, it sends them oldest first with `POST /v1/results/late`, up to 500 per call:

```json
{
  "results": [
    {"monitorId": "mnt_7Qk2…", "checkedAt": "2026-09-29T11:20:00Z", "result": {"status": "down", "responseTime": 5000, "error": "Connection timeout"}}
  ],
  "dropped": 0,
  "bufferedSince": "2026-09-29T11:20:00Z"
}
```

`dropped` counts results the full buffer dropped. The answer refers to results by index: `{"accepted": [0, 2], "rejected": [{"index": 1, "reason": "result.too_old"}]}`. `reason` is `monitor.unknown`, `result.too_old` (more than 2 hours ago) or `result.invalid`. The agent removes accepted and rejected results and sends the rest again. Sending a result twice stores it once.

## Heartbeat relay

The relay lets jobs without internet access ping the agent, which forwards the pings.

**Ping list.** The connect answer for an agent with `capabilities.relay` contains `"relay": {"version": "…", "pingHashes": ["…"]}`. `pingHashes` are the SHA-256 hashes (lower-case hex) of the ping tokens of the organization's heartbeat monitors, at most 20,000. `version` changes when the list changes. The agent sends its version with `GET /v1/jobs?relay=<version>`. The answer includes `relay` only when the version is different.

**Upload.** `POST /v1/heartbeats/relay` with up to 500 pings, oldest first:

```json
{
  "pings": [
    {"pingId": "<token>", "kind": "start", "at": "2026-10-01T12:00:00.000Z", "run": "nightly-42"},
    {"pingId": "<token>", "kind": "ping", "at": "2026-10-01T12:03:12.512Z", "run": "nightly-42"}
  ],
  "dropped": 0
}
```

`kind` is `ping`, `start` or `fail`. `at` is when the ping reached the agent. `run` is optional. The answer refers to pings by index, like late results. `reason` is `ping.unknown`, `ping.invalid` or `ping.too_old` (more than 2 hours ago).

## Kubernetes service discovery

An agent with discovery on sends the full set of annotated Services with `PUT /v1/discovery/kubernetes`, a few seconds after a change and every 5 minutes. Up to 500 monitors, sorted by key:

```json
{
  "monitors": [
    {"key": "shop/api", "type": "http", "target": "http://api.shop.svc:8080/healthz", "name": "Shop API", "intervalSeconds": 60},
    {"key": "data/postgres", "type": "tcp", "target": "postgres.data.svc:5432", "name": "data/postgres", "intervalSeconds": 300}
  ]
}
```

`key` is `<namespace>/<service>`. `type` is `http` or `tcp`. `target` must point at the key's own Service. `intervalSeconds` is 30 to 86400.

```json
{
  "created": ["shop/api"], "updated": [], "paused": ["shop/old"], "resumed": [],
  "skipped": [{"key": "shop/web", "reason": "discovery.limit_reached", "message": "This location runs at most 100 discovered monitors"}],
  "limit": 100,
  "busy": false
}
```

`reason` is `discovery.limit_reached`, `plan.limit_reached` or `monitor.invalid`. `busy: true` means another agent of the location was sending its set; the agent tries again after 15 seconds.

## Heartbeat

`POST /v1/heartbeat` with no body when the agent made no other call for `heartbeatSeconds`. When its Chromium state changes, the agent sends `{"chromium": "off" | "starting" | "ready" | "failed"}` at once. The answer is `204`.

A location is offline when none of its agents made a call for 3 minutes.

## Goodbye

`POST /v1/goodbye` with `{"reason": "stopping"}` when the agent stops cleanly, or `{"reason": "updating"}`. The answer is `204`, and the session ends. The agent sends no goodbye after `agent.replaced` or a refused token.

## Metrics

Only when sharing is on (`shareMetrics: true` in the answers), the agent sends `POST /v1/agent/metrics` every 60 seconds. The body is a snapshot in the Prometheus text format (`Content-Type: text/plain`), at most 64 KB. The answer is `200 {"kept": 18, "dropped": 0}`, or `403` when sharing is off.

StatusTick keeps only the metric names listed in [the agent guide](agent.md#metrics) and the process CPU and memory metrics. It drops any other name or label.

## Versions

| Field | Meaning |
| -- | -- |
| `minimumVersion` | Older agents get `426` on every call |
| `recommendedVersion` | Older agents still work; the dashboard shows "Update available" |
| `upcomingMinimum` | A minimum that applies from `from` |

## Limits

120 requests a minute per token and 600 per client address. A normal agent makes about 3 calls a minute, plus one per batch of results. Metrics pushes are limited separately: one per token every 30 seconds.
