# Agent protocol v1

How an agent in a customer network gets checks from StatusTick and sends back results. The agent only makes
outbound HTTPS calls to one host, `https://agent.statustick.com` (port 443). StatusTick never calls the agent; a firewall
needs to allow only `agent.statustick.com:443`.

The protocol is served only on `agent.statustick.com` (it answers 404 on `api.statustick.com`). Agent calls have their own
rate limits, apart from the page and API key limits.

## Reachability

`GET /health` needs no token and no headers and answers `200` with the body `ok`. `statustick-agent doctor` calls it
before it checks the token, so a firewall or proxy problem is told apart from a wrong token.

## Every request

| Header | Value |
| -- | -- |
| `Authorization` | `Bearer sta_live_…`, the agent's own token, issued once when an owner or admin adds the agent to a private location. The token names the agent; no other agent uses it. A rotated token works 60 more minutes; a revoked token, or the token of a removed agent, is refused on the next call (see "Token rotation") |
| `Agent-Version` | The agent's version, `major.minor.patch` (for example `1.0.0`) |
| `Agent-Id` | The `agentId` from connect; on every call except connect |
| `Agent-Session` | The `sessionId` from the latest connect; on every call except connect. Calls without it are still accepted for now |
| `Content-Type` | `application/json` on requests with a body; `image/png` or `application/zip` on an artifact upload |

Every accepted call counts as a heartbeat of the agent, except `GET /v1/settings`.

## Errors

Errors are JSON `{"error": "<code>"}`, some with a `message`, with these statuses:

| Status | `error` | What the agent does |
| -- | -- | -- |
| 401 | `token.unauthorized` | Token missing or wrong, or its agent was removed. Log "token rejected" and retry with backoff |
| 401 | `token.rotated` | The token was rotated and its 60-minute overlap ended. The body's `message` is "Token rotated; set the new STATUSTICK_TOKEN": log it, `doctor` prints it, retry with backoff |
| 401 | `token.revoked` | The token was revoked. Log the body's `message`, `doctor` prints it, retry with backoff |
| 401 | `agent.unauthorized` | `Agent-Id` is not the token's agent, or the agent never connected. Connect again |
| 409 | `agent.replaced` | Another connect with the same token started a newer session (see "Newest connection wins"). Log "another machine used this token" and stop; do not connect again by itself |
| 426 | `agent.update_required` | Version below the minimum, or below an upcoming minimum that is now enforced (see "Versions"). The body also has `message` and `minimumVersion`. Log "update required" and stop polling |
| 429 | `rate_limited` | Wait `Retry-After` seconds |
| 400 | `<field>.format.validation` | A malformed request |
| 404 | `lease.not_found` | Artifact upload for a lease the agent does not hold (unknown, answered or run out) |
| 413 | `payload_too_large` | Body over 256 KB (20 MB for an artifact upload) |
| 503 | `unavailable` | StatusTick side failed. Retry with backoff |

```json
HTTP/1.1 426 Upgrade Required
{"error": "agent.update_required", "message": "Agent version 0.9.0 is too old. Install version 1.0.0 or later.", "minimumVersion": "1.0.0"}
```

## 1. Connect

`POST /v1/connect` once at start and after `agent.unauthorized`. The token picks the agent: the answer always carries the
`agentId` of the agent the token was issued to, whatever host name it reports. `hostName`, `os`, `arch` and the version
are what the agent reports about its machine (shown as Host and Version); connecting again replaces them.

```json
{
  "hostName": "office-pi", "os": "linux", "arch": "arm64",
  "capabilities": {"browser": {"playwright": "1.63.0", "chromium": "153.0.8010.12", "concurrency": 2}},
  "startedAt": "2026-10-03T10:00:00.000Z", "installType": "docker",
  "memoryLimitBytes": 2147483648, "memoryLimited": true, "shmBytes": 536870912, "cpuCount": 2,
  "chromium": "off",
  "envSettings": ["STATUSTICK_CONCURRENCY"],
  "applied": {"browserConcurrency": 2, "concurrency": 10, "shareMetrics": false}
}
```

The machine fields are shown on the agent's page in the dashboard. All are optional: an agent that sends none of
them still connects, and a value out of range is dropped.

| Field | Meaning |
| -- | -- |
| `startedAt` | When the agent process started (ISO-8601), shown as "Running since". A connect with a new `startedAt` is a restart |
| `installType` | `docker`, `compose`, `helm` or `other` |
| `memoryLimitBytes`, `memoryLimited` | The container's memory limit; without one the machine's memory and `false` |
| `shmBytes` | The size of `/dev/shm`, `null` without one |
| `cpuCount` | The container's CPU quota rounded up, else the CPUs the agent may use |
| `chromium` | `off`, `starting`, `ready` or `failed`; later changes come by heartbeat (see "5. Heartbeat") |
| `envSettings` | Which of `BROWSER_CONCURRENCY`, `STATUSTICK_CONCURRENCY` and `STATUSTICK_SHARE_METRICS` are set on the machine, by name only; the dashboard shows them as locked. Other names are dropped |
| `applied` | The values the agent runs with for those three settings |

StatusTick also stores the address each connect came from (the client address behind its proxy), shown as "Connects
from".

`capabilities` is optional. `capabilities.browser` says the agent can run browser checks: its Playwright and
Chromium versions and how many runs it takes at once (1 to 8). There is one agent image, `ghcr.io/statustick/agent`,
with Chromium and the pinned Playwright runner (about 330 MB to download, 1.2 GB on disk), so every agent reports it and
browser checks need no extra install; an agent whose browser runs are 0 (`BROWSER_CONCURRENCY=0`) sends `null`.
Absent or `null`: no browser checks, and no browser job is ever handed to it. Connecting again replaces what was
reported before.

`capabilities.relay: true` says the agent's heartbeat relay is on (see "Heartbeat relay"); the answer then
carries `relay`, the organization's ping list.

`buffering` is optional: `{"count": 120, "since": "2026-09-29T11:20:00Z"}` when the agent checked results while
StatusTick was unreachable and will upload them now (see "Late results"); `since` is the oldest one's check time. An
agent that went offline connects again before anything else, so this reaches StatusTick first. When the location had
gone offline, its "back online" alert says how many results the agents that connected again buffered.

`shareMetrics` is optional: the install's `STATUSTICK_SHARE_METRICS` (`true` or `false`), absent when it is not set.
See "6. Metrics".

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

`os` and `arch` are lower case (`linux`, `arm64`, `amd64`). `recommendedVersion` is absent and `upcomingMinimum` null
while none is set; the agent compares its own version with them (see "Versions"). `relay` is absent unless the agent reported
`capabilities.relay`. `shareMetrics` says whether the agent pushes its metrics (see "6. Metrics"). `settings` are the
agent's settings (see "Settings").

### Settings

Owners and admins set four settings per agent in the dashboard. Every connect answer and every `GET /v1/jobs`
answer carries them as `settings`, so a change reaches a running agent with its next lease (within 30 seconds), without
a restart.

| Field | Meaning | Machine variable |
| -- | -- | -- |
| `browserRuns` | Browser runs at once, 0 (Off) to 8; default 1 | `BROWSER_CONCURRENCY` |
| `maxChecks` | Checks at once, 1 to 50; default 5 | `STATUSTICK_CONCURRENCY` |
| `paused` | Stay connected and send heartbeats, but get no jobs; default `false` | none |
| `shareHealth` | Push metrics (see "6. Metrics"); default `false` | `STATUSTICK_SHARE_METRICS` |

A value set on the agent's machine always wins. For a setting the agent reported in `envSettings` at connect, `settings`
carries the value it reported in `applied`, and the dashboard shows the setting as set on the machine and refuses to
change it (`422 setting.set_on_machine.unprocessable`). The agent applies the other values as they arrive.

A paused agent's `GET /v1/jobs` answers carry no jobs; the location's other agents take its checks. A location whose
only online agents are paused counts as offline for its monitors.

### Reading the settings without connecting

`GET /v1/settings` with `Authorization` and `Agent-Version` only (no `Agent-Id`, no `Agent-Session`) answers the
agent's settings as the dashboard sets them, for `doctor`, which never connects (a connect would replace the running
agent). It works for an agent that never connected and changes nothing: no heartbeat, no last seen, no session, no
token use. A wrong, rotated or revoked token is refused as on every call.

```json
{"agentId": "agt_7Hq2…", "settings": {"browserRuns": 4, "maxChecks": 5, "paused": false, "shareHealth": false}}
```

A value set on the doctor's machine (for example `BROWSER_CONCURRENCY`) still wins over the answer.

### Newest connection wins

Every connect answer carries a new `sessionId`; the agent sends it as `Agent-Session` on every later call. When a second
connect arrives with the same token (the token was copied to another machine, or a second replica runs), the newer
connection wins: calls with the older session get `409 agent.replaced`, and StatusTick logs the older connection as
ended with the reason "another machine used this token". Run one agent per token (one replica per Helm release).

### Token rotation

Every agent has its own token, so rotating one touches no other agent. On the agent's page an owner or admin:

- Rotate: a new token, shown once with the install commands. The old token keeps
  working for 60 minutes (`token.rotatingUntil`), then every call with it is `401 token.rotated`. Rotating again during
  that hour stops the earlier old token at once. The page shows when the new and the old token were last used; owners
  and admins get one email when the old token is still used in its last 10 minutes.
- End now: the old token stops at once.
- Revoke, for a leaked token: the current and any old token stop at once (`401
  token.revoked`), with no overlap. Rotate then issues a new token, also with no overlap.

To rotate many agents, rotate one at a time: rotate, set the new `STATUSTICK_TOKEN` on that machine, restart the agent,
check that the page shows the new token as last used, then End now and go to the next. Expiry is checked on every call. Members see the token's start and last use but cannot rotate, end or revoke.

## 2. Get jobs (long-poll)

`GET /v1/jobs?wait=25&max=10`. The answer comes as soon as a job is due, or after `wait` seconds (at most 30) with
an empty list. `max` is at most 20. An agent with the heartbeat relay on adds `relay=<version>` (see "Heartbeat
relay").

```json
{
  "jobs": [
    {
      "leaseId": "0192f3a1-7c2e-7b0a-9d41-5e8f1c2b3a4d",
      "expiresAt": "2026-09-29T12:01:00Z",
      "type": "http",
      "check": {
        "url": "https://intranet.example.com/health", "method": "GET", "timeout": 10000,
        "expectedStatus": null, "expectedText": "ok", "textMode": "contains", "caseSensitive": true,
        "body": null, "bodyType": "RAW", "followRedirects": true, "headers": {}, "ipVersion": null, "assets": null,
        "expectedHeaders": {"content-type": "application/json"},
        "json": [{"path": "$.status", "equals": "ok"}, {"path": "$.error", "exists": false}]
      }
    }
  ],
  "shareMetrics": false,
  "settings": {"browserRuns": 1, "maxChecks": 10, "paused": false, "shareHealth": false}
}
```

`shareMetrics` and `settings` are as in the connect answer (see "Settings").

Every job also carries `schedule`, `{"monitorId": "mnt_…", "intervalSeconds": 60}`: the monitor's id and
interval. The agent keeps the last job per monitor (no browser or `ssl` jobs) to repeat while StatusTick is unreachable;
it may be null or absent, and an `ssl` job never has one.

`type` is `http`, `tcp`, `ping`, `dns`, `browser`, `postgres`, `mysql`, `redis`, `mongodb`, `mcp`, `grpc`, `smtp`, `imap`
or `ssl`. For the first four, `mcp`, `grpc`, `smtp`, `imap` and `ssl`, `check` is exactly what the public locations
check (`crates/checks`):

| Type | `check` fields |
| -- | -- |
| `http` | as above |
| `tcp` | `host`, `port`, `timeout`, `ipVersion` |
| `ping` | `host`, `timeout`, `count`, `ipVersion` |
| `dns` | `hostname`, `recordType`, `timeout`, `expectedIP`, `expectedValue` |
| `mcp` | `url`, `timeout`, `authHeaderName`, `authHeaderValue` |
| `grpc`, `smtp`, `imap` | `host`, `port`, `timeout`, `service`, `tlsMode`, `tlsVerify`, `requireStartTLS`, `ipVersion` |
| `ssl` | `host`, `port`, `timeout` |

`timeout` is in milliseconds. `ipVersion` is `"4"`, `"6"` or null (either).

A `browser` job goes only to an agent that reported `capabilities.browser`, and an agent never holds more running
browser leases than its `concurrency`:

```json
{
  "leaseId": "0192f3a1-7c2e-7b0a-9d41-5e8f1c2b3a4d", "expiresAt": "2026-09-29T12:03:00Z", "type": "browser",
  "check": {
    "script": "import { test, expect } from '@playwright/test';\ntest('log in', async ({ page }) => { … });",
    "language": "typescript", "variables": {"PASSWORD": "hunter2"}, "allowedHosts": ["intranet.example.com"]
  }
}
```

`language` is `typescript` or `javascript`; `variables` are in clear text (StatusTick stores them encrypted and decrypts
them only for this answer) and the script reads them from `process.env`; `allowedHosts` are the hosts the run may reach,
the monitor URL's host first (`example.com` or `*.example.com`). Any field may be null.

A `postgres`, `mysql`, `redis` or `mongodb` job connects to a database and runs a read-only health command. These
monitors run only on private locations, never on public locations:

```json
{
  "leaseId": "0192f3a1-7c2e-7b0a-9d41-5e8f1c2b3a4d", "expiresAt": "2026-09-29T12:01:00Z", "type": "postgres",
  "check": {
    "host": "db.internal", "port": 5432, "database": "shop", "user": null, "password": null,
    "userEnv": "STATUSTICK_SECRET_DB_USER", "passwordEnv": "STATUSTICK_SECRET_DB_PASSWORD", "tls": true, "tlsVerify": true,
    "query": "SELECT count(*) FROM orders", "expectedValue": null, "timeout": 10000
  }
}
```

Credentials are either `user` / `password` (StatusTick stores the password encrypted and decrypts it only for this
answer) or `userEnv` / `passwordEnv`, names of environment variables on the agent that start with `STATUSTICK_SECRET_`
(the agent refuses any other name with `SECRET_NOT_ALLOWED`, and `SECRET_MISSING` when it is not set). `query` (only
`postgres` and `mysql`) is a read-only query whose first value is compared with `expectedValue`; null runs the type's
health command only. `timeout` is the monitor's timeout in milliseconds. Any field but `host`, `port`, `tls`,
`tlsVerify` and `timeout` may be null.

An `mcp` job checks an MCP server over Streamable HTTP: `initialize`, then `tools/list`. `url` is the server's
endpoint (`http` or `https`, no user name or password). `authHeaderName` and `authHeaderValue` are one optional header sent
on every request, both or neither; StatusTick stores the value encrypted and decrypts it only for this answer, so the
agent must not write it to disk or logs. `timeout` is the monitor's timeout in milliseconds for the whole check.

```json
{
  "leaseId": "0192f3a1-7c2e-7b0a-9d41-5e8f1c2b3a4d", "expiresAt": "2026-10-01T12:01:00Z", "type": "mcp",
  "check": {"url": "https://mcp.internal/mcp", "authHeaderName": "Authorization", "authHeaderValue": "Bearer …", "timeout": 10000}
}
```

A `grpc`, `smtp` or `imap` job checks a server the agent reaches by `host` and `port`. `grpc` calls the standard
`grpc.health.v1.Health/Check` once for `service` (null or empty: the whole server) over HTTP/2, without TLS (`tlsMode`
`NONE`) or with TLS and ALPN `h2` (`TLS`). `smtp` and `imap` read the greeting, ask for the server's capabilities (EHLO,
CAPABILITY), switch to TLS with STARTTLS when `tlsMode` is `STARTTLS` (`TLS` is TLS from the first byte), and say QUIT or
LOGOUT; they never log in. `requireStartTLS` (with `NONE`) makes a server that does not offer STARTTLS down; `service` is
null and `requireStartTLS` false for the types that do not use them. `tlsVerify` checks the chain (the agent also trusts
the CAs in its `NODE_EXTRA_CA_CERTS`) and the host name.

```json
{
  "leaseId": "0192f3a1-7c2e-7b0a-9d41-5e8f1c2b3a4d", "expiresAt": "2026-10-01T12:01:00Z", "type": "smtp",
  "check": {"host": "mail.internal", "port": 587, "timeout": 10000, "service": null, "tlsMode": "STARTTLS",
    "tlsVerify": true, "requireStartTLS": false, "ipVersion": null}
}
```

An `ssl` job reads the TLS certificate of a monitor checked only from private locations, once a day, from the
location whose agents called last; the agent trusts the CAs in its `NODE_EXTRA_CA_CERTS`, so an internal CA's
certificate counts as valid. It has no `schedule` and is no part of a round: its result only updates the monitor's
certificate.

```json
{"leaseId": "0192f3a1-7c2e-7b0a-9d41-5e8f1c2b3a4d", "expiresAt": "2026-10-01T12:01:00Z", "type": "ssl", "check": {"host": "mail.internal", "port": 993, "timeout": 10000}}
```

A lease lasts 60 seconds, a browser lease 180 seconds (`expiresAt`), long enough for the 2-minute run and its uploads. A lease with no result by then goes back to the queue once; after a second
missed lease on the same agent the job is dropped until the monitor's next check. Only jobs of the agent's location and
organization are ever handed out.

### Several agents per location

A location has any number of agents, each added on its own with its own token. Each job is leased to exactly one agent
at a time, and only that agent's result for that lease is accepted.

- Spread: the agents that asked for jobs in the last 30 seconds and are not paused share the location's jobs (for
  browser jobs only those with browser support). Each monitor's rounds go to them in turn, so with two agents each runs every second round of
  every monitor. A due job waits up to 5 seconds for the agent whose turn it is; after that any agent that asks gets it,
  so no job waits on an agent that stopped. An answer never holds more than `max` jobs.
- Takeover: when an agent makes no call for 45 seconds, the next agent that asks gets its running leases at once; an
  expired lease goes to the next agent as before. The stopped agent's late result is answered `lease.unknown`. An agent
  must therefore send a heartbeat every `heartbeatSeconds` while it runs long jobs. A lease taken over by another agent
  starts its count of missed leases again.
- When only one of two or more agents seen in the last 24 hours is online, the dashboard shows "degraded redundancy" and
  the organization's OWNERs and ADMINs get one email; the next one comes only after two or more agents were online again.

## 3. Upload browser artifacts

Before posting a browser job's result, the agent uploads the run's files, each with
`PUT /v1/leases/{leaseId}/artifacts/{name}`: `name` is `screenshot.png` (`Content-Type: image/png`) or `trace.zip`
(`Content-Type: application/zip`), the body is the raw file, at most 20 MB. Answer: `204`. Only the agent that holds the
lease may upload, while the lease runs (`404 lease.not_found` otherwise); uploading the same name again replaces the
file. A failed upload does not stop the result: the run then shows no screenshot or trace. Files are kept 30 days, like
the run.

## 4. Post results

`POST /v1/results` with at most 20 results. `result` is exactly what the public locations
answer for the same check (`crates/checks`).

```json
{
  "results": [
    {
      "leaseId": "0192f3a1-7c2e-7b0a-9d41-5e8f1c2b3a4d",
      "result": {
        "status": "up", "responseTime": 84, "httpStatus": 200,
        "details": {"textMatch": true, "headerMismatch": null}
      }
    }
  ]
}
```

Rules for `result`: `status` is `up`, `down`, `blocked` or `error`; `responseTime` is a number of milliseconds from 0 to
600000; `error`, when set, is a string of at most 2000 characters; `details`, when set, is an object. Other fields by
type: `http` `httpStatus`, `details.textMatch`, `details.headerMismatch`; `tcp` `errorCode`; `ping` `packetLoss`,
`details.alive|min|max|avg|stddev`; `dns` `records`, `recordCount`, `errorCode`. Response bodies and header values are
never sent: the agent compares the job's `expectedHeaders` itself and answers `details.headerMismatch`, null when
all match, else `{name, reason}` with `reason` `missing` or `different`, and the check is then `down`. JSON assertions (`json`) run on the
agent too; a failure is `down` with an `error` that names the path (`JSON path $.status is not the expected value`),
never a value from the body.

A browser job's `result` carries the run in `browser`, as the browser runner reports it, and which files were uploaded:

```json
{
  "status": "down", "responseTime": 7012, "error": "Timeout 5000ms exceeded.",
  "browser": {
    "status": "failed", "durationMs": 7012, "failedStep": "log in > click submit", "error": "Timeout 5000ms exceeded.",
    "tests": [{"title": "log in", "status": "failed", "durationMs": 7012,
               "steps": [{"title": "log in > click submit", "durationMs": 5004, "status": "failed"}]}],
    "webVitals": {"lcpMs": 910, "cls": 0.01, "tbtMs": 40}, "playwright": "1.63.0",
    "artifacts": {"screenshot": true, "trace": true}
  }
}
```

`browser.status` is `passed`, `failed` or `error`; `durationMs` 0 to 600000; `failedStep`, `error` and `playwright` are
strings or null; `tests` a list of objects whose `steps` is a list; `webVitals` an object or null. When the agent could
not run the script at all it may send only `{"status": "error", "responseTime": 0, "error": "…"}`.

A database job's `result` carries timings in milliseconds and, from a query, only the compared value; never rows:

```json
{
  "status": "down", "responseTime": 41, "error": "Unexpected value", "errorCode": "UNEXPECTED_VALUE",
  "details": {"connectTime": 12, "authTime": 9, "queryTime": 20, "value": "42"}
}
```

`status` is `up`, `down` or `error`; `errorCode` one of `CONNECT_FAILED`, `AUTH_FAILED`, `TIMEOUT`, `QUERY_FAILED`,
`UNEXPECTED_VALUE`, `TARGET_NOT_ALLOWED`, `SECRET_NOT_ALLOWED`, `SECRET_MISSING`, `INVALID_DATABASE` (at most 64
characters); `details.connectTime|authTime|queryTime` are numbers from 0 to 600000 or null; `details.value` is a string,
number or boolean of at most 1000 characters, or absent. StatusTick keeps only `status`, `responseTime`, `error`,
`errorCode` and these `details`, and drops any other field.

An `mcp` job's `result` carries what the server said about itself and a hash of its tools; never tool
descriptions, schemas or server error texts:

```json
{
  "status": "up", "responseTime": 212,
  "details": {
    "protocolVersion": "2025-06-18", "serverName": "Docs MCP", "serverVersion": "1.2.3", "toolCount": 12,
    "toolsHash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "initializeTime": 140, "toolsListTime": 72
  }
}
```

`status` is `up` only when `initialize` and `tools/list` succeeded within `timeout` and at least one tool is listed;
otherwise `down` (or `error` for an invalid check) with `errorCode` one of `INVALID_URL`, `INVALID_HEADER`,
`TARGET_NOT_ALLOWED`, `CONNECT_FAILED`, `TLS_FAILED`, `TIMEOUT`, `AUTH_FAILED`, `MCP_INITIALIZE_FAILED`,
`MCP_TOOLS_LIST_FAILED`, `MCP_NO_TOOLS`. `details` is there once `initialize` succeeded: `protocolVersion`, `serverName`
and `serverVersion` strings of at most 100 characters or null, `initializeTime|toolsListTime` numbers from 0 to 600000 or
null, `toolCount` a whole number from 0 to 100000 and `toolsHash` 64 lowercase hex characters (the SHA-256 of the sorted
tool names and input schemas), both once `tools/list` finished. StatusTick keeps only `status`, `responseTime`, `error`,
`errorCode` and these `details`, and drops any other field.

A `grpc`, `smtp` or `imap` job's `result` carries what the check saw, never the server's texts:

```json
{
  "status": "down", "responseTime": 38, "error": "Health status NOT_SERVING", "errorCode": "GRPC_NOT_SERVING",
  "details": {"grpcStatus": 0, "servingStatus": "NOT_SERVING", "tlsVersion": "TLSv1.3",
    "certificateExpiresAt": "2027-01-15T00:00:00.000Z", "certificateDaysLeft": 106}
}
```

`details` may have `servingStatus` (`SERVING`, `NOT_SERVING`, `UNKNOWN`, `SERVICE_UNKNOWN`), `grpcStatus` (the call's gRPC
status code), `greetingCode` (`"220"` for SMTP; `OK`, `PREAUTH` or `BYE` for IMAP), `startTLSOffered`, and after TLS
`tlsVersion`, `certificateExpiresAt` and `certificateDaysLeft`; texts are at most 100 characters. `errorCode` is one of
`GRPC_NOT_SERVING`, `GRPC_STATUS`, `GRPC_INVALID_ANSWER`, `SMTP_GREETING`, `IMAP_GREETING`, `SMTP_INVALID_ANSWER`,
`IMAP_INVALID_ANSWER`, `INVALID_ANSWER`, `STARTTLS_NOT_OFFERED`, `STARTTLS_FAILED`, `TARGET_NOT_ALLOWED`, `NO_ADDRESS`,
`TLS_FAILED`, `CONNECT_FAILED`, `TIMEOUT`, `INVALID_REQUEST`. StatusTick keeps only `status`, `responseTime`, `error`,
`errorCode` and these `details`.

An `ssl` job's `result` is the certificate check's answer (`crates/checks`): `status` (`up` valid, `down` invalid, `error` no TLS
connection), `responseTime`, `error`, `errorCode` and `certificate` (`valid`, `error`, `validFrom`, `validTo`, `daysLeft`,
`lifetimeDays`, `issuer`, `subject`; `validFrom` and `validTo` ISO-8601 strings, `valid` a boolean).

```json
{"accepted": ["0192f3a1-7c2e-7b0a-9d41-5e8f1c2b3a4d"], "rejected": [{"leaseId": "0192f3a0-…", "reason": "lease.expired"}]}
```

| `reason` | Meaning |
| -- | -- |
| `lease.expired` | The lease ran out; the result is dropped |
| `lease.unknown` | Not a lease of this agent and location (or already answered) |
| `result.invalid` | `result` breaks the rules above |

A rejected result is not sent again.

### Late results

When StatusTick does not answer (network error or 5xx) for longer than one poll, the agent repeats each monitor's last
job on its `schedule` for up to an hour and buffers the results with the time each check ran. A `401` or `426` is not
"offline". After it connected again, it sends them oldest first with `POST /v1/results/late`, at most 500 per call and
within the 256 KB body limit:

```json
{
  "results": [
    {"monitorId": "mnt_7Qk2…", "checkedAt": "2026-09-29T11:20:00Z", "result": {"status": "down", "responseTime": 5000, "error": "Connection timeout"}}
  ],
  "dropped": 0,
  "bufferedSince": "2026-09-29T11:20:00Z"
}
```

`result` follows the rules of "Post results" for the job's type (no browser runs). `dropped` is how many results the
agent's full buffer dropped, oldest first; `bufferedSince` is the oldest buffered check. The answer names each result by
its index:

```json
{"accepted": [0, 2], "rejected": [{"index": 1, "reason": "result.too_old"}]}
```

| `reason` | Meaning |
| -- | -- |
| `monitor.unknown` | No active monitor of the agent's organization with that id uses this location (browser and heartbeat monitors take no late results) |
| `result.too_old` | `checkedAt` is more than 2 hours ago |
| `result.invalid` | `checkedAt` is not an ISO-8601 instant or more than a minute in the future, or `result` breaks the rules |

The agent drops accepted and rejected results from its buffer; others it sends again. Sending the same result twice
stores it once. An accepted result is stored as a check of the monitor at `checkedAt`, from the location, flagged as late:

- One older than 15 minutes fills history and uptime only: it never changes the monitor's status, opens or resolves an
  incident, or sends an alert.
- A younger one counts like a normal agent answer when the monitor uses only private locations and no newer result is
  stored; otherwise it is history only.
- Hourly stats of hours already rolled up are rolled up again for those monitors; the daily stats of yesterday are
  rolled up again by the next daily run.
- Each upload adds one `REPORTED_LATE` entry per monitor to its timeline (`periodFrom`, `periodTo`, `resultCount`, the
  agent's host name), so the dashboard shows that period as "reported late", not offline and not down.

### Heartbeat relay

Jobs without internet access can ping the agent instead of `https://webhook.statustick.com/v1/ping/<token>`
(`STATUSTICK_RELAY_PORT` on the agent, `/ping/<token>[/start|/fail]` or `/v1/ping/…`); the agent forwards the pings
over its own connection. The relay takes only tokens on its ping list:

- **Ping list.** The connect answer of an agent with `capabilities.relay` carries
  `"relay": {"version": "…", "pingHashes": ["…"]}`: the lowercase hex SHA-256 of the UTF-8 ping token of every heartbeat
  monitor of the agent's organization, paused ones included, at most 20,000 (the oldest monitors). `version` (64 hex
  characters, at most 128) is the SHA-256 of the sorted hashes, so it changes whenever the set does. An empty list is
  valid.
- **Changes.** The agent sends its version as `GET /v1/jobs?…&relay=<version>` (empty before it has a list). The answer
  carries `relay` only when the organization's version differs (otherwise it is null), and then comes at once, without
  waiting for a job. The list is read again at most every 10 seconds, so a new heartbeat monitor or regenerated ping URL
  reaches the agent with its next poll.
- **Upload.** `POST /v1/heartbeats/relay`, with the same headers, rate limits and 256 KB body limit as late results, at
  most 500 pings, oldest first:

```json
{
  "pings": [
    {"pingId": "<token>", "kind": "start", "at": "2026-10-01T12:00:00.000Z", "run": "nightly-42"},
    {"pingId": "<token>", "kind": "ping", "at": "2026-10-01T12:03:12.512Z", "run": "nightly-42"}
  ],
  "dropped": 0
}
```

`pingId` is the token, `kind` is `ping` (success), `start` or `fail`, and `at` is when the ping arrived at the agent.
`run` (left out when the job sent none) is the ping URL's `run` query parameter, 1 to 64 letters, digits, `-` or `_`;
it ties a start to its finish. The relay answers `400` to a malformed one and does not forward the ping.
`dropped` is how many pings the agent's full buffer dropped since it was last empty; above 0 it is logged
and shown on the agent's page.
The answer names each ping by its index:

```json
{"accepted": [0, 1], "rejected": [{"index": 2, "reason": "ping.unknown"}]}
```

| `reason` | Meaning |
| -- | -- |
| `ping.unknown` | No heartbeat monitor of the agent's organization has this ping token; such a ping is never recorded |
| `ping.invalid` | `kind` is not `ping`, `start` or `fail`, `at` is not an ISO-8601 instant or more than a minute in the future, or `run` is malformed |
| `ping.too_old` | `at` is more than 2 hours ago |

An accepted ping is recorded like a ping on the public URL, at `at` (a time up to a minute ahead counts as now):

- A ping newer than the monitor's last one moves the last ping (and the deadline) to `at`; a `start` newer than the last
  ping and start becomes the run's start. An older one never moves them back.
- A success or failure ping is stored as a check result at `at`, flagged late, so the same ping sent again stores
  nothing twice. It changes the status, opens or resolves an incident only when it is the monitor's latest ping and its
  deadline (`at` + interval + grace, or the next cron run + grace) is still ahead; otherwise it is history and uptime
  only. Hourly stats of hours already rolled up are rolled up again.

### Kubernetes service discovery

An agent with `STATUSTICK_DISCOVERY=kubernetes` lists and watches the Services of its cluster and makes a monitor of
each Service with a `statustick.com/monitor` annotation (`http:/healthz`, `http:8081/ready`, `http:<port name>/path`,
`tcp:5432`, `tcp`; optional `statustick.com/name` and `statustick.com/interval`). It sends the full set, never a
change, with `PUT /v1/discovery/kubernetes` about two seconds after a Service changed and again every 5 minutes, and only
once every watched namespace was listed. Same headers, rate limits and 256 KB body limit as late results; at most 500
monitors, sorted by key:

```json
{
  "monitors": [
    {"key": "shop/api", "type": "http", "target": "http://api.shop.svc:8080/healthz", "name": "Shop API", "intervalSeconds": 60},
    {"key": "data/postgres", "type": "tcp", "target": "postgres.data.svc:5432", "name": "data/postgres", "intervalSeconds": 300}
  ]
}
```

| Field | Rule |
| -- | -- |
| `key` | `<namespace>/<service>`, two DNS labels; unique in the request |
| `type` | `http` or `tcp` |
| `target` | `http(s)://<service>.<namespace>.svc[:port][/path]` or `<service>.<namespace>.svc:<port>`: the host must be the key's own Service |
| `name` | The monitor's name, cut to 64 characters; empty is the key |
| `intervalSeconds` | 30 to 86400 |

StatusTick makes the location's discovered monitors match the set, one reconcile per location at a time:

- A new key gets an HTTP or TCP monitor checked only from this location, without SSL or domain expiry checks, first
  checked at once. A known key whose name, target, type or interval changed is updated.
- A discovered monitor whose key is missing is paused (`pausedReason` `DISCOVERY`); its history stays. A paused one whose
  key is back is resumed. An entry that breaks a rule above is skipped and leaves the monitor of its key as it is.
- At most the location's limit of discovered monitors run (100 unless StatusTick set another for the location). Running
  ones keep their place; new or returning keys over the limit are skipped. The plan's monitor limit and minimum
  interval apply as for monitors made by hand.

The answer lists the keys StatusTick changed and the ones it skipped:

```json
{
  "created": ["shop/api"], "updated": [], "paused": ["shop/old"], "resumed": [],
  "skipped": [{"key": "shop/web", "reason": "discovery.limit_reached", "message": "This location runs at most 100 discovered monitors"}],
  "limit": 100,
  "busy": false
}
```

| `reason` | Meaning |
| -- | -- |
| `discovery.limit_reached` | Over the location's limit of discovered monitors |
| `plan.limit_reached` | The plan allows no more monitors, or no interval this short; `message` has the plan's text |
| `monitor.invalid` | The entry breaks a rule above; `message` names the field (`target.format.validation`) |

`busy: true` means another agent of the location was sending its set and nothing was changed; the agent sends again
after 15 seconds. Other errors as usual; the agent retries after 30 seconds. Discovered monitors carry `managedBy:
"KUBERNETES"` and `managedKey: "<namespace>/<service>"`; the dashboard and API refuse changing anything but their alert
settings (alert policy, notification delay, mute) with 422 `monitor.managed.unprocessable`. All agents of a location
should watch the same cluster: agents of one location in two clusters pause each other's monitors.

## 5. Heartbeat

`POST /v1/heartbeat` with no body when the agent has made no other call for `heartbeatSeconds`, and at once with
`{"chromium": "<state>"}` when its Chromium state changes after connect (`off`, `starting`, `ready` or `failed`; an
unknown state is ignored). Answer: `204`.

A private location is offline when none of its agents has made an accepted call for 3 minutes. Its monitors then get no
result from it: a monitor with only offline locations shows "Location offline" and opens no incident, and its uptime
for that time is "no data" unless the agent kept checking and uploads late results for it. The organization's alert
channels get one alert when the location goes offline and one when it is back.

## Goodbye

`POST /v1/goodbye` with `{"reason": "stopping"}` when the agent stops cleanly (after its running checks finished), or
`{"reason": "updating"}` when it exits to update itself. Answer: `204`, or `400 reason.format.validation` for another
reason. The session ends: any later call with it is answered `401 agent.unauthorized`, so a process that keeps running
connects again. Agents send no goodbye after `agent.replaced` or a refused token.

### How a connection ended

The agent's page shows its last disconnect with its time and one of these reasons; StatusTick never guesses beyond them.

| Reason | When |
| -- | -- |
| `STOPPED` | A goodbye, and no connect since |
| `RESTARTED` | A goodbye, then a connect with a new `startedAt` |
| `RESTARTED_UNCLEAN` | A connect with a new `startedAt` without a goodbye; the time is the old process's last call |
| `TOKEN_ROTATED` | A call refused because the agent's rotated token ran out |
| `TOKEN_REVOKED` | A call refused because the agent's token was revoked |
| `REPLACED` | A call with an older session after another machine connected with the token |
| `LOST_CONTACT` | No accepted call for 3 minutes, no goodbye and no new process; the time is the last call |

## 6. Metrics

Agents push their metrics only when the customer chooses so; it is off by default.

- The agent's own setting "Share health" (owners and admins, on the agent's settings page of the dashboard; see
  "Settings"). Every connect answer and every `GET /v1/jobs` answer carries `shareMetrics`, so a change reaches a
  running agent within 30 seconds.
- The install's `STATUSTICK_SHARE_METRICS`, sent as `shareMetrics` at connect, always wins: `true` shares, `false` never
  shares. Unset follows the agent's setting. The dashboard shows each agent's choice and whether it is sharing.

While `shareMetrics` is true the agent sends `POST /v1/agent/metrics` every 60 seconds with the usual headers and a
snapshot of its metrics in the Prometheus text format (`Content-Type: text/plain`). Answer: `200` with
`{"kept": 18, "dropped": 0}`, or `403 agent.metrics_not_shared.forbidden` while it does not share.

- At most 64 KB per snapshot (413 above) and one push per token every 30 seconds (429 with `Retry-After` above).
- Only the agent's own metric names are kept (`st_build_info{version,browser}`, `st_connected`,
  `st_last_contact_timestamp_seconds`, `st_reconnects_total`, `st_jobs`, `st_checks_total{type,result}`,
  `st_check_duration_seconds{type}` with the buckets 0.1, 0.25, 0.5, 1, 2.5, 5, 10 and 30, `st_buffer_results`,
  `st_buffer_dropped_total`, `st_uploads_total{result}`, `st_browser_runs_active`, `st_browser_concurrency`,
  `st_relay_pings_total{result}`) and the process CPU and memory ones (`process_cpu_*_seconds_total`,
  `process_resident_memory_bytes`).
  Label values come from fixed sets (check type and result, a version number, `true`/`false`). Any other name, label
  or value, and NaN or infinite values, are dropped; the rest of the snapshot is kept.
- StatusTick keeps only the agent's latest snapshot with its time (the next push overwrites it). Turning the
  agent's setting off, or an install connecting with `shareMetrics: false`, deletes it. The organization's owners and admins
  see it on the private agent page; StatusTick exports the agents only as fleet totals, never per organization,
  location or agent.

## Versions

StatusTick stores each agent's version, `os` and `arch` from connect and shows them on the dashboard's private
locations page.

| Field | Meaning | What the agent does |
| -- | -- | -- |
| `minimumVersion` | Older agents are refused with 426 on every call | Stops polling |
| `recommendedVersion` | Older agents show "update available" in the dashboard | Logs "Update available" at connect |
| `upcomingMinimum` | A minimum announced ahead: older agents are refused from `from` (ISO-8601) | Logs "Update required from <date>" at connect |

While an upcoming minimum is set, a daily job emails the OWNERs and ADMINs of each organization with an older agent
that called in the last 30 days, once per version: the version, the date, the agents (host name, location, version)
and a link to the update steps. An organization's `from` is the announced date, but never earlier than 30 days after
its email (an organization never emailed counts as emailed on the announced date); for a security update it is the
announced date exactly. From then on every call of an older agent, connect included, is answered with 426 as above,
with the upcoming version as `minimumVersion`.

## Limits

Per agent token 120 requests a minute and per client IP 600. A normal agent makes about 3 calls a minute plus one result call per batch of jobs.
Metrics pushes are limited apart from this: one per token every 30 seconds, at most 64 KB.

## How results are used

A result is read like a public location's answer (the monitor's expected status codes, text and headers are applied by
StatusTick) and stored as a check from the location. For a monitor with only private locations, the check is
recorded as soon as every location of the round has answered, given up or is offline; answers of a round that never
finished are recorded when the next round starts. A monitor that also has public locations adds the
private locations' last answers to its next scheduled check. The normal check, incident and alert flow follows.

A browser job's run is stored as a browser run of the monitor from the location (failed → down, passed with a
step slower than its threshold → degraded, error → error), with the uploaded screenshot and trace; variable values are
replaced by `********` in its texts. A round does not wait for a location none of whose online agents runs browser
checks.

A database job's result counts as up, down or error as the agent says. A down check shows `Unexpected value <value>` for
`UNEXPECTED_VALUE`, and otherwise the agent's `error`.

A `grpc`, `smtp` or `imap` job's result counts as up, down or error as the agent says; a down check shows the agent's
`error`. An `ssl` job's certificate is stored as the monitor's certificate and alerts like one a public location read:
invalid, expired or wrong host name at once, expiring at the monitor's `sslExpiryAlertDays`.

An `mcp` job's result counts as up only when the agent says `up`; anything else is down and shows the agent's `error`
with the `errorCode`. When the `toolsHash` of an up check differs from the monitor's last one, the monitor shows the tool
list as changed and the destinations of its alert policy get an information-only alert.
