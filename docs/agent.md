# Private agent

The agent runs inside your own network and checks what StatusTick's public locations cannot reach. A private location is a group of agents that a monitor runs from: its agents share the work and take over from each other when one stops. Each agent has its own token. With `STATUSTICK_TOKEN` set an agent connects out over HTTPS to `agent.statustick.com` (port 443; the only host a firewall needs to allow), long-polls for checks, runs them with the same check code as StatusTick's public locations and posts the results back (agent protocol v1). Nothing calls the agent, and it opens no port (unless you turn on the health port for Kubernetes probes, `STATUSTICK_HEALTH_PORT`, or the heartbeat relay, `STATUSTICK_RELAY_PORT`).

## Run it

Add an agent to a private location in StatusTick (see "Add or remove an agent"), then run the command it shows on the machine. The command carries that agent's token:

```bash
docker run -d --name statustick-agent --restart unless-stopped --shm-size 512m \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  -e STATUSTICK_URL="https://agent.statustick.com" \
  -e STATUSTICK_TOKEN="sta_live_…" \
  -e STATUSTICK_INSTALL=docker \
  ghcr.io/statustick/agent:1
```

Or with Docker Compose:

```yaml
services:
  statustick-agent:
    image: ghcr.io/statustick/agent:1
    restart: unless-stopped
    environment:
      STATUSTICK_URL: "https://agent.statustick.com"
      STATUSTICK_TOKEN: "sta_live_…"
      STATUSTICK_INSTALL: compose
    shm_size: 512m
    cap_drop: [ALL]
    cap_add: [SETUID, SETGID]
```

The command is the same for every agent but for its token: one image, `ghcr.io/statustick/agent`, runs every check type, browser checks included, with Chromium and the pinned Playwright runner inside. Browser checks need no other image, setting or install. Chromium runs only while a browser check runs (see "Browser checks"), so an agent without browser checks uses no more memory than one without Chromium. The 512 MB `/dev/shm` (`--shm-size 512m`, `shm_size`) is for Chromium, which crashes with Docker's 64 MB default. `--cap-drop ALL --cap-add SETUID --cap-add SETGID` (`cap_drop`, `cap_add`) leaves only the two capabilities that start each browser check as its own user (see "Browser checks"). There is no memory limit by default: each browser run can use up to 2 GB.

The image is built for `linux/amd64` and `linux/arm64` (so it runs on a Raspberry Pi) and is about 330 MB to download and 1.2 GB on disk (Debian with Node.js 24 for the Playwright runner, Chromium's headless shell and its fonts). It runs as user `10001` and works with a read-only root file system when `/tmp` stays writable: `--read-only --tmpfs /tmp`, or `read_only: true` with `tmpfs: /tmp` in Compose. Browser runs use `/tmp` for their work folders and `/dev/shm`; the offline buffer writes only to `STATUSTICK_BUFFER_DIR`.

Without Docker, run the binary below.

### The binary, without Docker

`statustick-agent` is the agent of the image as one static binary for Linux (`amd64` and `arm64`, no dependencies). Outside the image it runs every check type but browser checks, with the same settings, offline buffer, heartbeat relay, Kubernetes discovery, metrics and `doctor` as the image, and connects with the same token. Browser checks need the image's Chromium and Playwright runner, so outside the image it reports `capabilities.browser` as `null` and StatusTick sends it no browser checks; run the image for those. Download `statustick-agent-linux-amd64.tar.gz` or `statustick-agent-linux-arm64.tar.gz` from a [release](https://github.com/statustick/agent/releases) and check it against `SHA256SUMS`, or build it from this repository with Docker:

```bash
docker buildx build --target binary-export --platform linux/amd64,linux/arm64 --output type=local,dest=dist .
# dist/linux_amd64/statustick-agent, dist/linux_arm64/statustick-agent
```

or with Rust stable on the machine itself: `cargo build --release -p statustick-agent` (`target/release/statustick-agent`).

Install it as a systemd service:

```bash
sudo install -m 0755 statustick-agent /usr/local/bin/statustick-agent
sudo useradd --system --no-create-home --shell /usr/sbin/nologin statustick
sudo install -d -o statustick -m 0700 /var/lib/statustick
sudo install -m 0600 /dev/null /etc/statustick-agent.env
echo 'STATUSTICK_TOKEN=sta_live_…' | sudo tee /etc/statustick-agent.env >/dev/null
sudo tee /etc/systemd/system/statustick-agent.service >/dev/null <<'UNIT'
[Unit]
Description=StatusTick agent
After=network-online.target
Wants=network-online.target

[Service]
User=statustick
EnvironmentFile=/etc/statustick-agent.env
Environment=STATUSTICK_INSTALL=other STATUSTICK_BUFFER_DIR=/var/lib/statustick
ExecStart=/usr/local/bin/statustick-agent
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/statustick

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload && sudo systemctl enable --now statustick-agent
journalctl -u statustick-agent -f
```

`statustick-agent doctor` checks the setup (run it with the same environment: `sudo -u statustick env $(sudo cat /etc/statustick-agent.env) statustick-agent doctor`). Ping uses an unprivileged ICMP socket where the kernel allows it for the user (`net.ipv4.ping_group_range`), else a TCP connection to port 443, as in the image.

## Add or remove an agent

Owners and admins add, edit, rotate, revoke and remove agents; members can view them.

To add an agent, open the private location in StatusTick and choose "Add agent":

1. Give the agent a name, for example the machine or site it runs on.
2. Copy the install command for Docker, Docker Compose or Helm. It holds the agent's token, which is shown only this once.
3. Run it on the machine. The page waits and shows the agent as connected, usually within a few seconds.

Add a second agent to the same location the same way, on another machine, and the two share the location's checks. One token runs on one machine: for another machine, add another agent.

Removing an agent revokes its token at once, so its process can no longer connect. Its history stays for 30 days. The location's monitors keep running on the other agents of the location.

## Kubernetes

The Helm chart in `charts/statustick-agent` runs one agent per release as a Deployment with one pod, a PodDisruptionBudget, probes, a CPU limit and no memory limit, a non-root and read-only pod with all capabilities dropped (`browser.isolation: true` adds `SETUID` and `SETGID` so each browser run gets its own user, see "Browser checks"), and `emptyDir` volumes for the offline buffer, `/tmp` and a 512 MB in-memory `/dev/shm`. The chart refuses more than one replica: a second pod with the same token would stop the first. For a second agent, install the chart again with that agent's token. The token comes from a Secret you create:

```bash
kubectl create namespace statustick
kubectl create secret generic statustick-agent -n statustick --from-literal=token='sta_live_…'
helm install statustick-agent oci://ghcr.io/statustick/charts/statustick-agent --version 0.1.0 \
  -n statustick --set existingSecret.name=statustick-agent --set browser.isolation=true
```

Proxy, extra CA certificates, ping and the other values: `charts/statustick-agent/README.md`.

## Settings

<!-- settings:start -->
| Variable | Type | Default | Values | What it does |
| -- | -- | -- | -- | -- |
| `STATUSTICK_TOKEN` | text | none (required) | any | The agent's token, from its page in StatusTick. The agent sends it as `Authorization: Bearer` on every call. |
| `STATUSTICK_URL` | URL | `https://agent.statustick.com` | `https`; `http` for `localhost`, `*.localhost` and `127.0.0.1` | Where the agent connects. Plain `http` is accepted only for local development. |
| `STATUSTICK_CONCURRENCY` | whole number | `5` | 1 to 50 | How many checks run at the same time. Set on the machine, it wins over the agent's "Max checks" setting in the dashboard. Higher values use more memory. |
| `STATUSTICK_ALLOW` | list | none | address ranges, single addresses, host names and `*.` subdomain wildcards, for example `10.0.0.0/8,192.168.1.20,*.corp.example` | Optional allowlist. When set, the agent checks only matching targets; any other check fails with "target not allowed by agent policy" and is never attempted. See "Target rules" below. |
| `STATUSTICK_HOSTNAME` | text | the container's host name | any | The name the agent reports, shown as Host on its page. The token picks the agent, so a recreated container stays the same agent whatever its host name. |
| `STATUSTICK_INSTALL` | choice | set by the install command or the chart | `docker`, `compose`, `helm` or `other` | How the agent was installed, shown on its page in the dashboard. Unset: `helm` inside Kubernetes, `docker` inside a Docker container, else `other`. |
| `HTTPS_PROXY` | URL | none | `http://host:port` or `https://host:port`, with `user:password@` for basic authentication | Proxy for `https` traffic: the connection to StatusTick and HTTPS checks. Falls back to `HTTP_PROXY`. |
| `HTTP_PROXY` | URL | none | as `HTTPS_PROXY` | Proxy for plain `http` checks. |
| `NO_PROXY` | list | none | `db.internal`, `.corp` (the domain and its subdomains), `host:8443` (that port only), IP addresses, CIDR ranges such as `10.0.0.0/8`, or `*` for all | Hosts that skip the proxy. |
| `NODE_EXTRA_CA_CERTS` | path | none | a PEM file | Extra CA certificates, for example your TLS-inspecting proxy's CA or your internal CA. Trusted for the connection to StatusTick and for HTTPS checks, next to the usual public CAs. |
| `STATUSTICK_BUFFER_SIZE` | whole number | `10000` | 1 to 100000 | How many results the agent keeps while StatusTick is unreachable. When full, the oldest are dropped and counted. See "Offline buffer" below. |
| `STATUSTICK_BUFFER_DIR` | path | none (memory only) | a writable folder | Keeps the buffer and the checks to repeat across restarts, usually on a mounted volume. The agent does not start when the folder cannot be written. |
| `STATUSTICK_HEALTH_PORT` | port | none (no port) | 1 to 65535 | Opens `GET /healthz` (`200 ok` while the process runs) and `GET /readyz` (`200 ok` while StatusTick answered in the last two minutes, `503` otherwise) on this port, for Kubernetes probes. Nothing else is served. The Helm chart sets it to `8080`. |
| `STATUSTICK_RELAY_PORT` | port | none (no port) | 1 to 65535, not the health port | Opens the heartbeat relay on this port: jobs inside your network ping the agent instead of `webhook.statustick.com`. Internal only, never expose it to the internet. See "Heartbeat relay" below. |
| `STATUSTICK_RELAY_HOST` | IP address | `0.0.0.0` | an address of this host | The address the heartbeat relay listens on. Inside a container `0.0.0.0` is needed for a published port; on a host with several networks set the internal address. |
| `STATUSTICK_DISCOVERY` | choice | none (off) | `kubernetes` | Turns on Kubernetes service discovery: annotated Services get monitors in the agent's location. Only inside a pod with a service account token. See "Kubernetes service discovery" below. |
| `STATUSTICK_DISCOVERY_NAMESPACES` | list | none (every namespace) | namespaces, for example `shop,payments` | The namespaces to watch instead of all of them. |
| `METRICS_PORT` | port | none (no port) | 1 to 65535, not the health or relay port | Opens `GET /metrics` (Prometheus text format) on this port. Nothing else is served there. See "Metrics" below. |
| `METRICS_HOST` | IP address | `0.0.0.0` | an address of this host | The address the metrics port listens on. Set `127.0.0.1` to keep it on the host. |
| `STATUSTICK_SHARE_METRICS` | choice | none (follows the dashboard) | `true` or `false` | `true` sends the agent's health to StatusTick every minute; `false` never does, whatever the dashboard says. Unset follows the agent's "Share health" setting in the dashboard (off by default). See "Metrics" below. |
| `BROWSER_CONCURRENCY` | whole number | `1` | 0 to 8 | Browser checks only. How many browser checks run at the same time; `0` turns them off. Set on the machine, it wins over the agent's "Browser runs" setting in the dashboard. Each run needs up to 2 GB of memory (see below). |
| `STATUSTICK_BROWSER_ISOLATION` | choice | none (isolated when the container allows it) | `user` or `off` | Browser checks: each run runs as its own user, so a script cannot read the agent's token or files. `user` refuses to start when the container does not allow it; `off` runs browser checks as the agent's user. See "Browser checks" below. |
| `STATUSTICK_REQUIRE_SECRET_HOSTS` | choice | none | `true` | `true` refuses every `STATUSTICK_SECRET_` variable that has no `_HOSTS` list. |
| `STATUSTICK_SECRET_<NAME>_HOSTS` | list | none | as `STATUSTICK_ALLOW` | The hosts the secret `STATUSTICK_SECRET_<NAME>` may be sent to. A database check that uses the secret for any other host fails with `SECRET_NOT_ALLOWED`. See "Database checks" below. |
<!-- settings:end -->

Lower-case `https_proxy`, `http_proxy` and `no_proxy` work too and win over the upper-case names.

## Token

Each agent has its own token, shown once when the agent is added. Rotating or revoking it touches no other agent. Members see when the token was made and last used. On the agent's page in StatusTick an owner or admin can:

- **Rotate**: a new token, shown once with the install command. The old token keeps working for 60 minutes, so the agent keeps running while you change it. After that the agent logs `Token rotated; set the new STATUSTICK_TOKEN` and retries with backoff until it is restarted with the new token. Rotating again during the 60 minutes stops the earlier old token at once.
- **End now**: stops the old token before the 60 minutes are over.
- **Revoke**, for a leaked token: the token stops at once, with no overlap. The agent logs `Token revoked; rotate it on the agent's page in StatusTick and set the new STATUSTICK_TOKEN` and retries with backoff; rotate to get a new token.

To rotate many agents, go one at a time:

1. Rotate the agent's token.
2. Set the new `STATUSTICK_TOKEN` on that machine (the Secret, for the Helm chart).
3. Restart the agent.
4. Check on the agent's page that the new token was used last.
5. End now, then go to the next agent.

`doctor` prints what StatusTick says about a rotated or revoked token.

## Settings from the dashboard

Four settings of an agent are set on its page in StatusTick by owners and admins; members see them. The agent gets them when it connects and with every answer to its long-poll, so a change takes effect within about 30 seconds, with no restart and no reinstall. It logs each change once, for example `Browser runs at once: 2 → 1, from the dashboard`.

| Setting | What it does | Variable that overrides it |
| -- | -- | -- |
| Browser runs | Browser checks at once: Off, or 1 to 8 (default 1). Lowering it lets running runs finish and starts no new one above the new value. Off means no browser checks; Chromium is off as soon as its runs finished. | `BROWSER_CONCURRENCY` |
| Max checks | Checks at once, 1 to 50 (default 5). | `STATUSTICK_CONCURRENCY` |
| Paused | The agent finishes its running checks, stays connected and takes no new ones until it is unpaused; it runs no checks of its own while offline either. It logs `Paused from the dashboard` and `Resumed from the dashboard`, and `/readyz` on the health port answers `paused` (still `200`). | none |
| Share health | Sends the agent's metrics to StatusTick, see "Share agent health with StatusTick". | `STATUSTICK_SHARE_METRICS` |

A variable set on the machine always wins: the agent ignores the dashboard value for that setting, and the dashboard shows the setting as locked, set on the machine. Use the variables where the agent's configuration is managed locally; changing one needs a restart.

## Target rules

The agent exists to check what is not on the internet, so it may reach private and internal addresses (`10.x`, `192.168.x`, `.internal` host names and similar). Two rules still apply:

- Cloud metadata addresses (`169.254.169.254`, `fd00:ec2::254`) are always refused, unless you list them in `STATUSTICK_ALLOW` yourself.
- With `STATUSTICK_ALLOW`, the agent checks only the targets in the list. The list lives on your side, so nobody with StatusTick access can widen it. A host name is matched as written; an address range is matched against every address the host resolves to.

StatusTick adds its own rule: a monitor may use an internal target only when all of its locations are private locations of your organization. Public locations keep refusing internal targets.

## Browser checks

Browser (Playwright) checks run on every agent: the image has Chromium and the same pinned Playwright version as the hosted browser checks, and the agent tells StatusTick so when it connects. Nothing extra to install.

- How many browser checks run at once is the agent's "Browser runs" setting in the dashboard (Off, 1 to 8; default 1). `BROWSER_CONCURRENCY` on the machine wins over it, for setups whose config is managed locally; `BROWSER_CONCURRENCY=0` turns browser checks off on that machine.
- Chromium is off until the agent gets its first browser check. Each run then starts its own fresh Chromium and stops it when the run ends, so no Chromium runs between checks; the agent reports Chromium as ready while runs keep coming and as off again after 5 minutes without one. Idle, with no browser checks, the agent process uses about 5 MB of memory (RSS, measured on arm64).
- Each run is a separate process with a fresh browser and its own work folder, removed after the run, and stops after 2 minutes like hosted runs. The screenshot and trace go to StatusTick before the result.
- Memory: plan for up to 2 GB per concurrent browser run, plus 256 MB for the agent and its other checks: browser runs × 2 GB + 256 MB. The install commands set no memory limit; if you set one (`--memory`), leave that much room.
- The browser follows the same target rules as the other checks: it reaches internal hosts but never cloud metadata, and with `STATUSTICK_ALLOW` only the listed targets; a request to any other host fails the run with "target not allowed by agent policy". The script's own Node.js code is held to the same rules: its `fetch` and `http(s)` requests go through the same proxy, and any other connection, DNS lookup or program it starts fails the run with "target not allowed by agent policy". The script reads only Playwright, the browsers and its own run folder, never the agent's token, environment or files; the browser opens only web pages and uploads only files from the run folder; and the script cannot listen on a port. This is enforced inside the script's Node.js process, not by the kernel, so turn browser runs off (Off in the dashboard, or `BROWSER_CONCURRENCY=0`) on agents that should never run a script. No extra privileges or capabilities are needed. Kernel-level separation (each check as another user, `/proc` mounted with `hidepid=2`) would need root at start and is not done.
- Each browser run runs as its own user (`run1` to `run8`), not as the agent's user, so the kernel keeps a script and its Chromium from the agent's environment (the token and `STATUSTICK_SECRET_*` values), from the agent's files and from other runs, whatever the script does inside its own process. When a run ends, every process of its user is stopped and what it left in `/tmp` and `/dev/shm` is removed. The agent switches user through one helper in the image (`/usr/local/bin/statustick-run-as`, `setpriv` with the `SETUID` and `SETGID` file capabilities, usable only by the agent's group); the agent itself stays the unprivileged user `10001`, and a run can never gain privileges again (`no_new_privs`). This needs two things from the container:
  - the `SETUID` and `SETGID` capabilities. The install commands drop every other one: `--cap-drop ALL --cap-add SETUID --cap-add SETGID` (Compose: `cap_drop`, `cap_add`); Docker grants both by default too. The Helm command sets `browser.isolation=true`.
  - no `--security-opt no-new-privileges` (Kubernetes: `allowPrivilegeEscalation: true`, which `browser.isolation` sets), or the helper cannot use its capabilities.

  The agent logs at start whether browser runs are isolated. Where the container does not allow it, browser checks run as the agent's user, as before, and the agent says so. `STATUSTICK_BROWSER_ISOLATION=user` refuses to start instead; `off` never switches user. With `--cap-drop ALL --cap-add SETUID --cap-add SETGID` the two capabilities are the only ones in the container.
- Error texts in browser results are cut to 200 characters and test and step titles to 120, so little page text leaves your network; the screenshot and trace do show the page.
- Browser runs need a writable `/tmp` and the 512 MB `/dev/shm` of the install commands.

## Database checks

Private agents also check PostgreSQL (`postgres`), MySQL and MariaDB (`mysql`), Redis (`redis`) and MongoDB (`mongodb`). The agent connects to the host through the target rules above, logs in and runs one read-only command: `SELECT 1`, `PING` or the `ping` admin command. Public locations do not run database checks.

| Field | What it does |
| -- | -- |
| `host`, `port` | The database server. Required. |
| `database` | PostgreSQL and MySQL: the database name. MongoDB: the authentication database (`admin` when empty). Redis: the database number, for example `0`. |
| `user`, `password` | Credentials stored in StatusTick. PostgreSQL needs a user; the agent never falls back to `PGUSER`, `PGPASSWORD`, other `PG*` variables or `~/.pgpass`. |
| `userEnv`, `passwordEnv` | Instead, the name of an environment variable on the agent that holds the value. Only names that start with `STATUSTICK_SECRET_` (and do not end in `_HOSTS`) are read; any other name fails the check, so StatusTick cannot read the agent's other settings. |
| `tls`, `tlsVerify` | Connect with TLS (default off); verify the certificate and host name (default on). |
| `query` | PostgreSQL and MySQL only: your own query instead of `SELECT 1`. It runs in a read-only transaction with a statement timeout and is rolled back; one statement only. The first column of the first row is the value. |
| `expectedValue` | The check is down (`UNEXPECTED_VALUE`) unless the value equals this text (trimmed; numbers compare as numbers, so `1.0` equals `1`). |
| `timeout` | Milliseconds for the whole check, default `10000`. |

The result has the connect, login and query times and an error code (`CONNECT_FAILED`, `AUTH_FAILED`, `TIMEOUT`, `QUERY_FAILED`, `UNEXPECTED_VALUE`, `TARGET_NOT_ALLOWED`, `SECRET_NOT_ALLOWED`, `SECRET_MISSING`). Nothing of the query result leaves the agent, except the one compared value (up to 200 characters) when you set `expectedValue`. A failed query reports only the database's error code, and passwords never appear in error texts.

Keep database passwords on the agent, and bind each one to the hosts it belongs to:

```bash
docker run -d --name statustick-agent --restart unless-stopped --shm-size 512m \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  -e STATUSTICK_TOKEN="sta_live_…" \
  -e STATUSTICK_INSTALL=docker \
  -e STATUSTICK_SECRET_PG_PASSWORD="…" \
  -e STATUSTICK_SECRET_PG_PASSWORD_HOSTS="db1.corp.example,10.0.0.5" \
  -e STATUSTICK_REQUIRE_SECRET_HOSTS=true \
  ghcr.io/statustick/agent:1
```

Then set `passwordEnv` to `STATUSTICK_SECRET_PG_PASSWORD` in the monitor.

We recommend a `_HOSTS` list for every secret. Some protocols send the password itself (Redis `AUTH`, PostgreSQL `password` authentication), so a monitor changed to point at another host would hand that host the password. With `STATUSTICK_SECRET_<NAME>_HOSTS` the agent refuses such a check with `SECRET_NOT_ALLOWED` before it connects. The list takes host names (matched as written in the monitor, `*.` for subdomains), addresses and ranges such as `10.0.0.0/24` (matched against the address the agent connects to). When the list has only host names, a check that names another host is refused before any DNS lookup; with addresses or ranges in the list, the agent resolves the host first. Every secret a check reads must allow the host; `user` and `password` stored in StatusTick are not bound. `STATUSTICK_REQUIRE_SECRET_HOSTS=true` refuses any secret without a list, and the agent does not start when a list is not valid. `STATUSTICK_ALLOW` still limits all checks; the `_HOSTS` list limits where each secret goes.

Give the agent its own user with the least rights the check needs:

```sql
-- PostgreSQL
CREATE ROLE statustick_monitor LOGIN PASSWORD '…';
GRANT CONNECT ON DATABASE app TO statustick_monitor;
GRANT pg_monitor TO statustick_monitor; -- only for queries on replication lag and other statistics

-- MySQL and MariaDB
CREATE USER 'statustick'@'%' IDENTIFIED BY '…';
GRANT USAGE ON *.* TO 'statustick'@'%';
-- only when the query needs it: GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'statustick'@'%';
```

```text
# Redis 6 and later; add +select when the check sets a database number
ACL SETUSER statustick on >… -@all +ping
```

```js
// MongoDB: no roles are needed for ping; clusterMonitor for server status
db.getSiblingDB('admin').createUser({ user: 'statustick', pwd: '…', roles: [{ role: 'clusterMonitor', db: 'admin' }] })
```

Grant `SELECT` on the tables a custom query reads, and nothing else.

## MCP server checks

Private agents check MCP servers inside your network with job type `mcp`: the same fields and check as `POST /check/mcp` (`url`, `authHeaderName`, `authHeaderValue`, `timeout`), through the target rules and `STATUSTICK_ALLOW`, and through `HTTPS_PROXY`/`HTTP_PROXY` like HTTP checks. Only `status`, `responseTime`, `error`, `errorCode` and `details` (`protocolVersion`, `serverName`, `serverVersion`, `toolCount`, `toolsHash`, `initializeTime`, `toolsListTime`) leave the agent; the URL, the auth header, tool descriptions and schemas do not. The auth header value is never written to the offline buffer's `jobs.json`, so after a restart such a check waits until StatusTick leases it again.

## gRPC, SMTP and IMAP checks

Private agents run job types `grpc`, `smtp` and `imap` with the same fields and checks as `POST /check/grpc`, `/check/smtp` and `/check/imap`, through the target rules and `STATUSTICK_ALLOW` (never through a proxy). Only `status`, `responseTime`, `error`, `errorCode` and `details` (`servingStatus`, `grpcStatus`, `greetingCode`, `startTLSOffered`, `tlsVersion`, `certificateExpiresAt`, `certificateDaysLeft`) leave the agent.

## Certificate checks

StatusTick reads the TLS certificate of a monitor on private locations once a day with an `ssl` job: `{host, port, timeout}`, the same check as `POST /check/ssl`. The result has `status`, `responseTime`, `error`, `errorCode` and `certificate` (`valid`, `error`, `validFrom`, `validTo`, `daysLeft`, `lifetimeDays`, `issuer`, `subject`). Certificates of your own CA count as trusted when the agent has it in `NODE_EXTRA_CA_CERTS` (below); the same holds for `tlsVerify` on gRPC, SMTP, IMAP and database checks. `ssl` jobs are not repeated while StatusTick is unreachable.

HTTP and certificate checks also reach servers that offer only TLS 1.0 or 1.1, or only CBC ciphers. Such a connection adds `legacyTLS: true` and `tlsVersion` (`TLSv1`, `TLSv1.1` or `TLSv1.2`) to the result (`details` for HTTP checks); it is information only and never changes the status. A certificate key that is RSA or DSA under 2048 bits passes only on such a connection, and adds `weakKey: true`; over TLS 1.2 or later with an AEAD cipher it fails the check as before.

## Behind a proxy or with your own CA

```bash
docker run -d --name statustick-agent --restart unless-stopped --shm-size 512m \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  -e STATUSTICK_TOKEN="sta_live_…" \
  -e STATUSTICK_INSTALL=docker \
  -e HTTPS_PROXY="http://agent:password@proxy.corp.example:3128" \
  -e NO_PROXY=".corp.example,10.0.0.0/8" \
  -e NODE_EXTRA_CA_CERTS=/certs/ca.pem \
  -v /etc/company/ca.pem:/certs/ca.pem:ro \
  ghcr.io/statustick/agent:1
```

- The agent reaches StatusTick through `HTTPS_PROXY` unless `NO_PROXY` matches `agent.statustick.com`. The start line shows the proxy it uses, without the password.
- HTTP checks follow the same rules: a target that matches `NO_PROXY` is checked directly, any other target goes through the proxy. TCP, ping, DNS, gRPC, SMTP, IMAP, certificate and database checks always go directly.
- The target rules do not change with a proxy. The agent still resolves each target itself and refuses it before any request is sent, so the agent needs working DNS for the hosts it checks.
- When the proxy refuses the connection to StatusTick, the agent logs one line with the proxy address and the HTTP status, for example `Proxy http://proxy.corp.example:3128 blocked the connection to https://agent.statustick.com: HTTP 403.` A `407` means the user name or password is wrong. HTTP checks that the proxy refuses report `The proxy refused the request: HTTP 403`.
- The agent does not start when the `NODE_EXTRA_CA_CERTS` file cannot be read or has no PEM certificate. If the CA is missing, the agent logs `Disconnected: UNABLE_TO_VERIFY_LEAF_SIGNATURE` or a similar certificate error.

## Offline buffer

When the agent cannot reach StatusTick (no answer, or a StatusTick error) for longer than one poll (25 seconds), it keeps checking on its own:

- It repeats the last check it got for each monitor on that monitor's interval, with the same concurrency limit, target rules and job checks, and buffers each result with the time it ran. After one hour offline it stops checking and keeps the buffer. Browser checks are not repeated (each run needs up to 2 GB and 2 minutes).
- The buffer holds `STATUSTICK_BUFFER_SIZE` results (10,000 by default). When it is full the oldest result is dropped, and the agent reports how many it dropped.
- When StatusTick answers again, the agent connects again and reports the buffer (the location's "back online" alert says how many results it buffered), then uploads the results oldest first, 500 at a time, next to its normal checks. StatusTick stores them with their real check time and shows the period as "reported late". Results older than 15 minutes fill history and uptime but open no incident; results older than 2 hours are refused.
- A rejected token (`401`) or `Update required` (`426`) is not offline: the agent behaves as before and runs no checks of its own.

Without `STATUSTICK_BUFFER_DIR` the buffer lives in memory and is lost when the agent restarts. To keep it, mount a volume and point the agent at it:

```bash
docker run -d --name statustick-agent --restart unless-stopped --shm-size 512m --read-only --tmpfs /tmp \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  -e STATUSTICK_TOKEN="sta_live_…" \
  -e STATUSTICK_INSTALL=docker \
  -e STATUSTICK_BUFFER_DIR=/var/lib/statustick \
  -v statustick-buffer:/var/lib/statustick \
  ghcr.io/statustick/agent:1
```

`--read-only` keeps working: only the volume and `/tmp` are written. The image runs as user `10001` and has an empty `/var/lib/statustick` owned by it, so a new named volume mounted there is writable; a host folder must be writable by `10001` (`chown 10001 /srv/statustick`). The folder holds `results.jsonl` (the buffer) and `jobs.json` (the checks to repeat, including HTTP request headers and bodies, but never a database password or an MCP auth header value: such a check waits for StatusTick after a restart). Both files are readable only by the agent's user.

## Heartbeat relay

Heartbeat monitors expect each job to call its ping URL, `https://webhook.statustick.com/v1/ping/<token>`. A server without internet access can ping the agent instead, and the agent forwards the ping over its own connection to StatusTick. The relay is off until you set `STATUSTICK_RELAY_PORT`:

```bash
docker run -d --name statustick-agent --restart unless-stopped --shm-size 512m \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  -e STATUSTICK_TOKEN="sta_live_…" \
  -e STATUSTICK_INSTALL=docker \
  -e STATUSTICK_RELAY_PORT=8080 \
  -e STATUSTICK_BUFFER_DIR=/var/lib/statustick \
  -v statustick-buffer:/var/lib/statustick \
  -p 10.0.0.5:8080:8080 \
  ghcr.io/statustick/agent:1
```

Then replace the host of the ping URL with the agent's internal address; the path stays the same:

```bash
curl -fsS -m 10 http://10.0.0.5:8080/ping/<token>          # success (also /v1/ping/<token>)
curl -fsS -m 10 http://10.0.0.5:8080/ping/<token>/start    # the job started
curl -fsS -m 10 http://10.0.0.5:8080/ping/<token>/fail     # the job failed
```

Add a run id, as on the public URL, so StatusTick ties each start to its own finish even when runs overlap:

```bash
RUN="nightly-$(date +%Y%m%d%H%M)"
curl -fsS -m 10 "http://10.0.0.5:8080/ping/<token>/start?run=$RUN"
backup.sh && curl -fsS -m 10 "http://10.0.0.5:8080/ping/<token>?run=$RUN" \
          || curl -fsS -m 10 "http://10.0.0.5:8080/ping/<token>/fail?run=$RUN"
```

- `GET`, `POST` and `HEAD` work, with the same meaning as the public URL. Like the public URL, the relay ignores a request body (up to 10 KB; larger bodies get `413`) and every query parameter but `run`; nothing else in them leaves your network.
- `run` is 1 to 64 letters, digits, `-` or `_`; any other value gets `400 Invalid run parameter` and the ping is not forwarded. The agent forwards the run id with the ping and keeps it with the ping in the offline buffer.
- `agent doctor` shows the relay port and these URLs when `STATUSTICK_RELAY_PORT` is set.
- Answers, in plain text: `200 OK` when the ping is taken; `404 Unknown ping URL` for any other path and for a token that is not a heartbeat monitor of your organization (such pings are not forwarded); `503` until the agent has received the list of your organization's heartbeat monitors from StatusTick (after its first connect, or from `STATUSTICK_BUFFER_DIR` after a restart); `429 Too many pings` above 600 pings a minute from one address; `405` for other methods.
- The agent forwards pings within about a second, in batches, next to its normal calls. While StatusTick is unreachable it keeps them, with the time each arrived, in the offline buffer (`STATUSTICK_BUFFER_SIZE` pings, the oldest dropped first; on disk as `pings.jsonl` with `STATUSTICK_BUFFER_DIR`) and sends them when StatusTick answers again. StatusTick records each ping at the time it arrived at the agent.
- New heartbeat monitors and regenerated ping URLs reach the agent within one poll (about 30 seconds).
- The relay is plain HTTP and has no authentication of its own: the ping token in the path is the secret, as on the public URL. Publish the port only on an internal address (`-p 10.0.0.5:8080:8080`, or `STATUSTICK_RELAY_HOST` without Docker), never to the internet, and limit who can reach it with your firewall. The address of the connecting host is used for the rate limit; `X-Forwarded-For` is not trusted.
- In Kubernetes, `relay.enabled: true` in the Helm chart opens the port and adds a `ClusterIP` Service (see `charts/statustick-agent/README.md`).

## Kubernetes service discovery

In Kubernetes the agent can create monitors from annotations instead of the dashboard. With `STATUSTICK_DISCOVERY=kubernetes` (the Helm chart's `discovery.enabled`) it lists and watches the Services of the cluster (or of `STATUSTICK_DISCOVERY_NAMESPACES`), and every Service with a `statustick.com/monitor` annotation gets a monitor in the agent's location within a minute:

```yaml
metadata:
  annotations:
    statustick.com/monitor: "http:/healthz"   # or "http:8081/ready", "http:metrics/ready", "http", "tcp:5432", "tcp"
    statustick.com/name: "Shop API"           # optional, default "<namespace>/<service>"
    statustick.com/interval: "5m"             # optional: seconds, or with s, m or h; 30 seconds to 1 day, default 60
```

- The target is the Service's cluster DNS name: `http://<service>.<namespace>.svc:<port><path>` for `http` (path `/` when none is given), `<service>.<namespace>.svc:<port>` for `tcp`. The port is the annotation's (a number, or the name of one of the Service's ports), otherwise the Service's first port.
- A wrong annotation is logged once with the reason, and the Service gets no monitor.
- Changing the annotation updates the monitor. Removing the annotation or the Service pauses it, with its history kept; it resumes when the annotation comes back. Deleting a discovered monitor in the dashboard deletes its history; the agent creates it again while the annotation is there.
- In StatusTick, discovered monitors are managed by Kubernetes (`managedBy: KUBERNETES`, `managedKey: <namespace>/<service>`): only their alert settings (alert policy, notification delay, mute) can be changed in the dashboard or API. Everything else comes from the annotation.
- Each location takes at most 100 discovered monitors (StatusTick can set another limit per location), and your account's monitor limit applies. The agent logs the Services left out and why (`discovery.limit_reached`, `plan.limit_reached`, `monitor.invalid`).
- The agent sends the full set to StatusTick about two seconds after a change and again every 5 minutes, so a missed change is corrected. It sends nothing until every namespace was listed once, so a failing list never pauses monitors.
- RBAC: the service account needs only `get`, `list` and `watch` on `services` (a ClusterRole, or a Role per namespace with `STATUSTICK_DISCOVERY_NAMESPACES`); the agent reads nothing else. It calls the API server at `KUBERNETES_SERVICE_HOST` with the mounted token and CA, never through `HTTPS_PROXY`. On `403` it logs which permission is missing and keeps trying.
- With `STATUSTICK_ALLOW`, add `*.svc` (or the Service CIDR); otherwise the checks of discovered monitors fail with "target not allowed by agent policy".
- Use one cluster per location: all agents of a location send their set to the same place, so agents of one location in two clusters would pause each other's monitors.

## Metrics

The agent keeps Prometheus metrics. Labels come from fixed sets only (check type and result, a version number,
`true`/`false`); a target, host name, monitor, location or token is never a metric or a label.

<!-- metrics:start -->
| Metric | Type | Labels | Meaning |
| -- | -- | -- | -- |
| `st_build_info` | gauge | `version`, `browser` | Always 1; the agent version and whether it runs browser checks (BROWSER_CONCURRENCY above 0). |
| `st_connected` | gauge |  | 1 while connected to StatusTick, 0 otherwise. |
| `st_last_contact_timestamp_seconds` | gauge |  | Unix time of the last call StatusTick answered. |
| `st_reconnects_total` | counter |  | Connects after the first one. |
| `st_jobs` | gauge |  | Checks running now. |
| `st_checks_total` | counter | `type`, `result` | Checks run, by check type (http, tcp, ping, dns, mcp, grpc, smtp, imap, ssl, postgres, mysql, redis, mongodb, browser) and result (up, down, blocked or error). |
| `st_check_duration_seconds` | histogram | `type` | Check response time, by check type; buckets 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30 s. |
| `st_buffer_results` | gauge |  | Results kept while StatusTick is unreachable. |
| `st_buffer_dropped_total` | counter |  | Results dropped because the buffer was full. |
| `st_uploads_total` | counter | `result` | Result uploads to StatusTick, by result: ok, failed (retried) or rejected. |
| `st_browser_runs_active` | gauge |  | Browser checks on only: browser checks running now. |
| `st_browser_concurrency` | gauge |  | Browser checks on only: browser checks that may run at once (the "Browser runs" setting, or BROWSER_CONCURRENCY). |
| `st_relay_pings_total` | counter | `result` | Heartbeat relay on: relayed pings, by result: accepted, rejected or failed. |
<!-- metrics:end -->

The agent also has `process_*` metrics: CPU time and resident memory. The table is generated from the agent's metrics:
`UPDATE_DOCS=1 cargo test -p statustick-agent docs` rewrites it, and `cargo test` fails when it is out of date.

### Scrape them yourself

Set `METRICS_PORT` (for example `9464`) and scrape `http://<agent>:9464/metrics`. With Docker, publish it on an internal
address only: `-p 10.0.0.5:9464:9464`. The Helm chart has `metrics.enabled` and an optional `ServiceMonitor`.

Three example alert rules:

```yaml
groups:
  - name: statustick-agent
    rules:
      - alert: StatusTickAgentDisconnected
        expr: st_connected == 0
        for: 5m
      - alert: StatusTickAgentBufferGrowing
        expr: delta(st_buffer_results[15m]) > 0 and st_connected == 0
        for: 15m
      - alert: StatusTickAgentChecksErroring
        expr: sum by (instance) (rate(st_checks_total{result="error"}[10m])) / sum by (instance) (rate(st_checks_total[10m])) > 0.2
        for: 10m
```

### Share agent health with StatusTick

Off by default. When it is on, the agent sends a snapshot of the metrics above every 60 seconds over its existing
connection (`POST /v1/agent/metrics`), so StatusTick can see that your agents are healthy and help when they are not.
It works without `METRICS_PORT`.

- On: the agent's "Share health" setting in the dashboard (owners and admins), or `STATUSTICK_SHARE_METRICS=true` on
  the agent. A change of the setting reaches a running agent within 30 seconds.
- Off for good: `STATUSTICK_SHARE_METRICS=false`. It wins over the dashboard setting, and the agent tells StatusTick
  so the page shows "Refused on the agent".
- It sends only the `st_*` metrics in the table, `process_cpu_*_seconds_total` and
  `process_resident_memory_bytes`. Never a target, host name, result detail, response body, secret or token.
- StatusTick keeps only the latest snapshot of each agent and deletes it when sharing is turned off. Your organization's
  owners and admins see it.
- For itself StatusTick keeps only totals across all customers, and never URLs, host names, IPs, results or errors.
- A push that fails waits for the next minute; it is never buffered and never holds up checks. The agent logs whether
  sharing is on when it starts and whenever it changes.

## Troubleshooting

Run `doctor` first. It uses the same settings as the agent and checks, in this order: the token format, DNS for the StatusTick host, TCP 443, TLS (and which CA signed the certificate the agent sees), the proxy settings, whether StatusTick itself answers (`GET /health`, no token), whether StatusTick accepts the token, and the clock drift. Each step prints `OK` or `FAIL` with one sentence on how to fix it; a step that needs a failed one prints `SKIP`. It exits with `0` when every step passes and `1` otherwise.

```bash
# Inside the running agent, with its exact settings:
docker exec statustick-agent statustick-agent doctor

# Or as a one-off container with the same settings you run the agent with:
docker run --rm -e STATUSTICK_TOKEN="sta_live_…" ghcr.io/statustick/agent:1 doctor
```

```text
StatusTick agent 1.0.0 doctor

OK    Token format: sta_live_ab12cd… (53 characters)
OK    DNS for agent.statustick.com: agent.statustick.com is 203.0.113.10, 4 ms
OK    TCP 443: connected to 203.0.113.10, 21 ms
FAIL  TLS to agent.statustick.com: the certificate issued by Corp Inspection CA is not trusted (UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
      Fix: A proxy or firewall on the way probably inspects TLS: put its CA certificate in a PEM file and set NODE_EXTRA_CA_CERTS to it.
OK    Proxy settings: no proxy set, connects directly
SKIP  StatusTick answers: needs the connection steps above
SKIP  Token accepted: needs an answer from StatusTick
SKIP  Clock drift: needs an answer from StatusTick

1 check failed.
```

- With a proxy, the DNS and TCP steps test the proxy, and the TLS step goes through its `CONNECT` tunnel, like the agent does.
- The reachability check calls `GET /health`, which needs no token and answers `ok`; a proxy or firewall page in its place fails this step, not the token check.
- The token check sends one heartbeat call without an agent id, so it does not register this host as an agent.
- The clock step compares this host's clock with the time StatusTick answers with and fails above 10 seconds.
- `doctor --target https://intranet.corp.example/health` also tests one target from the agent: DNS through the agent's target rules, then connect and TLS, each with its time. A target that resolves to a private or internal address fails at DNS with the reason, and doctor does not connect to it, the same as a check.
- `doctor --report` prints the same steps for a support email: the token is shown only by its prefix, and proxy and target host names and addresses are replaced with `<proxy>`, `<target>` and similar labels. Add `--include-hosts` to keep them.
- After the steps, `doctor` prints `WARN` lines when the machine has too little memory or `/dev/shm` for its browser runs, with the same texts as the agent's page in StatusTick: `Low memory: 310 MB free. Browser checks may fail. Lower browser runs at once to 1.` and `Small /dev/shm: 64 MB. Browser checks may crash. Give the agent 512 MB (--shm-size 512m).` It counts 256 MB for the agent plus 500 MB per browser run at once and warns when less than 512 MB is left of the memory limit (of the total memory without a limit), or when `/dev/shm` is below 512 MB. It counts with `BROWSER_CONCURRENCY` when that is set on the machine, otherwise with the browser runs set for the agent in StatusTick, which it reads without connecting (`GET /v1/settings`), and says so under the warning; when it cannot read them it counts with the default of 1 and says that instead. A warning does not fail `doctor`.
- The full token is never printed, only its prefix (the part the dashboard shows).
- Without Docker: `STATUSTICK_TOKEN=… statustick-agent doctor`.

## What it does

- Runs HTTP(S), TCP, ping, DNS, MCP server, gRPC health, SMTP, IMAP, TLS certificate and database checks. Response bodies, header values, cookies, MCP tool descriptions and schemas and query results stay on the agent; only the status, timings, status code, the text match result, the name of an expected header that did not match, an MCP server's name, version, protocol version, tool count and tool hash, and a database check's compared value are sent (`docs/agent-security.md`).
- HTTP, MCP server and gRPC checks send `User-Agent: StatusTick/2.0 (+https://statustick.com/docs/checks)` (an HTTP check that sets its own `User-Agent` header keeps it). Browser checks keep Chromium's User-Agent and add the same text at its end, unless the script sets its own `userAgent`.
- Where the agent may not send ICMP (no `NET_RAW` and no unprivileged ICMP sockets, as in a locked-down Kubernetes pod) or has no `ping` program, a ping check connects to TCP port 443 of the host instead: a host that accepts or refuses the connection is up. The agent logs this once, and the result says so (`details.method` is `tcp`, with a `details.note`).
- Target rules: see "Allowed targets" below; cloud metadata addresses are always refused.
- Reconnects with exponential backoff (up to one minute) when the connection drops; after 25 seconds without StatusTick it keeps checking for up to an hour and uploads the results later (see "Offline buffer").
- Logs one line per state change: `Connected …`, `Disconnected …`, `Token rejected …`, `Token rotated …`, `Token revoked …`, `Update required …`, `Another machine connected with this agent's token …`. After `Update required` it stops polling until it is restarted with a newer image.
- Sends its session (from the connect answer) on every call. When another machine connects with the same token, StatusTick keeps the newer connection and answers the older one `409 agent.replaced`: that agent logs `Another machine connected with this agent's token. This one stopped taking checks; give each machine its own agent.`, stops polling, answers `/readyz` with `503` and does not connect again until it is restarted, so two machines never take turns.
- After connecting it logs `Update available: version …` when StatusTick recommends a newer version, or `Update required from <date> …` when a new minimum version has been announced (see "Versions and updates").
- Sends a heartbeat only when it made no other call for the interval the platform asks for; otherwise the long-poll is the only traffic.
- On `SIGTERM` or `SIGINT` it stops leasing new checks, waits up to 8 seconds for running checks and posts their results, then says goodbye (`POST /v1/goodbye` with the reason `stopping`) and exits, so StatusTick can tell a clean stop from lost contact. The goodbye waits at most 5 seconds and never extends those 8 seconds; if it fails, the agent exits anyway. It says nothing after `409 agent.replaced`, after a rejected token or when it crashes.

## What it reports at connect

Each connect tells StatusTick about the machine, for the agent's page in the dashboard. Nothing else about the host is sent, and the values of environment variables never are.

| Field | What it is |
| -- | -- |
| `hostName`, `os`, `arch` | `STATUSTICK_HOSTNAME` (or the host name), the operating system and the CPU architecture |
| version | The agent version, in the `Agent-Version` header |
| `startedAt` | When the agent process started |
| `installType` | `docker`, `compose`, `helm` or `other`: `STATUSTICK_INSTALL`, which the install commands and the chart set; without it `helm` inside Kubernetes, `docker` inside a Docker container, else `other` |
| `memoryLimitBytes`, `memoryLimited` | The container's memory limit (cgroup v2 `memory.max`, v1 `memory.limit_in_bytes`); the total memory and `false` without a limit |
| `shmBytes` | The size of `/dev/shm` (`null` without one) |
| `cpuCount` | The container's CPU quota rounded up, else the CPUs the agent may use |
| `chromium` | `off`, `starting`, `ready` or `failed`. A change after connect is sent at once as a heartbeat with `{"chromium": "<state>"}` |
| `envSettings` | Which of `BROWSER_CONCURRENCY`, `STATUSTICK_CONCURRENCY` and `STATUSTICK_SHARE_METRICS` are set on the machine, by name only; the dashboard shows these settings as locked |
| `applied` | The values the agent runs with for those three: `browserConcurrency`, `concurrency` and `shareMetrics` |
| `capabilities`, `buffering`, `shareMetrics` | Browser and relay support, buffered results and `STATUSTICK_SHARE_METRICS` (see above) |

## Resource budget

| What | Budget |
| -- | -- |
| Memory (RSS), idle | under 64 MB (measured on arm64: about 70 MB, and 75 MB for the former image without Chromium) |
| Memory (RSS), 50 HTTP checks a minute | under 128 MB |
| CPU, idle | under 1% of one core; no busy polling (long-poll or backoff only) |
| Compressed image | under 400 MB (about 330 MB with Chromium) |
| Smallest host | Raspberry Pi with 512 MB (arm64), default settings |

CI builds the image for both architectures and runs `scripts/agent-budget.sh` on the amd64 image (size, non-root user, no exposed port, idle CPU and idle memory with a read-only root file system). To check an arm64 host, build the `Dockerfile` there and run the same script.

## Versions and updates

Agent releases follow semantic versioning and are listed in `CHANGELOG.md`. The image is published as `X.Y.Z`, `X.Y`, `X` and `latest`. `ghcr.io/statustick/agent:1` follows every 1.x release; pin `ghcr.io/statustick/agent:1.0.0` to stay on one version.

Update with Docker:

```bash
docker pull ghcr.io/statustick/agent:1 && docker rm -f statustick-agent && docker run -d --name statustick-agent --restart unless-stopped --shm-size 512m --cap-drop ALL --cap-add SETUID --cap-add SETGID -e STATUSTICK_TOKEN=sta_live_… -e STATUSTICK_INSTALL=docker ghcr.io/statustick/agent:1
```

Update with Docker Compose (in the folder of your `compose.yaml`):

```bash
docker compose pull statustick-agent && docker compose up -d statustick-agent
```

StatusTick keeps a minimum and a recommended agent version. An agent older than the recommended one still works; the dashboard shows "Update available" on its location. An agent older than the minimum is refused (`Update required`, the agent stops polling). A new minimum is announced by email to the owners and admins of every organization with an older agent at least 30 days before it is enforced, and the agent logs the date; only a security fix can raise the minimum sooner.

## Verify the image

Images are signed with cosign (keyless, from this repository's release workflow) and carry an SBOM and build provenance:

```bash
cosign verify ghcr.io/statustick/agent:1.0.0 \
  --certificate-identity 'https://github.com/statustick/agent/.github/workflows/agent-image.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker buildx imagetools inspect ghcr.io/statustick/agent:1.0.0 --format '{{ json .SBOM }}'
```

The signing identity is this repository's `Agent image` workflow, run by the `Release` workflow on `main`: `https://github.com/statustick/agent/.github/workflows/agent-image.yml@refs/heads/main`.
