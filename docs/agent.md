# Private agent

The agent runs inside your network and checks what StatusTick's public locations can't reach. A private location is
a group of agents that share its checks and take over when one stops. Each agent connects out to
`agent.statustick.com:443` with its own token; nothing connects to the agent.

## Install

In StatusTick, open the private location, choose **Add agent** and run the install command it shows. The token is
shown once and belongs to one machine: if two machines use it, the newer one wins.

### Docker

```bash
docker run -d --name statustick-agent --restart unless-stopped --shm-size 512m \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  -e STATUSTICK_TOKEN="sta_live_…" \
  -e STATUSTICK_INSTALL=docker \
  ghcr.io/statustick/agent:1
```

With Docker Compose:

```yaml
services:
  statustick-agent:
    image: ghcr.io/statustick/agent:1
    restart: unless-stopped
    environment:
      STATUSTICK_TOKEN: "sta_live_…"
      STATUSTICK_INSTALL: compose
    shm_size: 512m
    cap_drop: [ALL]
    cap_add: [SETUID, SETGID]
```

The image (about 330 MB) runs every check type, browser checks included. Chromium needs `--shm-size 512m`;
`SETUID` and `SETGID` let each browser check run as its own user. The agent runs as user `10001` and works with
`--read-only --tmpfs /tmp`.

### Binary

The static Linux binary (`amd64`, `arm64`) runs everything except browser checks. Download it from a
[release](https://github.com/statustick/agent/releases), check it against `SHA256SUMS`, and run it as a service:

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
```

### Kubernetes

Use the [Helm chart](../charts/statustick-agent/README.md); one release is one agent.

## Settings

<!-- settings:start -->
| Variable | Type | Default | Values | What it does |
| -- | -- | -- | -- | -- |
| `STATUSTICK_TOKEN` | text | none (required) | any | The agent's token, from its page in StatusTick. |
| `STATUSTICK_URL` | URL | `https://agent.statustick.com` | `https`; `http` for `localhost`, `*.localhost` and `127.0.0.1` | Where the agent connects. |
| `STATUSTICK_CONCURRENCY` | whole number | `5` | 1 to 50 | Checks at the same time. Overrides "Max checks" in the dashboard. |
| `STATUSTICK_ALLOW` | list | none | address ranges, single addresses, host names and `*.` subdomain wildcards, for example `10.0.0.0/8,192.168.1.20,*.corp.example` | Only check these targets; others fail without being tried. See "Target rules". |
| `STATUSTICK_HOSTNAME` | text | the container's host name | any | The host name shown on the agent's page. |
| `STATUSTICK_INSTALL` | choice | set by the install command or the chart | `docker`, `compose`, `helm` or `other` | How the agent was installed, shown on its page. Detected when unset. |
| `HTTPS_PROXY` | URL | none | `http://host:port` or `https://host:port`, with `user:password@` for basic authentication | Proxy for StatusTick and HTTPS checks. Falls back to `HTTP_PROXY`. |
| `HTTP_PROXY` | URL | none | as `HTTPS_PROXY` | Proxy for plain `http` checks. |
| `NO_PROXY` | list | none | `db.internal`, `.corp` (the domain and its subdomains), `host:8443` (that port only), IP addresses, CIDR ranges such as `10.0.0.0/8`, or `*` for all | Hosts that skip the proxy. |
| `NODE_EXTRA_CA_CERTS` | path | none | a PEM file | Extra CA certificates to trust, such as your proxy's or internal CA. |
| `STATUSTICK_BUFFER_SIZE` | whole number | `10000` | 1 to 100000 | Results kept while StatusTick is unreachable. The oldest are dropped when full. |
| `STATUSTICK_BUFFER_DIR` | path | none (memory only) | a writable folder | Keeps the buffer across restarts. The agent stops if it can't write here. |
| `STATUSTICK_HEALTH_PORT` | port | none (no port) | 1 to 65535 | Serves `/healthz` and `/readyz` for Kubernetes probes. The chart sets `8080`. |
| `STATUSTICK_RELAY_PORT` | port | none (no port) | 1 to 65535, not the health port | Opens the heartbeat relay. Internal only; never expose it. See "Heartbeat relay". |
| `STATUSTICK_RELAY_HOST` | IP address | `0.0.0.0` | an address of this host | Address the relay listens on. Use the internal one on multi-network hosts. |
| `STATUSTICK_DISCOVERY` | choice | none (off) | `kubernetes` | Creates monitors from annotated Kubernetes Services. See "Kubernetes service discovery". |
| `STATUSTICK_DISCOVERY_NAMESPACES` | list | none (every namespace) | namespaces, for example `shop,payments` | Namespaces to watch. |
| `METRICS_PORT` | port | none (no port) | 1 to 65535, not the health or relay port | Serves Prometheus `/metrics`. See "Metrics". |
| `METRICS_HOST` | IP address | `0.0.0.0` | an address of this host | Address the metrics port listens on. |
| `STATUSTICK_SHARE_METRICS` | choice | none (follows the dashboard) | `true` or `false` | Share the agent's health with StatusTick. Unset follows the dashboard. |
| `BROWSER_CONCURRENCY` | whole number | `1` | 0 to 8 | Browser checks only. Browser checks at the same time; `0` turns them off. Each needs up to 2 GB. |
| `STATUSTICK_BROWSER_ISOLATION` | choice | none (isolated when the container allows it) | `user` or `off` | Run each browser check as its own user. `user` requires it; `off` disables it. |
| `STATUSTICK_REQUIRE_SECRET_HOSTS` | choice | none | `true` | Refuse secrets that have no `_HOSTS` list. |
| `STATUSTICK_SECRET_<NAME>_HOSTS` | list | none | as `STATUSTICK_ALLOW` | Hosts that may receive `STATUSTICK_SECRET_<NAME>`. See "Database checks". |
<!-- settings:end -->

Lower-case `https_proxy`, `http_proxy` and `no_proxy` work too and win over the upper-case names.

Owners and admins can change four settings on the agent's page; the agent picks them up within about 30 seconds. A
variable set on the machine wins, and the dashboard shows the setting as locked.

| Dashboard setting | Values | Variable |
| -- | -- | -- |
| Browser runs | Off or 1 to 8 (default 1) | `BROWSER_CONCURRENCY` |
| Max checks | 1 to 50 (default 5) | `STATUSTICK_CONCURRENCY` |
| Paused | Connected but takes no checks | |
| Share health | Sends metrics to StatusTick | `STATUSTICK_SHARE_METRICS` |

## Token

On the agent's page: **Rotate** (the old token works for 60 more minutes), **End now** (stop the old token early),
**Revoke** (stops a leaked token at once). With many agents, rotate one at a time and choose **End now** after the
agent's page shows the new token in use.

## Target rules

The agent may reach private addresses; that is its job. Cloud metadata (`169.254.169.254`, `fd00:ec2::254`) is
refused unless listed in `STATUSTICK_ALLOW`. With `STATUSTICK_ALLOW` set, only listed targets are checked. The list
lives on your machine, so nobody in StatusTick can change it.

## Browser checks

- Each run is its own process, browser and work folder, stopped after 2 minutes.
- Allow up to 2 GB of memory per concurrent run plus 256 MB for the agent.
- The browser and the script follow the target rules; other requests fail with `target not allowed by agent policy`.
- Each run is its own user, so a script can't read the agent's token, secrets or files. The agent logs at start
  whether runs are isolated; `STATUSTICK_BROWSER_ISOLATION=user` makes it refuse to start when they can't be.
- The screenshot and trace are uploaded to StatusTick.
- Turn browser checks off with **Browser runs** Off or `BROWSER_CONCURRENCY=0`.

## Database checks

PostgreSQL, MySQL/MariaDB, Redis and MongoDB: connect, log in, run one read-only command (`SELECT 1`, `PING`,
`ping`) or, for PostgreSQL and MySQL, your query in a read-only transaction that is rolled back. Only the one value
compared with your expected value leaves the network.

Keep passwords on the agent in `STATUSTICK_SECRET_*` variables, name them in the monitor (`passwordEnv`), and bind
each to its hosts:

```bash
-e STATUSTICK_SECRET_PG_PASSWORD="…" \
-e STATUSTICK_SECRET_PG_PASSWORD_HOSTS="db1.corp.example,10.0.0.5" \
-e STATUSTICK_REQUIRE_SECRET_HOSTS=true
```

A check that would send the secret elsewhere fails with `SECRET_NOT_ALLOWED` before connecting. Use a database user
with minimal rights:

```sql
-- PostgreSQL
CREATE ROLE statustick_monitor LOGIN PASSWORD '…';
GRANT CONNECT ON DATABASE app TO statustick_monitor;

-- MySQL and MariaDB
CREATE USER 'statustick'@'%' IDENTIFIED BY '…';
GRANT USAGE ON *.* TO 'statustick'@'%';
```

```text
# Redis 6 or later
ACL SETUSER statustick on >… -@all +ping
```

Grant `SELECT` on the tables a custom query reads.

## Behind a proxy or with your own CA

```bash
-e HTTPS_PROXY="http://user:password@proxy.corp.example:3128" \
-e NO_PROXY=".corp.example,10.0.0.0/8" \
-e NODE_EXTRA_CA_CERTS=/certs/ca.pem \
-v /etc/company/ca.pem:/certs/ca.pem:ro
```

The connection to StatusTick and HTTP checks use the proxy unless `NO_PROXY` matches; other checks connect directly.
The agent still resolves targets itself, so it needs DNS. A proxy refusal is logged with its status (`407`: wrong
credentials). The agent doesn't start if `NODE_EXTRA_CA_CERTS` can't be read.

## Offline buffer

After about 25 seconds without StatusTick, the agent keeps repeating each monitor's last check for up to an hour
(not browser checks) and uploads the results later; StatusTick shows them as reported late and drops those older
than 2 hours. Results live in memory unless `STATUSTICK_BUFFER_DIR` points at a volume user `10001` can write. Keep
that folder private; database passwords and MCP auth headers are never written to it.

## Heartbeat relay

Servers without internet access can ping the agent instead of the public ping URL:

```bash
-e STATUSTICK_RELAY_PORT=8080 -p 10.0.0.5:8080:8080
```

```bash
curl -fsS -m 10 http://10.0.0.5:8080/ping/<token>          # success
curl -fsS -m 10 http://10.0.0.5:8080/ping/<token>/start    # the job started
curl -fsS -m 10 http://10.0.0.5:8080/ping/<token>/fail     # the job failed
```

`?run=<id>` (1 to 64 letters, digits, `-`, `_`) pairs a start with its finish. Unknown tokens get `404`; the relay
answers `503` until it has the monitor list and `429` above 600 pings a minute per address. Pings are kept while
StatusTick is unreachable. The token in the path is the only secret: publish the port on an internal address only.

## Kubernetes service discovery

With `STATUSTICK_DISCOVERY=kubernetes`, annotated Services become monitors:

```yaml
metadata:
  annotations:
    statustick.com/monitor: "http:/healthz"   # or "http:8081/ready", "http", "tcp:5432", "tcp"
    statustick.com/name: "Shop API"           # optional
    statustick.com/interval: "5m"             # optional, 30 seconds to 1 day, default 60 seconds
```

The target is the Service's cluster DNS name. Removing the annotation pauses the monitor; in StatusTick only its
alert settings can change. Up to 100 per location. The service account needs `get`, `list` and `watch` on
`services`. With `STATUSTICK_ALLOW`, add `*.svc`. Use one cluster per location.

## Metrics

Labels come from fixed sets; never a target, host, monitor or token.

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

Plus `process_*` CPU and resident memory. Scrape with `METRICS_PORT` on an internal address. Example alert:

```yaml
- alert: StatusTickAgentDisconnected
  expr: st_connected == 0
  for: 5m
```

**Share health** (off by default) sends these metrics to StatusTick every minute; it keeps only the latest snapshot.
`STATUSTICK_SHARE_METRICS=false` turns sharing off for good.

## Troubleshooting

```bash
docker exec statustick-agent statustick-agent doctor
```

`doctor` checks the token format, DNS, TCP and TLS to StatusTick, the proxy, the token and the clock, printing `OK`,
`FAIL` with a fix, or `SKIP`, and exits `1` on a failure. `--target <url>` also tests one target; `--report` hides
host names and addresses for support. The agent logs one line per state change (`Connected`, `Disconnected`,
`Token rejected`, `Update required`).

## Updates

`ghcr.io/statustick/agent:1` follows every 1.x release; pin `1.0.1` to stay on one.

```bash
docker compose pull statustick-agent && docker compose up -d statustick-agent
```

Agents below StatusTick's recommended version show "Update available"; below the minimum they are refused. A new
minimum is announced by email at least 30 days ahead, except for security fixes.
