# Private agent

The agent runs inside your network and checks what StatusTick's public locations cannot reach. A private location is a group of agents. The agents share the location's checks and take over when one of them stops.

Each agent has its own token. With the token, the agent connects out to `agent.statustick.com` on port 443, asks for checks, runs them and sends the results back. That is the only host your firewall needs to allow. Nothing connects to the agent.

## Install

In StatusTick, open the private location, choose **Add agent** and give it a name. You get an install command with the agent's token. The token is shown only once. Run the command on the machine; the page shows the agent as connected within a few seconds.

One token is for one machine. For a second machine, add a second agent. If two machines use the same token, the newer one wins and the older one stops.

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

- One image runs every check type, browser checks included. It is about 330 MB to download.
- Chromium only runs while a browser check runs.
- `--shm-size 512m` is for Chromium. It crashes with Docker's default of 64 MB.
- `SETUID` and `SETGID` let the agent run each browser check as a separate user. All other capabilities are dropped.
- The agent runs as user `10001`. It works with a read-only root file system if `/tmp` stays writable: `--read-only --tmpfs /tmp`.

### Binary

Without Docker, use the static binary for Linux (`amd64` or `arm64`). It runs every check type except browser checks, which need the image. Download it from a [release](https://github.com/statustick/agent/releases) and check it against `SHA256SUMS`.

To run it as a systemd service:

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

Use the [Helm chart](../charts/statustick-agent/README.md). One release is one agent.

## Settings

Set these as environment variables.

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

Lower-case `https_proxy`, `http_proxy` and `no_proxy` work too, and win over the upper-case names.

### Settings in the dashboard

Owners and admins can change four settings on the agent's page. A change reaches the agent within about 30 seconds, without a restart.

| Setting | Values | Variable that overrides it |
| -- | -- | -- |
| Browser runs | Off, or 1 to 8 browser checks at once (default 1) | `BROWSER_CONCURRENCY` |
| Max checks | 1 to 50 checks at once (default 5) | `STATUSTICK_CONCURRENCY` |
| Paused | The agent stays connected but takes no new checks | none |
| Share health | Sends the agent's metrics to StatusTick (see [Metrics](#metrics)) | `STATUSTICK_SHARE_METRICS` |

If the variable is set on the machine, it wins. The dashboard then shows the setting as locked.

## Token

On the agent's page, an owner or admin can:

- **Rotate** the token. The old token keeps working for 60 minutes, so you have time to update the machine. After that, the agent logs `Token rotated` and retries until it is restarted with the new token.
- **End now**: stop the old token before the 60 minutes are over.
- **Revoke** a leaked token. It stops at once. Rotate to get a new one.

To rotate many agents, do one at a time: rotate, set the new token on the machine, restart the agent, check on its page that the new token is in use, then choose **End now**.

## Target rules

The agent may reach private and internal addresses. That is what it is for. Two rules apply:

- Cloud metadata addresses (`169.254.169.254`, `fd00:ec2::254`) are always refused, unless you list them in `STATUSTICK_ALLOW`.
- If `STATUSTICK_ALLOW` is set, the agent only checks targets on that list. The list lives on your machine, so nobody with access to StatusTick can change it.

## Browser checks

Every agent that runs the image can run Playwright browser checks. There is nothing extra to install.

- Each run is a separate process with a fresh browser and its own work folder. A run stops after 2 minutes.
- Plan for up to 2 GB of memory per browser run at once, plus 256 MB for the agent. The install commands set no memory limit. If you set one, leave that much room.
- The browser and the script follow the same target rules as other checks. Any other request fails the run with `target not allowed by agent policy`.
- Each run runs as its own user, so a script cannot read the agent's token, its `STATUSTICK_SECRET_*` values or its files. This needs the `SETUID` and `SETGID` capabilities and no `no-new-privileges` option. The agent logs at start whether runs are isolated. If the container does not allow it, runs share the agent's user. `STATUSTICK_BROWSER_ISOLATION=user` makes the agent refuse to start in that case.
- The screenshot and trace of a run are uploaded to StatusTick. Error texts are cut to 200 characters and step titles to 120.
- If an agent should never run a script, set **Browser runs** to Off, or `BROWSER_CONCURRENCY=0`.

## Database checks

Private agents can check PostgreSQL, MySQL and MariaDB, Redis and MongoDB. The agent connects, logs in and runs one read-only command: `SELECT 1`, `PING` or MongoDB's `ping`. For PostgreSQL and MySQL you can set your own query. It runs in a read-only transaction with a timeout and is rolled back. Only the first value of the first row is compared with the expected value.

Nothing from the database leaves your network except, when you set an expected value, the one value the check compared.

Keep passwords on the agent instead of in StatusTick. Put them in variables that start with `STATUSTICK_SECRET_`, and name the variable in the monitor (`passwordEnv`). The agent reads no other variable for a check. Bind each secret to the hosts it is for:

```bash
-e STATUSTICK_SECRET_PG_PASSWORD="…" \
-e STATUSTICK_SECRET_PG_PASSWORD_HOSTS="db1.corp.example,10.0.0.5" \
-e STATUSTICK_REQUIRE_SECRET_HOSTS=true
```

With a `_HOSTS` list, a check that would send the secret to another host fails with `SECRET_NOT_ALLOWED` before the agent connects. This matters because some protocols send the password itself, for example Redis `AUTH`. `STATUSTICK_REQUIRE_SECRET_HOSTS=true` refuses every secret without a list.

Give the agent a database user with as few rights as possible:

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

For a custom query, also grant `SELECT` on the tables it reads.

## Behind a proxy or with your own CA

```bash
-e HTTPS_PROXY="http://user:password@proxy.corp.example:3128" \
-e NO_PROXY=".corp.example,10.0.0.0/8" \
-e NODE_EXTRA_CA_CERTS=/certs/ca.pem \
-v /etc/company/ca.pem:/certs/ca.pem:ro
```

- The agent reaches StatusTick through the proxy, unless `NO_PROXY` matches `agent.statustick.com`.
- HTTP checks use the proxy too, unless the target matches `NO_PROXY`. Other check types always connect directly.
- The agent still resolves each target itself to apply the target rules, so it needs working DNS.
- If the proxy refuses the connection, the agent logs the proxy and the HTTP status. `407` means the user name or password is wrong.
- `NODE_EXTRA_CA_CERTS` adds CA certificates, for example a TLS-inspecting proxy's. The agent does not start if the file cannot be read.

## Offline buffer

If the agent cannot reach StatusTick for more than about 25 seconds, it keeps checking on its own for up to an hour. It repeats each monitor's last check and keeps the results. Browser checks are not repeated.

When StatusTick answers again, the agent uploads the results. StatusTick stores them with the time they were checked and shows the period as "reported late". Results older than 2 hours are dropped.

The agent keeps up to `STATUSTICK_BUFFER_SIZE` results and drops the oldest when full. By default they are in memory and lost on restart. To keep them, set `STATUSTICK_BUFFER_DIR` to a mounted volume that user `10001` can write. The folder holds the repeated checks, including HTTP headers and bodies, so keep it private to the agent. Database passwords and MCP auth headers are never written to it.

## Heartbeat relay

Heartbeat monitors expect each job to call its ping URL. If a server has no internet access, it can ping the agent instead, and the agent forwards the ping to StatusTick. Turn it on with `STATUSTICK_RELAY_PORT`:

```bash
-e STATUSTICK_RELAY_PORT=8080 -p 10.0.0.5:8080:8080
```

Then use the agent's address with the path of the ping URL:

```bash
curl -fsS -m 10 http://10.0.0.5:8080/ping/<token>          # success
curl -fsS -m 10 http://10.0.0.5:8080/ping/<token>/start    # the job started
curl -fsS -m 10 http://10.0.0.5:8080/ping/<token>/fail     # the job failed
```

- Add `?run=<id>` to match each start to its finish. The id is 1 to 64 letters, digits, `-` or `_`.
- The agent only forwards pings for your organization's heartbeat monitors. Other paths and tokens get `404`.
- It answers `503` until it has received the list of monitors from StatusTick, and `429` above 600 pings a minute from one address.
- While StatusTick is unreachable, the agent keeps the pings and sends them later with the time they arrived.
- The relay is plain HTTP without its own authentication: the token in the path is the secret. Only publish the port on an internal address, never to the internet.

## Kubernetes service discovery

With `STATUSTICK_DISCOVERY=kubernetes`, the agent creates monitors from Service annotations:

```yaml
metadata:
  annotations:
    statustick.com/monitor: "http:/healthz"   # or "http:8081/ready", "http", "tcp:5432", "tcp"
    statustick.com/name: "Shop API"           # optional
    statustick.com/interval: "5m"             # optional, 30 seconds to 1 day, default 60 seconds
```

- The target is the Service's cluster DNS name, on the port in the annotation or the Service's first port.
- Changing the annotation updates the monitor. Removing it pauses the monitor and keeps its history.
- In StatusTick you can only change a discovered monitor's alert settings. Everything else comes from the annotation.
- A location takes up to 100 discovered monitors. The agent logs Services it left out and why.
- The service account only needs `get`, `list` and `watch` on `services`.
- With `STATUSTICK_ALLOW`, add `*.svc`, or the checks will be refused.
- Use one cluster per location. Agents of one location in two clusters would pause each other's monitors.

## Metrics

The agent keeps Prometheus metrics. Labels only come from fixed sets, such as check type and result. A target, host name, monitor or token is never a metric or a label.

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

The agent also exposes `process_*` metrics for CPU time and resident memory.

To scrape them, set `METRICS_PORT` (for example `9464`) and publish it on an internal address only. An alert for a disconnected agent:

```yaml
- alert: StatusTickAgentDisconnected
  expr: st_connected == 0
  for: 5m
```

### Share health with StatusTick

This is off by default. When you turn it on, with **Share health** in the dashboard or `STATUSTICK_SHARE_METRICS=true`, the agent sends the metrics above to StatusTick every minute. StatusTick keeps only the latest snapshot and deletes it when you turn sharing off. `STATUSTICK_SHARE_METRICS=false` turns it off for good.

## Troubleshooting

Run `doctor` first:

```bash
docker exec statustick-agent statustick-agent doctor
```

It checks, in order: the token format, DNS, TCP and TLS to StatusTick, the proxy, whether StatusTick answers, whether it accepts the token, and the clock. Each step prints `OK`, `FAIL` with a fix, or `SKIP`. It exits with `1` if a step failed.

```text
OK    Token format: sta_live_ab12cd… (53 characters)
OK    DNS for agent.statustick.com: agent.statustick.com is 203.0.113.10, 4 ms
OK    TCP 443: connected to 203.0.113.10, 21 ms
FAIL  TLS to agent.statustick.com: the certificate issued by Corp Inspection CA is not trusted (UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
      Fix: A proxy or firewall on the way probably inspects TLS: put its CA certificate in a PEM file and set NODE_EXTRA_CA_CERTS to it.
```

- `doctor --target https://intranet.corp.example/health` also tests one target, with the agent's target rules.
- `doctor --report` hides host names and addresses so you can send the output to support.
- `doctor` warns when the machine has too little memory or `/dev/shm` for its browser runs.

The agent logs one line each time its state changes, for example `Connected`, `Disconnected`, `Token rejected` or `Update required`.

## Updates

Releases follow semantic versioning. `ghcr.io/statustick/agent:1` follows every 1.x release. Pin a version such as `1.0.1` to stay on it.

```bash
docker compose pull statustick-agent && docker compose up -d statustick-agent
```

StatusTick has a recommended and a minimum agent version. An agent older than the recommended one still works, and the dashboard shows "Update available". An agent older than the minimum is refused and stops. A new minimum is announced by email at least 30 days ahead, except for security fixes.
