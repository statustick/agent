# Agent security: threat model

The agent runs inside a customer's network and takes check definitions from StatusTick over the internet. This file
names who could abuse it, what stops them, and which test shows it. The public summary is the "Agent security" page of
the docs (statustick.com/docs/agent-security).

## What the agent does and never does

- It only makes outbound calls: HTTPS to one host (`agent.statustick.com`) and the checks it is given. It opens no
  port, except the optional health port for Kubernetes probes (`STATUSTICK_HEALTH_PORT`): `GET /healthz` and
  `GET /readyz` answer `ok`, `paused` or `not connected to StatusTick`, and nothing else is served; and the optional heartbeat
  relay (`STATUSTICK_RELAY_PORT`, off by default), an internal-only port that takes heartbeat pings, see below.
  With Kubernetes service discovery (off by default) it also reads Services from the cluster's API server.
- A job is data with a fixed schema per check type (`crates/agent/src/schema.rs`): fields outside the schema are dropped, a
  field of the wrong type refuses the job, and no field is ever run as code or as a shell command. The agent has no
  shell entry point for jobs at all.
- Exception: browser checks run customer Playwright scripts, on every agent whose browser runs are above 0 (Off in
  the dashboard or `BROWSER_CONCURRENCY=0` turns them off on the machine); each run is its own process with a
  2-minute limit. The browser goes through an egress proxy for that run (`crates/agent/src/browser/proxy.rs`)
  that applies the same target policy as the other checks: cloud metadata is refused, and with `STATUSTICK_ALLOW` only the listed ranges and host names are reached; any other
  request fails the run with "target not allowed by agent policy". The script's own Node.js code is held to the same
  rules: its `fetch` and `http(s)` requests go through that proxy, and any other connection, DNS lookup, UDP
  socket or program it starts is refused in its process and fails the run the same way. It cannot read the agent's
  token or other files outside Playwright and its run folder, and cannot listen on a port. A run's screenshot and trace
  show the page and are uploaded for the lease, by design. Its error texts are cut to 200 characters and its test and step titles to 120
  (`MAX_BROWSER_ERROR_CHARS`, `MAX_STEP_TITLE_CHARS` in `crates/agent/src/browser/mod.rs`). See "Open items".
- What leaves the network is the documented result fields only (`result_fields` in `crates/agent/src/schema.rs`): status,
  response time, HTTP status code, error text, keyword match, the name of an expected header that is missing or
  different (compared on the agent), whether an HTTP check's answer came over legacy TLS, its TLS version and whether the certificate key is weak, DNS records, ping statistics (and, when ICMP is not available and a TCP connection stood in, `details.method` `tcp`
  with a fixed note), for asset checks counts
  and status codes, for database checks an error code and the connect, login and query times, and for MCP
  server checks an error code, the server's protocol version, name and version (cut to 100 characters), the
  tool count, a SHA-256 of the tool names and input schemas, and the initialize and tools/list times, for gRPC, SMTP
  and IMAP checks an error code, the gRPC and serving status, the greeting code, whether STARTTLS is offered,
  the TLS version and the certificate's expiry, and for certificate (`ssl`) jobs the certificate's dates, validity,
  issuer organisation or common name and subject common name, and whether it was read over legacy TLS, with its TLS version and whether its key is weak. Never a
  response body, header values, cookies, the URLs of a page's assets, MCP tool descriptions or schemas, JSON-RPC
  error messages or query results; the one exception is the
  single value a database check compared with `expectedValue`, cut to 200 characters and sent only when the job has
  `expectedValue`.
- About the machine, connect sends only the fields listed in "What it reports at connect" in `docs/agent.md`
  (host name, OS, architecture, start time, install type, memory limit, `/dev/shm` size, CPU count, Chromium state,
  and the applied values of three settings). Of the environment it sends the names of `BROWSER_CONCURRENCY`,
  `STATUSTICK_CONCURRENCY` and `STATUSTICK_SHARE_METRICS` when they are set, never a value of a variable; no other
  variable is read for it (`MACHINE_SETTINGS` in `crates/agent/src/settings.rs`).
- Results checked while StatusTick was unreachable are the same documented fields, uploaded later with the
  monitor id and the time of the check (`POST /v1/results/late`), plus how many results the full buffer dropped.
- Heartbeat pings the relay took leave as the ping token, the kind (`ping`, `start`, `fail`), the time the ping
  arrived and the `run` query parameter when the job sent one (1 to 64 of `[A-Za-z0-9_-]`, anything else gets `400`)
  (`POST /v1/heartbeats/relay`), plus how many the full buffer dropped. Request bodies, headers and other query
  parameters of the pings are never forwarded, as the public ping URL ignores them too.
- Agent health, only while the customer shares it (off by default; the agent's "Share health" setting in the
  dashboard, or `STATUSTICK_SHARE_METRICS=true`; `STATUSTICK_SHARE_METRICS=false` always wins): every 60 seconds the
  `st_*` metrics and the process CPU and memory values listed in `docs/agent.md` "Metrics" (`SHARED_METRICS` in
  `crates/agent/src/metrics.rs`), as numbers with labels from fixed sets only (check type and result, version, `true`/`false`). No
  target, host, monitor, location, result detail or token is a metric or label. StatusTick drops any other name.
- The optional metrics port (`METRICS_PORT`, off by default) serves `GET /metrics` with the same metrics, and nothing else.

## Threats and mitigations

| Threat | Mitigation | Test |
| -- | -- | -- |
| Stolen agent token | The token is one agent's: it can lease jobs of that agent's location and post their results, nothing else, and using it from a second machine stops the first, which shows on the agent's page. StatusTick stores a hash; an owner or admin rotates or revokes it without touching any other agent (a revoked token is refused on the next call). Rate limits per token and per IP. The agent never sends results anywhere but StatusTick. | `crates/agent/tests/contract.rs` (`logs_a_rejected_token_once_keeps_retrying_and_never_says_goodbye`) |
| Compromised StatusTick platform | It can send any check definition, so: `STATUSTICK_ALLOW` limits targets on the customer's side and StatusTick cannot change it; cloud metadata is refused unless listed; only documented result fields leave, so no page content comes back; jobs are data, never code (except browser scripts). | `crates/checks/tests/targets.rs`; `crates/agent/src/schema.rs` (`drops_unknown_fields_and_refuses_wrong_types`, `keeps_only_documented_result_fields`) |
| Malicious organization member | Only ADMINs create monitors, and every change is in the audit log. A monitor may use an internal target only when all its locations are private (platform). `STATUSTICK_ALLOW` bounds what any member can reach. | `crates/checks/tests/targets.rs`; `crates/checks/src/targets.rs` (`policies_decide_what_a_check_may_reach`) |
| Man in the middle | `STATUSTICK_URL` must be `https` (plain `http` only for `localhost`). The agent verifies the certificate chain (Mozilla's roots, rustls) and host name; `NODE_EXTRA_CA_CERTS` only adds trusted CAs for a TLS-inspecting proxy, it does not turn checks off. No pinning: certificates rotate, and pinning would break agents on renewal. | `crates/agent/src/settings.rs` (`refuses_wrong_values_with_the_operator_messages`); no test yet for a CA file that is not mounted |
| Huge responses | Only the first 5 MB of a response is read for keyword and asset checks; the rest is never buffered. Request bodies the agent sends are at most 64 KB. | `crates/checks/tests/engine.rs` (`http`, "http body cut at 5 MB"); `crates/agent/src/jobs.rs` (`refuses_jobs_it_cannot_run`, 64 KB) |
| Slow-loris targets | The check timeout covers connect, headers and reading the body. | `crates/checks/tests/engine.rs` (`http`, "http timeout": a server that answers late); no test yet for a body sent slowly |
| Redirects to metadata or internal hosts | Redirects are followed by hand, at most 5, and every hop's address goes through the target policy again, so a public target cannot redirect into metadata or outside the allowlist. | `crates/checks/tests/engine.rs` (`http`, "http redirect to an internal address", "http redirect loop stops after 5 hops") |
| Database credentials and data | A job names credentials with `userEnv`/`passwordEnv`: the agent reads only variables that start with `STATUSTICK_SECRET_`, and any other name refuses the job, so a compromised platform cannot read `STATUSTICK_TOKEN` or other settings. A secret with a `<name>_HOSTS` list is sent only to those hosts: a job that uses it for another host is refused with `SECRET_NOT_ALLOWED` before the agent connects, so a compromised platform cannot point it at its own server; `STATUSTICK_REQUIRE_SECRET_HOSTS=true` refuses secrets without a list. PostgreSQL never falls back to `PG*` variables, `$USER` or `~/.pgpass`. Passwords are removed from error texts. A custom query runs in a read-only transaction with a statement timeout and is rolled back; PostgreSQL gets it as one prepared statement (a second statement is refused), MySQL refuses multiple statements. Only the timings, an error code and, with `expectedValue`, the first column of the first row leave; a failed query reports its error code, not the database's message, which can quote data. The agent docs show a least-privilege user per database. | `crates/agent/src/database.rs` (`reads_secrets_only_from_statustick_secret_variables_and_their_hosts`, `maps_driver_failures_to_codes_without_quoting_query_errors`); `crates/agent/tests/contract.rs` (`databases_log_in_run_the_read_only_query_and_report_failures_with_their_codes`) |
| Offline buffer on disk | Only with `STATUSTICK_BUFFER_DIR`, a folder the customer mounts. The agent writes results (documented fields only) and the jobs it repeats while offline, files mode `0600`. A database password is never written: a restored database job without it is skipped until StatusTick leases it again. Jobs repeated offline go through the same schema check and target policy as leased ones, and browser jobs are never kept or repeated. The buffer is bounded (`STATUSTICK_BUFFER_SIZE`), and the agent stops checking after an hour offline. | `crates/agent/src/buffer.rs` (`never_writes_a_password_or_auth_header_value_to_disk`, `keeps_at_most_the_bound_and_counts_what_it_drops`) |
| Browser runs | The browser of each run goes through a per-run proxy that resolves every host once and checks it with the agent's target policy, so `STATUSTICK_ALLOW` and the metadata rule hold for page loads, redirects and subresources. Error texts, test titles and step titles are rebuilt at the result schema and cut short; unknown test statuses count as failed. | `crates/agent/tests/browser.rs` (`refuses_cloud_metadata_and_targets_outside_statustick_allow`); `crates/agent/src/browser/proxy.rs` (`applies_the_agent_policy_to_tunnels_and_plain_requests`); `crates/agent/src/browser/mod.rs` (`cuts_texts_and_counts_an_unknown_test_status_as_failed`) |
| A browser script reading the agent's token | The agent's environment (`/proc/<agent pid>/environ`) holds `STATUSTICK_TOKEN` and the `STATUSTICK_SECRET_*` values, and the script runs as the same user. The run gets none of that environment: the process sandbox starts `run.mts` with only `PATH`, the run folder and the browsers path, and the script's process gets only its own variables. Node's permission model reads only Playwright (`/runner`), the browsers, the run folder and named files Playwright checks (`/etc/os-release`, its container and WSL probes, and the `package.json`, `tsconfig.json` and `jsconfig.json` paths above the run folder and `/runner`): no `/proc` entry of another process, no agent file, no Kubernetes service account token, and no symbolic or hard link to one. Chromium is not under the permission model, so the guard checks every DevTools command on its pipe (sent re-serialized, so Chromium reads what was checked): navigations, new targets, `Network.loadNetworkResource` and request rewrites only to `http(s)`, `about:`, `data:` and `blob:` URLs, also inside `Target.sendMessageToTarget`; file uploads and dropped files only from the run folder. The kernel-level alternative, running checks as another user with `/proc` mounted `hidepid=2`, needs root or `CAP_SETUID` at start and a `/proc` mount option, which the documented setups do not grant. | `sandbox/test/guard.test.ts` ("reads only", "no local file"); `crates/agent/tests/browser.rs` (`runs_as_a_run_user_without_the_agent_environment`) |
| A browser script reading the agent's environment or files through Chromium | Inside Node the guard cannot stop raw DevTools commands, so the kernel does: each run is started as its own user (`run1` to `run8`, one per run at a time) by `/usr/local/bin/statustick-run-as`, a copy of `setpriv` with the `SETUID` and `SETGID` file capabilities that only the agent's group may execute. The run, its Playwright and its Chromium have no groups, no capabilities and `no_new_privs`, so they can neither use the helper nor a setuid program. Another user's process cannot read `/proc/<agent pid>/environ`, the agent's `0600` buffer files or another run's `0700` work folder, and cannot signal the agent. After each run, and at the time limit, the agent runs a fixed clean-up as that user: it stops every process of the user and removes its work folder and what it left in `/tmp` and `/dev/shm`. The agent keeps user `10001` and holds no capability itself. The container must grant `SETUID` and `SETGID` and must not set `no-new-privileges`; the agent logs at start whether runs are isolated, falls back to its own user where they cannot be, and refuses to start with `STATUSTICK_BROWSER_ISOLATION=user`. | `crates/agent/tests/browser.rs` (`runs_as_a_run_user_without_the_agent_environment`); `scripts/agent-isolation.sh`; the CI chart install with `browser.isolation` |
| A browser script hiding a refusal or listening | Besides the `egress-refused` marker, which the script can delete, the guard writes each refusal to descriptor 4, which `run.mts` reads (it passes the pipe to the Playwright runner and the guard to each forked Node child at the same number, whatever the script asked for); `run.mts` then exits with 3 and the process sandbox fails the run. A script that closed or replaced the descriptor (checked by device and inode) is killed at its next refusal, which fails the run too. Every Node server's `listen` (net, http, https, http2, tls, local sockets) and UDP sockets are refused; Playwright and Chromium need none, since Chromium talks to Playwright on a pipe. | `sandbox/test/guard.test.ts` ("deletes the marker", "closes or replaces", "forked Node process", "cannot listen") |
| A browser script's own network calls | The script shares the agent's network, and the agent has no privileges for a network namespace (that needs `CAP_SYS_ADMIN`, or user namespaces that Docker's and Kubernetes' default seccomp profiles refuse). So the Playwright runner and its workers run under Node's permission model, with no addons, WASI, worker threads, inspector or `process.binding`, and file writes only in the run's folder (`run.mts`). `sandbox/guard.cts`, loaded first, then allows one connection target, the run's proxy: Node's `fetch` and `http(s)` use it (`NODE_USE_ENV_PROXY`), every other TCP, TLS or local socket connection, DNS call (`lookup`, `resolve*`, resolvers, promises) and UDP socket throws "target not allowed by agent policy" and fails the run, even if the script catches the error. Child processes are only Playwright's worker (with the same flags) and Chromium, which starts with the run's proxy, no direct WebRTC UDP, no switch that starts other programs or loads extensions, and every new context on the run's proxy. The hooks that hand out a pending connection's request object (`async_hooks`, `process._getActiveRequests`) return nothing. | `sandbox/test/guard.test.ts`; `crates/browser/src/sandbox.rs` (`runs_a_job_with_its_own_proxy_and_only_its_environment`) |
| MCP server checks | Every request of the check (initialize, tools/list, the session `DELETE`) resolves its host through the target policy and connects through the guarded dispatcher or the agent's proxy; redirects are not followed and the transport's optional `GET` stream is never opened. A job's `authHeaderValue` is sent only to the job's URL, never logged, never in a result and never written to `jobs.json` (a restored job without it waits for a lease). At most 5 MB of each answer is read and at most 20 tools/list pages are followed. Server tool schemas are hashed, never compiled into validators. Error texts are the agent's own words and status codes, never the server's. | `crates/checks/tests/engine.rs` (`mcp`); `crates/checks/src/mcp.rs` (`checks_the_request_without_quoting_the_auth_value`); `crates/agent/src/buffer.rs` (`never_writes_a_password_or_auth_header_value_to_disk`) |
| Heartbeat relay port | Off unless `STATUSTICK_RELAY_PORT` is set. Internal only: the docs say to publish it on an internal address (`STATUSTICK_RELAY_HOST`, `-p <internal address>:port`, a `ClusterIP` Service in the chart) and never to the internet. Plain HTTP without authentication of its own, like the public ping URL: the token in the path is the secret. It serves only `/ping/<token>[/start\|/fail]` (and the `/v1` form) by GET, POST or HEAD, with an optional `run` parameter checked against `[A-Za-z0-9_-]{1,64}` (`400` otherwise), and answers `OK` or a fixed error text, never data. A token must be in the list StatusTick sent (SHA-256 hashes of the organization's heartbeat tokens, so neither memory nor `relay.json` holds a token); any other gets `404` and is not forwarded, so the port cannot be used to reach another organization's monitors or to send anything else out; until a list arrives it answers `503`. Bodies are read up to 10 KB and dropped (`413` above), at most 600 pings a minute per source address (`429`, the connecting address only, `X-Forwarded-For` ignored), 5-second header and request timeouts, at most 256 connections. Buffered pings are bounded by `STATUSTICK_BUFFER_SIZE`. | `crates/agent/src/relay.rs` (`reads_the_public_ping_paths`, `keeps_only_well_formed_hashes_and_reads_them_back`, `limits_pings_per_source_in_a_window`); `crates/agent/tests/contract.rs` (`answers_health_relays_listed_pings_and_serves_only_its_own_metric_names`) |
| gRPC, SMTP and IMAP checks | Each connects once to the address `resolveAllowed` checked (target policy, `STATUSTICK_ALLOW`), so no later lookup can swap the address. They never log in or send credentials. Answers are bounded: a gRPC answer of at most 1 KB, at most 200 lines of at most 4 KB per mail connection, and the job's timeout over the whole conversation. Bytes a mail server sends with its STARTTLS answer fail the check instead of being read as sent over TLS. Error texts are the agent's own words and codes; greeting, capability and `grpc-message` texts are never sent. Certificate (`ssl`) jobs are never kept in `jobs.json` or repeated offline. | `crates/checks/tests/engine.rs` (`grpc`, `mail`); `crates/checks/tests/targets.rs` |
| Kubernetes service discovery | Off unless `STATUSTICK_DISCOVERY=kubernetes`. The service account may only `get`, `list` and `watch` `services` (the chart's ClusterRole, or a Role per listed namespace), so a leaked token reads Service names, ports and annotations, nothing else (no Secrets, no pods). The token is mounted only in that case. The agent reads only the three `statustick.com/*` annotations, the name, namespace and ports, and sends StatusTick only the derived `{key, type, target, name, intervalSeconds}`; targets are always `<service>.<namespace>.svc`, and StatusTick refuses any other host. Monitor checks keep the agent's target policy (`STATUSTICK_ALLOW`). API server calls go directly with the mounted CA, never through the proxy. | `crates/agent/src/kubernetes.rs` (`makes_monitors_from_annotations`); no test yet for the API server's `403` |
| DNS rebinding | A host is resolved once and the request connects to the checked address (`resolveAllowed`, guarded lookup on every connection). | `crates/checks/tests/targets.rs`; `crates/checks/tests/engine.rs` (`http`, "http redirect to an internal address"); no separate rebinding test yet |

## Kubernetes

The Helm chart (`charts/statustick-agent`) runs the agent as user `10001` with a read-only root file system, no
privilege escalation, the `RuntimeDefault` seccomp profile, all capabilities dropped and no service account token (only `discovery.enabled` mounts one). `browser.isolation: true` adds the `SETUID` and `SETGID` capabilities and allows privilege escalation, for the helper that starts each browser run as its own user (allowed by the baseline Pod Security level, not by restricted); it is off by default, and browser runs then share the agent's user. The
token is read from an existing Secret; the chart has no value for it. `ping.enabled` sets the safe sysctl
`net.ipv4.ping_group_range` (unprivileged ICMP sockets) and adds no capability; only `ping.netRaw` adds `NET_RAW`.

## External review (AC5)

Not done yet.

## Open items

- Anyone who can reach the relay port and knows or guesses a valid ping token can send pings for that monitor, the
  same as on the public URL; a flood from many addresses can fill the buffer while StatusTick is unreachable and push
  older pings out. Tokens are 24 random bytes, and the port must stay internal.
- `jobs.json` in `STATUSTICK_BUFFER_DIR` keeps HTTP request headers and bodies of the repeated jobs, which can hold API
  keys; anyone who can read the volume can read them. The docs say to keep the volume private to the agent.

- A browser script's own network calls are refused inside its Node process, not by the kernel: the guard is
  as strong as the permission model and the patched Node APIs. A script that reaches Playwright's internal objects can
  still write raw DevTools commands to the browser's pipe past the guard's check, for example to create a context with
  another proxy and connect to hosts outside the target policy. Refusal reporting is in-process too: a script that fakes
  `fs.Stats` can hide a replaced descriptor, though the connection itself stays refused. A network namespace per run
  would close this; it needs privileges the documented setups do not grant.
- Where the container does not allow switching user (no `SETUID` and `SETGID`, or `no-new-privileges`; the Helm chart
  without `browser.isolation`), browser runs share the agent's user, and raw DevTools commands can open
  `file:///proc/<agent pid>/environ` and read `STATUSTICK_TOKEN`. The agent says so at start. The docs tell customers
  to turn browser runs off on agents that should never run a script.
- With run users, a compromised agent process could use the helper to become any user, root included, within the
  container's capability bounding set. With `--cap-drop ALL --cap-add SETUID --cap-add SETGID` (and in the chart) that
  set is only those two capabilities.
- Run users share `/tmp` and `/dev/shm` with the agent and can fill them during a run; what they leave is removed when
  the run ends.
- An MCP check's `authHeaderValue` is stored in StatusTick and sent with the job, so whoever can change the monitor's
  URL can send the header to another allowed host. There is no `STATUSTICK_SECRET_` variant for it yet; `STATUSTICK_ALLOW`
  bounds where it can go.
- A `STATUSTICK_SECRET_` variable without a `_HOSTS` list can still be pointed at another host by a compromised
  platform, and where the protocol sends the password itself (Redis `AUTH`, PostgreSQL `password` authentication) that
  host sees it. Binding is opt-in so existing agents keep working; the docs recommend a list for
  every secret and `STATUSTICK_REQUIRE_SECRET_HOSTS=true`. A host name in the list is trusted as written, so whoever
  controls its DNS controls where the secret goes; list addresses or ranges where that matters.
