# Agent security

The agent runs inside your network and takes check definitions from StatusTick over the internet. This page lists what it does, what it sends, the threats we designed against and the tests that cover them.

To report a problem, see [SECURITY.md](../SECURITY.md).

## What the agent does

- It only connects out: to `agent.statustick.com` and to the targets of its checks. It opens a port only if you set `STATUSTICK_HEALTH_PORT`, `STATUSTICK_RELAY_PORT` or `METRICS_PORT`.
- A job is data with a fixed schema per check type (`crates/agent/src/schema.rs`). Unknown fields are dropped, and no field is ever run as code or a shell command. The one exception is a browser check, which runs the customer's Playwright script in a sandbox.
- Only the result fields in `schema.rs` leave your network: status, timings, status codes, error texts and codes, and a few facts per check type. Never a response body, header value, cookie, query result, MCP tool description or server message. A database check sends one compared value, up to 200 characters, and only when the monitor has an expected value.
- At connect it sends the host name, OS, architecture, install type, memory and CPU limits, Chromium state and the names, not values, of three settings.
- It shares metrics with StatusTick only when you turn that on. Labels come from fixed sets only.

## Threats

| Threat | Mitigation | Tests |
| -- | -- | -- |
| Stolen agent token | A token belongs to one agent and can only lease that agent's jobs and post their results. Using it on a second machine stops the first. Owners and admins can rotate or revoke it. | `contract.rs` `logs_a_rejected_token_once_keeps_retrying_and_never_says_goodbye` |
| StatusTick itself is compromised | It could send any check. `STATUSTICK_ALLOW` limits targets on your side, cloud metadata is refused, and only the documented result fields come back. | `checks/tests/targets.rs`; `schema.rs` `keeps_only_documented_result_fields` |
| Man in the middle | `STATUSTICK_URL` must be `https`. The agent verifies the certificate chain and host name. `NODE_EXTRA_CA_CERTS` only adds trusted CAs. | `settings.rs` `refuses_wrong_values_with_the_operator_messages` |
| Huge or slow responses | At most 5 MB of a response is read. The check timeout covers connecting, headers and the body. | `engine.rs` `http` |
| Redirects into internal or metadata addresses | Redirects are followed by hand, at most 5. Each hop goes through the target rules again. | `engine.rs` `http` |
| DNS rebinding | A host is resolved once, and the check connects to the address that passed the target rules. | `checks/tests/targets.rs` |
| Database credentials | A job can only name variables that start with `STATUSTICK_SECRET_`. A secret with a `_HOSTS` list is only sent to those hosts. Custom queries run read-only and are rolled back. Passwords are removed from error texts. | `database.rs` `reads_secrets_only_from_statustick_secret_variables_and_their_hosts`; `contract.rs` `databases_log_in_run_the_read_only_query_and_report_failures_with_their_codes` |
| Offline buffer on disk | Only with `STATUSTICK_BUFFER_DIR`. Files are mode `0600`. Database passwords and MCP auth headers are never written. The buffer has a size limit. | `buffer.rs` `never_writes_a_password_or_auth_header_value_to_disk` |
| Browser script reaching other hosts | Each run's browser goes through a proxy that applies the target rules. In the script's Node process, a guard refuses every connection, DNS lookup and UDP socket except to that proxy, and refuses listening. | `browser.rs` `refuses_cloud_metadata_and_targets_outside_statustick_allow`; `sandbox/test/guard.test.ts` |
| Browser script reading the agent's token | Each run starts with an empty environment and runs as its own user (`run1` to `run8`). The kernel keeps it away from the agent's environment, files and other runs. After the run, all its processes and files are removed. | `browser.rs` `runs_as_a_run_user_without_the_agent_environment`; `scripts/agent-isolation.sh` |
| MCP auth header | Sent only to the job's URL. Never logged, put in a result or written to disk. | `mcp.rs` `checks_the_request_without_quoting_the_auth_value` |
| Heartbeat relay | Off by default. It only forwards tokens on the list StatusTick sent, which holds hashes, not tokens. It has a rate limit per address, a 10 KB body limit and short timeouts. | `relay.rs`; `contract.rs` `answers_health_relays_listed_pings_and_serves_only_its_own_metric_names` |
| Kubernetes discovery | Off by default. The service account can only read Services. Targets must be the Service's own cluster name. | `kubernetes.rs` `makes_monitors_from_annotations` |

The test names are in `crates/*/src` and `crates/*/tests`.

## Kubernetes

The Helm chart runs the agent as user `10001` with a read-only root file system, the `RuntimeDefault` seccomp profile and all capabilities dropped. `browser.isolation: true` adds `SETUID` and `SETGID` and allows privilege escalation, for the helper that switches each browser run to its own user. That fits the baseline Pod Security level, not the restricted one, so it is off by default.

## Known limits

- The guard in a browser script's process is not a kernel boundary. A script that reaches Playwright's internals could talk to the browser directly and get around the proxy. A network namespace per run would close this, but needs privileges the documented setups don't grant. Turn browser runs off on agents that should never run a script.
- Where the container doesn't allow switching users, browser runs share the agent's user and could read its token. The agent logs this at start.
- The relay port has no authentication beyond the ping token. Keep it on an internal network.
- `jobs.json` in the buffer folder holds HTTP headers and bodies of repeated checks, which can contain API keys. Keep the folder private.
- A secret without a `_HOSTS` list can be sent to another host by a compromised StatusTick. Use a list for every secret, and `STATUSTICK_REQUIRE_SECRET_HOSTS=true`.
- An MCP auth header is stored in StatusTick. Whoever can change the monitor's URL can send it to another allowed host.
- There has been no external security review yet.
