# statustick-agent Helm chart

Runs one StatusTick agent in Kubernetes: a Deployment with one pod and a PodDisruptionBudget. The agent connects out to `agent.statustick.com`; nothing calls it from outside the cluster.

## Install

Add an agent to a private location in StatusTick and copy its token. Put the token in a Secret, then install the chart:

```bash
kubectl create namespace statustick
kubectl create secret generic statustick-agent -n statustick --from-literal=token='sta_live_…'
helm install statustick-agent oci://ghcr.io/statustick/charts/statustick-agent \
  -n statustick --set existingSecret.name=statustick-agent --set browser.isolation=true
```

To upgrade, run `helm upgrade` with `--reuse-values`. To change the token, update the Secret and run `kubectl rollout restart -n statustick deploy/statustick-agent`.

One release is one agent, so the chart refuses more than one replica: a second pod with the same token would stop the first. For two agents, install the chart twice with two tokens.

Notes:

- `browser.isolation: true` runs each browser check as its own user, so a script cannot read the agent's token. It adds the `SETUID` and `SETGID` capabilities and allows privilege escalation, which the baseline Pod Security level allows and the restricted one does not. Without it, browser checks run as the agent's user.
- The pod has a 512 MB in-memory `/dev/shm` for Chromium and no memory limit, because a browser run can use up to 2 GB.
- `relay.enabled` adds a `ClusterIP` Service for the heartbeat relay. Keep it internal; never expose it through a public Ingress or load balancer.
- `discovery.enabled` adds a ServiceAccount that can only `get`, `list` and `watch` Services, and mounts its token. Without it, the pod gets no service account token.
- The offline buffer is an `emptyDir`. Set `buffer.persistence.enabled` to keep it on a volume.

See [the agent guide](https://github.com/statustick/agent/blob/main/docs/agent.md) for what each setting does.

## Values

<!-- settings:start -->
| Value | Default | What it does |
| -- | -- | -- |
| `replicaCount` | `1` | Agent replicas: must be 1, the chart refuses more. One release is one agent; for a second agent, install the chart again with that agent's token. |
| `image.repository` | `ghcr.io/statustick/agent` | The agent image. It runs every check type, browser checks included. |
| `image.tag` | the chart's `appVersion` | The image tag. |
| `image.pullPolicy` | `IfNotPresent` | The image pull policy. |
| `imagePullSecrets` | `[]` | Pull secrets for a mirrored image. |
| `nameOverride` | none | Replaces the chart name in resource names. |
| `fullnameOverride` | none | Replaces the full resource name. |
| `existingSecret.name` | none (required) | The Secret with the location token. |
| `existingSecret.key` | `token` | The key in that Secret. |
| `statustick.url` | `https://agent.statustick.com` | `STATUSTICK_URL`. |
| `statustick.concurrency` | unset (the dashboard's setting, `5` by default) | `STATUSTICK_CONCURRENCY`: checks at the same time, 1 to 50. Set here, it wins over the agent's "Max checks" in the dashboard. |
| `statustick.allow` | none | `STATUSTICK_ALLOW`: the only targets the agent checks, for example `10.0.0.0/8,*.corp.example`. |
| `statustick.bufferSize` | `10000` | Results kept while StatusTick is unreachable. |
| `health.port` | `8080` | `STATUSTICK_HEALTH_PORT`: `/healthz` and `/readyz` for the probes. |
| `relay.enabled` | `false` | Turns on the heartbeat relay (`STATUSTICK_RELAY_PORT`) and adds a `ClusterIP` Service, `<fullname>-relay` (`statustick-agent-relay` for the install command above). See "Heartbeat relay". |
| `relay.port` | `8081` | The relay's container port. |
| `relay.service.port` | `8081` | The relay Service port. |
| `relay.service.annotations` | none | The relay Service annotations. |
| `metrics.enabled` | `false` | Serves Prometheus metrics on `metrics.port` (`METRICS_PORT`) and adds a `ClusterIP` Service, `<fullname>-metrics`. |
| `metrics.port` | `9464` | The metrics container port. |
| `metrics.share` | unset | `STATUSTICK_SHARE_METRICS`: unset follows the agent's "Share health" setting in the dashboard, `true` always shares the agent's health with StatusTick, `false` never does. Works without `metrics.enabled`. |
| `metrics.service.port` | `9464` | The metrics Service port. |
| `metrics.service.annotations` | none | The metrics Service annotations. |
| `metrics.serviceMonitor.enabled` | `false` | Adds a `ServiceMonitor` for the Prometheus Operator. |
| `metrics.serviceMonitor.interval` | `30s` | How often Prometheus scrapes the agents. |
| `metrics.serviceMonitor.labels` | none | Labels for the `ServiceMonitor`, for example the one your Prometheus selects. |
| `discovery.enabled` | `false` | Turns on Kubernetes service discovery (`STATUSTICK_DISCOVERY=kubernetes`): annotated Services get monitors. Adds a ServiceAccount with read-only access to Services and mounts its token. See "Kubernetes service discovery". |
| `discovery.namespaces` | `[]` (every namespace) | `STATUSTICK_DISCOVERY_NAMESPACES`: only these namespaces, with a Role in each instead of a ClusterRole. |
| `livenessProbe` | `/healthz` | The liveness probe. |
| `readinessProbe` | `/readyz` | The readiness probe; `/readyz` fails while StatusTick has not answered for two minutes. |
| `resources` | requests 20m CPU, 64Mi; limit 500m CPU | Per replica. No memory limit: each browser run can use up to 2 GB. A limit needs room for the browser runs × 2 GB + 256 MB. |
| `browser.isolation` | `false` | Runs each browser check as its own user, so a script cannot read the agent's token or files. Adds the `SETUID` and `SETGID` capabilities and allows privilege escalation for the helper that switches user, so it is not allowed by the restricted Pod Security level (baseline allows it). See "Security". |
| `ping.enabled` | `false` | Allows ICMP for the non-root agent with the safe sysctl `net.ipv4.ping_group_range`. Off: the agent checks a TCP connection to port 443 instead of ping. See "Ping". |
| `ping.netRaw` | `false` | Also adds the `NET_RAW` capability, for runtimes that give it to non-root processes. Not allowed by the baseline or restricted Pod Security levels. |
| `proxy.https` | none | `HTTPS_PROXY`: the connection to StatusTick and HTTPS checks. |
| `proxy.http` | none | `HTTP_PROXY`: plain http checks. |
| `proxy.noProxy` | none | `NO_PROXY`, for example `.corp.example,10.0.0.0/8`. |
| `proxy.existingSecret.name` | none | `HTTPS_PROXY` from this Secret instead of `proxy.https`, for a proxy URL with a password. |
| `proxy.existingSecret.key` | `https-proxy` | The key in that Secret. |
| `extraCA.configMap` | none | The ConfigMap with the PEM file. |
| `extraCA.secret` | none | Or the Secret with the PEM file. |
| `extraCA.key` | `ca.pem` | The key of the PEM file. |
| `buffer.sizeLimit` | `128Mi` | Size of the `emptyDir` at `/var/lib/statustick` (`STATUSTICK_BUFFER_DIR`). It keeps the offline buffer across container restarts, not when the pod is replaced. |
| `buffer.persistence.enabled` | `false` | A PersistentVolumeClaim for the buffer instead, kept across pod replacements. |
| `buffer.persistence.existingClaim` | none | An existing claim to use instead of a new one. |
| `buffer.persistence.storageClass` | none | The storage class of the new claim. |
| `buffer.persistence.size` | `1Gi` | The size of the new claim. |
| `extraEnv` | `[]` | Extra environment variables, for example `STATUSTICK_SECRET_*` database passwords with `valueFrom.secretKeyRef`. |
| `podSecurityContext` | see "Security" | The pod security context. |
| `securityContext` | see "Security" | The container security context. |
| `podDisruptionBudget.enabled` | `true` | Adds a PodDisruptionBudget. Not-ready agents can always be evicted, so an outage of StatusTick does not block node drains. |
| `podDisruptionBudget.maxUnavailable` | `1` | Replicas that may be down at once. |
| `spreadAcrossNodes` | `true` | Prefers a different node for each replica. |
| `podAnnotations` | none | Pod annotations. |
| `podLabels` | none | Pod labels. |
| `nodeSelector` | none | The usual node selector. |
| `tolerations` | `[]` | The usual tolerations. |
| `affinity` | none | The usual affinity. |
| `priorityClassName` | none | The pod's priority class. |
<!-- settings:end -->
