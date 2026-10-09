# statustick-agent Helm chart

Runs the StatusTick private agent in Kubernetes: a Deployment with one agent pod for one private location, with a PodDisruptionBudget. The agent connects out to `agent.statustick.com` over HTTPS; nothing calls it from outside the cluster. The image is the same for every check type: browser checks need no other image or install, and Chromium runs only while a browser check runs.

## Install

Create a private location in StatusTick and copy its token. Put the token in a Secret (the chart never takes the token itself), then install the chart from GHCR:

```bash
kubectl create namespace statustick
kubectl create secret generic statustick-agent -n statustick --from-literal=token='sta_live_…'
helm install statustick-agent oci://ghcr.io/statustick/charts/statustick-agent --version 0.1.0 \
  -n statustick --set existingSecret.name=statustick-agent --set browser.isolation=true
```

Upgrade with `helm upgrade statustick-agent oci://ghcr.io/statustick/charts/statustick-agent --version <new version> -n statustick --reuse-values`. To rotate the token, update the Secret and restart the pods: `kubectl rollout restart -n statustick deploy/statustick-agent`.

One release is one agent with its own token, so `replicaCount` stays 1 and the chart refuses more: a second pod with the same token would stop the first (StatusTick keeps the newest connection; the older agent logs it, stops taking checks and turns not ready). For two agents, install the chart twice, under two release names with two agents' tokens; StatusTick spreads the location's checks over its agents. A replaced pod is the same agent again.

The pod gets a 512 MB in-memory `/dev/shm` for Chromium and no memory limit, because each browser run can use up to 2 GB. `BROWSER_CONCURRENCY` (through `extraEnv`) sets the browser runs on the machine and wins over the agent's setting in the dashboard; `0` turns browser checks off.

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

## Security

- The pods run as user `10001` with a read-only root file system, no privilege escalation, the `RuntimeDefault` seccomp profile and all capabilities dropped. They get no service account token, except with `discovery.enabled` (see below).
- `browser.isolation: true` runs each browser check as its own user, so a script cannot read the agent's token, its `STATUSTICK_SECRET_*` values or its files. It adds the `SETUID` and `SETGID` capabilities (all others stay dropped) and sets `allowPrivilegeEscalation: true`, which the helper that switches user needs; the agent itself stays user `10001`. The baseline Pod Security level allows this, the restricted level does not, so it is off by default: browser checks then run as the agent's user. Turn it on wherever the namespace allows it, or set "Browser runs" to Off for agents that should never run a script.
- Writable folders are `emptyDir` volumes: `/var/lib/statustick` (the offline buffer), `/tmp` (1 GiB, also each browser run's work folder) and `/dev/shm` (512 MiB, in memory).
- The only port is the health port. It answers `/healthz` and `/readyz` with `ok`, `paused` or `not connected to StatusTick` and nothing else. With `relay.enabled` the relay port is added (see below), and with `metrics.enabled` the metrics port, which serves only `GET /metrics`.

## Heartbeat relay

With `relay.enabled: true` jobs that cannot reach the internet ping the agents instead: `http://statustick-agent-relay.<namespace>.svc:8081/ping/<token>` (and `/start`, `/fail`), the path of the public ping URL. The Service sends pings to the agent's pod even while it is not ready (an agent is not ready while StatusTick is unreachable, and then buffers the pings); it forwards them to StatusTick. The Service is `ClusterIP` on purpose: keep the relay internal and never put it behind a public Ingress or a public `LoadBalancer`. For jobs outside the cluster, use an internal load balancer and restrict who can reach it. Behind a Service the rate limit of 600 pings a minute counts per connecting address, which kube-proxy can rewrite to a node address; keep that in mind with many jobs on one node. See "Heartbeat relay" in `docs/agent.md` for the answers and limits.

## Kubernetes service discovery

With `discovery.enabled: true` the agents watch the cluster's Services, and each Service with a `statustick.com/monitor` annotation gets a monitor in this location within a minute, checked by these agents:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: shop
  annotations:
    statustick.com/monitor: "http:/healthz"   # GET http://api.shop.svc:8080/healthz
    statustick.com/name: "Shop API"           # optional, default "shop/api"
    statustick.com/interval: "60"             # optional seconds (or "5m", "1h"), 30 to 86400, default 60
spec:
  ports:
    - name: http
      port: 8080
```

| Annotation value | Monitor |
| -- | -- |
| `http:/healthz` | HTTP `http://<service>.<namespace>.svc:<first port>/healthz` |
| `http:8081/ready`, `http:metrics/ready` | HTTP on port 8081, or on the Service port named `metrics` |
| `http` | HTTP `/` on the first port |
| `tcp:5432`, `tcp` | TCP connection to `<service>.<namespace>.svc:5432`, or to the first port |

Changing an annotation updates the monitor. Removing the annotation or the Service pauses the monitor; its history stays, and it resumes when the annotation comes back. Discovered monitors are marked as managed by Kubernetes in StatusTick: their check is changed only through the annotation, while alert settings (alert policy, notification delay, mute) stay editable in the dashboard. A location takes at most 100 discovered monitors unless StatusTick raised its limit; the agents log the Services over the limit.

RBAC: the chart adds a ServiceAccount and binds it to a ClusterRole (or, with `discovery.namespaces`, a Role in each listed namespace) that allows only `get`, `list` and `watch` on `services`; nothing else, and no Secrets. Only then does the pod mount a service account token (`automountServiceAccountToken: true`); with discovery off it stays `false`. The agents call the API server directly, never through `proxy.https`. With `statustick.allow`, add `*.svc` (or your Service CIDR) so the checks of discovered monitors are allowed.

Watch one cluster per location: agents of the same location in another cluster would pause each other's monitors. See "Kubernetes service discovery" in `docs/agent.md` for the details.

## Ping

Ping needs ICMP. A non-root process can send it only through unprivileged ICMP sockets, which the pod's `net.ipv4.ping_group_range` sysctl allows. `ping.enabled: true` sets it; it is a safe sysctl, allowed at every Pod Security level. Some runtimes (containerd 2, Docker) allow it by default already.

Where the agent gets no ICMP, it checks a TCP connection to port 443 of the host instead: a host that accepts or refuses the connection is up. It logs this once, and each such result says so in `details.note` (`details.method` is `tcp`).

`ping.netRaw: true` adds `NET_RAW` as well. Most runtimes do not give added capabilities to a non-root process, and the baseline and restricted Pod Security levels refuse it, so use it only when you know your runtime needs it.

## Offline buffer

The buffer is an `emptyDir`: it survives a container restart, not a pod replacement. You can keep it on a PersistentVolumeClaim (`buffer.persistence.enabled: true`); the Deployment then uses the `Recreate` strategy so two pods never share the volume. The volume holds the jobs the agent repeats offline, including HTTP request headers and bodies, so keep it private to the agent.

## Releases

The chart is published to `oci://ghcr.io/statustick/charts/statustick-agent` by release-please: merging its release pull request for the chart tags `chart-vX.Y.Z` and the `Release` workflow (`.github/workflows/release.yml`) pushes it. Pull requests and pushes to `main` run `helm lint` and an install test on kind (`.github/workflows/ci.yml`), and the agent's tests fail when `appVersion` is not the agent version in `version.txt`; release-please sets both, so the default image tag is always a released one.
