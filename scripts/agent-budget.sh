#!/bin/sh
# Checks the agent image against the resource budget on the machine that runs it.
set -eu

image="$1"
name=agent-budget
fail() { echo "FAIL: $1"; exit 1; }
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

compressed=$(docker save "$image" | gzip -c | wc -c)
echo "Compressed image: $((compressed / 1024)) KB"
[ "$compressed" -lt $((400 * 1024 * 1024)) ] || fail "compressed image is 400 MB or more"

user=$(docker image inspect --format '{{.Config.User}}' "$image")
[ -n "$user" ] && [ "$user" != "root" ] && [ "$user" != "0" ] || fail "image runs as root"
[ "$(docker image inspect --format '{{json .Config.ExposedPorts}}' "$image")" = "null" ] || fail "image exposes a port"

# Nothing listens on port 9, so the agent stays in its reconnect backoff: the idle state.
docker run -d --name "$name" --read-only \
  -e STATUSTICK_TOKEN=sta_live_budget_check \
  -e STATUSTICK_URL=http://127.0.0.1:9 \
  "$image" >/dev/null
sleep 10

# tini is PID 1; the agent is its only child.
pid=$(docker exec "$name" sh -c "awk '\$4 == 1 { print \$1 }' /proc/[0-9]*/stat 2>/dev/null" | head -1)
[ -n "$pid" ] || fail "agent process not found"
ticks() { docker exec "$name" cat "/proc/$pid/stat" | awk '{ print $14 + $15 }'; }
before=$(ticks)
sleep 30
after=$(ticks)
[ "$(docker inspect --format '{{.State.Running}}' "$name")" = "true" ] || { docker logs "$name"; fail "agent stopped"; }

# 1% of one core for 30 s is 0.3 s, which is 30 ticks at the usual 100 per second.
echo "CPU over 30 s: $((after - before)) ticks"
[ $((after - before)) -le 30 ] || fail "idle CPU is over 1% of one core"

rss_kb=$(docker exec "$name" awk '/^VmRSS/ { print $2 }' "/proc/$pid/status")
echo "Idle RSS: $((rss_kb / 1024)) MB"
[ "$rss_kb" -lt $((64 * 1024)) ] || fail "idle memory is 64 MB or more"

docker logs "$name"
echo "Agent image is within the budget."
