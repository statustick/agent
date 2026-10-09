#!/bin/sh
# Checks browser-run isolation in the agent image with the documented Docker flags (only SETUID and SETGID): the helper
# that switches user has its two file capabilities, the agent logs that runs are isolated, and a run's user cannot read
# the agent's environment.
set -eu

image="$1"
name=agent-isolation
line='Browser runs are isolated: each runs as its own user.'
fail() { echo "FAIL: $1"; exit 1; }
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

caps=$(docker run --rm -u 0 --entrypoint getcap "$image" /usr/local/bin/statustick-run-as)
echo "$caps"
case "$caps" in
  *cap_setgid,cap_setuid=ep*) ;;
  *) fail "statustick-run-as lacks its SETUID and SETGID file capabilities" ;;
esac

# Nothing listens on port 9, so the agent stays idle as the container's main process.
docker run -d --name "$name" --shm-size 512m --cap-drop ALL --cap-add SETUID --cap-add SETGID \
  -e STATUSTICK_TOKEN=sta_live_isolation_check \
  -e STATUSTICK_URL=http://127.0.0.1:9 \
  "$image" >/dev/null
for _ in $(seq 1 30); do
  docker logs "$name" 2>&1 | grep -qF "$line" && break
  sleep 1
done
docker logs "$name" 2>&1 | grep -qF "$line" || { docker logs "$name"; fail "the agent did not log: $line"; }
echo "$line"

docker exec "$name" grep -q STATUSTICK_TOKEN /proc/1/environ || fail "the agent's own user cannot read /proc/1/environ, so the next check proves nothing"
if docker exec -u 10101 "$name" cat /proc/1/environ >/dev/null 2>&1; then fail "a browser run's user can read /proc/1/environ"; fi
agent=$(docker exec "$name" sh -c "awk '\$4 == 1 { print \$1 }' /proc/[0-9]*/stat 2>/dev/null" | head -1)
if docker exec -u 10101 "$name" cat "/proc/$agent/environ" >/dev/null 2>&1; then fail "a browser run's user can read the agent's environment"; fi
echo "A browser run's user cannot read the agent's environment."
