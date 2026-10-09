#!/bin/sh
# Runs two browser checks in the agent image and fails when a process is left as a zombie.
set -eu

image="$1"
name=agent-zombies
fail() { echo "FAIL: $1"; exit 1; }
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

# Nothing listens on port 9, so the agent stays idle as the container's main process, as in production.
docker run -d --name "$name" --read-only --tmpfs /tmp --shm-size 512m --cap-drop ALL \
  -e STATUSTICK_TOKEN=sta_live_zombie_check \
  -e STATUSTICK_URL=http://127.0.0.1:9 \
  "$image" >/dev/null
sleep 3

# The runs are exec'd into the container: when their processes end, Chromium's leftover helpers go to the container's PID 1.
job='{"fileName":"check.spec.ts","maxArtifactBytes":1048576,"script":"import { test } from \"@playwright/test\";\ntest(\"page\", async ({ page }) => { await page.setContent(\"<p>ok</p>\"); });"}'
for run in 1 2; do
  out=$(printf '%s' "$job" | docker exec -i -e ST_WORK_DIR="/tmp/zombie-run-$run" -e PLAYWRIGHT_BROWSERS_PATH=/ms-playwright "$name" node /runner/run.mts) || true
  printf '%s' "$out" | grep -q '"status":"passed"' || { printf '%s\n' "$out" | head -c 2000; fail "browser run $run did not pass"; }
done
sleep 3

zombies=$(docker exec "$name" sh -c "grep -l '^State:[[:space:]]*Z' /proc/[0-9]*/status 2>/dev/null | wc -l")
echo "Zombie processes after two browser runs: $zombies"
[ "$zombies" -eq 0 ] || { docker exec "$name" sh -c "grep -l '^State:[[:space:]]*Z' /proc/[0-9]*/status | xargs grep -H '^Name\|^PPid'" || true; fail "browser runs left zombie processes"; }
[ "$(docker inspect --format '{{.State.Running}}' "$name")" = "true" ] || { docker logs "$name"; fail "agent stopped"; }
echo "No zombie processes."
