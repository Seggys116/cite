#!/usr/bin/env bash
# End-to-end run on the mock profile: deploys, rollback, faults, health gate, crash fallback, warm grace, poll intervals.
set -euo pipefail

# Pin the default so a leftover value in the environment does not turn polling on.
export CITE_POLL_INTERVAL=off

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT=cite-e2e
# shellcheck source=layout-watch.sh
source "$ROOT/scripts/layout-watch.sh"
PORT="${CITE_PORT:-18081}"
MOCK_TOKEN='ghp_citeMockGithubPat00000000000000001'

fail() {
  echo "e2e-first-deploy FAIL: $*" >&2
  if [[ -n "${PROBE_PID:-}" ]]; then
    touch target/e2e-probe-stop 2>/dev/null || true
    kill "$PROBE_PID" 2>/dev/null || true
  fi
  if [[ -n "${MGR:-}" ]]; then
    docker logs "$MGR" --tail 80 >&2 || true
  fi
  exit 1
}

listen_ports() {
  local exec_id
  exec_id="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=executor" --format '{{.ID}}' | head -n1)"
  docker exec "$exec_id" /nodejs/bin/node -e '
const fs = require("fs");
const lines = fs.readFileSync("/proc/net/tcp", "utf8").trim().split("\n").slice(1);
const ports = [];
for (const line of lines) {
  const parts = line.trim().split(/\s+/);
  if (parts.length < 4 || parts[3] !== "0A") continue;
  ports.push(parseInt(parts[1].split(":")[1], 16));
}
process.stdout.write(ports.sort((a, b) => a - b).join(","));
'
}

cd "$ROOT"
mkdir -p target
rm -f target/e2e-layout-violations
LAYOUT_SAMPLES=0

export CITE_GITHUB_TOKEN="$MOCK_TOKEN"
export CITE_PORT="$PORT"
compose() {
  docker compose -p "$PROJECT" -f docker-compose.dev.yml -f docker-compose.e2e.yml -f docker-compose.e2e-static.yml --profile mock "$@"
}

stop_layout_watch
compose down --remove-orphans >/dev/null 2>&1 || true
docker volume rm -f "${PROJECT}_cite_data" >/dev/null 2>&1 || true
docker volume create "${PROJECT}_cite_data" >/dev/null

compose up -d --no-build manager mock-github
compose up -d --no-build executor
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
[[ -n "$MGR" ]] || fail "manager did not start"

for _ in $(seq 1 40); do
  if docker exec "$MGR" test -s /var/lib/cite/status/executor.json; then
    break
  fi
  sleep 0.5
done
docker exec "$MGR" test -s /var/lib/cite/status/executor.json || fail "executor never wrote status"
start_layout_watch

docker exec "$MGR" cite-manager poll || fail "first poll failed"
for _ in $(seq 1 40); do
  if curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/" 2>/dev/null | grep -q 'v1'; then
    break
  fi
  sleep 0.5
done
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "published port did not serve"
printf '%s\n' "$body" | grep -q 'v1' || fail "first release was not v1: $body"
echo "first boot: $body"
ports="$(listen_ports)"
case ",$ports," in
  *,3001,*|*,3002,*) fail "static release listened on a slot port: $ports" ;;
esac
echo "static listen ports: ${ports:-none}"

docker exec "$MGR" node -e '
fetch("http://mock-github:8080/__cite/push", {
  method: "POST",
  headers: {
    Authorization: "Bearer " + process.argv[1],
    "content-type": "application/json"
  },
  body: JSON.stringify({
    branch: "main",
    message: "v2",
    author: "tester",
    files: { "index.html": "<html>v2</html>" }
  })
}).then(async (res) => {
  const text = await res.text();
  if (!res.ok) { console.error(text); process.exit(1); }
  console.log(text);
}).catch((err) => { console.error(err); process.exit(1); });
' "$MOCK_TOKEN" || fail "mock push failed"

docker exec "$MGR" cite-manager poll || fail "second poll failed"
for _ in $(seq 1 40); do
  if curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/" 2>/dev/null | grep -q 'v2'; then
    break
  fi
  sleep 0.5
done
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "second release was not reachable"
printf '%s\n' "$body" | grep -q 'v2' || fail "second release was not v2: $body"
echo "second push: $body"

slots="$(docker exec "$MGR" ls /var/lib/cite/releases)"
echo "slots: $slots"
printf '%s\n' "$slots" | grep -q blue
printf '%s\n' "$slots" | grep -q green

release_hashes() {
  docker exec "$MGR" node -e '
const crypto = require("crypto");
const fs = require("fs");
for (const slot of ["blue", "green"]) {
  const path = "/var/lib/cite/releases/" + slot + "/release.json";
  if (!fs.existsSync(path)) continue;
  const digest = crypto.createHash("sha256").update(fs.readFileSync(path)).digest("hex");
  console.log(slot + " " + digest);
}
'
}

assert_two_slots() {
  docker exec "$MGR" node -e '
const fs = require("fs");
const releases = fs.readdirSync("/var/lib/cite/releases");
const extra = releases.filter((name) => name !== "blue" && name !== "green");
if (extra.length) {
  console.error("unexpected release path " + extra.join(","));
  process.exit(1);
}
for (const slot of releases) {
  for (const child of fs.readdirSync("/var/lib/cite/releases/" + slot)) {
    if (child !== "app" && child !== "release.json" && !/^\..+\.tmp\.\d+\.[0-9a-f]+$/.test(child)) {
      console.error("unexpected path in " + slot + ": " + child);
      process.exit(1);
    }
  }
}
const jobs = fs.readdirSync("/var/lib/cite/work").filter((name) => name.startsWith("job-"));
if (jobs.length) {
  console.error("job dir left: " + jobs.join(","));
  process.exit(1);
}
' || fail "volume layout"
}

push_files() {
  docker exec "$MGR" node -e '
fetch("http://mock-github:8080/__cite/push", {
  method: "POST",
  headers: {
    Authorization: "Bearer " + process.argv[1],
    "content-type": "application/json"
  },
  body: process.argv[2]
}).then(async (res) => {
  const text = await res.text();
  if (!res.ok) { console.error(text); process.exit(1); }
  console.log(text);
}).catch((err) => { console.error(err); process.exit(1); });
' "$MOCK_TOKEN" "$1" || fail "mock push failed"
}


sealed_before="$(release_hashes)"
push_files '{"branch":"main","message":"broken","author":"tester","files":{"build.js":"process.exit(1)\n"}}'
set +e
fail_out="$(docker exec "$MGR" cite-manager poll 2>&1)"
fail_code=$?
set -e
[[ "$fail_code" -ne 0 ]] || fail "failing build was accepted: $fail_out"
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "site died after the failed build"
printf '%s\n' "$body" | grep -q 'v2' || fail "failed build changed the live site: $body"
sealed_after="$(release_hashes)"
[[ "$sealed_before" == "$sealed_after" ]] || fail "failed build changed a sealed slot: $sealed_after"
failed_sha="$(docker exec "$MGR" node -e 'const s=JSON.parse(require("fs").readFileSync("/var/lib/cite/state/state.json","utf8")); if (!s.last_failed_sha) process.exit(1); process.stdout.write(s.last_failed_sha);')" \
  || fail "last_failed_sha was not recorded"
echo "failed build kept v2; last_failed_sha=$failed_sha"
assert_two_slots

good_build="const fs=require('fs');fs.mkdirSync('dist',{recursive:true});fs.copyFileSync('index.html','dist/index.html');"
V4_SHA=""
for version in v3 v4; do
  push_out="$(push_files "$(printf '{"branch":"main","message":"%s","author":"tester","files":{"index.html":"<html>%s</html>","build.js":"%s"}}' "$version" "$version" "$good_build")")"
  printf '%s\n' "$push_out"
  if [[ "$version" == v4 ]]; then
    V4_SHA="$(printf '%s' "$push_out" | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{process.stdout.write(JSON.parse(s).sha)})')"
  fi
  docker exec "$MGR" cite-manager poll || fail "$version poll failed"
  for _ in $(seq 1 40); do
    if curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/" 2>/dev/null | grep -q "$version"; then
      break
    fi
    sleep 0.5
  done
  body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "$version was not reachable"
  printf '%s\n' "$body" | grep -q "$version" || fail "expected $version, got $body"
  assert_two_slots
  echo "deploy $version: $body"
done
[[ -n "$V4_SHA" ]] || fail "did not record the v4 sha"

# Four ordered request streams across the v4 to v5 switch: each flips once, no bad response, at least 50/s in total.
rm -f target/e2e-probe-stop target/e2e-probe.jsonl target/e2e-probe-rate
node -e '
const http = require("http");
const fs = require("fs");
const port = Number(process.argv[1]);
const out = fs.createWriteStream("target/e2e-probe.jsonl");
function once(agent) {
  return new Promise((resolve) => {
    const req = http.get({ host: "127.0.0.1", port, path: "/", agent }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ ok: res.statusCode === 200, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", (err) => resolve({ ok: false, body: err.message }));
  });
}
async function worker(id) {
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  let n = 0;
  while (!fs.existsSync("target/e2e-probe-stop")) {
    const row = await once(agent);
    row.worker = id;
    n += 1;
    out.write(JSON.stringify(row) + "\n");
  }
  return n;
}
(async () => {
  const started = Date.now();
  const counts = await Promise.all([0, 1, 2, 3].map(worker));
  const n = counts.reduce((a, b) => a + b, 0);
  const elapsed = Math.max((Date.now() - started) / 1000, 0.001);
  fs.writeFileSync("target/e2e-probe-rate", String(n / elapsed));
  out.end(() => process.exit(0));
})().catch((err) => { console.error(err); process.exit(1); });
' "$PORT" &
PROBE_PID=$!
push_files "$(printf '{"branch":"main","message":"v5","author":"tester","files":{"index.html":"<html>v5</html>","build.js":"%s"}}' "$good_build")"
docker exec "$MGR" cite-manager poll || fail "v5 poll failed"
touch target/e2e-probe-stop
wait "$PROBE_PID" || fail "request probe exited badly"
PROBE_PID=""
node -e '
const fs = require("fs");
const from = process.argv[1];
const to = process.argv[2];
const lines = fs.readFileSync("target/e2e-probe.jsonl", "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
const rate = Number(fs.readFileSync("target/e2e-probe-rate", "utf8"));
if (!(rate >= 50)) {
  console.error("request rate " + rate);
  process.exit(1);
}
const phase = {};
const flips = {};
let sawFrom = false;
let sawTo = false;
for (const row of lines) {
  if (!row.ok || (row.body !== from && row.body !== to)) {
    console.error("bad response " + JSON.stringify(row));
    process.exit(1);
  }
  const w = row.worker;
  phase[w] = phase[w] || "from";
  flips[w] = flips[w] || 0;
  if (row.body === from) {
    sawFrom = true;
    if (phase[w] !== "from") {
      console.error("version flipped back on worker " + w);
      process.exit(1);
    }
  } else {
    sawTo = true;
    if (phase[w] === "from") {
      phase[w] = "to";
      flips[w] += 1;
    }
  }
}
if (!sawFrom || !sawTo || Object.values(flips).some((f) => f > 1)) {
  console.error("flips=" + JSON.stringify(flips) + " from=" + sawFrom + " to=" + sawTo + " n=" + lines.length);
  process.exit(1);
}
console.log("request loop: " + lines.length + " responses at " + rate.toFixed(1) + "/s, at most one flip per stream");
' "<html>v4</html>" "<html>v5</html>" || fail "zero-failed-request check"
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "v5 was not reachable"
printf '%s\n' "$body" | grep -q 'v5' || fail "expected v5, got $body"
assert_two_slots
echo "deploy v5: $body"

docker exec "$MGR" cite-manager rollback || fail "rollback failed"
for _ in $(seq 1 40); do
  if curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/" 2>/dev/null | grep -q 'v4'; then
    break
  fi
  sleep 0.5
done
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "rollback was not reachable"
printf '%s\n' "$body" | grep -q 'v4' || fail "rollback did not serve v4: $body"
echo "rollback: $body"
assert_two_slots

docker exec "$MGR" cite-manager pause || fail "pause failed"
paused="$(docker exec "$MGR" node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync("/var/lib/cite/state/state.json","utf8")).paused))')"
[[ "$paused" == "true" ]] || fail "pause did not stick: $paused"
docker exec "$MGR" cite-manager resume || fail "resume failed"
paused="$(docker exec "$MGR" node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync("/var/lib/cite/state/state.json","utf8")).paused))')"
[[ "$paused" == "false" ]] || fail "resume did not clear pause: $paused"
echo "pause/resume ok"

docker exec "$MGR" cite-manager restart-child || fail "restart-child failed"
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "site died after restart-child"
printf '%s\n' "$body" | grep -q 'v4' || fail "restart-child changed the live site: $body"
echo "restart-child kept: $body"

slot_before="$(docker exec "$MGR" node -e 'const s=JSON.parse(require("fs").readFileSync("/var/lib/cite/status/executor.json","utf8")); process.stdout.write(s.active_slot||"");')"
EXEC="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=executor" --format '{{.ID}}' | head -n1)"
started="$(docker inspect -f '{{.State.StartedAt}}' "$EXEC")"
docker exec "$MGR" cite-manager restart-executor || fail "restart-executor failed"
for _ in $(seq 1 40); do
  now="$(docker inspect -f '{{.State.StartedAt}}' "$EXEC" 2>/dev/null || true)"
  if [[ -n "$now" && "$now" != "$started" ]]; then
    break
  fi
  sleep 0.25
done
now="$(docker inspect -f '{{.State.StartedAt}}' "$EXEC")"
[[ "$now" != "$started" ]] || fail "executor container did not restart"
for _ in $(seq 1 40); do
  if curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/" 2>/dev/null | grep -q 'v4'; then
    break
  fi
  sleep 0.5
done
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "site did not return after executor restart"
printf '%s\n' "$body" | grep -q 'v4' || fail "executor restart changed the site: $body"
slot_after="$(docker exec "$MGR" node -e 'const s=JSON.parse(require("fs").readFileSync("/var/lib/cite/status/executor.json","utf8")); process.stdout.write(s.active_slot||"");')"
[[ "$slot_before" == "$slot_after" && -n "$slot_after" ]] || fail "live slot changed across restart: $slot_before -> $slot_after"
echo "restart-executor: container restarted, slot $slot_after still $body"

docker exec "$MGR" cite-manager redeploy || fail "redeploy of head failed"
for _ in $(seq 1 40); do
  if curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/" 2>/dev/null | grep -q 'v5'; then
    break
  fi
  sleep 0.5
done
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "redeploy head was not reachable"
printf '%s\n' "$body" | grep -q 'v5' || fail "redeploy head was not v5: $body"
echo "redeploy head: $body"
assert_two_slots

docker exec "$MGR" cite-manager redeploy --sha "$V4_SHA" || fail "redeploy --sha failed"
for _ in $(seq 1 40); do
  if curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/" 2>/dev/null | grep -q 'v4'; then
    break
  fi
  sleep 0.5
done
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "redeploy --sha was not reachable"
printf '%s\n' "$body" | grep -q 'v4' || fail "redeploy --sha was not v4: $body"
echo "redeploy --sha $V4_SHA: $body"
assert_two_slots

live_before="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")"
harvest_layout_watch
docker compose -p "$PROJECT" -f docker-compose.dev.yml -f docker-compose.e2e.yml -f docker-compose.e2e-ssr.yml --profile mock up -d --no-build --force-recreate manager
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
[[ -n "$MGR" ]] || fail "manager did not return for the SSR phase"
for _ in $(seq 1 40); do
  if docker exec "$MGR" cite-manager healthcheck >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
docker exec "$MGR" cite-manager healthcheck >/dev/null 2>&1 || fail "manager not healthy after SSR recreate"
start_layout_watch
deaf_build="const fs=require('fs');fs.writeFileSync('server.js','setInterval(()=>{},1e9);');"
push_files "$(node -e 'process.stdout.write(JSON.stringify({branch:"main",message:"deaf",author:"tester",files:{"build.js":process.argv[1]}}))' "$deaf_build")"
health_out="$(docker exec "$MGR" cite-manager poll 2>&1)" || fail "health-gate poll errored: $health_out"
printf '%s\n' "$health_out" | grep -q '"outcome": "failed"' || fail "silent server was promoted: $health_out"
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "site died after the health-gate failure"
[[ "$body" == "$live_before" ]] || fail "health-gate failure changed the live site: $body"
echo "health-gate failure kept: $body"

deploy_ssr() {
  local label="$1"
  local build
  build="$(node -e 'const label=process.argv[1]; const server="const http=require(\"http\");http.createServer((q,s)=>s.end(\"<html>"+label+"</html>\")).listen(process.env.PORT,\"127.0.0.1\");"; process.stdout.write("const fs=require(\"fs\");fs.writeFileSync(\"server.js\","+JSON.stringify(server)+");");' "$label")"
  push_files "$(node -e 'process.stdout.write(JSON.stringify({branch:"main",message:process.argv[2],author:"tester",files:{"build.js":process.argv[1]}}))' "$build" "$label")"
  docker exec "$MGR" cite-manager poll || fail "$label poll failed"
  for _ in $(seq 1 40); do
    if curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/" 2>/dev/null | grep -q "<html>${label}</html>"; then
      break
    fi
    sleep 0.5
  done
  body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "$label was not reachable"
  printf '%s\n' "$body" | grep -q "<html>${label}</html>" || fail "expected $label, got $body"
  echo "ssr live: $body"
}
deploy_ssr ssr-a
deploy_ssr ssr-b
ports="$(listen_ports)"
case ",$ports," in
  *,3001,*) ;;
  *) fail "blue SSR port 3001 was not listening: $ports" ;;
esac
case ",$ports," in
  *,3002,*) ;;
  *) fail "green SSR port 3002 was not listening: $ports" ;;
esac
echo "ssr listen ports: $ports"

previous_page="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")"
crash_build=$(cat <<'EOF'
const fs=require('fs');
fs.writeFileSync('server.js', 'const http=require("http");http.createServer((q,s)=>s.end("<html>crash</html>")).listen(process.env.PORT,"127.0.0.1",()=>setTimeout(()=>process.exit(1),2000));');
EOF
)
push_files "$(node -e 'process.stdout.write(JSON.stringify({branch:"main",message:"crash",author:"tester",files:{"build.js":process.argv[1]}}))' "$crash_build")"
crash_out="$(docker exec "$MGR" cite-manager poll 2>&1)" || fail "crash deploy poll errored: $crash_out"
printf '%s\n' "$crash_out" | grep -q '"outcome": "live"' || fail "crashing server was not promoted: $crash_out"
fell_back=0
for _ in $(seq 1 40); do
  body="$(curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/" 2>/dev/null || true)"
  if [[ "$body" == "$previous_page" ]]; then
    fell_back=1
    break
  fi
  sleep 0.25
done
[[ "$fell_back" == 1 ]] || fail "crash did not fall back to the warm page: $body"
fallback="$(docker exec "$MGR" node -e 'const s=JSON.parse(require("fs").readFileSync("/var/lib/cite/status/executor.json","utf8")); process.stdout.write((s.last_result&&s.last_result.outcome)||"");')"
[[ "$fallback" == "fallback" ]] || fail "executor did not record fallback: $fallback"
echo "crash fallback: $body ($fallback)"
assert_two_slots

harvest_layout_watch
docker compose -p "$PROJECT" -f docker-compose.dev.yml -f docker-compose.e2e.yml -f docker-compose.e2e-grace.yml --profile mock up -d --no-build --force-recreate manager
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
[[ -n "$MGR" ]] || fail "manager did not return for the warm-grace phase"
for _ in $(seq 1 40); do
  if docker exec "$MGR" cite-manager healthcheck >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
docker exec "$MGR" cite-manager healthcheck >/dev/null 2>&1 || fail "manager not healthy after warm-grace recreate"
start_layout_watch
push_files "$(printf '{"branch":"main","message":"v7","author":"tester","files":{"index.html":"<html>v7</html>","build.js":"%s"}}' "$good_build")"
docker exec "$MGR" cite-manager poll || fail "v7 poll failed"
for _ in $(seq 1 40); do
  if curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/" 2>/dev/null | grep -q 'v7'; then
    break
  fi
  sleep 0.5
done
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "v7 was not reachable"
printf '%s\n' "$body" | grep -q 'v7' || fail "expected v7, got $body"
stopped=0
for _ in $(seq 1 30); do
  other="$(docker exec "$MGR" node -e 'const s=JSON.parse(require("fs").readFileSync("/var/lib/cite/status/executor.json","utf8")); const other=s.active_slot==="blue"?"green":"blue"; process.stdout.write(s.slots[other].state);')"
  if [[ "$other" == "stopped" ]]; then
    stopped=1
    break
  fi
  sleep 0.25
done
[[ "$stopped" == 1 ]] || fail "previous slot did not stop after the warm grace: $other"
docker exec "$MGR" node -e '
const fs = require("fs");
for (const slot of ["blue", "green"]) {
  if (!fs.existsSync("/var/lib/cite/releases/" + slot + "/release.json")) process.exit(1);
}
' || fail "a sealed release disappeared when the warm slot stopped"
docker exec "$MGR" cite-manager rollback || fail "cold rollback failed"
for _ in $(seq 1 40); do
  if [[ "$(curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/" 2>/dev/null || true)" == "$previous_page" ]]; then
    break
  fi
  sleep 0.5
done
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "cold rollback was not reachable"
[[ "$body" == "$previous_page" ]] || fail "cold rollback did not serve the stopped release: $body"
echo "cold rollback after warm grace: $body"

clear_next_poll() {
  harvest_layout_watch
  compose stop manager >/dev/null
  docker run --rm --entrypoint node -v "${PROJECT}_cite_data:/data" cite-manager:dev -e '
const fs = require("fs");
const path = "/data/state/state.json";
const state = JSON.parse(fs.readFileSync(path, "utf8"));
state.next_poll_at = null;
fs.writeFileSync(path, JSON.stringify(state));
'
}
read_next_poll() {
  docker exec "$MGR" node -e 'const s=JSON.parse(require("fs").readFileSync("/var/lib/cite/state/state.json","utf8")); process.stdout.write(s.next_poll_at||"");'
}
wait_manager() {
  MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
  [[ -n "$MGR" ]] || fail "manager did not return"
  for _ in $(seq 1 40); do
    if docker exec "$MGR" cite-manager healthcheck >/dev/null 2>&1; then
      start_layout_watch
      return 0
    fi
    sleep 0.5
  done
  fail "manager not healthy"
}
for spec in "1m 60" "5m 300" "15m 900" "1h 3600" "1d 86400" "off 0"; do
  interval="${spec%% *}"
  seconds="${spec##* }"
  clear_next_poll
  CITE_POLL_INTERVAL="$interval" compose up -d --no-build --force-recreate manager >/dev/null
  wait_manager
  if [[ "$interval" == off ]]; then
    sleep 1
    next="$(read_next_poll)"
    [[ -z "$next" ]] || fail "off still scheduled a poll: $next"
    echo "poll off: unscheduled"
    continue
  fi
  next=""
  for _ in $(seq 1 40); do
    next="$(read_next_poll)"
    [[ -n "$next" ]] && break
    sleep 0.25
  done
  [[ -n "$next" ]] || fail "$interval did not schedule a poll"
  node -e '
const at = Date.parse(process.argv[1]);
const secs = Number(process.argv[2]);
const delta = (at - Date.now()) / 1000;
const low = secs * 0.8 - 15;
const high = secs * 1.2;
if (!(delta >= low && delta <= high)) {
  console.error(process.argv[3] + " next poll in " + delta.toFixed(1) + "s");
  process.exit(1);
}
console.log(process.argv[3] + " next poll in " + delta.toFixed(1) + "s");
' "$next" "$seconds" "$interval" || fail "poll interval $interval"
done

harvest_layout_watch
if [[ -s target/e2e-layout-violations ]]; then
  fail "layout watch saw: $(cat target/e2e-layout-violations)"
fi
[[ "$LAYOUT_SAMPLES" -ge 50 ]] || fail "layout watch only sampled $LAYOUT_SAMPLES times"
echo "layout watch: $LAYOUT_SAMPLES samples, only blue and green"

"$ROOT/scripts/assert-hardening.sh" "$PROJECT" || fail "hardening assertions failed"
"$ROOT/scripts/assert-shellless.sh" --compose "$PROJECT" || fail "executor is not shell-less"
stop_layout_watch
compose down -v --remove-orphans >/dev/null
docker volume rm -f "${PROJECT}_cite_data" >/dev/null 2>&1 || true
echo "e2e-first-deploy OK"
