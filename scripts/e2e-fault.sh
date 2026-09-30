#!/usr/bin/env bash
# Fault injection on the mock stack: after each fault the previous page is still served and no job directory is left.
set -euo pipefail

export CITE_POLL_INTERVAL=off
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT=cite-e2e
# shellcheck source=layout-watch.sh
source "$ROOT/scripts/layout-watch.sh"
PORT="${CITE_PORT:-18081}"
MOCK_TOKEN='ghp_citeMockGithubPat00000000000000001'

fail() {
  echo "e2e-fault FAIL: $*" >&2
  if [[ -n "${EXE:-}" ]]; then
    docker unpause "$EXE" >/dev/null 2>&1 || true
  fi
  if [[ -n "${MGR:-}" ]]; then
    docker logs "$MGR" --tail 40 >&2 || true
  fi
  stop_layout_watch >/dev/null 2>&1 || true
  exit 1
}

page_has() {
  local want="$1" msg="$2" body
  for _ in $(seq 1 40); do
    body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/" 2>/dev/null || true)"
    if printf '%s\n' "$body" | grep -q "$want"; then
      echo "$msg: $body"
      return 0
    fi
    sleep 0.5
  done
  fail "$msg (wanted $want, got ${body:-<empty>})"
}

release_hashes() {
  docker exec "$MGR" node -e '
const fs = require("fs");
const crypto = require("crypto");
function hash(slot) {
  const path = "/var/lib/cite/releases/" + slot + "/release.json";
  if (!fs.existsSync(path)) return slot + ":missing";
  return slot + ":" + crypto.createHash("sha256").update(fs.readFileSync(path)).digest("hex");
}
process.stdout.write(hash("blue") + " " + hash("green"));
'
}

push_html() {
  local html="$1" message="$2" build="$3"
  docker exec "$MGR" node -e '
fetch("http://mock-github:8080/__cite/push", {
  method: "POST",
  headers: { Authorization: "Bearer " + process.argv[1], "content-type": "application/json" },
  body: JSON.stringify({
    branch: "main",
    message: process.argv[4],
    author: "tester",
    files: { "index.html": process.argv[2], "build.js": process.argv[3] }
  })
}).then(async (res) => {
  const text = await res.text();
  if (!res.ok) { console.error(text); process.exit(1); }
  console.log(text);
}).catch((err) => { console.error(err); process.exit(1); });
' "$MOCK_TOKEN" "$html" "$build" "$message" || fail "mock push failed"
}

cd "$ROOT"
mkdir -p target
export CITE_GITHUB_TOKEN="$MOCK_TOKEN"
export CITE_PORT="$PORT"

compose() {
  docker compose -p "$PROJECT" -f docker-compose.dev.yml -f docker-compose.e2e.yml -f docker-compose.e2e-static.yml --profile mock "$@"
}

compose_ssr() {
  docker compose -p "$PROJECT" -f docker-compose.dev.yml -f docker-compose.e2e.yml -f docker-compose.e2e-ssr.yml --profile mock "$@"
}

wait_manager() {
  local MGR
  MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
  [[ -n "$MGR" ]] || fail "manager did not start"
  for _ in $(seq 1 40); do
    if docker exec "$MGR" cite-manager healthcheck >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  fail "manager healthcheck failed"
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
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "first release was not reachable"
printf '%s\n' "$body" | grep -q 'v1' || fail "first release was not v1: $body"

slow_build="const fs=require('fs'); const end=Date.now()+8000; while(Date.now()<end){} fs.mkdirSync('dist',{recursive:true}); fs.writeFileSync('index.html','<html>killed</html>'); fs.copyFileSync('index.html','dist/index.html');"
docker exec "$MGR" node -e '
fetch("http://mock-github:8080/__cite/push", {
  method: "POST",
  headers: { Authorization: "Bearer " + process.argv[1], "content-type": "application/json" },
  body: JSON.stringify({ branch: "main", message: "slow", author: "tester", files: { "build.js": process.argv[2] } })
}).then(async (res) => {
  const text = await res.text();
  if (!res.ok) { console.error(text); process.exit(1); }
  console.log(text);
}).catch((err) => { console.error(err); process.exit(1); });
' "$MOCK_TOKEN" "$slow_build" || fail "mock push failed"

docker exec -d "$MGR" cite-manager poll
seen_job=0
for _ in $(seq 1 40); do
  if docker exec "$MGR" node -e 'process.exit(require("fs").readdirSync("/var/lib/cite/work").some((name) => name.startsWith("job-")) ? 0 : 1)'; then
    seen_job=1
    break
  fi
  sleep 0.2
done
[[ "$seen_job" == 1 ]] || fail "build never started a job directory"
docker kill "$MGR" >/dev/null
echo "killed manager mid-build"

compose up -d --no-build manager
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
[[ -n "$MGR" ]] || fail "manager did not return"
for _ in $(seq 1 40); do
  if docker exec "$MGR" cite-manager healthcheck >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
docker exec "$MGR" cite-manager healthcheck >/dev/null 2>&1 || fail "manager not healthy after kill"
jobs="$(docker exec "$MGR" node -e 'process.stdout.write(require("fs").readdirSync("/var/lib/cite/work").filter((name) => name.startsWith("job-")).join(","))')"
[[ -z "$jobs" ]] || fail "startup left a job dir: $jobs"
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "site died after the manager kill"
printf '%s\n' "$body" | grep -q 'v1' || fail "kill changed the live site: $body"
slots="$(docker exec "$MGR" node -e 'const names=require("fs").readdirSync("/var/lib/cite/releases"); if (names.some((name) => name !== "blue" && name !== "green")) process.exit(1);')" || fail "extra release slot after kill"
echo "mid-build kill kept: $body"

docker exec "$MGR" node -e 'require("fs").writeFileSync("/var/lib/cite/control/desired.json", "{not-json");'
sleep 1
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "site died after corrupt desired.json"
printf '%s\n' "$body" | grep -q 'v1' || fail "corrupt desired.json changed the live site: $body"
echo "corrupt desired.json kept: $body"

docker exec "$MGR" node -e 'require("fs").writeFileSync("/var/lib/cite/state/state.json", "{not-json");'
docker kill "$MGR" >/dev/null
compose up -d --no-build manager
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
for _ in $(seq 1 40); do
  if docker exec "$MGR" cite-manager healthcheck >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
docker exec "$MGR" cite-manager healthcheck >/dev/null 2>&1 || fail "manager did not recover from corrupt state.json"
docker exec "$MGR" node -e 'const s=JSON.parse(require("fs").readFileSync("/var/lib/cite/state/state.json","utf8")); if (typeof s !== "object" || s === null) process.exit(1);' || fail "state.json was not replaced"
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")" || fail "site died after corrupt state.json"
printf '%s\n' "$body" | grep -q 'v1' || fail "corrupt state.json changed the live site: $body"
echo "corrupt state.json recovered, still: $body"

good_build='const fs=require("fs");fs.mkdirSync("dist",{recursive:true});fs.copyFileSync("index.html","dist/index.html");'
push_html '<html>v2</html>' v2 "$good_build"
docker exec "$MGR" cite-manager poll || fail "v2 poll failed"
page_has 'v2' "second release"

sealed="$(release_hashes)"
printf '%s\n' "$sealed" | grep -q 'missing' && fail "both slots were not sealed before evict: $sealed"
EXE="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=executor" --format '{{.ID}}' | head -n1)"
[[ -n "$EXE" ]] || fail "executor missing before evict"

slow_v3='const fs=require("fs"); const end=Date.now()+8000; while(Date.now()<end){} fs.mkdirSync("dist",{recursive:true}); fs.writeFileSync("index.html","<html>v3</html>"); fs.copyFileSync("index.html","dist/index.html");'
push_html '<html>v3</html>' v3 "$slow_v3"
docker exec "$MGR" cite-manager poll > target/e2e-fault-evict.out 2>&1 &
poll_pid=$!
seen_job=0
for _ in $(seq 1 50); do
  if docker exec "$MGR" node -e 'process.exit(require("fs").readdirSync("/var/lib/cite/work").some((name) => name.startsWith("job-")) ? 0 : 1)'; then
    seen_job=1
    break
  fi
  sleep 0.2
done
[[ "$seen_job" == 1 ]] || fail "evict deploy never started a job"
sleep 7
docker pause "$EXE"
set +e
wait "$poll_pid"
poll_code=$?
set -e
docker unpause "$EXE" >/dev/null
[[ "$poll_code" -ne 0 ]] || fail "deploy succeeded while the executor was paused: $(cat target/e2e-fault-evict.out)"
grep -q 'executor_unresponsive during evict' target/e2e-fault-evict.out || fail "evict did not abort on a stale executor: $(cat target/e2e-fault-evict.out)"
after="$(release_hashes)"
[[ "$after" == "$sealed" ]] || fail "evict abort changed releases: before $sealed after $after"
page_has 'v2' "unresponsive evict kept"

other="$(docker exec "$MGR" node -e '
const fs = require("fs");
const status = JSON.parse(fs.readFileSync("/var/lib/cite/status/executor.json", "utf8"));
const live = status.active_slot;
if (live !== "blue" && live !== "green") process.exit(1);
process.stdout.write(live === "blue" ? "green" : "blue");
')" || fail "could not read the live slot"
docker exec "$MGR" node -e 'require("fs").writeFileSync("/var/lib/cite/releases/" + process.argv[1] + "/release.json", "{not-json");' "$other"
page_has 'v2' "corrupt release.json kept"
docker exec "$MGR" node -e 'require("fs").rmSync("/var/lib/cite/releases/" + process.argv[1] + "/app", { recursive: true, force: true });' "$other"
page_has 'v2' "deleted warm slot kept"

EXE="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=executor" --format '{{.ID}}' | head -n1)"
started="$(docker inspect -f '{{.State.StartedAt}}' "$EXE")"
# SIGTERM pid 1 from inside: `docker kill` is a manual stop, so `unless-stopped` would not restart it.
docker exec "$EXE" /nodejs/bin/node -e 'process.kill(1, "SIGTERM")' >/dev/null 2>&1 || true
for _ in $(seq 1 40); do
  now="$(docker inspect -f '{{.State.Status}} {{.State.StartedAt}}' "$EXE" 2>/dev/null || true)"
  if [[ "$now" == running* && "$now" != "running $started" ]] && curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/" 2>/dev/null | grep -q 'v2'; then
    break
  fi
  sleep 0.5
done
page_has 'v2' "executor kill restored"

export CITE_MOCK_TARBALL_DELAY_MS=4000
compose up -d --no-build --force-recreate mock-github
for _ in $(seq 1 30); do
  if docker exec "$MGR" node -e 'fetch("http://mock-github:8080/__cite/head/main",{headers:{Authorization:"Bearer "+process.argv[1]}}).then((res)=>process.exit(res.ok?0:1)).catch(()=>process.exit(1))' "$MOCK_TOKEN"; then
    break
  fi
  sleep 0.3
done
docker exec "$MGR" node -e 'fetch("http://mock-github:8080/__cite/head/main",{headers:{Authorization:"Bearer "+process.argv[1]}}).then((res)=>process.exit(res.ok?0:1)).catch(()=>process.exit(1))' "$MOCK_TOKEN" || fail "delayed mock did not come back"
push_html '<html>fetched</html>' mid-fetch "$good_build"
docker exec "$MGR" cite-manager poll > target/e2e-fault-fetch.out 2>&1 &
poll_pid=$!
sleep 0.8
if docker exec "$MGR" node -e 'process.exit(require("fs").readdirSync("/var/lib/cite/work").some((name) => name.startsWith("job-")) ? 0 : 1)'; then
  fail "job directory appeared before the tarball fetch finished"
fi
docker kill "$MGR" >/dev/null
set +e
wait "$poll_pid"
set -e
echo "killed manager mid-fetch"
compose up -d --no-build manager
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
[[ -n "$MGR" ]] || fail "manager did not return after mid-fetch kill"
for _ in $(seq 1 40); do
  if docker exec "$MGR" cite-manager healthcheck >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
docker exec "$MGR" cite-manager healthcheck >/dev/null 2>&1 || fail "manager not healthy after mid-fetch kill"
jobs="$(docker exec "$MGR" node -e 'process.stdout.write(require("fs").readdirSync("/var/lib/cite/work").filter((name) => name.startsWith("job-")).join(","))')"
[[ -z "$jobs" ]] || fail "mid-fetch kill left a job dir: $jobs"
page_has 'v2' "mid-fetch kill kept"
if curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/" | grep -q 'fetched'; then
  fail "mid-fetch kill published the in-flight commit"
fi

export CITE_MOCK_TARBALL_DELAY_MS=0
compose_ssr up -d --no-build --force-recreate manager mock-github
wait_manager
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
for _ in $(seq 1 30); do
  if docker exec "$MGR" node -e 'fetch("http://mock-github:8080/__cite/head/main",{headers:{Authorization:"Bearer "+process.argv[1]}}).then((res)=>process.exit(res.ok?0:1)).catch(()=>process.exit(1))' "$MOCK_TOKEN"; then
    break
  fi
  sleep 0.3
done
deploy_ssr() {
  local label="$1" build
  build="$(node -e 'const label=process.argv[1]; const server="const http=require(\"http\");http.createServer((q,s)=>s.end(\"<html>"+label+"</html>\")).listen(process.env.PORT,\"127.0.0.1\");"; process.stdout.write("const fs=require(\"fs\");fs.writeFileSync(\"server.js\","+JSON.stringify(server)+");");' "$label")"
  push_html "<html>${label}</html>" "$label" "$build"
  docker exec "$MGR" cite-manager poll || fail "$label poll failed"
  page_has "<html>${label}</html>" "ssr $label"
}
deploy_ssr ssr-a
deploy_ssr ssr-b
warm="$(docker exec "$MGR" node -e '
const fs = require("fs");
const status = JSON.parse(fs.readFileSync("/var/lib/cite/status/executor.json", "utf8"));
const warm = ["blue", "green"].find((name) => status.slots[name].state === "warm" && status.slots[name].pid);
if (!warm) process.exit(1);
if (!status.slots[status.active_slot].pid) process.exit(1);
process.stdout.write(warm);
')" || fail "expected a warm SSR process beside the live one"
docker exec "$MGR" node -e 'require("fs").rmSync("/var/lib/cite/releases/" + process.argv[1] + "/app", { recursive: true, force: true });' "$warm"
page_has '<html>ssr-b</html>' "deleted warm process slot kept"
if docker exec "$MGR" node -e 'process.exit(require("fs").existsSync("/var/lib/cite/releases/" + process.argv[1] + "/app") ? 0 : 1)' "$warm"; then
  fail "warm slot app directory was not deleted"
fi

export CITE_FAULT_HOLD_BEFORE_ACTIVATE_MS=4000
export CITE_MOCK_TARBALL_DELAY_MS=0
compose up -d --no-build --force-recreate manager
wait_manager
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
page_has '<html>ssr-b</html>' "page before mid-promote"
push_out="$(push_html '<html>held</html>' held "$good_build")"
held_sha="$(printf '%s\n' "$push_out" | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const m=s.match(/"sha":"([0-9a-f]{40})"/); if(!m) process.exit(1); process.stdout.write(m[1]);})')" || fail "held push did not return a sha: $push_out"
docker exec "$MGR" cite-manager poll > target/e2e-fault-promote.out 2>&1 &
poll_pid=$!
sealed_new=0
for _ in $(seq 1 80); do
  if docker exec "$MGR" node -e 'const fs=require("fs"); const sha=process.argv[1]; const hit=["blue","green"].some((slot)=>{const path="/var/lib/cite/releases/"+slot+"/release.json"; return fs.existsSync(path)&&fs.readFileSync(path,"utf8").includes(sha);}); process.exit(hit?0:1);' "$held_sha"; then
    sealed_new=1
    break
  fi
  sleep 0.1
done
[[ "$sealed_new" == 1 ]] || fail "new release was not sealed during the activate hold"
docker kill "$MGR" >/dev/null
set +e
wait "$poll_pid"
set -e
echo "killed manager mid-promote"
compose up -d --no-build manager
wait_manager
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
docker exec "$MGR" node -e 'JSON.parse(require("fs").readFileSync("/var/lib/cite/control/desired.json","utf8"));' || fail "desired.json was torn by the mid-promote kill"
page_has '<html>ssr-b</html>' "mid-promote kill kept"
if curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/" | grep -q 'held'; then
  fail "mid-promote kill published the held release"
fi

export CITE_FAULT_HOLD_BEFORE_ACTIVATE_MS=0
export CITE_MOCK_TARBALL_DELAY_MS=0
compose_ssr up -d --no-build --force-recreate manager
wait_manager
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
page_has '<html>ssr-b</html>' "page before mid-switch"
old_gen="$(docker exec "$MGR" node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync("/var/lib/cite/control/desired.json","utf8")).generation))')"
switch_build="$(node -e 'const server="const http=require(\"http\");setTimeout(()=>http.createServer((q,s)=>s.end(\"<html>switch</html>\")).listen(process.env.PORT,\"127.0.0.1\"),2000);"; process.stdout.write("const fs=require(\"fs\");fs.writeFileSync(\"server.js\","+JSON.stringify(server)+");");')"
push_html '<html>switch</html>' switch "$switch_build"
docker exec "$MGR" cite-manager poll > target/e2e-fault-switch.out 2>&1 &
poll_pid=$!
saw_activate=0
for _ in $(seq 1 80); do
  if docker exec "$MGR" node -e 'const d=JSON.parse(require("fs").readFileSync("/var/lib/cite/control/desired.json","utf8")); process.exit(d.action==="activate" && d.generation>Number(process.argv[1]) ? 0 : 1);' "$old_gen"; then
    saw_activate=1
    break
  fi
  sleep 0.1
done
[[ "$saw_activate" == 1 ]] || fail "activate desired was not written before health"
mid_body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/" 2>/dev/null || true)"
printf '%s\n' "$mid_body" | grep -q '<html>ssr-b</html>' || fail "switch finished before the executor kill: ${mid_body:-<empty>}"
EXE="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=executor" --format '{{.ID}}' | head -n1)"
started="$(docker inspect -f '{{.State.StartedAt}}' "$EXE")"
docker exec "$EXE" /nodejs/bin/node -e 'process.kill(1, "SIGTERM")' >/dev/null 2>&1 || true
set +e
wait "$poll_pid"
set -e
echo "killed executor mid-switch"
restarted=0
for _ in $(seq 1 40); do
  now="$(docker inspect -f '{{.State.Status}} {{.State.StartedAt}}' "$EXE" 2>/dev/null || true)"
  if [[ "$now" == running* && "$now" != "running $started" ]]; then
    restarted=1
    break
  fi
  sleep 0.5
done
[[ "$restarted" == 1 ]] || fail "executor did not relaunch after the mid-switch kill"
page_has '<html>ssr-b</html>' "executor kill mid-switch kept"
slots="$(docker exec "$MGR" node -e 'const names=require("fs").readdirSync("/var/lib/cite/releases"); if (names.some((name)=>name!=="blue"&&name!=="green")) process.exit(1); process.stdout.write(names.join(","));')" || fail "extra release slot after mid-switch"
echo "mid-switch slots: $slots"

# The candidate slot is a 128 KiB tmpfs, so the padded release cannot land.
inactive="$(docker exec "$MGR" node -e 'const s=JSON.parse(require("fs").readFileSync("/var/lib/cite/status/executor.json","utf8")); process.stdout.write(s.active_slot==="blue"?"green":"blue");')"
[[ "$inactive" == "blue" || "$inactive" == "green" ]] || fail "no inactive slot for the disk-full promote"
cat > target/e2e-tiny-slot.yml <<EOF
services:
  manager:
    tmpfs:
      - /var/lib/cite/releases/${inactive}:size=131072,mode=0755
EOF
export CITE_FAULT_HOLD_DURING_ATOMIC_MS=0
docker compose -p "$PROJECT" -f docker-compose.dev.yml -f docker-compose.e2e.yml -f docker-compose.e2e-static.yml -f target/e2e-tiny-slot.yml --profile mock up -d --no-build --force-recreate manager
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
wait_manager
fat_build='const fs=require("fs");fs.mkdirSync("dist",{recursive:true});fs.writeFileSync("dist/index.html","<html>full</html>");fs.writeFileSync("dist/pad.bin",Buffer.alloc(512*1024,1));'
push_html '<html>full</html>' 'disk-full' "$fat_build"
set +e
disk_out="$(docker exec "$MGR" cite-manager poll 2>&1)"
disk_rc=$?
set -e
[[ "$disk_rc" -ne 0 ]] || fail "disk-full promote succeeded: $disk_out"
page_has '<html>ssr-b</html>' "disk-full promote kept"

export CITE_FAULT_HOLD_DURING_ATOMIC_MS=4000
compose up -d --no-build --force-recreate manager
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
wait_manager
push_html '<html>atomic</html>' 'mid-desired' "$good_build"
docker exec -d "$MGR" cite-manager poll
saw_tmp=0
for _ in $(seq 1 80); do
  if docker exec "$MGR" node -e 'process.exit(require("fs").readdirSync("/var/lib/cite/control").some((name)=>name.startsWith(".desired.json.tmp."))?0:1)'; then
    saw_tmp=1
    break
  fi
  sleep 0.05
done
[[ "$saw_tmp" == 1 ]] || fail "desired.json temp file never appeared"
docker kill "$MGR" >/dev/null
echo "killed manager during desired.json write"
compose up -d --no-build manager
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
wait_manager
docker exec "$MGR" node -e 'JSON.parse(require("fs").readFileSync("/var/lib/cite/control/desired.json","utf8"));' || fail "desired.json was torn"
if docker exec "$MGR" node -e 'process.exit(require("fs").readdirSync("/var/lib/cite/control").some((name)=>name.startsWith(".desired.json.tmp."))?0:1)'; then
  fail "startup left a desired.json temp file"
fi
page_has '<html>ssr-b</html>' "mid-desired kill kept"
body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/")"
printf '%s\n' "$body" | grep -q 'atomic' && fail "mid-desired kill published the new page: $body"
export CITE_FAULT_HOLD_DURING_ATOMIC_MS=0

harvest_layout_watch
if [[ -s target/e2e-layout-violations ]]; then
  fail "layout watch saw: $(cat target/e2e-layout-violations)"
fi
[[ "$LAYOUT_SAMPLES" -ge 50 ]] || fail "layout watch only sampled $LAYOUT_SAMPLES times"
echo "layout watch: $LAYOUT_SAMPLES samples, only blue and green"

stop_layout_watch
compose down -v --remove-orphans >/dev/null
docker volume rm -f "${PROJECT}_cite_data" >/dev/null 2>&1 || true
echo "e2e-fault OK"
