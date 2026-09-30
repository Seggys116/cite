#!/usr/bin/env bash
# A vulnerable SSR process inside the executor cannot leave its box and never sees the GitHub token.
set -euo pipefail

PROJECT="${1:-cite-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

fail() {
  echo "assert-rce FAIL: $*" >&2
  exit 1
}

mgr="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
exe="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=executor" --format '{{.ID}}' | head -n1)"
[[ -n "$mgr" && -n "$exe" ]] || fail "stack is not running"
port="$(docker inspect "$exe" --format '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}')"
[[ -n "$port" ]] || fail "executor has no published port"
mgr_ip="$(docker inspect "$mgr" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"

docker exec "$mgr" mkdir -p /var/lib/cite/releases/green/app
docker cp "$ROOT/tests/fixtures/rce/server.js" "$mgr":/var/lib/cite/releases/green/app/server.js
docker exec "$mgr" node -e '
const fs = require("fs");
const release = {
  v: 1,
  release_id: "rcefixture01",
  slot: "green",
  sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  branch: "main",
  commit_message: "rce fixture",
  commit_author: "cite",
  built_at: "2026-01-01T00:00:00Z",
  rendering: "ssr",
  runtime: "node",
  node_major: "22",
  start_argv: ["node", "server.js"],
  port_env: "PORT",
  health: { path: "/health", expect: "2xx", timeout_s: 5, consecutive: 1 },
  spa_fallback: null,
  root: "app",
  bytes: 1,
  file_count: 1,
  tree_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
};
const desired = {
  v: 1,
  generation: 1,
  live_slot: "green",
  action: "activate",
  evict_slot: null,
  warm_grace_s: 30,
  restart_nonce: "",
  written_at: "2026-01-01T00:00:00Z"
};
fs.writeFileSync("/var/lib/cite/releases/green/release.json", JSON.stringify(release));
fs.writeFileSync("/var/lib/cite/control/desired.json", JSON.stringify(desired));
'

ready=""
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if curl -fsS --max-time 1 "http://127.0.0.1:${port}/health" | grep -q ok; then
    ready=1
    break
  fi
  sleep 0.5
done
[[ -n "$ready" ]] || fail "fixture never became healthy"

probe() {
  local name="$1" code="$2" expect="$3"
  local body
  body="$(curl -fsS --max-time 5 -X POST --data-binary "$code" "http://127.0.0.1:${port}/eval")"
  printf '%s\n' "$body" | grep -q "$expect" || fail "$name returned: $body"
  echo "$name: $body"
}

probe shell '(() => { const r = require("child_process").spawnSync("sh", ["-c", "echo pwned"]); return r.error ? ("shell " + r.error.code) : ("shell RAN " + r.stdout); })()' "shell ENOENT"
probe releases '(() => { try { require("fs").writeFileSync("/var/lib/cite/releases/pwned", "x"); return "releases WROTE"; } catch (e) { return "releases " + e.code; } })()' "releases EROFS"
probe state '(() => { try { require("fs").readdirSync("/var/lib/cite/state"); return "state SEEN"; } catch (e) { return "state " + e.code; } })()' "state ENOENT"
probe work '(() => { try { require("fs").readdirSync("/var/lib/cite/work"); return "work SEEN"; } catch (e) { return "work " + e.code; } })()' "work ENOENT"
probe cache '(() => { try { require("fs").readdirSync("/var/lib/cite/cache"); return "cache SEEN"; } catch (e) { return "cache " + e.code; } })()' "cache ENOENT"
probe status '(() => { require("fs").writeFileSync("/var/lib/cite/status/forged.json", "{\"pwned\":true}"); require("fs").writeFileSync("/var/lib/cite/status/executor.json", "not-json"); return "status WROTE"; })()' "status WROTE"
probe token '(() => "token " + (process.env.CITE_GITHUB_TOKEN === undefined ? "ABSENT" : "PRESENT"))()' "token ABSENT"
probe egress 'new Promise((resolve) => { const s = require("net").connect(443, "1.1.1.1"); const t = setTimeout(() => { s.destroy(); resolve("egress TIMEOUT"); }, 1500); s.on("connect", () => { clearTimeout(t); s.destroy(); resolve("egress CONNECTED"); }); s.on("error", (e) => { clearTimeout(t); resolve("egress " + e.code); }); })' "egress "
probe manager "new Promise((resolve) => { const s = require(\"net\").connect(8080, \"$mgr_ip\"); const t = setTimeout(() => { s.destroy(); resolve(\"manager TIMEOUT\"); }, 1500); s.on(\"connect\", () => { clearTimeout(t); s.destroy(); resolve(\"manager CONNECTED\"); }); s.on(\"error\", (e) => { clearTimeout(t); resolve(\"manager \" + e.code); }); })" "manager "

if probe_out=$(curl -fsS --max-time 5 -X POST --data-binary 'new Promise((resolve) => { const s = require("net").connect(443, "1.1.1.1"); const t = setTimeout(() => { s.destroy(); resolve("egress TIMEOUT"); }, 1500); s.on("connect", () => { clearTimeout(t); s.destroy(); resolve("egress CONNECTED"); }); s.on("error", (e) => { clearTimeout(t); resolve("egress " + e.code); }); })' "http://127.0.0.1:${port}/eval"); then
  printf '%s\n' "$probe_out" | grep -q CONNECTED && fail "egress succeeded: $probe_out"
fi
mgr_body="$(curl -fsS --max-time 5 -X POST --data-binary "new Promise((resolve) => { const s = require(\"net\").connect(8080, \"$mgr_ip\"); const t = setTimeout(() => { s.destroy(); resolve(\"manager TIMEOUT\"); }, 1500); s.on(\"connect\", () => { clearTimeout(t); s.destroy(); resolve(\"manager CONNECTED\"); }); s.on(\"error\", (e) => { clearTimeout(t); resolve(\"manager \" + e.code); }); })" "http://127.0.0.1:${port}/eval")"
printf '%s\n' "$mgr_body" | grep -q CONNECTED && fail "manager was reachable: $mgr_body"

docker exec "$mgr" test -f /var/lib/cite/status/forged.json
docker exec "$mgr" cite-manager healthcheck
echo "assert-rce OK"
