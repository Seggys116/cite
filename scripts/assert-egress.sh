#!/usr/bin/env bash
# The SSR fixture cannot connect outbound on the default network, and can after docker-compose.egress.yml replaces it.
set -euo pipefail

PROJECT="${1:-cite-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT_WAIT=20

fail() {
  echo "assert-egress FAIL: $*" >&2
  exit 1
}

compose() {
  docker compose -f "$ROOT/docker-compose.dev.yml" "$@"
}

mgr() {
  docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1
}
exe() {
  docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=executor" --format '{{.ID}}' | head -n1
}

publish_port() {
  docker inspect "$(exe)" --format '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}'
}

install_fixture() {
  local id
  id="$(mgr)"
  [[ -n "$id" ]] || fail "manager is not running"
  docker exec "$id" mkdir -p /var/lib/cite/releases/green/app
  docker cp "$ROOT/tests/fixtures/rce/server.js" "$id":/var/lib/cite/releases/green/app/server.js
  docker exec "$id" node -e '
const fs = require("fs");
fs.writeFileSync("/var/lib/cite/releases/green/release.json", JSON.stringify({
  v: 1, release_id: "rcefixture01", slot: "green",
  sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  branch: "main", commit_message: "egress fixture", commit_author: "cite",
  built_at: "2026-01-01T00:00:00Z", rendering: "ssr", runtime: "node",
  node_major: "22", start_argv: ["node", "server.js"], port_env: "PORT",
  health: { path: "/health", expect: "2xx", timeout_s: 5, consecutive: 1 },
  spa_fallback: null, root: "app", bytes: 1, file_count: 1,
  tree_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}));
fs.writeFileSync("/var/lib/cite/control/desired.json", JSON.stringify({
  v: 1, generation: 1, live_slot: "green", action: "activate", evict_slot: null,
  warm_grace_s: 30, restart_nonce: "", written_at: "2026-01-01T00:00:00Z"
}));
'
}

wait_health() {
  local port="$1"
  for _ in $(seq 1 "$PORT_WAIT"); do
    if curl -fsS --max-time 1 "http://127.0.0.1:${port}/health" 2>/dev/null | grep -q ok; then
      return 0
    fi
    sleep 0.5
  done
  fail "fixture never became healthy"
}

egress_result() {
  local port="$1"
  curl -fsS --max-time 5 -X POST --data-binary \
    'new Promise((resolve) => { const s = require("net").connect(443, "1.1.1.1"); const t = setTimeout(() => { s.destroy(); resolve("TIMEOUT"); }, 1500); s.on("connect", () => { clearTimeout(t); s.destroy(); resolve("CONNECTED"); }); s.on("error", (e) => { clearTimeout(t); resolve(e.code); }); })' \
    "http://127.0.0.1:${port}/eval"
}

remove_fixture() {
  local id
  id="$(mgr)" || true
  if [[ -n "$id" ]]; then
    docker exec "$id" sh -c 'rm -rf /var/lib/cite/releases/green /var/lib/cite/control/desired.json; mkdir -p /var/lib/cite/releases/green' || true
  fi
}

cd "$ROOT"
compose up -d --no-build --no-deps executor
install_fixture
port="$(publish_port)"
wait_health "$port"
# Docker Desktop NATs the bridge anyway, so a pass here also needs a host DOCKER-USER drop that compose does not create.
denied="$(egress_result "$port")"
echo "default: $denied"
printf '%s\n' "$denied" | grep -q CONNECTED && fail "default egress succeeded: $denied"

docker compose -f docker-compose.dev.yml -f docker-compose.egress.yml up -d --no-build --no-deps executor
port="$(publish_port)"
wait_health "$port"
allowed="$(egress_result "$port")"
echo "override: $allowed"
printf '%s\n' "$allowed" | grep -q CONNECTED || fail "egress override did not connect: $allowed"

remove_fixture
compose up -d --no-build --no-deps executor
echo "assert-egress OK"
