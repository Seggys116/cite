#!/usr/bin/env bash
# Deploys a real fixture through the mock stack for one package manager and runtime. Usage: scripts/e2e-runtimes.sh pnpm|npm|yarn|bun|static|node24
set -euo pipefail

SCENARIO="${1:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="cite-rt-${SCENARIO}"
PORT="${CITE_PORT:-18095}"
MOCK_TOKEN='ghp_citeMockGithubPat00000000000000001'

export CITE_E2E_MANAGER_IMAGE=cite-manager:dev
export CITE_E2E_EXECUTOR_IMAGE=cite-executor-node:e2e
export CITE_E2E_RENDERING=static
export CITE_E2E_OUTPUT_DIR=dist
export CITE_E2E_RUNTIME=node
export CITE_NODE=22
case "$SCENARIO" in
  pnpm) FIXTURE=runtime-pnpm; EXPECT='pnpm-ok true' ;;
  npm) FIXTURE=runtime-npm; EXPECT='npm-ok true' ;;
  yarn) FIXTURE=runtime-yarn; EXPECT='yarn-ok true' ;;
  static) FIXTURE=runtime-npm; EXPECT='npm-ok true'; CITE_E2E_EXECUTOR_IMAGE=cite-executor-static:e2e; CITE_E2E_RUNTIME=static ;;
  bun) FIXTURE=runtime-bun; EXPECT='bun-ok true'; CITE_E2E_EXECUTOR_IMAGE=cite-executor-bun:e2e; CITE_E2E_RUNTIME=bun; CITE_E2E_RENDERING=ssr; CITE_E2E_OUTPUT_DIR=. ;;
  node24) FIXTURE=runtime-node-ssr; EXPECT='node-ok true v24.'; CITE_E2E_MANAGER_IMAGE=cite-manager:dev-node24; CITE_E2E_EXECUTOR_IMAGE=cite-executor-node:e2e-node24; CITE_E2E_RENDERING=ssr; CITE_E2E_OUTPUT_DIR=.; CITE_NODE=24 ;;
  *) echo "usage: $0 pnpm|npm|yarn|bun|static|node24" >&2; exit 2 ;;
esac

export CITE_GITHUB_TOKEN="$MOCK_TOKEN" CITE_PORT="$PORT" CITE_REPO=cite-e2e/runtime
compose() {
  docker compose -p "$PROJECT" -f "$ROOT/docker-compose.dev.yml" -f "$ROOT/docker-compose.e2e-runtime.yml" --profile mock "$@"
}

fail() {
  echo "e2e-runtimes ${SCENARIO} FAIL: $*" >&2
  docker logs "${MGR:-${PROJECT}-manager-1}" --tail 60 >&2 2>/dev/null || true
  docker logs "${PROJECT}-executor-1" --tail 20 >&2 2>/dev/null || true
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  exit 1
}

cd "$ROOT"
compose down -v --remove-orphans >/dev/null 2>&1 || true
compose up -d --no-build init manager executor mock-github >/dev/null 2>&1 || fail "stack did not start"
MGR="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
[[ -n "$MGR" ]] || fail "manager is not running"

payload="$(node -e '
const fs = require("fs");
const path = require("path");
const dir = process.argv[1];
const files = {};
for (const name of fs.readdirSync(dir)) {
  const full = path.join(dir, name);
  if (fs.statSync(full).isFile()) files[name] = fs.readFileSync(full, "utf8");
}
process.stdout.write(JSON.stringify({ branch: "main", message: process.argv[2], author: "tester", files }));
' "$ROOT/tests/fixtures/$FIXTURE" "$SCENARIO")"
for _ in $(seq 1 30); do
  docker exec "$MGR" node -e 'fetch("http://mock-github:8080/__cite/push",{method:"POST",headers:{Authorization:"Bearer "+process.argv[1],"content-type":"application/json"},body:process.argv[2]}).then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))' "$MOCK_TOKEN" "$payload" && break
  sleep 1
done || fail "mock push failed"

docker exec "$MGR" cite-manager poll >/dev/null 2>&1 || true
body=""
for _ in $(seq 1 150); do
  body="$(curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/" 2>/dev/null || true)"
  [[ "$body" == *"$EXPECT"* ]] && break
  sleep 2
done
[[ "$body" == *"$EXPECT"* ]] || fail "site never served '${EXPECT}' (last body: ${body:0:200})"

if [[ "$SCENARIO" == pnpm ]]; then
  docker exec "$MGR" sh -c 'test -n "$(ls -A /var/lib/cite/cache/pnpm 2>/dev/null)"' || fail "pnpm store did not use the cache volume"
fi
if [[ "$CITE_E2E_RENDERING" == ssr ]]; then
  top="$(docker top "${PROJECT}-executor-1" 2>/dev/null || true)"
  [[ "$top" == *"server.js"* ]] || fail "no SSR child running server.js in the executor"
fi
docker exec "$MGR" cite status >/dev/null 2>&1 || fail "cite status failed"

compose down -v --remove-orphans >/dev/null 2>&1 || true
echo "e2e-runtimes ${SCENARIO} OK: ${body//$'\n'/}"
