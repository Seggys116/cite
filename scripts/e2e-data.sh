#!/usr/bin/env bash
# End to end check of the site data services against a real Docker daemon: sealed secrets, dedicated and shared Postgres,
# privilege levels, backup and restore, password rotation, external databases through the egress forward, S3 backups, Docker
# proxy denials, conversion and node to node transfer. Two connectors run as separate compose projects on one daemon.
#
# Run: scripts/e2e-data.sh
# Images (tagged $REGISTRY/<name>:<tag> with REGISTRY=ghcr.io/seggys116, built here unless E2E_SKIP_BUILD=1):
#   cite-connector:$CITE_VERSION, cite-dockerproxy:$CITE_VERSION, cite-manager:$CITE_STACK_VERSION-node22,
#   cite-executor-bun:$CITE_STACK_VERSION, cite-egress:$CITE_STACK_VERSION, cite-postgres:$CITE_STACK_VERSION-pg17 and -pg18,
#   plus cite-mock-github:e2e. SeaweedFS (S3_IMAGE, an S3-compatible server) and curl are pulled.
# Environment: CITE_VERSION (default 0.0.1), CITE_STACK_VERSION (default CITE_VERSION), E2E_SKIP_BUILD=1, E2E_KEEP=1 skips
# teardown, E2E_CLEAN=1 removes leftovers of an earlier run first, E2E_EXT_HOST overrides the address the external database is
# reached at, DOCKER_GID is the group of the Docker socket (detected).
# On a failure the container logs are written to target/e2e-data-logs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="$ROOT/tests/fixtures/data-bun"
LOG_DIR="$ROOT/target/e2e-data-logs"
REGISTRY=ghcr.io/seggys116
CURL_IMAGE=docker.io/curlimages/curl:latest
S3_IMAGE="${S3_IMAGE:-docker.io/chrislusf/seaweedfs:3.97}"

export CITE_VERSION="${CITE_VERSION:-0.0.1}"
export CITE_STACK_VERSION="${CITE_STACK_VERSION:-$CITE_VERSION}"
PG17_IMAGE="$REGISTRY/cite-postgres:$CITE_STACK_VERSION-pg17"
PG18_IMAGE="$REGISTRY/cite-postgres:$CITE_STACK_VERSION-pg18"
PSQL_IMAGE=$PG18_IMAGE

export CITE_PUBLIC_BIND=127.0.0.1
export CITE_CONNECTOR_BIND=127.0.0.1
export CITE_CONNECTOR_ALLOW=allow-all
export CITE_DEPLOY_BUILD_TIMEOUT=300
export CITE_STACK_EGRESS_MODE=filtered
export CITE_STACK_EGRESS_ALLOW_PORTS=
export CITE_DATA_S3_ALLOW_PRIVATE=true

SITE=e2edata
SITE_HOST=data.e2e.test
SITE_A=e2esha
HOST_A=sha.e2e.test
SITE_B=e2eshb
HOST_B=shb.e2e.test
SITE_I=e2eimp
HOST_I=imp.e2e.test
SITES=("$SITE" "$SITE_A" "$SITE_B" "$SITE_I")
FIXTURE_REPO=acme/live
MOCK_NAME=cite-e2e-data-mock-github
MOCK_IMAGE="${MOCK_IMAGE:-cite-mock-github:e2e}"
MOCK_PORT=18091
MOCK_TOKEN=ghp_citeMockGithubPat00000000000000001
MINIO_NAME=cite-e2e-data-minio
MINIO_USER=e2eminio
MINIO_PASSWORD=e2eminio-secret-1
MINIO_BUCKET=e2ebackups
EXT_NAME=cite-e2e-data-ext
EXT_PORT=18543
EXT_USER=extuser
EXT_PASSWORD=ext-user-pass

for tool in docker jq curl python3 openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "e2e-data: $tool is required" >&2; exit 2; }
done
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || { echo "e2e-data: sha256sum or shasum is required" >&2; exit 2; }

if [ -z "${DOCKER_GID:-}" ]; then
  if [ "$(uname -s)" = Darwin ]; then
    DOCKER_GID=0
  else
    DOCKER_GID=$(stat -c %g /var/run/docker.sock)
  fi
fi
export DOCKER_GID

WORK="$(mktemp -d)"
OVERLAY="$WORK/overlay.yml"
START_TIME=$(date +%s)
CODE=""
BODY=""
JOB_BODY=""
PCODE=""
PBODY=""
PSQL_RC=0
PSQL_OUT=""
LOOP_PID=""
STEP_NO=0
STEP_NAME=setup
PREFLIGHT_DONE=0
LOGS_SAVED=0
NODE=1
TOKEN=""
LAST_STEP=0
CA=""
declare -a TOKENS=("" "" "") STEPS=(0 0 0) USERS=("" "" "") PASSES=("" "" "") TOTPS=("" "" "")
# Per node: compose project, ports, and the names compose fixes for HAProxy, the edge network and the backup volume.
PROJECT="" API_PORT="" HTTP_PORT="" HTTPS_PORT="" HAPROXY="" EGRESS_BRIDGE=""
BRIDGE_1=cite-egress-e2e1
BRIDGE_2=cite-egress-e2e2

use_node() {
  TOKENS[NODE]=$TOKEN
  STEPS[NODE]=$LAST_STEP
  NODE=$1
  TOKEN=${TOKENS[NODE]:-}
  LAST_STEP=${STEPS[NODE]:-0}
  CA="$WORK/ca$NODE.pem"
  case $NODE in
    1)
      PROJECT=cite-e2e-data
      API_PORT=17445
      HTTP_PORT=18083
      HTTPS_PORT=18447
      HAPROXY=cite-haproxy-e2e1
      EGRESS_BRIDGE=$BRIDGE_1
      export E2E_EDGE=cite_edge_e2e1 E2E_BACKUPS=cite-backups-e2e1
      ;;
    2)
      PROJECT=cite-e2e-data2
      API_PORT=17446
      HTTP_PORT=18084
      HTTPS_PORT=18448
      HAPROXY=cite-haproxy-e2e2
      EGRESS_BRIDGE=$BRIDGE_2
      export E2E_EDGE=cite_edge_e2e2 E2E_BACKUPS=cite-backups-e2e2
      ;;
  esac
  export E2E_HAPROXY=$HAPROXY
  export CITE_HTTP_PORT=$HTTP_PORT CITE_HTTPS_PORT=$HTTPS_PORT CITE_CONNECTOR_PORT=$API_PORT
  export CITE_STACK_EGRESS_BRIDGE=$EGRESS_BRIDGE
}

# The three fixed names of docker-compose.node.yml and docker-compose.orchestrator.yml are renamed per node, so two nodes and
# a real node can share a daemon.
cat >"$OVERLAY" <<'EOF'
services:
  dockerproxy:
    environment:
      CITE_PROXY_HAPROXY_CONTAINER: ${E2E_HAPROXY}
      CITE_PROXY_EDGE_NETWORK: ${E2E_EDGE}
      CITE_PROXY_BACKUP_VOLUME: ${E2E_BACKUPS}
  haproxy:
    container_name: ${E2E_HAPROXY}
  connector:
    environment:
      CITE_HAPROXY_CONTAINER: ${E2E_HAPROXY}
      CITE_EDGE_NETWORK: ${E2E_EDGE}
      CITE_DATA_BACKUP_VOLUME: ${E2E_BACKUPS}
networks:
  cite_edge:
    name: ${E2E_EDGE}
volumes:
  cite_backups:
    name: ${E2E_BACKUPS}
EOF

use_node 1

compose() {
  docker compose -p "$PROJECT" -f "$ROOT/docker-compose.node.yml" -f "$ROOT/docker-compose.orchestrator.yml" -f "$OVERLAY" "$@" </dev/null
}

# Only what this script created is removed, by name and by the site label, so a real node on the daemon is never touched.
remove_all() {
  local id site n
  docker rm -f "$MOCK_NAME" "$MINIO_NAME" "$EXT_NAME" >/dev/null 2>&1 || true
  for site in "${SITES[@]}"; do
    while read -r id; do
      docker rm -f "$id" >/dev/null 2>&1 || true
    done < <(docker ps -aq --filter "label=cite.site=$site")
  done
  docker rm -f cite-pg-shared cite-pg-shared-job >/dev/null 2>&1 || true
  for n in 1 2; do
    use_node "$n"
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  done
  for site in "${SITES[@]}"; do
    while read -r id; do
      docker network rm "$id" >/dev/null 2>&1 || true
    done < <(docker network ls -q --filter "label=cite.site=$site")
    while read -r id; do
      docker volume rm -f "$id" >/dev/null 2>&1 || true
    done < <(docker volume ls -q --filter "label=cite.site=$site")
  done
  docker volume rm -f cite-pg-shared-data cite-pg-shared-conf >/dev/null 2>&1 || true
  docker network rm cite-pg-shared-admin "$BRIDGE_1" "$BRIDGE_2" >/dev/null 2>&1 || true
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  [ -z "$LOOP_PID" ] || kill "$LOOP_PID" 2>/dev/null || true
  if [ "$PREFLIGHT_DONE" = 1 ] && [ "${E2E_KEEP:-0}" != 1 ]; then
    remove_all
  fi
  if [ "${E2E_KEEP:-0}" != 1 ]; then
    rm -rf "$WORK"
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

collect_logs() {
  local name
  [ "$LOGS_SAVED" = 0 ] || return 0
  LOGS_SAVED=1
  mkdir -p "$LOG_DIR"
  docker ps -a --format '{{.Names}} {{.Status}} {{.Image}}' >"$LOG_DIR/containers.txt" 2>&1 || true
  while read -r name; do
    docker logs --tail 400 "$name" >"$LOG_DIR/$name.log" 2>&1 || true
  done < <(docker ps -a --format '{{.Names}}' | grep -E '^cite[-_]' || true)
  for name in "cite-e2e-data-connector-1" "cite-e2e-data-dockerproxy-1" "$EXT_NAME" "$MINIO_NAME"; do
    echo "--- last log lines of $name" >&2
    docker logs --tail 25 "$name" >&2 2>&1 || true
  done
}

fail() {
  echo "FAIL step $STEP_NO ($STEP_NAME): $*" >&2
  collect_logs
  echo "where to look: container logs and 'docker ps -a' output are in $LOG_DIR;" >&2
  echo "  rerun with E2E_KEEP=1 to keep the stacks (compose projects cite-e2e-data and cite-e2e-data2)" >&2
  exit 1
}

pass() {
  echo "ok   $*"
}

begin_step() {
  STEP_NO=$1
  STEP_NAME=$2
  echo "== step $1: $2"
}

end_step() {
  echo "PASS step $STEP_NO: $STEP_NAME"
}

expect() {
  [ "$2" = "$3" ] || fail "$1: expected '$2', got '$3'"
  pass "$1"
}

truthy() {
  local what=$1
  shift
  "$@" >/dev/null 2>&1 || fail "$what"
  pass "$what"
}

api() {
  local method=$1 path=$2 data=${3:-} auth=${4-$TOKEN}
  local -a args=(-sS --max-time "${API_TIMEOUT:-30}" --cacert "$CA"
    --resolve "localhost:$API_PORT:127.0.0.1" -o "$WORK/body" -w '%{http_code}' -X "$method")
  [ -z "$auth" ] || args+=(-H "Authorization: Bearer $auth")
  [ -z "$data" ] || args+=(-H 'Content-Type: application/json' --data "$data")
  CODE=$(curl "${args[@]}" "https://localhost:$API_PORT$path") || fail "curl $method $path failed"
  BODY=$(<"$WORK/body")
}

# Like api, but keeps the body as raw bytes in a file and the response headers in $WORK/headers.
fetch_to() {
  local out=$1 method=$2 path=$3
  shift 3
  CODE=$(curl -sS --max-time 300 --cacert "$CA" --resolve "localhost:$API_PORT:127.0.0.1" -X "$method" \
    -H "Authorization: Bearer $TOKEN" -D "$WORK/headers" -o "$out" -w '%{http_code}' "$@" "https://localhost:$API_PORT$path") ||
    fail "curl $method $path failed"
}

header_value() {
  grep -i "^$1:" "$WORK/headers" | head -n 1 | tr -d '\r' | sed 's/^[^:]*: *//' || true
}

code_is() {
  [ "$2" = "$CODE" ] || fail "$1: expected HTTP $2, got $CODE: $(printf '%s' "$BODY" | head -c 400)"
  pass "$1 (HTTP $2)"
}

code_4xx() {
  case $CODE in
    4*) pass "$1 (HTTP $CODE)" ;;
    *) fail "$1: expected a 4xx answer, got HTTP $CODE: $(printf '%s' "$BODY" | head -c 400)" ;;
  esac
}

jq_ok() {
  printf '%s' "$BODY" | jq -e "$2" >/dev/null || fail "$1: jq '$2' failed on: $(printf '%s' "$BODY" | head -c 600)"
  pass "$1"
}

no_secret() {
  [ -n "$2" ] || fail "$1: no secret value to look for"
  case $BODY in
    *"$2"*) fail "$1: the answer contains a secret" ;;
  esac
  pass "$1"
}

sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  else
    shasum -a 256 | cut -d' ' -f1
  fi
}

# Prints the 30 second step and the code so login() can wait for a fresh step instead of reusing a consumed one.
totp() {
  python3 -I -c '
import base64, hashlib, hmac, struct, sys, time
secret = sys.argv[1]
key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
step = int(time.time()) // 30
mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
off = mac[-1] & 15
print(step, "%06d" % ((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1000000))
' "$1"
}

login() {
  local step code
  while :; do
    read -r step code < <(totp "${TOTPS[NODE]}")
    [ "$step" -gt "$LAST_STEP" ] && break
    sleep 1
  done
  LAST_STEP=$step
  api POST /api/v1/auth/login "$(jq -nc --arg u "${USERS[NODE]}" --arg p "${PASSES[NODE]}" --arg t "$code" '{username:$u,password:$p,totp:$t}')" ""
  code_is "login on node $NODE" 200
  TOKEN=$(printf '%s' "$BODY" | jq -r .token)
}

wait_api() {
  for _ in $(seq 1 60); do
    if curl -fsS --max-time 3 --cacert "$CA" --resolve "localhost:$API_PORT:127.0.0.1" \
      -o /dev/null "https://localhost:$API_PORT/api/v1/healthz" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  fail "connector API of node $NODE did not become healthy"
}

wait_for() {
  local what=$1 tries=$2
  shift 2
  for _ in $(seq 1 "$tries"); do
    if "$@" >/dev/null 2>&1; then
      pass "$what"
      return 0
    fi
    sleep 1
  done
  fail "$what: gave up waiting"
}

proxy_healthy() {
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q dockerproxy)")" = healthy ]
}

haproxy_settled() {
  local before after
  before=$(docker inspect -f '{{.State.Status}} {{.RestartCount}}' "$HAPROXY")
  sleep 4
  after=$(docker inspect -f '{{.State.Status}} {{.RestartCount}}' "$HAPROXY")
  [ "$before" = "$after" ] && [ "${after%% *}" = running ]
}

# Requests the Docker proxy of the current node from a throwaway container on its internal docker_api network.
proxy() {
  local method=$1 path=$2 data=${3:-} out
  local -a args=(-s --max-time 20 -w '\n%{http_code}' -X "$method" -H 'Content-Type: application/json')
  [ -z "$data" ] || args+=(--data-binary "$data")
  out=$(docker run --rm --network "${PROJECT}_docker_api" "$CURL_IMAGE" "${args[@]}" "http://dockerproxy:2375$path") ||
    fail "proxy request $method $path could not be sent"
  PCODE=${out##*$'\n'}
  PBODY=${out%$'\n'*}
}

# A denial must be a 403 carrying the proxy message, not an engine error.
denied() {
  proxy "$2" "$3" "${4:-}"
  expect "proxy denies: $1 (HTTP 403)" 403 "$PCODE"
  case $PBODY in
    *denied*) pass "proxy denial body for: $1" ;;
    *) fail "$1: denial body missing: $PBODY" ;;
  esac
}

docker_state() {
  {
    docker ps -aq --no-trunc | sed 's/^/c /'
    docker volume ls -q | sed 's/^/v /'
    docker network ls -q --no-trunc | sed 's/^/n /'
  } | sort
}

conf_file() {
  docker run --rm --entrypoint cat -v "${PROJECT}_cite_conf:/conf:ro" "$REGISTRY/cite-connector:$CITE_VERSION" "/conf/$1"
}

# ---- the mock GitHub the managers build from ----

mock_endpoint() {
  if [ "$(uname -s)" = Darwin ]; then
    MOCK_BIND=127.0.0.1
    MOCK_HOST=host.docker.internal
  else
    MOCK_BIND=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
    MOCK_HOST=$MOCK_BIND
  fi
  export CITE_GITHUB_API_URL="http://$MOCK_HOST:$MOCK_PORT"
}

mock_push() {
  jq -nc --rawfile pkg "$FIXTURE/package.json" --rawfile srv "$FIXTURE/server.js" --rawfile mig "$FIXTURE/migrate.js" '{
    branch: "main", message: "e2e data fixture", author: "e2e",
    files: {"package.json": $pkg, "server.js": $srv, "migrate.js": $mig}}' >"$WORK/push.json"
  curl -fsS --max-time 15 -H "Authorization: Bearer $MOCK_TOKEN" -H 'Content-Type: application/json' \
    --data-binary "@$WORK/push.json" "http://$MOCK_BIND:$MOCK_PORT/__cite/push" >/dev/null || fail "could not push the fixture to the mock"
}

# ---- sites and the fixture app ----

fixture_site_json() {
  jq -nc --arg id "$1" --arg host "$2" --argjson outbound "$3" --arg token "$MOCK_TOKEN" --arg repo "$FIXTURE_REPO" '{
    id: $id, name: $id, hosts: [$host], active: "blue",
    blue: {targets: []}, green: {targets: []},
    outbound: $outbound,
    source: {repo: $repo, branch: "main", runtime: "bun", node_major: 22, package_manager: "bun",
             rendering: "ssr", output_dir: ".", build_command: "bun migrate.js", start_command: "bun server.js",
             poll_interval: "off"},
    github_token: $token
  }'
}

edge() {
  local host=$1 path=$2
  shift 2
  curl -sS --max-time 10 -H "Host: $host" "$@" "http://127.0.0.1:$HTTP_PORT$path"
}

edge_code() {
  edge "$1" "$2" -o /dev/null -w '%{http_code}' "${@:3}" || true
}

wait_app() {
  local got=""
  for _ in $(seq 1 120); do
    got=$(edge "$1" /health 2>/dev/null || true)
    [ "$got" = ok ] && return 0
    sleep 1
  done
  fail "the fixture on $1 never answered /health (last: '$got')"
}

create_fixture_site() {
  API_TIMEOUT=300 api POST /api/v1/sites "$(fixture_site_json "$1" "$2" "$3")"
  code_is "create site $1 from the mock repository" 200
  jq_ok "site $1 is active on blue" '.active == "blue"'
  wait_app "$2"
}

deploy_site() {
  API_TIMEOUT=300 api POST "/api/v1/sites/$1/deploy" "$(jq -nc --arg n "$2" '{git_ref:"main",note:$n}')"
  code_is "deploy $1 ($2)" 200
  wait_app "$3"
}

app_env() {
  local v
  v=$(edge "$1" "/__env?name=$2" -f) || fail "the fixture on $1 has no $2"
  printf '%s' "$v"
}

app_count() {
  edge "$1" "${2:-/notes/count}" 2>/dev/null || true
}

wait_count() {
  local got=""
  for _ in $(seq 1 60); do
    got=$(app_count "$1" "${4:-/notes/count}")
    [ "$got" = "$2" ] && break
    sleep 1
  done
  expect "$3" "$2" "$got"
}

url_user() {
  local r=${1#*://}
  printf '%s' "${r%%:*}"
}

url_pass() {
  local r=${1#*://}
  r=${r#*:}
  printf '%s' "${r%%@*}"
}

url_host() {
  local r=${1#*@}
  printf '%s' "${r%%[:/]*}"
}

url_with_db() {
  local base=${1%%\?*} query
  query=${1#"$base"}
  printf '%s/%s%s' "${base%/*}" "$2" "$query"
}

pg_tag() {
  printf 'cite-pg-v1:%s' "$1" | sha256_hex | cut -c1-10
}

# ---- psql as the test harness, in a one-off container on a site's database network (test only, outside the product) ----

psql_try() {
  PSQL_RC=0
  PSQL_OUT=$(docker run --rm --network "$1" -e PGCONNECT_TIMEOUT=10 --entrypoint psql "$PSQL_IMAGE" "$2" \
    -v ON_ERROR_STOP=1 -tA -c "$3" 2>&1) || PSQL_RC=$?
}

psql_ok() {
  psql_try "$1" "$2" "$3"
  [ "$PSQL_RC" = 0 ] || fail "$4: $PSQL_OUT"
  pass "$4"
}

psql_refused() {
  psql_try "$1" "$2" "$3"
  [ "$PSQL_RC" != 0 ] || fail "$4: expected a refusal, got: $PSQL_OUT"
  printf '%s' "$PSQL_OUT" | grep -Eqi "$5" || fail "$4: the refusal does not look like '$5': $PSQL_OUT"
  pass "$4"
}

# ---- jobs and sessions ----

job_wait() {
  local id=$1 state=""
  for _ in $(seq 1 "${JOB_TRIES:-180}"); do
    api GET "/api/v1/data/jobs/$id"
    [ "$CODE" = 200 ] || fail "job $id lookup answered HTTP $CODE: $BODY"
    state=$(printf '%s' "$BODY" | jq -r .state)
    case $state in
      ok) return 0 ;;
      failed) fail "job $id failed: $(printf '%s' "$BODY" | jq -r '.error // "no error text"')" ;;
    esac
    sleep 2
  done
  fail "job $id did not finish (last state $state)"
}

# An API call that answers 202 with a job id; waits for the job and leaves the 202 body in BODY.
run_job() {
  local what=$1
  shift
  api "$@"
  code_is "$what accepted" 202
  JOB_BODY=$BODY
  job_wait "$(printf '%s' "$JOB_BODY" | jq -er .job_id)"
  pass "$what finished"
  BODY=$JOB_BODY
}

# Polls a conversion, export or import session until it reaches one of the given states.
wait_state() {
  local path=$1 state="" want
  shift
  for _ in $(seq 1 "${STATE_TRIES:-150}"); do
    api GET "$path"
    [ "$CODE" = 200 ] || fail "session $path answered HTTP $CODE: $BODY"
    state=$(printf '%s' "$BODY" | jq -r .state)
    for want in "$@"; do
      [ "$state" != "$want" ] || return 0
    done
    case $state in
      failed | rolled_back) fail "session $path is $state: $(printf '%s' "$BODY" | jq -r '.error // "no error text"')" ;;
    esac
    sleep 2
  done
  fail "session $path did not reach $* (last state $state)"
}

traffic() {
  local host=$1 out=$2 body
  : >"$out"
  while [ ! -e "$WORK/stop" ]; do
    body=$(curl -s --max-time 5 -H "Host: $host" -w ' %{http_code}' "http://127.0.0.1:$HTTP_PORT/ping" || true)
    printf '%s\n' "$body" >>"$out"
    sleep 0.1
  done
}

traffic_failures() {
  local n
  n=$(grep -vc '^pong 200$' "$1" || true)
  if [ "$n" != 0 ]; then
    echo "bad responses in $1:" >&2
    grep -v '^pong 200$' "$1" | sort | uniq -c >&2
  fi
  echo "$n"
}

# ---- bring a node up ----

onboard() {
  compose run --rm --no-deps -T init >"$WORK/init$NODE.log" 2>&1 || fail "volume init of node $NODE failed: $(<"$WORK/init$NODE.log")"
  compose run --rm --no-deps -T connector init --non-interactive --json >"$WORK/creds$NODE.json" 2>"$WORK/init$NODE.err" ||
    fail "connector init of node $NODE failed: $(<"$WORK/init$NODE.err")"
  USERS[NODE]=$(jq -er .username "$WORK/creds$NODE.json")
  PASSES[NODE]=$(jq -er .password "$WORK/creds$NODE.json")
  TOTPS[NODE]=$(jq -er .totp_secret "$WORK/creds$NODE.json")
  compose run --rm --no-deps -T --entrypoint cat connector /conf/tls/ca.pem >"$CA" || fail "could not read ca.pem of node $NODE"
  compose up -d >"$WORK/up$NODE.log" 2>&1 || fail "compose up of node $NODE failed: $(<"$WORK/up$NODE.log")"
  wait_api
  login
  wait_for "dockerproxy of node $NODE is healthy" 90 proxy_healthy
  wait_for "HAProxy of node $NODE stopped restarting" 90 haproxy_settled
  api GET /api/v1/node
  jq_ok "orchestrator of node $NODE is enabled and reachable" '.orchestrator.enabled == true and .orchestrator.reachable == true'
}

# ---- preflight ----

pg_base_image() {
  awk -v major="$1" '
    function done_block() { if (inpg && m == major && img != "" && dg != "") { print img "@" dg; found = 1; exit } }
    /^\[/ { done_block(); inpg = ($0 == "[[postgres]]"); m = ""; img = ""; dg = ""; next }
    inpg && $1 == "major" { m = $3 }
    inpg && $1 == "image" { gsub(/"/, "", $3); img = $3 }
    inpg && $1 == "digest" { gsub(/"/, "", $3); dg = $3 }
    END { if (!found) done_block() }
  ' "$ROOT/images/images.toml"
}

build_images() {
  local major base
  docker build -q -f images/connector/Dockerfile -t "$REGISTRY/cite-connector:$CITE_VERSION" . >/dev/null
  docker build -q -f images/dockerproxy/Dockerfile -t "$REGISTRY/cite-dockerproxy:$CITE_VERSION" . >/dev/null
  docker build -q -f images/manager/Dockerfile -t "$REGISTRY/cite-manager:$CITE_STACK_VERSION-node22" . >/dev/null
  docker build -q -f images/executor-bun/Dockerfile -t "$REGISTRY/cite-executor-bun:$CITE_STACK_VERSION" . >/dev/null
  docker build -q -f images/egress/Dockerfile -t "$REGISTRY/cite-egress:$CITE_STACK_VERSION" . >/dev/null
  docker build -q -f images/mock-github/Dockerfile -t "$MOCK_IMAGE" . >/dev/null
  for major in 17 18; do
    base=$(pg_base_image "$major")
    [ -n "$base" ] || { echo "e2e-data: images/images.toml has no pinned image for postgres $major" >&2; exit 2; }
    docker build -q -f images/postgres/Dockerfile --build-arg "PG_IMAGE=$base" --build-arg "VERSION=$CITE_STACK_VERSION" \
      -t "$REGISTRY/cite-postgres:$CITE_STACK_VERSION-pg$major" . >/dev/null
  done
}

cd "$ROOT"
if [ "${E2E_SKIP_BUILD:-0}" != 1 ]; then
  echo "== building images"
  build_images
fi
for ref in "cite-connector:$CITE_VERSION" "cite-dockerproxy:$CITE_VERSION" "cite-manager:$CITE_STACK_VERSION-node22" \
  "cite-executor-bun:$CITE_STACK_VERSION" "cite-egress:$CITE_STACK_VERSION" \
  "cite-postgres:$CITE_STACK_VERSION-pg17" "cite-postgres:$CITE_STACK_VERSION-pg18"; do
  docker image inspect "$REGISTRY/$ref" >/dev/null 2>&1 || { echo "e2e-data: image $REGISTRY/$ref is missing (unset E2E_SKIP_BUILD to build it)" >&2; exit 2; }
done
docker image inspect "$MOCK_IMAGE" >/dev/null 2>&1 || { echo "e2e-data: image $MOCK_IMAGE is missing" >&2; exit 2; }
docker pull -q "$CURL_IMAGE" >/dev/null
docker pull -q "$S3_IMAGE" >/dev/null

if [ "${E2E_CLEAN:-0}" = 1 ]; then
  remove_all
  use_node 1
fi
if [ -n "$(docker ps -aq --filter label=cite.managed=true)" ] || docker inspect cite-pg-shared >/dev/null 2>&1; then
  echo "e2e-data: a node or stack already exists on this daemon; refusing to run next to it (E2E_CLEAN=1 removes the leftovers of an earlier run)" >&2
  rm -rf "$WORK"
  trap - EXIT
  exit 2
fi
PREFLIGHT_DONE=1
mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/*

echo "== node 1 and the mock GitHub"
mock_endpoint
docker run -d --name "$MOCK_NAME" -p "$MOCK_BIND:$MOCK_PORT:8080" "$MOCK_IMAGE" >/dev/null || fail "the mock GitHub did not start"
wait_for "the mock GitHub answers" 30 curl -fsS --max-time 3 -H "Authorization: Bearer $MOCK_TOKEN" "http://$MOCK_BIND:$MOCK_PORT/repos/$FIXTURE_REPO"
mock_push
use_node 1
onboard
create_fixture_site "$SITE" "$SITE_HOST" true

# ---------------------------------------------------------------------------------------------------------------------
begin_step 1 "secrets are sealed on disk after first start"
conf_file secrets.json >"$WORK/secrets.out" || fail "could not read secrets.json from the conf volume"
[ -s "$WORK/secrets.out" ] || fail "secrets.json is empty"
if grep -q "$MOCK_TOKEN" "$WORK/secrets.out"; then
  fail "secrets.json holds the GitHub token in plaintext"
fi
if jq -e 'type == "object" and (keys | any(startswith("site-")))' "$WORK/secrets.out" >/dev/null 2>&1; then
  fail "secrets.json is a plain JSON map of secret names"
fi
pass "secrets.json carries no token and no plain secret map"
conf_file credentials.json >"$WORK/credentials.out" || fail "could not read credentials.json from the conf volume"
if grep -q "${TOTPS[NODE]}" "$WORK/credentials.out"; then
  fail "credentials.json holds the TOTP secret in plaintext"
fi
pass "credentials.json does not hold the TOTP secret in plaintext"
KEY_BYTES=$(conf_file secrets.key | wc -c | tr -d ' ')
[ "$KEY_BYTES" -ge 32 ] || fail "the managed secrets.key is missing or too short ($KEY_BYTES bytes)"
expect "the managed key file is private" 600 "$(docker run --rm --entrypoint stat -v "${PROJECT}_cite_conf:/conf:ro" "$REGISTRY/cite-connector:$CITE_VERSION" -c %a /conf/secrets.key)"
compose restart connector >"$WORK/restart.log" 2>&1 || fail "connector restart failed: $(<"$WORK/restart.log")"
wait_api
login
api GET /api/v1/data
code_is "data node view" 200
jq_ok "data services are on with a key and the backup volume" '.enabled == true and .backup_volume_ok == true and (.key.kid | length) > 0'
jq_ok "both Postgres majors are offered" '(.pg_majors | index(17)) != null and (.pg_majors | index(18)) != null'
api GET "/api/v1/sites/$SITE"
code_is "the site still loads from the sealed secrets after a restart" 200
end_step

# ---------------------------------------------------------------------------------------------------------------------
begin_step 2 "dedicated Postgres on a site, fixture writes through DATABASE_URL"
run_job "enable dedicated Postgres 17 with the generic preset" PUT "/api/v1/sites/$SITE/data/postgres" '{"mode":"dedicated","major":17,"preset":"generic"}'
api GET "/api/v1/sites/$SITE/data"
code_is "site data view" 200
jq_ok "the site has a dedicated pg17 with the app database" '.postgres.mode == "dedicated" and .postgres.major == 17 and any(.postgres.databases[]; .name == "app")'
jq_ok "the preset created app and migrate users" '[.postgres.databases[] | select(.name == "app") | .users[].name] | sort == ["app","migrate"]'
jq_ok "the preset linked DATABASE_URL to runtime and MIGRATION_DATABASE_URL to build" \
  'any(.links[]; .var == "DATABASE_URL" and .target == "runtime") and any(.links[]; .var == "MIGRATION_DATABASE_URL" and .target == "build")'
expect "the database container runs" true "$(docker inspect -f '{{.State.Running}}' "cite-$SITE-db")"
expect "the database network is internal" true "$(docker network inspect -f '{{.Internal}}' "cite-$SITE-dbnet")"
expect "the database publishes no port" 0 "$(docker inspect -f '{{len .HostConfig.PortBindings}}' "cite-$SITE-db")"
run_job "create the readonly user" POST "/api/v1/sites/$SITE/data/postgres/databases/app/users" '{"name":"ro","level":"readonly"}'
api POST "/api/v1/sites/$SITE/data/links" '{"links":[{"var":"RO_DATABASE_URL","target":"runtime","source":{"kind":"postgres","database":"app","user":"ro","field":"url"}}]}'
code_is "link RO_DATABASE_URL to the readonly user" 200
deploy_site "$SITE" "e2e data deploy" "$SITE_HOST"
RW_URL=$(app_env "$SITE_HOST" DATABASE_URL)
RO_URL=$(app_env "$SITE_HOST" RO_DATABASE_URL)
expect "DATABASE_URL points at the site's database container" "cite-$SITE-db" "$(url_host "$RW_URL")"
case $RW_URL in
  *sslmode=disable*) pass "the generated URL states sslmode=disable" ;;
  *) fail "the generated URL does not state sslmode: $RW_URL" ;;
esac
api GET "/api/v1/sites/$SITE/data"
no_secret "the data view does not return the app password" "$(url_pass "$RW_URL")"
api GET "/api/v1/sites/$SITE"
no_secret "the site does not return the app password" "$(url_pass "$RW_URL")"
POSTED=$(edge "$SITE_HOST" /notes -X POST --data 'written by the fixture') || fail "the fixture could not write a note"
printf '%s' "$POSTED" | jq -e '.id == 1' >/dev/null || fail "the fixture did not report the first row id: $POSTED"
pass "the fixture wrote a row through DATABASE_URL"
wait_count "$SITE_HOST" 1 "the fixture reads the row back over HTTP"
psql_ok "cite-$SITE-dbnet" "$RW_URL" "select 1 where (select body from notes where id = 1) = 'written by the fixture'" "the row is in the database when read as the app user"
expect "psql sees exactly the row the fixture wrote" 1 "$PSQL_OUT"
end_step

# ---------------------------------------------------------------------------------------------------------------------
begin_step 3 "privilege levels"
DBNET="cite-$SITE-dbnet"
psql_ok "$DBNET" "$RW_URL" "begin; insert into notes (body) values ('rw insert'); rollback" "readwrite can insert"
psql_refused "$DBNET" "$RW_URL" "create table harness_ddl (i int)" "readwrite cannot CREATE TABLE" 'permission denied'
psql_refused "$DBNET" "$RW_URL" "drop table notes" "readwrite cannot DROP a table it does not own" 'must be owner|permission denied'
psql_ok "$DBNET" "$RO_URL" "select count(*) from notes" "readonly can read"
psql_refused "$DBNET" "$RO_URL" "insert into notes (body) values ('ro insert')" "readonly cannot INSERT" 'permission denied'
psql_refused "$DBNET" "$RO_URL" "delete from notes" "readonly cannot DELETE" 'permission denied'
psql_refused "$DBNET" "$RO_URL" "create table harness_ddl (i int)" "readonly cannot CREATE TABLE" 'permission denied'
wait_count "$SITE_HOST" 1 "the readonly user reads the same row through the fixture" /ro/count
api GET "/api/v1/sites/$SITE/data"
no_secret "the data view does not return the readonly password" "$(url_pass "$RO_URL")"
end_step

# ---------------------------------------------------------------------------------------------------------------------
begin_step 4 "backup, mutate, restore, pre-restore backup, download checksum"
edge "$SITE_HOST" /notes -X POST --data 'baseline two' >/dev/null || fail "could not write a note"
edge "$SITE_HOST" /notes -X POST --data 'baseline three' >/dev/null || fail "could not write a note"
wait_count "$SITE_HOST" 3 "three rows before the backup"
api POST "/api/v1/sites/$SITE/data/backups" '{"database":"pg:app","label":"e2e baseline"}'
code_is "start a backup" 202
BACKUP_ID=$(printf '%s' "$BODY" | jq -er .backup_id)
job_wait "$(printf '%s' "$BODY" | jq -er .job_id)"
api GET "/api/v1/sites/$SITE/data/backups/$BACKUP_ID"
code_is "read the backup record" 200
jq_ok "the backup finished, is encrypted at rest and carries a checksum" \
  '.status == "ok" and .database == "pg:app" and .version == 1 and .trigger == "manual" and .label == "e2e baseline" and .size_bytes > 0 and (.sha256 | test("^[0-9a-f]{64}$")) and .encryption.scheme == "cite-stream-v1" and .local.stored_bytes > 0'
BACKUP_SHA=$(printf '%s' "$BODY" | jq -er .sha256)
fetch_to "$WORK/backup.dump" GET "/api/v1/sites/$SITE/data/backups/$BACKUP_ID/download"
expect "download answers 200" 200 "$CODE"
HEADER_SHA=$(header_value x-backup-sha256)
[ -n "$HEADER_SHA" ] || fail "the download has no x-backup-sha256 header: $(<"$WORK/headers")"
expect "the sha256 header matches the record" "$BACKUP_SHA" "$HEADER_SHA"
expect "the sha256 header matches the downloaded bytes" "$HEADER_SHA" "$(sha256_hex <"$WORK/backup.dump")"
expect "the download is a pg_dump custom archive (plaintext, not the sealed file)" PGDMP "$(head -c 5 "$WORK/backup.dump")"
edge "$SITE_HOST" /notes -X DELETE >/dev/null || fail "could not delete the notes"
edge "$SITE_HOST" /notes -X POST --data 'written after the backup' >/dev/null || fail "could not write a note"
wait_count "$SITE_HOST" 1 "mutated: one different row remains"
api POST "/api/v1/sites/$SITE/data/backups/$BACKUP_ID/restore" '{"confirm":"wrong"}'
code_4xx "a restore without the site id as confirmation is refused"
api POST "/api/v1/sites/$SITE/data/backups/$BACKUP_ID/restore" "$(jq -nc --arg c "$SITE" '{confirm:$c}')"
code_is "start the restore" 202
PRE_ID=$(printf '%s' "$BODY" | jq -er .pre_restore_backup_id)
job_wait "$(printf '%s' "$BODY" | jq -er .job_id)"
wait_count "$SITE_HOST" 3 "the three baseline rows are back after the restore"
api GET "/api/v1/sites/$SITE/data/backups/$PRE_ID"
code_is "read the pre-restore backup" 200
jq_ok "the pre-restore backup exists and finished" '.status == "ok" and .trigger == "pre_restore" and .size_bytes > 0'
api GET "/api/v1/sites/$SITE/data/backups?database=pg:app"
jq_ok "both versions are listed" "any(.[]; .id == \"$BACKUP_ID\") and any(.[]; .id == \"$PRE_ID\") and ([.[].version] | unique | length) == 2"
psql_ok "$DBNET" "$RW_URL" "begin; insert into notes (body) values ('after restore'); rollback" "the restored database accepts writes from the app user again"
psql_refused "$DBNET" "$RW_URL" "create table harness_ddl (i int)" "the restore kept the privilege levels" 'permission denied'
end_step

# ---------------------------------------------------------------------------------------------------------------------
begin_step 5 "password rotation, redeploy, no failed requests, old login retired"
OLD_URL=$(app_env "$SITE_HOST" DATABASE_URL)
OLD_USER=$(url_user "$OLD_URL")
rm -f "$WORK/stop"
traffic "$SITE_HOST" "$WORK/rotate.out" &
LOOP_PID=$!
sleep 2
run_job "rotate the app user's password" POST "/api/v1/sites/$SITE/data/postgres/databases/app/users/app/rotate"
jq_ok "the rotation says a redeploy is needed" '.redeploy_needed == true'
api GET "/api/v1/sites/$SITE/data"
jq_ok "the previous login is waiting to be retired" '.postgres.databases[] | select(.name == "app") | .users[] | select(.name == "app") | .retiring != null'
psql_ok "$DBNET" "$OLD_URL" "select 1" "the previous login still works while the running slot uses it"
deploy_site "$SITE" "e2e rotation redeploy" "$SITE_HOST"
sleep 3
touch "$WORK/stop"
wait "$LOOP_PID"
LOOP_PID=""
rm -f "$WORK/stop"
[ "$(wc -l <"$WORK/rotate.out" | tr -d ' ')" -gt 30 ] || fail "too few requests were sent during the rotation"
expect "failed requests during the rotation and redeploy" 0 "$(traffic_failures "$WORK/rotate.out")"
NEW_URL=$(app_env "$SITE_HOST" DATABASE_URL)
[ "$(url_user "$NEW_URL")" != "$OLD_USER" ] || fail "the app login did not change to the other alternate ($OLD_USER)"
[ "$(url_pass "$NEW_URL")" != "$(url_pass "$OLD_URL")" ] || fail "the app password did not change"
pass "the redeployed app received a new login and password"
psql_ok "$DBNET" "$NEW_URL" "select 1" "the new login works"
RETIRED=""
for _ in $(seq 1 60); do
  api GET "/api/v1/sites/$SITE/data"
  if printf '%s' "$BODY" | jq -e '.postgres.databases[] | select(.name == "app") | .users[] | select(.name == "app") | .retiring == null' >/dev/null; then
    RETIRED=1
    break
  fi
  sleep 5
done
[ -n "$RETIRED" ] || fail "the previous login was not retired within five minutes of the redeploy"
pass "the previous login was retired"
psql_refused "$DBNET" "$OLD_URL" "select 1" "the retired login is refused" 'authentication failed|does not exist|password|role'
wait_count "$SITE_HOST" 3 "the data survived the rotation"
end_step

# ---------------------------------------------------------------------------------------------------------------------
begin_step 6 "shared mode: tenants cannot reach each other"
run_job "enable the shared Postgres 17 instance" PUT /api/v1/data/shared '{"major":17,"memory_mb":512,"cpus":1,"max_connections":100}'
api GET /api/v1/data/shared
jq_ok "the shared instance is enabled" '.enabled == true and .major == 17'
create_fixture_site "$SITE_A" "$HOST_A" false
create_fixture_site "$SITE_B" "$HOST_B" false
for pair in "$SITE_A:$HOST_A" "$SITE_B:$HOST_B"; do
  run_job "enable shared Postgres on ${pair%%:*}" PUT "/api/v1/sites/${pair%%:*}/data/postgres" '{"mode":"shared","preset":"generic"}'
  deploy_site "${pair%%:*}" "e2e shared deploy" "${pair#*:}"
done
A_URL=$(app_env "$HOST_A" DATABASE_URL)
B_URL=$(app_env "$HOST_B" DATABASE_URL)
TAG_A=$(pg_tag "$SITE_A")
TAG_B=$(pg_tag "$SITE_B")
expect "site A connects to the shared instance" cite-pg-shared "$(url_host "$A_URL")"
case $A_URL in
  */"t${TAG_A}_app"\?*) pass "site A's database is t<tag>_app with the documented tag" ;;
  *) fail "site A's URL does not name t${TAG_A}_app: $A_URL" ;;
esac
NET_A="cite-$SITE_A-dbnet"
NET_B="cite-$SITE_B-dbnet"
psql_ok "$NET_A" "$A_URL" "select current_database()" "site A's credentials work from site A's network"
expect "site A sees its own database" "t${TAG_A}_app" "$PSQL_OUT"
psql_ok "$NET_B" "$B_URL" "select current_database()" "site B's credentials work from site B's network"
psql_refused "$NET_B" "$A_URL" "select 1" "site A's credentials are refused from site B's network" 'pg_hba|rejects|authentication|no pg_hba'
psql_refused "$NET_A" "$B_URL" "select 1" "site B's credentials are refused from site A's network" 'pg_hba|rejects|authentication|no pg_hba'
psql_refused "$NET_A" "$(url_with_db "$A_URL" "t${TAG_B}_app")" "select 1" "a tenant cannot connect to another tenant's database" 'pg_hba|rejects|permission denied|authentication|not have CONNECT'
psql_refused "$NET_A" "$(url_with_db "$A_URL" postgres)" "select 1" "a tenant cannot connect to the postgres database" 'pg_hba|rejects|permission denied|authentication|not have CONNECT'
psql_refused "$NET_A" "$(url_with_db "$A_URL" template1)" "select 1" "a tenant cannot connect to template1" 'pg_hba|rejects|permission denied|authentication|not have CONNECT'
psql_ok "$NET_A" "$A_URL" "select datname from pg_database where datallowconn and has_database_privilege(datname, 'CONNECT') order by 1" "a tenant lists the databases it may connect to"
expect "the only connectable database is the tenant's own" "t${TAG_A}_app" "$PSQL_OUT"
edge "$HOST_A" /notes -X POST --data 'tenant a' >/dev/null || fail "site A could not write"
wait_count "$HOST_A" 1 "site A reads its own row"
wait_count "$HOST_B" 0 "site B does not see site A's row"
end_step

# ---------------------------------------------------------------------------------------------------------------------
begin_step 7 "external Postgres through the egress forward, private target refused until allowed"
docker run -d --name "$EXT_NAME" -p "0.0.0.0:$EXT_PORT:5432" -e POSTGRES_PASSWORD=ext-admin-pass "$PG18_IMAGE" >/dev/null || fail "the external database did not start"
wait_for "the external database accepts connections" 90 docker exec "$EXT_NAME" pg_isready -q -h 127.0.0.1 -p 5432
ext_sql() {
  docker exec "$EXT_NAME" psql -U postgres -v ON_ERROR_STOP=1 -q "$@" >/dev/null || fail "could not prepare the external database"
}
ext_sql -c "create role $EXT_USER login password '$EXT_PASSWORD'"
ext_sql -c "create database extdb owner $EXT_USER"
ext_sql -d extdb -c "create table ext_items (id int primary key, v text); insert into ext_items values (1,'a'),(2,'b'),(3,'c'); alter table ext_items owner to $EXT_USER"
if [ -n "${E2E_EXT_HOST:-}" ]; then
  EXT_HOST=$E2E_EXT_HOST
elif [ "$(uname -s)" = Darwin ]; then
  # The egress proxy denies its own networks and gateways, so the database is reached through the host's address
  # as Docker Desktop publishes it to containers.
  EXT_HOST=$(docker run --rm --entrypoint sh "$PG18_IMAGE" -c 'getent ahostsv4 host.docker.internal' | awk 'NR == 1 {print $1}')
  [ -n "$EXT_HOST" ] || fail "could not resolve host.docker.internal; set E2E_EXT_HOST"
else
  # The host's primary address: not a Docker bridge or its gateway, which the egress proxy denies outright.
  EXT_HOST=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}')
  [ -n "$EXT_HOST" ] || fail "could not find the host's primary address; set E2E_EXT_HOST"
fi
pass "the external database is reached at $EXT_HOST:$EXT_PORT, a private address"
EXT_URL="postgres://$EXT_USER:$EXT_PASSWORD@$EXT_HOST:$EXT_PORT/extdb?sslmode=disable"
api PUT "/api/v1/sites/$SITE/data/external/ext" "$(jq -nc --arg u "$EXT_URL" '{url:$u}')"
code_is "attach the external database" 200
jq_ok "the attachment shows host and port but never the URL" ".name == \"ext\" and .host == \"$EXT_HOST\" and .port == $EXT_PORT and (tostring | contains(\"$EXT_PASSWORD\") | not)"
api POST "/api/v1/sites/$SITE/data/links" '{"links":[{"var":"EXT_DATABASE_URL","target":"runtime","source":{"kind":"external","name":"ext","field":"url"}}]}'
code_is "link EXT_DATABASE_URL" 200
deploy_site "$SITE" "e2e external attach" "$SITE_HOST"
RUNTIME_EXT=$(app_env "$SITE_HOST" EXT_DATABASE_URL)
case $RUNTIME_EXT in
  *"-egress-proxy:15432/"*) pass "the runtime URL goes through the stack's egress proxy forward" ;;
  *) fail "the runtime URL is not rewritten to the egress proxy forward: $RUNTIME_EXT" ;;
esac
case $RUNTIME_EXT in
  *"$EXT_HOST"*) fail "the runtime URL still names the external host" ;;
esac
EGRESS_PROXY=$(docker ps --format '{{.Names}}' | grep -E "^cite-$SITE-(blue|green)-egress-proxy\$" | head -n 1 || true)
[ -n "$EGRESS_PROXY" ] || fail "no running egress proxy for $SITE"
FORWARDS=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$EGRESS_PROXY" | grep '^CITE_EGRESS_FORWARDS=' || true)
expect "the egress proxy carries the forward" "CITE_EGRESS_FORWARDS=15432=$EXT_HOST:$EXT_PORT" "$FORWARDS"
expect "a private target is refused by the forward until it is allowed" 500 "$(edge_code "$SITE_HOST" /ext/count)"
api GET "/api/v1/sites/$SITE"
code_is "read the site for its outbound rules" 200
api PUT "/api/v1/sites/$SITE" "$(printf '%s' "$BODY" | jq -c --arg h "$EXT_HOST" 'del(.live) | .outbound_rules.allow = [$h]')"
code_is "allow the external address in the site's outbound rules" 200
deploy_site "$SITE" "e2e external allow" "$SITE_HOST"
wait_count "$SITE_HOST" 3 "the app reads three rows from the external database through the forward" /ext/count
api GET "/api/v1/sites/$SITE/data"
no_secret "the data view does not return the external password" "$EXT_PASSWORD"
wait_count "$SITE_HOST" 3 "the managed database was not disturbed"
end_step

# ---------------------------------------------------------------------------------------------------------------------
begin_step 8 "S3 backup target on an S3-compatible server, push a backup, see the object"
S3_CONFIG=$(jq -nc --arg u "$MINIO_USER" --arg p "$MINIO_PASSWORD" \
  '{identities: [{name: "e2e", credentials: [{accessKey: $u, secretKey: $p}], actions: ["Admin", "Read", "Write", "List", "Tagging"]}]}')
docker run -d --name "$MINIO_NAME" --network "${PROJECT}_public" --network-alias minio \
  -e S3_CONFIG="$S3_CONFIG" --entrypoint sh "$S3_IMAGE" \
  -c 'printf "%s" "$S3_CONFIG" > /etc/s3.json && exec weed server -dir=/data -s3 -s3.port=9000 -s3.config=/etc/s3.json -master.volumeSizeLimitMB=64 -volume.max=8' \
  >/dev/null || fail "the S3 server did not start"
# Create the bucket, then confirm the filer lists it; retried until the master and filer are up.
wait_for "the S3 server is up with bucket $MINIO_BUCKET" 90 docker exec "$MINIO_NAME" sh -c \
  "echo 's3.bucket.create -name $MINIO_BUCKET' | weed shell -master=127.0.0.1:9333 -filer=127.0.0.1:8888 >/dev/null 2>&1; wget -qO- http://127.0.0.1:8888/buckets/ | grep -q '$MINIO_BUCKET'"
api POST /api/v1/data/targets "$(jq -nc --arg u "$MINIO_USER" --arg p "$MINIO_PASSWORD" --arg b "$MINIO_BUCKET" '{
  name: "e2eminio", endpoint: "http://minio:9000", bucket: $b, region: "us-east-1", path_style: true,
  access_key_id: $u, secret_access_key: $p}')"
code_is "create the S3 backup target" 201
TARGET_ID=$(printf '%s' "$BODY" | jq -er .id)
no_secret "the target view does not return the secret key" "$MINIO_PASSWORD"
TARGET_OK=""
for _ in $(seq 1 60); do
  api POST "/api/v1/data/targets/$TARGET_ID/test"
  if [ "$CODE" = 200 ] && printf '%s' "$BODY" | jq -e '.ok == true' >/dev/null; then
    TARGET_OK=1
    break
  fi
  sleep 1
done
[ -n "$TARGET_OK" ] || fail "the connector could not reach the S3 server through the target: $BODY"
pass "the target test reaches the S3 server (private address allowed by CITE_DATA_S3_ALLOW_PRIVATE)"
api POST "/api/v1/sites/$SITE/data/backups" '{"database":"pg:app","label":"e2e s3"}'
code_is "start a backup to push" 202
S3_BACKUP_ID=$(printf '%s' "$BODY" | jq -er .backup_id)
job_wait "$(printf '%s' "$BODY" | jq -er .job_id)"
run_job "push the backup to the target" POST "/api/v1/sites/$SITE/data/backups/$S3_BACKUP_ID/push" "$(jq -nc --arg t "$TARGET_ID" '{target:$t}')"
api GET "/api/v1/sites/$SITE/data/backups/$S3_BACKUP_ID"
jq_ok "the record carries the S3 copy" ".s3.target == \"$TARGET_ID\" and (.s3.key | endswith(\"$S3_BACKUP_ID.cbk\")) and (.s3.uploaded_at | length) > 0"
S3_KEY=$(printf '%s' "$BODY" | jq -er .s3.key)
# The filer serves bucket objects by key, which reads the stored bytes without going through S3 auth.
docker exec "$MINIO_NAME" wget -qO /tmp/object "http://127.0.0.1:8888/buckets/$MINIO_BUCKET/$S3_KEY" \
  || fail "the bucket holds no object $S3_KEY for backup $S3_BACKUP_ID"
SIZE=$(docker exec "$MINIO_NAME" sh -c 'wc -c < /tmp/object' | tr -d ' ')
[ "${SIZE:-0}" -gt 0 ] || fail "the object $S3_KEY is empty"
pass "the object $S3_KEY exists in the bucket ($SIZE bytes)"
if docker exec "$MINIO_NAME" grep -q PGDMP /tmp/object; then
  fail "the object in the bucket contains a plaintext pg_dump archive"
fi
pass "the stored object is not a plaintext dump"
api GET /api/v1/data/targets
no_secret "the target list does not return the secret key" "$MINIO_PASSWORD"
end_step

# ---------------------------------------------------------------------------------------------------------------------
begin_step 9 "the Docker proxy refuses host mounts and another site's database network"
BEFORE=$(docker_state)
proxy GET "/v1.45/containers/cite-$SITE-db/json"
expect "the proxy inspects the site's database container (control, HTTP 200)" 200 "$PCODE"
denied "a host bind on a data job" POST "/v1.45/containers/create?name=cite-$SITE-dbjob" \
  "$(jq -nc --arg i "$PG17_IMAGE" '{Image:$i,User:"10001:10001",Entrypoint:["cite-pg-job"],Cmd:["backup"],HostConfig:{Binds:["/:/host"]}}')"
denied "a host bind mount on a database container" POST "/v1.45/containers/create?name=cite-$SITE-db" \
  "$(jq -nc --arg i "$PG17_IMAGE" '{Image:$i,User:"70:70",HostConfig:{Mounts:[{Type:"bind",Source:"/var/lib",Target:"/var/lib/postgresql/data"}]}}')"
denied "a host bind mount on the shared instance" POST "/v1.45/containers/create?name=cite-pg-shared" \
  "$(jq -nc --arg i "$PG17_IMAGE" '{Image:$i,User:"70:70",HostConfig:{Binds:["/etc:/etc"]}}')"
denied "a data job attached to another site's database network" POST "/v1.45/containers/create?name=cite-$SITE-dbjob" \
  "$(jq -nc --arg i "$PG17_IMAGE" --arg n "cite-$SITE_A-dbnet" '{Image:$i,User:"10001:10001",Entrypoint:["cite-pg-job"],Cmd:["backup"],HostConfig:{NetworkMode:$n},NetworkingConfig:{EndpointsConfig:{($n):{}}}}')"
denied "a database container on a foreign image" POST "/v1.45/containers/create?name=cite-$SITE-db" \
  '{"Image":"docker.io/library/postgres:17-alpine","HostConfig":{}}'
denied "attaching a site's executor to another site's database network" POST "/v1.45/networks/cite-$SITE_A-dbnet/connect" \
  "{\"Container\":\"cite-$SITE-blue-executor\"}"
denied "attaching a site's database to another site's database network" POST "/v1.45/networks/cite-$SITE_A-dbnet/connect" \
  "{\"Container\":\"cite-$SITE-db\"}"
denied "attaching the shared instance to a stack network" POST "/v1.45/networks/cite-$SITE-blue-net/connect" \
  '{"Container":"cite-pg-shared"}'
denied "exec in a database container" POST "/v1.45/containers/cite-$SITE-db/exec" '{"Cmd":["sh"]}'
expect "docker state is unchanged by every denied request" "$BEFORE" "$(docker_state)"
end_step

# ---------------------------------------------------------------------------------------------------------------------
begin_step 10 "conversion from dedicated to shared with the data intact"
edge "$SITE_HOST" /notes -X POST --data 'before the conversion' >/dev/null || fail "could not write a note"
wait_count "$SITE_HOST" 4 "four rows before the conversion"
api POST "/api/v1/sites/$SITE/data/postgres/convert" '{"to":"shared","freeze":"maintenance"}'
code_is "start the conversion" 202
CONVERT_ID=$(printf '%s' "$BODY" | jq -er .session)
wait_state "/api/v1/sites/$SITE/data/postgres/convert/$CONVERT_ID" awaiting_cutover
jq_ok "the copy is verified before the cutover" '.error == null and (.counts == null or .peer_counts == null or .counts == .peer_counts)'
api POST "/api/v1/sites/$SITE/data/postgres/convert/$CONVERT_ID/cutover"
code_is "cut over to the shared instance" 200
wait_state "/api/v1/sites/$SITE/data/postgres/convert/$CONVERT_ID" "done"
api GET "/api/v1/sites/$SITE/data"
jq_ok "the site is shared and keeps the dedicated database as retired" '.postgres.mode == "shared" and .postgres.retired.mode == "dedicated"'
deploy_site "$SITE" "e2e after conversion" "$SITE_HOST"
SHARED_URL=$(app_env "$SITE_HOST" DATABASE_URL)
expect "the app now connects to the shared instance" cite-pg-shared "$(url_host "$SHARED_URL")"
wait_count "$SITE_HOST" 4 "all four rows are in the shared database"
run_job "delete the retired dedicated database" DELETE "/api/v1/sites/$SITE/data/postgres/retired"
if docker inspect "cite-$SITE-db" >/dev/null 2>&1; then
  fail "the retired dedicated container still exists"
fi
pass "the retired dedicated container is gone"
wait_count "$SITE_HOST" 4 "the data is intact after the retired database was deleted"
end_step

# ---------------------------------------------------------------------------------------------------------------------
begin_step 11 "transfer between two connectors on one daemon, row counts match, cutover"
# A second node needs Docker networks of its own, and the daemon's default address pools are small, so the two
# shared-mode sites go first; deleting them with purge is checked on the way.
for gone in "$SITE_A" "$SITE_B"; do
  api DELETE "/api/v1/sites/$gone?purge_volumes=true&purge_data=true"
  code_is "delete $gone with its data" 200
done
for gone in "$SITE_A" "$SITE_B"; do
  wait_for "the containers, networks and volumes of $gone are gone" 60 sh -c \
    "[ -z \"\$(docker ps -aq --filter label=cite.site=$gone)\$(docker network ls -q --filter label=cite.site=$gone)\$(docker volume ls -q --filter label=cite.site=$gone)\" ]"
done
use_node 2
onboard
create_fixture_site "$SITE_I" "$HOST_I" false
run_job "enable dedicated Postgres 18 on the target site" PUT "/api/v1/sites/$SITE_I/data/postgres" '{"mode":"dedicated","major":18,"preset":"generic"}'
use_node 1
api POST "/api/v1/sites/$SITE/data/exports" '{"database":"pg:app","freeze":"none"}'
code_is "start the export on node 1" 202
EXPORT_ID=$(printf '%s' "$BODY" | jq -er .session)
wait_state "/api/v1/sites/$SITE/data/exports/$EXPORT_ID" ready
EXPORT_SESSION=$BODY
CHUNKS=$(printf '%s' "$EXPORT_SESSION" | jq -er .chunks)
[ "$CHUNKS" -ge 1 ] || fail "the export has no chunks: $EXPORT_SESSION"
api GET "/api/v1/sites/$SITE/data/exports/$EXPORT_ID/manifest"
code_is "read the manifest" 200
MANIFEST=$BODY
use_node 2
api POST "/api/v1/sites/$SITE_I/data/imports" "$(jq -nc --argjson m "$MANIFEST" '{manifest:$m,replace:true}')"
code_is "open the import on node 2" 201
IMPORT_ID=$(printf '%s' "$BODY" | jq -er .session)
for ((n = 0; n < CHUNKS; n++)); do
  use_node 1
  fetch_to "$WORK/chunk.bin" GET "/api/v1/sites/$SITE/data/exports/$EXPORT_ID/chunks/$n"
  expect "export chunk $n is served" 200 "$CODE"
  CHUNK_SHA=$(header_value x-chunk-sha256)
  expect "chunk $n hash header matches its bytes" "$CHUNK_SHA" "$(sha256_hex <"$WORK/chunk.bin")"
  use_node 2
  fetch_to "$WORK/chunk.out" PUT "/api/v1/sites/$SITE_I/data/imports/$IMPORT_ID/chunks/$n" \
    -H "x-chunk-sha256: $CHUNK_SHA" -H 'Content-Type: application/octet-stream' --data-binary "@$WORK/chunk.bin"
  expect "import chunk $n is accepted" 204 "$CODE"
done
run_job "commit the import" POST "/api/v1/sites/$SITE_I/data/imports/$IMPORT_ID/commit" '{}'
wait_state "/api/v1/sites/$SITE_I/data/imports/$IMPORT_ID" awaiting_cutover
jq_ok "the imported tables have the same row counts as the source" '(.counts | length) > 0 and .counts == .peer_counts and any(.counts[]; .table == "notes" and .rows == 4)'
api POST "/api/v1/sites/$SITE_I/data/imports/$IMPORT_ID/finish" '{"outcome":"cutover"}'
code_is "cut over the import" 200
jq_ok "the import is done" '.state == "done"'
use_node 1
api POST "/api/v1/sites/$SITE/data/exports/$EXPORT_ID/finish" '{"outcome":"cutover"}'
code_is "finish the export on the source" 200
jq_ok "the export is done" '.state == "done"'
use_node 2
deploy_site "$SITE_I" "e2e after import" "$HOST_I"
wait_count "$HOST_I" 4 "the target app serves the four imported rows from its own database"
expect "the target database is on node 2's site network" "cite-$SITE_I-db" "$(url_host "$(app_env "$HOST_I" DATABASE_URL)")"
use_node 1
wait_count "$SITE_HOST" 4 "the source still holds its rows"
end_step

END_TIME=$(date +%s)
echo "e2e-data: all steps passed in $((END_TIME - START_TIME)) seconds"
