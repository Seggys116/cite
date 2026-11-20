#!/usr/bin/env bash
# End to end upgrade check: a node installed from the published v0.4.1 release is upgraded in place to the working tree (the
# way scripts/setup.sh do_update does it) and everything it held must survive. Phases:
#   1. an orchestrated node on the published ghcr.io/seggys116 0.4.1 images, with the v0.4.1 compose files taken from git;
#   2. state is seeded on it: an API token, an orchestrated node site built from the mock GitHub (a runtime env var, a per-site
#      GitHub token and a persistent volume holding a file), a plain upstream site, a firewall rule and analytics rows;
#   3. the upgrade: CITE_VERSION is set in .env, the working tree compose files are swapped in and "docker compose up -d
#      --remove-orphans" runs with no volume flag, while a request loop measures the outage;
#   4. verification on 0.5.0 (login with the old password, the old API token, CA fingerprint, site list, serving, env, token,
#      firewall, analytics, volume, sealed files with .pre-seal copies, redeploy, the client compatibility shim, data services),
#      then a connector restart that must remove the .pre-seal copies;
#   5. a downgrade back to 0.4.1, informational only: what happens is printed and never fails the run.
# Checks from phase 3 on are recorded and the run continues, so one run reports every breakage; the exit status is 1 if any
# check failed. Setup problems before the upgrade abort the run.
#
# Run: scripts/e2e-upgrade.sh
# Images (tagged ghcr.io/seggys116/<name>:<tag>): the old ones are pulled; the new ones are built from the working tree unless
# they exist locally or E2E_SKIP_BUILD=1: cite-connector, cite-dockerproxy, cite-manager and cite-executor-node (-node22),
# cite-egress, cite-postgres (-pg18), plus cite-mock-github:e2e.
# Environment: OLD_VERSION (default 0.4.1, must be a git tag v$OLD_VERSION), NEW_VERSION (default 0.5.0), E2E_SKIP_BUILD=1,
# E2E_REBUILD=1 rebuilds the new images even when present, E2E_KEEP=1 skips teardown, E2E_CLEAN=1 removes leftovers of an
# earlier run first, E2E_LOG_DIR (default target/e2e-upgrade-logs), DOCKER_GID (detected).
# The node uses the fixed names of the compose files (cite-node-haproxy, cite_edge, cite-backups), so the script refuses to run
# next to another Cite node on the daemon.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="${E2E_LOG_DIR:-$ROOT/target/e2e-upgrade-logs}"
REGISTRY=ghcr.io/seggys116
CURL_IMAGE=docker.io/curlimages/curl:latest
OLD_VERSION="${OLD_VERSION:-0.4.1}"
NEW_VERSION="${NEW_VERSION:-0.5.0}"

PROJECT=cite-e2e-upgrade
API_PORT=17447
HTTP_PORT=18085
HTTPS_PORT=18449
HAPROXY=cite-node-haproxy
SITE=e2eupg
SITE_HOST=app.upgrade.e2e.test
PLAIN=e2eplain
PLAIN_HOST=plain.upgrade.e2e.test
PLAIN_UPSTREAM=cite-e2e-upgrade-upstream
FIXTURE_REPO=acme/live
MOCK_NAME=cite-e2e-upgrade-mock-github
MOCK_IMAGE="${MOCK_IMAGE:-cite-mock-github:e2e}"
MOCK_PORT=18092
MOCK_TOKEN=ghp_citeMockGithubPat00000000000000001
ENV_NAME=E2E_RUNTIME_VAR
ENV_VALUE=runtime-value-for-the-upgrade-check
VOLUME_NAME=data
SEED_PREFIX=volume-seed

for tool in docker jq curl python3 openssl awk; do
  command -v "$tool" >/dev/null 2>&1 || { echo "e2e-upgrade: $tool is required" >&2; exit 2; }
done
docker compose version >/dev/null 2>&1 || { echo "e2e-upgrade: docker compose is required" >&2; exit 2; }
git -C "$ROOT" rev-parse "v$OLD_VERSION^{commit}" >/dev/null 2>&1 || { echo "e2e-upgrade: git tag v$OLD_VERSION is missing" >&2; exit 2; }

if [ -z "${DOCKER_GID:-}" ]; then
  if [ "$(uname -s)" = Darwin ]; then
    DOCKER_GID=0
  else
    DOCKER_GID=$(stat -c %g /var/run/docker.sock)
  fi
fi
export DOCKER_GID

WORK="$(mktemp -d)"
DIR="$WORK/node"
ENV_PATH="$DIR/.env"
mkdir -p "$DIR"
CA="$WORK/ca.pem"
CODE=""
BODY=""
TOKEN=""
LAST_STEP=0
USERNAME=""
PASSWORD=""
TOTP_SECRET=""
LOOP_PID=""
SOFT=0
STEP_NAME=setup
PREFLIGHT_DONE=0
LOGS_SAVED=0
CONF_IMAGE="$REGISTRY/cite-connector:$OLD_VERSION"
declare -a FAILS=() PASSED=()

# The compose files are always run from $DIR with its .env, like an installed node.
compose() {
  docker compose --project-directory "$DIR" -p "$PROJECT" -f "$DIR/docker-compose.node.yml" -f "$DIR/docker-compose.orchestrator.yml" "$@" </dev/null
}

now_ms() {
  if command -v perl >/dev/null 2>&1; then
    perl -MTime::HiRes=time -e 'printf "%d\n", time * 1000'
  else
    echo "$(date +%s)000"
  fi
}

# Only what this script created is removed: by compose project, by name and by the site label.
remove_all() {
  local id site
  docker rm -f "$MOCK_NAME" "$PLAIN_UPSTREAM" >/dev/null 2>&1 || true
  for site in "$SITE" "$PLAIN"; do
    while read -r id; do
      [ -z "$id" ] || docker rm -f "$id" >/dev/null 2>&1 || true
    done < <(docker ps -aq --filter "label=cite.site=$site")
  done
  # Dedicated databases and their jobs of the site carry the site label too; compose then takes the project down.
  if [ -f "$DIR/docker-compose.node.yml" ] && [ -f "$DIR/docker-compose.orchestrator.yml" ]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  while read -r id; do
    [ -z "$id" ] || docker rm -f "$id" >/dev/null 2>&1 || true
  done < <(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")
  for site in "$SITE" "$PLAIN"; do
    while read -r id; do
      [ -z "$id" ] || docker network rm "$id" >/dev/null 2>&1 || true
    done < <(docker network ls -q --filter "label=cite.site=$site")
    while read -r id; do
      [ -z "$id" ] || docker volume rm -f "$id" >/dev/null 2>&1 || true
    done < <(docker volume ls -q --filter "label=cite.site=$site")
  done
  while read -r id; do
    [ -z "$id" ] || docker network rm "$id" >/dev/null 2>&1 || true
  done < <(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT")
  while read -r id; do
    [ -z "$id" ] || docker volume rm -f "$id" >/dev/null 2>&1 || true
  done < <(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")
  # The connector creates the egress bridge itself; it is only removable once nothing is attached, so a node in use keeps it.
  docker network rm cite-egress >/dev/null 2>&1 || true
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
}

# Before the upgrade a failed check aborts the run; from the upgrade on it is recorded and the run continues.
fail() {
  echo "FAIL ($STEP_NAME): $*" >&2
  if [ "$SOFT" = 1 ]; then
    FAILS+=("$STEP_NAME: $*")
    return 0
  fi
  collect_logs
  echo "where to look: container logs and 'docker ps -a' output are in $LOG_DIR; rerun with E2E_KEEP=1 to keep the stack (compose project $PROJECT)" >&2
  exit 1
}

pass() {
  echo "ok   $*"
  PASSED+=("$*")
}

step() {
  STEP_NAME=$1
  echo "== $1"
}

expect() {
  if [ "$2" = "$3" ]; then
    pass "$1"
  else
    fail "$1: expected '$2', got '$3'"
  fi
}

truthy() {
  local what=$1
  shift
  if "$@" >/dev/null 2>&1; then
    pass "$what"
  else
    fail "$what"
  fi
}

api() {
  local method=$1 path=$2 data=${3:-} auth=${4-$TOKEN}
  local -a args=(-sS --max-time "${API_TIMEOUT:-30}" --cacert "$CA"
    --resolve "localhost:$API_PORT:127.0.0.1" -o "$WORK/body" -w '%{http_code}' -X "$method")
  [ -z "$auth" ] || args+=(-H "Authorization: Bearer $auth")
  [ -z "$data" ] || args+=(-H 'Content-Type: application/json' --data "$data")
  if [ -n "${API_HEADER:-}" ]; then
    args+=(-H "$API_HEADER")
  fi
  : >"$WORK/body"
  if ! CODE=$(curl "${args[@]}" "https://localhost:$API_PORT$path" 2>"$WORK/curl.err"); then
    fail "curl $method $path failed: $(<"$WORK/curl.err")"
    CODE=000
  fi
  BODY=$(<"$WORK/body")
}

code_is() {
  if [ "$2" = "$CODE" ]; then
    pass "$1 (HTTP $2)"
  else
    fail "$1: expected HTTP $2, got $CODE: $(printf '%s' "$BODY" | head -c 400)"
  fi
}

jq_ok() {
  if printf '%s' "$BODY" | jq -e "$2" >/dev/null 2>&1; then
    pass "$1"
  else
    fail "$1: jq '$2' failed on: $(printf '%s' "$BODY" | head -c 600)"
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
    read -r step code < <(totp "$TOTP_SECRET")
    [ "$step" -gt "$LAST_STEP" ] && break
    sleep 1
  done
  LAST_STEP=$step
  api POST /api/v1/auth/login "$(jq -nc --arg u "$USERNAME" --arg p "$PASSWORD" --arg t "$code" '{username:$u,password:$p,totp:$t}')" ""
  code_is "$1" 200
  TOKEN=$(printf '%s' "$BODY" | jq -r '.token // empty')
}

healthy() {
  curl -fsS --max-time 3 --cacert "$CA" --resolve "localhost:$API_PORT:127.0.0.1" \
    -o /dev/null "https://localhost:$API_PORT/api/v1/healthz" 2>/dev/null
}

wait_api() {
  for _ in $(seq 1 90); do
    healthy && return 0
    sleep 1
  done
  fail "connector API did not become healthy"
  return 1
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
  return 1
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

# Reads one file from the connector config volume, with whichever connector image is current.
conf_file() {
  docker run --rm --user 0 --entrypoint cat -v "${PROJECT}_cite_conf:/conf:ro" "$CONF_IMAGE" "/conf/$1"
}

conf_sh() {
  docker run --rm --user 0 --entrypoint sh -v "${PROJECT}_cite_conf:/conf:ro" "$CONF_IMAGE" -c "$1"
}

ca_fingerprint() {
  conf_file tls/ca.pem | openssl x509 -noout -fingerprint -sha256 | sed 's/^[^=]*=//'
}

# ---- the mock GitHub and the fixture ----

mock_endpoint() {
  if [ "$(uname -s)" = Darwin ]; then
    MOCK_BIND=127.0.0.1
    MOCK_HOST=host.docker.internal
  else
    MOCK_BIND=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
    MOCK_HOST=$MOCK_BIND
  fi
  MOCK_API_URL="http://$MOCK_HOST:$MOCK_PORT"
}

# One commit to the mock: a small node server that keeps a seed file on the site volume, prints a runtime variable on request
# and serves the marker of the commit.
mock_push() {
  local marker=$1
  local server
  server=$(
    cat <<'EOF'
const http = require("http");
const fs = require("fs");
const marker = fs.readFileSync("marker.txt", "utf8").trim();
const file = "/data/state.txt";
let note = "";
try {
  fs.readFileSync(file);
} catch (e) {
  try {
    fs.writeFileSync(file, "SEEDPREFIX\n");
  } catch (err) {
    note = "write failed: " + err.code;
  }
}
const text = (res, body, status) => {
  res.writeHead(status || 200, { "content-type": "text/plain" });
  res.end(body);
};
http
  .createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    if (url.pathname === "/file") {
      try {
        return text(res, fs.readFileSync(file, "utf8").trim());
      } catch (e) {
        return text(res, "no file " + e.code + " " + note, 404);
      }
    }
    if (url.pathname === "/env") {
      const name = url.searchParams.get("name") || "";
      return name === "ENVNAME" && process.env[name] !== undefined ? text(res, process.env[name]) : text(res, "not set", 404);
    }
    if (url.pathname === "/ping") return text(res, "pong");
    return text(res, "e2e-upgrade-" + marker);
  })
  .listen(Number(process.env.PORT), "127.0.0.1");
EOF
  )
  server=${server//SEEDPREFIX/$SEED_PREFIX}
  server=${server//ENVNAME/$ENV_NAME}
  jq -nc --arg marker "$marker" --arg server "$server" '{
    branch: "main", message: ("e2e " + $marker), author: "e2e",
    files: {
      "package.json": "{\"name\":\"upgrade-fixture\",\"private\":true,\"scripts\":{\"build\":\"node build.js\",\"start\":\"node server.js\"}}",
      "build.js": "require(\"fs\").writeFileSync(\"built.txt\", \"ok\");\n",
      "marker.txt": ($marker + "\n"),
      "server.js": $server
    }}' >"$WORK/push.json"
  curl -fsS --max-time 15 -H "Authorization: Bearer $MOCK_TOKEN" -H 'Content-Type: application/json' \
    --data-binary "@$WORK/push.json" "http://$MOCK_BIND:$MOCK_PORT/__cite/push" >/dev/null || fail "could not push $marker to the mock"
}

edge() {
  local host=$1 path=$2
  shift 2
  curl -sS --max-time 10 -H "Host: $host" "$@" "http://127.0.0.1:$HTTP_PORT$path"
}

edge_code() {
  edge "$1" "$2" -o /dev/null -w '%{http_code}' "${@:3}" 2>/dev/null || true
}

serves() {
  [ "$(edge "$SITE_HOST" / 2>/dev/null)" = "e2e-upgrade-$1" ]
}

# ---- the request loop that measures the outage ----

traffic() {
  local out=$1 t code
  : >"$out"
  while [ ! -e "$WORK/stop" ]; do
    t=$(now_ms)
    code=$(curl -s -o /dev/null --max-time 3 -H "Host: $SITE_HOST" -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/ping" 2>/dev/null || true)
    printf '%s %s\n' "$t" "${code:-000}" >>"$out"
    sleep 0.1
  done
}

# Prints: total requests, failed requests, longest outage in ms, total outage in ms (first failure to the next success).
traffic_report() {
  awk '
    { n++; if ($2 != 200) { f++; if (!inrun) { inrun = 1; start = $1 } } else if (inrun) { d = $1 - start; if (d > longest) longest = d; total += d; inrun = 0 } }
    END { if (inrun) { d = $1 - start; if (d > longest) longest = d; total += d } printf "%d %d %d %d\n", n, f, longest, total }
  ' "$1"
}

# ---- preflight ----

build_images() {
  local base
  docker build -q -f images/connector/Dockerfile --build-arg "VERSION=$NEW_VERSION" -t "$REGISTRY/cite-connector:$NEW_VERSION" . >/dev/null
  docker build -q -f images/dockerproxy/Dockerfile --build-arg "VERSION=$NEW_VERSION" -t "$REGISTRY/cite-dockerproxy:$NEW_VERSION" . >/dev/null
  docker build -q -f images/manager/Dockerfile --build-arg NODE_MAJOR=22 --build-arg "VERSION=$NEW_VERSION" -t "$REGISTRY/cite-manager:$NEW_VERSION-node22" . >/dev/null
  docker build -q -f images/executor-node/Dockerfile --build-arg NODE_MAJOR=22 --build-arg "VERSION=$NEW_VERSION" -t "$REGISTRY/cite-executor-node:$NEW_VERSION-node22" . >/dev/null
  docker build -q -f images/egress/Dockerfile --build-arg "VERSION=$NEW_VERSION" -t "$REGISTRY/cite-egress:$NEW_VERSION" . >/dev/null
  base=$(awk '
    function done_block() { if (inpg && m == 18 && img != "" && dg != "") { print img "@" dg; found = 1; exit } }
    /^\[/ { done_block(); inpg = ($0 == "[[postgres]]"); m = ""; img = ""; dg = ""; next }
    inpg && $1 == "major" { m = $3 }
    inpg && $1 == "image" { gsub(/"/, "", $3); img = $3 }
    inpg && $1 == "digest" { gsub(/"/, "", $3); dg = $3 }
    END { if (!found) done_block() }
  ' "$ROOT/images/images.toml")
  [ -n "$base" ] || { echo "e2e-upgrade: images/images.toml has no pinned image for postgres 18" >&2; exit 2; }
  docker build -q -f images/postgres/Dockerfile --build-arg "PG_IMAGE=$base" --build-arg "VERSION=$NEW_VERSION" \
    -t "$REGISTRY/cite-postgres:$NEW_VERSION-pg18" . >/dev/null
  docker image inspect "$MOCK_IMAGE" >/dev/null 2>&1 || docker build -q -f images/mock-github/Dockerfile -t "$MOCK_IMAGE" . >/dev/null
}

new_images() {
  printf '%s\n' "cite-connector:$NEW_VERSION" "cite-dockerproxy:$NEW_VERSION" "cite-manager:$NEW_VERSION-node22" \
    "cite-executor-node:$NEW_VERSION-node22" "cite-egress:$NEW_VERSION" "cite-postgres:$NEW_VERSION-pg18"
}

old_images() {
  printf '%s\n' "cite-connector:$OLD_VERSION" "cite-dockerproxy:$OLD_VERSION" "cite-manager:$OLD_VERSION-node22" \
    "cite-executor-node:$OLD_VERSION-node22" "cite-egress:$OLD_VERSION"
}

# Informational: puts the old compose files and connector back and prints what the 0.4.1 connector does with the 0.5.0 data.
downgrade_probe() {
  local f cid
  SOFT=0
  for f in docker-compose.node.yml docker-compose.orchestrator.yml; do
    git -C "$ROOT" show "v$OLD_VERSION:$f" >"$DIR/$f"
  done
  set_env CITE_VERSION "$OLD_VERSION"
  CONF_IMAGE="$REGISTRY/cite-connector:$OLD_VERSION"
  compose up -d --remove-orphans >"$WORK/downgrade.log" 2>&1 || echo "     downgrade: compose up exited with an error"
  sleep 20
  cid=$(compose ps -aq connector)
  echo "     downgrade: connector state: $(docker inspect -f '{{.State.Status}} restarts={{.RestartCount}} exit={{.State.ExitCode}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>&1)"
  echo "     downgrade: API healthz: $(curl -sS --max-time 5 --cacert "$CA" --resolve "localhost:$API_PORT:127.0.0.1" -o /dev/null -w '%{http_code}' "https://localhost:$API_PORT/api/v1/healthz" 2>/dev/null || true)"
  echo "     downgrade: connector log (distinct lines):"
  docker logs --tail 30 "$cid" 2>&1 | sed 's/^/       | /' | sort | uniq -c | sort -rn | head -n 5 | cut -c1-400 || true
  echo "     downgrade: secrets.json starts with: $(conf_file secrets.json 2>/dev/null | head -c 40 | tr -c '[:print:]' '?')"
  echo "     downgrade: edge.json holds site data: $(conf_file edge.json 2>/dev/null | jq -r 'if any(.sites[]?; has("data")) then "yes" else "no" end' 2>/dev/null || echo unreadable)"
}

cd "$ROOT"
if [ "${E2E_CLEAN:-0}" = 1 ]; then
  remove_all
fi
if docker inspect "$HAPROXY" >/dev/null 2>&1 || [ -n "$(docker ps -aq --filter label=cite.managed=true)" ]; then
  echo "e2e-upgrade: a node or stack already exists on this daemon; refusing to run next to it (E2E_CLEAN=1 removes the leftovers of an earlier run)" >&2
  rm -rf "$WORK"
  trap - EXIT
  exit 2
fi
PREFLIGHT_DONE=1

step "images"
while read -r ref; do
  docker image inspect "$REGISTRY/$ref" >/dev/null 2>&1 || docker pull -q "$REGISTRY/$ref" >/dev/null ||
    { echo "e2e-upgrade: cannot pull $REGISTRY/$ref" >&2; exit 2; }
done < <(old_images)
pass "the published $OLD_VERSION images are present"
missing=0
while read -r ref; do
  docker image inspect "$REGISTRY/$ref" >/dev/null 2>&1 || missing=1
done < <(new_images)
if [ "${E2E_SKIP_BUILD:-0}" != 1 ] && { [ "$missing" = 1 ] || [ "${E2E_REBUILD:-0}" = 1 ]; }; then
  echo "building the $NEW_VERSION images from the working tree"
  build_images
fi
while read -r ref; do
  docker image inspect "$REGISTRY/$ref" >/dev/null 2>&1 || { echo "e2e-upgrade: image $REGISTRY/$ref is missing (unset E2E_SKIP_BUILD to build it)" >&2; exit 2; }
done < <(new_images)
docker image inspect "$MOCK_IMAGE" >/dev/null 2>&1 || { echo "e2e-upgrade: image $MOCK_IMAGE is missing" >&2; exit 2; }
docker pull -q "$CURL_IMAGE" >/dev/null 2>&1 || docker image inspect "$CURL_IMAGE" >/dev/null 2>&1 || { echo "e2e-upgrade: no curl image" >&2; exit 2; }
pass "the $NEW_VERSION images are present"

step "old node: v$OLD_VERSION compose files and images"
mock_endpoint
for f in docker-compose.node.yml docker-compose.orchestrator.yml; do
  git -C "$ROOT" show "v$OLD_VERSION:$f" >"$DIR/$f" || { echo "e2e-upgrade: could not extract $f from v$OLD_VERSION" >&2; exit 2; }
done
set_env() {
  local key=$1 value=$2
  if grep -q "^$key=" "$ENV_PATH" 2>/dev/null; then
    awk -v k="$key" -v v="$value" 'BEGIN { FS = OFS = "=" } $1 == k { print k "=" v; next } { print }' "$ENV_PATH" >"$ENV_PATH.new"
    mv "$ENV_PATH.new" "$ENV_PATH"
  else
    printf '%s=%s\n' "$key" "$value" >>"$ENV_PATH"
  fi
}
{
  echo "CITE_VERSION=$OLD_VERSION"
  echo "DOCKER_GID=$DOCKER_GID"
  echo "CITE_PUBLIC_BIND=127.0.0.1"
  echo "CITE_HTTP_PORT=$HTTP_PORT"
  echo "CITE_HTTPS_PORT=$HTTPS_PORT"
  echo "CITE_CONNECTOR_BIND=127.0.0.1"
  echo "CITE_CONNECTOR_PORT=$API_PORT"
  echo "CITE_CONNECTOR_ALLOW=allow-all"
  echo "CITE_DEPLOY_BUILD_TIMEOUT=300"
  echo "CITE_GITHUB_API_URL=$MOCK_API_URL"
} >"$ENV_PATH"
truthy "the v$OLD_VERSION compose files validate" compose config -q
expect "the old compose files name the old connector image" "$REGISTRY/cite-connector:$OLD_VERSION" "$(compose config --images | grep cite-connector | sort -u)"

step "mock GitHub"
docker run -d --name "$MOCK_NAME" -p "$MOCK_BIND:$MOCK_PORT:8080" "$MOCK_IMAGE" >/dev/null || fail "the mock GitHub did not start"
wait_for "the mock GitHub answers" 30 curl -fsS --max-time 3 -H "Authorization: Bearer $MOCK_TOKEN" "http://$MOCK_BIND:$MOCK_PORT/repos/$FIXTURE_REPO"
mock_push marker-v1

step "old node: onboarding on $OLD_VERSION"
compose run --rm --no-deps -T init >"$WORK/init.log" 2>&1 || fail "volume init failed: $(<"$WORK/init.log")"
compose run --rm --no-deps -T connector init --non-interactive --json >"$WORK/creds.json" 2>"$WORK/init.err" ||
  fail "connector init failed: $(<"$WORK/init.err")"
USERNAME=$(jq -er .username "$WORK/creds.json")
PASSWORD=$(jq -er .password "$WORK/creds.json")
TOTP_SECRET=$(jq -er .totp_secret "$WORK/creds.json")
compose run --rm --no-deps -T --entrypoint cat connector /conf/tls/ca.pem >"$CA" || fail "could not read ca.pem"
pass "init --json printed credentials for $USERNAME"
compose up -d >"$WORK/up.log" 2>&1 || fail "compose up failed: $(<"$WORK/up.log")"
wait_api
login "login on $OLD_VERSION"
wait_for "dockerproxy is healthy" 90 proxy_healthy
wait_for "HAProxy stopped restarting" 90 haproxy_settled
api GET /api/v1/node
code_is "node status on $OLD_VERSION" 200
jq_ok "the old node reports $OLD_VERSION with the orchestrator reachable" ".version == \"$OLD_VERSION\" and .orchestrator.enabled == true and .orchestrator.reachable == true"
OLD_CA_FP=$(ca_fingerprint)
[ -n "$OLD_CA_FP" ] || fail "no CA fingerprint"
pass "recorded the node CA fingerprint $OLD_CA_FP"

step "seed state on $OLD_VERSION"
api POST /api/v1/tokens '{"name":"upgrade-e2e"}'
code_is "create an API token" 200
OLD_API_TOKEN=$(printf '%s' "$BODY" | jq -er .token)
OLD_API_TOKEN_ID=$(printf '%s' "$BODY" | jq -er .id)
api GET /api/v1/node "" "$OLD_API_TOKEN"
code_is "the API token works on $OLD_VERSION" 200

site_json=$(jq -nc --arg token "$MOCK_TOKEN" --arg repo "$FIXTURE_REPO" --arg host "$SITE_HOST" --arg id "$SITE" \
  --arg vol "$VOLUME_NAME" '{
  id: $id, name: "Upgrade Site", hosts: [$host], active: "blue",
  blue: {targets: []}, green: {targets: []},
  volumes: [{name: $vol, mount_path: "/data"}],
  source: {repo: $repo, branch: "main", runtime: "node", node_major: 22, rendering: "ssr", output_dir: ".",
           build_command: "node build.js", start_command: "node server.js", poll_interval: "off"},
  github_token: $token
}')
API_TIMEOUT=300 api POST /api/v1/sites "$site_json"
code_is "create the orchestrated node site" 200
jq_ok "the site is active on blue" '.active == "blue"'
# On 0.4.1 the first promote can give up with executor_unresponsive while a node executor is still booting (0.5.0 waits up to
# 30 s); the first-boot deploy is not retried, so one explicit deploy brings the site up.
SOFT_SEED=0
for _ in $(seq 1 45); do
  serves marker-v1 && SOFT_SEED=1 && break
  sleep 1
done
if [ "$SOFT_SEED" = 0 ]; then
  echo "     note: the first-boot deploy did not serve on $OLD_VERSION; deploying again"
  API_TIMEOUT=300 api POST "/api/v1/sites/$SITE/deploy" '{"git_ref":"main","note":"retry after the first boot"}'
  code_is "deploy again after the first-boot promote gave up" 200
fi
wait_for "the site serves marker-v1 through HAProxy" 180 serves marker-v1
expect "the volume file was written by the app" "$SEED_PREFIX" "$(edge "$SITE_HOST" /file 2>/dev/null || true)"

api PATCH "/api/v1/sites/$SITE/runtime-env" "$(jq -nc --arg n "$ENV_NAME" --arg v "$ENV_VALUE" '{set: {($n): $v}}')"
code_is "set a runtime env var" 200
API_TIMEOUT=300 api POST "/api/v1/sites/$SITE/deploy" '{"git_ref":"main","note":"apply the runtime env"}'
code_is "deploy so the env var reaches the executor" 200
wait_for "the executor sees the runtime env var" 120 test "$(edge "$SITE_HOST" "/env?name=$ENV_NAME" 2>/dev/null || true)" = "$ENV_VALUE"
wait_for "the site still serves marker-v1" 60 serves marker-v1
expect "the volume file survived the deploy" "$SEED_PREFIX" "$(edge "$SITE_HOST" /file 2>/dev/null || true)"
api GET "/api/v1/sites/$SITE/runtime-env"
code_is "runtime env names on $OLD_VERSION" 200
OLD_ENV_NAMES=$(printf '%s' "$BODY" | jq -cS .)
api GET "/api/v1/sites/$SITE/github-token"
code_is "GitHub token status on $OLD_VERSION" 200
OLD_TOKEN_STATUS=$(printf '%s' "$BODY" | jq -cS .)
echo "     token status: $OLD_TOKEN_STATUS, env names: $OLD_ENV_NAMES"

# A plain upstream: a tiny node server on the edge network, reached by HAProxy under its own host.
docker run -d --name "$PLAIN_UPSTREAM" --network cite_edge --entrypoint node "$REGISTRY/cite-manager:$OLD_VERSION-node22" \
  -e 'require("http").createServer((q,r)=>{r.writeHead(200,{"content-type":"text/plain"});r.end("plain-upstream")}).listen(8080)' >/dev/null ||
  fail "the plain upstream did not start"
plain_json=$(jq -nc --arg id "$PLAIN" --arg host "$PLAIN_HOST" --arg up "$PLAIN_UPSTREAM:8080" '{
  id: $id, name: "Plain Upstream", hosts: [$host], active: "blue",
  blue: {targets: [{addr: $up}]}, green: {targets: []}
}')
api POST /api/v1/sites "$plain_json"
code_is "create the plain upstream site" 200
plain_up() {
  [ "$(edge "$PLAIN_HOST" / 2>/dev/null)" = plain-upstream ]
}
wait_for "the plain upstream is served through HAProxy" 60 plain_up

api POST /api/v1/firewall/rules '{"id":"e2e-deny-blocked","name":"deny /blocked","enabled":true,"action":"deny","matchers":{"path_prefixes":["/blocked"]},"site":null}'
code_is "create a firewall rule" 200
wait_for "the firewall rule blocks /blocked" 30 test "$(edge_code "$SITE_HOST" /blocked)" = 403

for i in $(seq 1 30); do
  edge "$SITE_HOST" "/seed/$i" -o /dev/null 2>/dev/null || true
done
edge "$PLAIN_HOST" /plain-seed -o /dev/null 2>/dev/null || true
# Reads the analytics row count into ROWS (the stats reply is flat on 0.4.1; the nested form is accepted too).
analytics_rows() {
  api GET /api/v1/analytics/stats
  ROWS=$(printf '%s' "$BODY" | jq -r '.rows // .store.rows // empty' 2>/dev/null || true)
}
rows=0
for _ in $(seq 1 60); do
  analytics_rows
  rows=$ROWS
  [ "${rows:-0}" -ge 20 ] 2>/dev/null && break
  sleep 1
done
[ "${rows:-0}" -ge 20 ] 2>/dev/null || fail "analytics has no rows: $BODY"
OLD_ROWS=$rows
pass "analytics holds $OLD_ROWS rows"
api GET /api/v1/analytics/stats
echo "     analytics stats on $OLD_VERSION: $BODY"

api GET /api/v1/sites
code_is "site list on $OLD_VERSION" 200
printf '%s' "$BODY" | jq -S . >"$WORK/sites.before.json"
jq_ok "two sites are listed" 'length == 2'
api GET /api/v1/firewall/rules
code_is "firewall rules on $OLD_VERSION" 200
printf '%s' "$BODY" | jq -S . >"$WORK/firewall.before.json"
OLD_SECRETS_PLAIN=$(conf_file secrets.json | head -c 200 | wc -c | tr -d ' ')
echo "     secrets.json on $OLD_VERSION is plaintext JSON: $(conf_file secrets.json | jq -e . >/dev/null 2>&1 && echo yes || echo no) ($OLD_SECRETS_PLAIN bytes sampled)"

# ---------------------------------------------------------------------------------------------------------------------
step "upgrade to $NEW_VERSION the way setup.sh does"
SOFT=1
rm -f "$WORK/stop"
traffic "$WORK/traffic.out" &
LOOP_PID=$!
sleep 2
for f in docker-compose.node.yml docker-compose.orchestrator.yml; do
  cp "$ROOT/$f" "$DIR/$f"
done
set_env CITE_VERSION "$NEW_VERSION"
truthy "the working tree compose files validate" compose config -q
while read -r img; do
  docker image inspect "$img" >/dev/null 2>&1 || fail "image $img is not local"
done < <(compose config --images | grep "$REGISTRY")
UPGRADE_START=$(now_ms)
if compose up -d --remove-orphans >"$WORK/upgrade.log" 2>&1; then
  pass "docker compose up -d --remove-orphans"
else
  fail "docker compose up -d --remove-orphans failed: $(<"$WORK/upgrade.log")"
fi
UPGRADE_COMPOSE_MS=$(($(now_ms) - UPGRADE_START))
sed 's/^/     compose: /' "$WORK/upgrade.log" | grep -Ei 'recreat|start|creat|running|error' | head -n 20 || true
CONF_IMAGE="$REGISTRY/cite-connector:$NEW_VERSION"
wait_api
API_UP_MS=$(($(now_ms) - UPGRADE_START))
wait_for "dockerproxy is healthy" 90 proxy_healthy
wait_for "HAProxy stopped restarting" 90 haproxy_settled
wait_for "the site serves again" 120 serves marker-v1
sleep 5
touch "$WORK/stop"
wait "$LOOP_PID" 2>/dev/null || true
LOOP_PID=""
read -r REQS FAILED LONGEST TOTAL < <(traffic_report "$WORK/traffic.out")
echo "     upgrade: compose returned after ${UPGRADE_COMPOSE_MS} ms, connector healthy after ${API_UP_MS} ms"
echo "     request loop through HAProxy: $REQS requests, $FAILED failed, longest outage ${LONGEST} ms, total outage ${TOTAL} ms"
awk '$2 != 200 { print $2 }' "$WORK/traffic.out" | sort | uniq -c | sed 's/^/     failed status /'
cp "$WORK/traffic.out" "$WORK/traffic.keep" 2>/dev/null || true

step "after the upgrade: connector"
api GET /api/v1/healthz "" ""
code_is "the connector is healthy" 200
CONNECTOR_ID=$(compose ps -q connector)
expect "the connector runs the $NEW_VERSION image" "$REGISTRY/cite-connector:$NEW_VERSION" "$(docker inspect -f '{{.Config.Image}}' "$CONNECTOR_ID")"
expect "the connector never restarted" 0 "$(docker inspect -f '{{.RestartCount}}' "$CONNECTOR_ID")"
login "login with the old password and a TOTP code"
api GET /api/v1/node
code_is "node status on $NEW_VERSION" 200
jq_ok "the node reports $NEW_VERSION, the orchestrator is reachable" ".version == \"$NEW_VERSION\" and .orchestrator.enabled == true and .orchestrator.reachable == true"
NODE_BODY=$BODY
api GET /api/v1/node "" "$OLD_API_TOKEN"
code_is "the API token from $OLD_VERSION still works" 200
api GET /api/v1/tokens
jq_ok "the old token is still listed" "any(.[]; .id == \"$OLD_API_TOKEN_ID\")"
expect "the node CA fingerprint is unchanged" "$OLD_CA_FP" "$(ca_fingerprint)"
api GET /api/v1/healthz "" ""
code_is "the CA from before the upgrade still verifies the new server certificate" 200

step "after the upgrade: state"
api GET /api/v1/sites
code_is "site list on $NEW_VERSION (no client header)" 200
printf '%s' "$BODY" | jq -S . >"$WORK/sites.after.json"
if diff -u "$WORK/sites.before.json" "$WORK/sites.after.json" >"$WORK/sites.diff"; then
  pass "the site list is identical in every field $OLD_VERSION had"
else
  fail "the site list changed: $(head -n 40 "$WORK/sites.diff")"
fi
expect "the orchestrated site still serves" "e2e-upgrade-marker-v1" "$(edge "$SITE_HOST" / 2>/dev/null || true)"
expect "the plain upstream site still serves" plain-upstream "$(edge "$PLAIN_HOST" / 2>/dev/null || true)"
expect "the volume file is still there" "$SEED_PREFIX" "$(edge "$SITE_HOST" /file 2>/dev/null || true)"
expect "the executor still sees the runtime env var" "$ENV_VALUE" "$(edge "$SITE_HOST" "/env?name=$ENV_NAME" 2>/dev/null || true)"
api GET "/api/v1/sites/$SITE/runtime-env"
code_is "runtime env names on $NEW_VERSION" 200
expect "the env var names are unchanged" "$OLD_ENV_NAMES" "$(printf '%s' "$BODY" | jq -cS .)"
api GET "/api/v1/sites/$SITE/github-token"
code_is "GitHub token status on $NEW_VERSION" 200
expect "the per-site GitHub token status is unchanged" "$OLD_TOKEN_STATUS" "$(printf '%s' "$BODY" | jq -cS .)"
api GET "/api/v1/sites/$SITE/volumes"
code_is "volumes of the site" 200
jq_ok "the declared volume is listed and exists" "any(.[]; .name == \"$VOLUME_NAME\" and .declared == true and .created_at != null)"
api GET /api/v1/firewall/rules
code_is "firewall rules on $NEW_VERSION" 200
if diff -u "$WORK/firewall.before.json" <(printf '%s' "$BODY" | jq -S .) >"$WORK/firewall.diff"; then
  pass "the firewall rules are unchanged"
else
  fail "the firewall rules changed: $(head -n 30 "$WORK/firewall.diff")"
fi
expect "the firewall rule still blocks /blocked" 403 "$(edge_code "$SITE_HOST" /blocked)"
analytics_rows
code_is "analytics stats on $NEW_VERSION" 200
NEW_ROWS=$ROWS
if [ "${NEW_ROWS:-0}" -ge "$OLD_ROWS" ] 2>/dev/null; then
  pass "analytics rows are preserved ($OLD_ROWS before, $NEW_ROWS now)"
else
  fail "analytics rows were lost: $OLD_ROWS before, '${NEW_ROWS:-}' now; stats: $BODY"
fi
api GET "/api/v1/analytics/requests?limit=5"
code_is "analytics requests are readable" 200

step "after the upgrade: secrets are sealed"
SEALED_FILES=$(conf_sh 'cd /conf && ls -1 | grep -Ev "^(haproxy|certs|state|tls)$" | sort | tr "\n" " "')
echo "     files in /conf: $SEALED_FILES"
truthy "the managed key file /conf/secrets.key exists" conf_sh 'test -s /conf/secrets.key'
for f in secrets.json credentials.json; do
  conf_file "$f" >"$WORK/$f.out" 2>/dev/null || true
  if [ ! -s "$WORK/$f.out" ]; then
    fail "$f is missing or empty on $NEW_VERSION"
  elif ! jq -e '.cite_sealed == 1 and (.ct | type == "string")' "$WORK/$f.out" >/dev/null 2>&1; then
    fail "$f is not a sealed envelope on $NEW_VERSION: $(head -c 120 "$WORK/$f.out")"
  elif grep -q "$MOCK_TOKEN" "$WORK/$f.out"; then
    fail "$f is a sealed envelope but still carries the GitHub token"
  else
    pass "$f is sealed ($(jq -c '{cite_sealed, alg, kid}' "$WORK/$f.out"))"
  fi
  truthy "$f.pre-seal exists" conf_sh "test -s /conf/$f.pre-seal"
done
if conf_sh 'grep -l "BEGIN .*PRIVATE KEY" /conf/tls/*.key 2>/dev/null' | grep -q .; then
  fail "a TLS private key is still plaintext PEM: $(conf_sh 'grep -l "BEGIN .*PRIVATE KEY" /conf/tls/*.key')"
else
  pass "no TLS private key is plaintext PEM"
fi
echo "     pre-seal copies: $(conf_sh 'cd /conf && ls -1 *.pre-seal tls/*.pre-seal 2>/dev/null | tr "\n" " "')"

step "after the upgrade: a redeploy on the $NEW_VERSION images"
mock_push marker-v2
API_TIMEOUT=300 api POST "/api/v1/sites/$SITE/deploy" '{"git_ref":"main","note":"redeploy on the new images"}'
code_is "redeploy the site" 200
wait_for "the site serves marker-v2" 120 serves marker-v2
api GET "/api/v1/sites/$SITE"
SLOT=$(printf '%s' "$BODY" | jq -r .active)
expect "the executor runs the $NEW_VERSION image" "$REGISTRY/cite-executor-node:$NEW_VERSION-node22" "$(docker inspect -f '{{.Config.Image}}' "cite-$SITE-$SLOT-executor" 2>/dev/null || true)"
expect "the manager runs the $NEW_VERSION image" "$REGISTRY/cite-manager:$NEW_VERSION-node22" "$(docker inspect -f '{{.Config.Image}}' "cite-$SITE-$SLOT-manager" 2>/dev/null || true)"
expect "the volume file survived the redeploy" "$SEED_PREFIX" "$(edge "$SITE_HOST" /file 2>/dev/null || true)"
expect "the runtime env var survived the redeploy" "$ENV_VALUE" "$(edge "$SITE_HOST" "/env?name=$ENV_NAME" 2>/dev/null || true)"

step "after the upgrade: a second start removes the .pre-seal copies"
compose restart connector >"$WORK/restart.log" 2>&1 || fail "connector restart failed: $(<"$WORK/restart.log")"
wait_api
api GET /api/v1/healthz "" ""
code_is "the connector is healthy after the restart" 200
login "login after the restart"
api GET /api/v1/node
jq_ok "the orchestrator is reachable after the restart" '.orchestrator.enabled == true and .orchestrator.reachable == true'
expect "no .pre-seal copy is left" "" "$(conf_sh 'cd /conf && ls -1 *.pre-seal tls/*.pre-seal 2>/dev/null' || true)"
api GET /api/v1/sites
code_is "site list after the restart" 200
expect "the CA fingerprint is still the same" "$OLD_CA_FP" "$(ca_fingerprint)"
expect "the old API token still works after the restart" 200 "$(
  api GET /api/v1/node "" "$OLD_API_TOKEN"
  echo "$CODE"
)"

# ---------------------------------------------------------------------------------------------------------------------
# Informational only: nothing below fails the run.
step "downgrade back to $OLD_VERSION (informational, before any site data exists)"
downgrade_probe

# Rolling forward again must work after the failed downgrade: the data the 0.4.1 connector could not read is untouched.
step "roll forward to $NEW_VERSION again after the downgrade"
SOFT=1
for f in docker-compose.node.yml docker-compose.orchestrator.yml; do
  cp "$ROOT/$f" "$DIR/$f"
done
set_env CITE_VERSION "$NEW_VERSION"
CONF_IMAGE="$REGISTRY/cite-connector:$NEW_VERSION"
if compose up -d --remove-orphans >"$WORK/rollforward.log" 2>&1; then
  pass "docker compose up -d --remove-orphans back on $NEW_VERSION"
else
  fail "roll forward failed: $(<"$WORK/rollforward.log")"
fi
wait_api
wait_for "dockerproxy is healthy" 90 proxy_healthy
wait_for "HAProxy stopped restarting" 90 haproxy_settled
login "login after rolling forward"
api GET /api/v1/node
jq_ok "the node reports $NEW_VERSION, the orchestrator is reachable" ".version == \"$NEW_VERSION\" and .orchestrator.reachable == true"
wait_for "the site serves marker-v2" 120 serves marker-v2
expect "the old API token still works after rolling forward" 200 "$(
  api GET /api/v1/node "" "$OLD_API_TOKEN"
  echo "$CODE"
)"

step "after the upgrade: client compatibility and data services"
BODY=$NODE_BODY
jq_ok "the node advertises the data capabilities" '[.capabilities[] | select(startswith("data-"))] | length > 0'
api GET /api/v1/data
code_is "the data service answers" 200
JOB_TRIES=${JOB_TRIES:-120}
api PUT "/api/v1/sites/$SITE/data/postgres" '{"mode":"dedicated","major":18,"preset":"generic"}'
code_is "enable dedicated Postgres 18 on the upgraded site is accepted" 202
JOB=$(printf '%s' "$BODY" | jq -r '.job_id // empty')
state=""
for _ in $(seq 1 "$JOB_TRIES"); do
  [ -n "$JOB" ] || break
  api GET "/api/v1/data/jobs/$JOB"
  state=$(printf '%s' "$BODY" | jq -r '.state // empty')
  case $state in ok | failed) break ;; esac
  sleep 2
done
if [ "$state" = ok ]; then
  pass "the Postgres job finished"
else
  fail "the Postgres job ended as '${state:-none}': $(printf '%s' "$BODY" | head -c 500)"
fi
API_HEADER="X-Cite-Client: $NEW_VERSION" api GET "/api/v1/sites/$SITE/data"
code_is "site data with the client header" 200
jq_ok "the site has a dedicated pg18 with the app database" '.postgres.mode == "dedicated" and .postgres.major == 18 and any(.postgres.databases[]; .name == "app")'
API_HEADER="X-Cite-Client: $NEW_VERSION" api GET /api/v1/sites
jq_ok "a client sending X-Cite-Client $NEW_VERSION gets the data field" 'any(.[]; .id == "'"$SITE"'" and has("data"))'
api GET /api/v1/sites
code_is "site list without the client header" 200
jq_ok "GET /api/v1/sites without X-Cite-Client has no data field" 'all(.[]; has("data") | not)'
api GET "/api/v1/sites/$SITE"
jq_ok "GET /api/v1/sites/{id} without X-Cite-Client has no data field" 'has("data") | not'
expect "the site still serves after Postgres was enabled" "e2e-upgrade-marker-v2" "$(edge "$SITE_HOST" / 2>/dev/null || true)"

step "downgrade again once Postgres data exists (informational)"
downgrade_probe

echo
if [ "${#FAILS[@]}" -gt 0 ]; then
  echo "e2e-upgrade: ${#FAILS[@]} check(s) failed, ${#PASSED[@]} passed"
  printf '  FAIL %s\n' "${FAILS[@]}"
  collect_logs
  echo "container logs are in $LOG_DIR" >&2
  exit 1
fi
echo "e2e-upgrade: all ${#PASSED[@]} checks passed; upgrade outage: $FAILED of $REQS requests failed, longest ${LONGEST} ms"
