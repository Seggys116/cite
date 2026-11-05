#!/usr/bin/env bash
# End to end check of the orchestrator against a real Docker daemon, ending in a live phase that builds a site from a mock GitHub and serves it through HAProxy.
# Needs local images tagged ghcr.io/seggys116/cite-{connector,dockerproxy,executor-static}:$CITE_VERSION, cite-{manager,executor-node}:$CITE_VERSION-node22 and $MOCK_IMAGE (images/mock-github/Dockerfile).
# E2E_KEEP=1 skips teardown. On Linux the managers cannot resolve host.docker.internal, so the mock is published on the docker0 gateway address instead.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT=cite-e2e-orch
API_PORT=17444
SITE=e2eshop
TOKEN_VALUE=ghp_e2eFakeTokenNotReal0123456789
REGISTRY=ghcr.io/seggys116
HAPROXY=cite-node-haproxy
NET="cite-$SITE-blue-net"
EGRESS="cite-$SITE-blue-egress"
GREEN_NET="cite-$SITE-green-net"
LIVE_SITE=e2elive
LIVE_HOST=app.e2e.test
LIVE_REPO=acme/live
MOCK_NAME=cite-e2e-mock-github
MOCK_IMAGE="${MOCK_IMAGE:-cite-mock-github:e2e}"
MOCK_PORT=18090
MOCK_TOKEN=ghp_citeMockGithubPat00000000000000001
CURL_IMAGE=docker.io/curlimages/curl:latest

export CITE_VERSION="${CITE_VERSION:-0.0.1}"
export CITE_STACK_VERSION="${CITE_STACK_VERSION:-$CITE_VERSION}"
export CITE_PUBLIC_BIND=127.0.0.1
export CITE_HTTP_PORT=18081
export CITE_HTTPS_PORT=18445
export CITE_CONNECTOR_BIND=127.0.0.1
export CITE_CONNECTOR_PORT=$API_PORT
export CITE_CONNECTOR_ALLOW=allow-all

for tool in docker jq curl python3 openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "e2e-orchestrator: $tool is required" >&2; exit 2; }
done

if [ -z "${DOCKER_GID:-}" ]; then
  if [ "$(uname -s)" = Darwin ]; then
    DOCKER_GID=0
  else
    DOCKER_GID=$(stat -c %g /var/run/docker.sock)
  fi
fi
export DOCKER_GID

WORK="$(mktemp -d)"
CA="$WORK/ca.pem"
TOKEN=""
LAST_STEP=0
CODE=""
BODY=""
PCODE=""
PBODY=""

compose() {
  docker compose -p "$PROJECT" -f "$ROOT/docker-compose.node.yml" -f "$ROOT/docker-compose.orchestrator.yml" "$@" </dev/null
}

# Only resources of the test site are removed by label, so a real node on the same daemon is never touched.
remove_stack() {
  local c site
  docker rm -f "$MOCK_NAME" >/dev/null 2>&1 || true
  for site in "$SITE" "$LIVE_SITE"; do
    for c in $(docker ps -aq --filter "label=cite.site=$site"); do
      docker rm -f "$c" >/dev/null 2>&1 || true
    done
  done
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  for site in "$SITE" "$LIVE_SITE"; do
    for c in $(docker network ls -q --filter "label=cite.site=$site"); do
      docker network rm "$c" >/dev/null 2>&1 || true
    done
    for c in $(docker volume ls -q --filter "label=cite.site=$site"); do
      docker volume rm -f "$c" >/dev/null 2>&1 || true
    done
  done
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [ "${E2E_KEEP:-0}" != 1 ]; then
    remove_stack
    rm -rf "$WORK"
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  echo "e2e-orchestrator FAIL: $*" >&2
  compose logs --no-color --tail 40 connector dockerproxy >&2 2>/dev/null || true
  local c
  for c in "cite-$SITE-blue-manager" "cite-$LIVE_SITE-blue-manager" "cite-$LIVE_SITE-green-manager" "cite-$LIVE_SITE-blue-executor" "$MOCK_NAME"; do
    docker logs --tail 30 "$c" >&2 2>&1 || true
  done
  exit 1
}

pass() {
  echo "ok   $*"
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

code_is() {
  [ "$2" = "$CODE" ] || fail "$1: expected HTTP $2, got $CODE: $BODY"
  pass "$1 (HTTP $2)"
}

jq_ok() {
  printf '%s' "$BODY" | jq -e "$2" >/dev/null || fail "$1: jq '$2' failed on: $BODY"
  pass "$1"
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
  code_is "login" 200
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
  fail "connector API did not become healthy"
}

# Requests the Docker proxy from a throwaway container on the internal docker_api network, as the connector would.
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

# Containers, volumes and networks, to prove a denied request changed nothing.
docker_state() {
  {
    docker ps -aq --no-trunc | sed 's/^/c /'
    docker volume ls -q | sed 's/^/v /'
    docker network ls -q --no-trunc | sed 's/^/n /'
  } | sort
}

resource_dump() {
  local id
  while read -r id; do docker network inspect "$id"; done < <(docker network ls -q)
  while read -r id; do docker volume inspect "$id"; done < <(docker volume ls -q)
}

nets_of() {
  docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$1" | sed '/^$/d' | sort
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

haproxy_settled() {
  local before after
  before=$(docker inspect -f '{{.State.Status}} {{.RestartCount}}' "$HAPROXY")
  sleep 4
  after=$(docker inspect -f '{{.State.Status}} {{.RestartCount}}' "$HAPROXY")
  [ "$before" = "$after" ] && [ "${after%% *}" = running ]
}

haproxy_on() {
  nets_of "$HAPROXY" | grep -qx "$1"
}

haproxy_off() {
  ! haproxy_on "$1"
}

container_running() {
  [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]
}

# The managers sit on a bridge network and reach the host through host.docker.internal on Docker Desktop; Linux has no such name inside stacks, so the docker0 gateway carries the mock.
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

# Pushes one commit to the mock; the files form a complete static site that builds with node build.js and a vite dependency resolved from the repo itself.
mock_push() {
  local branch=$1 marker=$2 payload
  payload=$(jq -nc --arg branch "$branch" --arg marker "$marker" '{
    branch: $branch, message: ("e2e " + $marker), author: "e2e",
    files: {
      "package.json": "{\"name\":\"live\",\"scripts\":{\"build\":\"node build.js\"},\"dependencies\":{\"vite\":\"file:./stub\"}}",
      "stub/package.json": "{\"name\":\"vite\",\"version\":\"6.0.0\"}",
      "build.js": "const fs = require(\"fs\");\nfs.mkdirSync(\"dist\", { recursive: true });\nfs.copyFileSync(\"index.html\", \"dist/index.html\");\n",
      "index.html": ("<html>" + $marker + "</html>\n")
    }}')
  curl -fsS --max-time 15 -H "Authorization: Bearer $MOCK_TOKEN" -H 'Content-Type: application/json' \
    --data "$payload" "http://$MOCK_BIND:$MOCK_PORT/__cite/push" >/dev/null || fail "could not push $marker to the mock"
}

live_get() {
  curl -sS --max-time 5 -H "Host: $LIVE_HOST" "http://127.0.0.1:$CITE_HTTP_PORT/${1:-}" 2>/dev/null
}

live_serves() {
  live_get | grep -q "$1"
}

container_stopped() {
  [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = false ]
}

# The hardening every stack container must show in docker inspect.
HARDENED='.[0] | .HostConfig.ReadonlyRootfs == true
  and .HostConfig.CapDrop == ["ALL"]
  and (.HostConfig.SecurityOpt | any(startswith("no-new-privileges")))
  and .HostConfig.Privileged == false
  and ((.HostConfig.Binds // []) | length == 0)
  and ((.HostConfig.Devices // []) | length == 0)
  and ((.Mounts // []) | all(.Type == "volume"))
  and .HostConfig.PidMode == ""
  and .HostConfig.Memory > 0
  and .HostConfig.PidsLimit > 0
  and .Config.Labels["cite.managed"] == "true"'

cd "$ROOT"
if docker inspect "$HAPROXY" >/dev/null 2>&1 || [ -n "$(docker ps -aq --filter label=cite.managed=true)" ]; then
  echo "e2e-orchestrator: a node or stack already exists on this daemon; refusing to run next to it" >&2
  trap - EXIT
  rm -rf "$WORK"
  exit 2
fi
for ref in "cite-connector:$CITE_VERSION" "cite-dockerproxy:$CITE_VERSION" \
  "cite-manager:$CITE_STACK_VERSION-node22" "cite-executor-node:$CITE_STACK_VERSION-node22" \
  "cite-executor-static:$CITE_STACK_VERSION"; do
  docker image inspect "$REGISTRY/$ref" >/dev/null 2>&1 || { echo "e2e-orchestrator: image $REGISTRY/$ref is missing" >&2; exit 2; }
done
docker image inspect "$MOCK_IMAGE" >/dev/null 2>&1 || { echo "e2e-orchestrator: image $MOCK_IMAGE is missing" >&2; exit 2; }
docker pull -q "$CURL_IMAGE" >/dev/null
remove_stack

echo "== onboarding"
compose run --rm --no-deps -T init >"$WORK/init.log" 2>&1 || fail "volume init failed: $(<"$WORK/init.log")"
compose run --rm --no-deps -T connector init --non-interactive --json >"$WORK/creds.json" 2>"$WORK/init.err" ||
  fail "connector init failed: $(<"$WORK/init.err")"
USERNAME=$(jq -er .username "$WORK/creds.json")
PASSWORD=$(jq -er .password "$WORK/creds.json")
TOTP_SECRET=$(jq -er .totp_secret "$WORK/creds.json")
compose run --rm --no-deps -T --entrypoint cat connector /conf/tls/ca.pem >"$CA" || fail "could not read ca.pem"
pass "init --json printed credentials for $USERNAME"

echo "== start"
compose up -d >"$WORK/up.log" 2>&1 || fail "compose up failed: $(<"$WORK/up.log")"
wait_api
login
wait_for "dockerproxy is healthy" 60 test "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q dockerproxy)")" = healthy
# HAProxy exits until the connector has written its first config, so the first site waits for it to settle.
wait_for "HAProxy stopped restarting" 90 haproxy_settled
api GET /api/v1/node
code_is "node status" 200
jq_ok "orchestrator is enabled and reachable" '.orchestrator.enabled == true and .orchestrator.reachable == true'
PROXY_ID=$(compose ps -q dockerproxy)
CONNECTOR_ID=$(compose ps -q connector)
BODY=$(docker inspect "$PROXY_ID")
jq_ok "dockerproxy: read-only, no capabilities, not privileged" \
  '.[0] | .HostConfig.ReadonlyRootfs == true and .HostConfig.CapDrop == ["ALL"] and .HostConfig.Privileged == false'
expect "dockerproxy is only on docker_api" "${PROJECT}_docker_api" "$(nets_of "$PROXY_ID")"
expect "connector has no published docker access" 0 "$(docker inspect "$CONNECTOR_ID" | jq '[.[0].Mounts[] | select(.Source | test("docker.sock"))] | length')"

echo "== create an orchestrated site"
site_json=$(jq -nc --arg token "$TOKEN_VALUE" '{
  id: "e2eshop", name: "E2E Shop", hosts: ["shop.e2e.test"], active: "blue",
  blue: {targets: []}, green: {targets: []},
  source: {repo: "acme/shop", branch: "main", runtime: "node", node_major: 22},
  github_token: $token
}')
API_TIMEOUT=240 api POST /api/v1/sites "$site_json"
code_is "create site from source" 200
jq_ok "site is active on blue with the executor target" \
  '.id == "e2eshop" and .active == "blue" and .blue.targets[0].addr == "cite-e2eshop-blue-executor:8080" and (.source.secret | startswith("site-"))'
jq_ok "the token is not in the API reply" "(tostring | contains(\"$TOKEN_VALUE\")) | not"

MANAGER=cite-$SITE-blue-manager
EXECUTOR=cite-$SITE-blue-executor
truthy "manager container exists" docker inspect "$MANAGER"
truthy "executor container exists" docker inspect "$EXECUTOR"
for name in "$MANAGER" "$EXECUTOR"; do
  BODY=$(docker inspect "$name")
  jq_ok "$name is hardened (read-only, caps dropped, no-new-privileges, unprivileged, volumes only, limits, labelled)" "$HARDENED"
done
BODY=$(docker inspect "$EXECUTOR")
jq_ok "executor runs as 65532 and has no added capabilities" '.[0].Config.User == "65532:65532" and ((.[0].HostConfig.CapAdd // []) | length == 0)'
BODY=$(docker inspect "$MANAGER")
jq_ok "manager only regains the build capabilities" '(.[0].HostConfig.CapAdd | sort) == ["CHOWN","DAC_READ_SEARCH","SETGID","SETUID"]'
if docker inspect "cite-$SITE-blue-init" >/dev/null 2>&1; then
  BODY=$(docker inspect "cite-$SITE-blue-init")
  jq_ok "init container is hardened and has no network" "$HARDENED and (.[0].HostConfig.NetworkMode == \"none\")"
fi

echo "== network isolation"
expect "executor is only on its own internal network" "$NET" "$(nets_of "$EXECUTOR")"
expect "executor is not on cite_edge" 0 "$(nets_of "$EXECUTOR" | grep -cx cite_edge || true)"
expect "manager is only on its egress network" "$EGRESS" "$(nets_of "$MANAGER")"
BODY=$(docker network inspect "$NET")
jq_ok "stack network is internal and labelled" '.[0].Internal == true and .[0].Labels["cite.managed"] == "true"'
jq_ok "stack network holds only the executor and HAProxy" "[.[0].Containers[].Name] | sort == [\"$EXECUTOR\", \"$HAPROXY\"]"
BODY=$(docker network inspect "$EGRESS")
jq_ok "egress network is not internal and holds only the manager" ".[0].Internal == false and ([.[0].Containers[].Name] == [\"$MANAGER\"])"
truthy "HAProxy is connected to the stack network" haproxy_on "$NET"
expect "HAProxy is not on the egress network" 0 "$(nets_of "$HAPROXY" | grep -cx "$EGRESS" || true)"
SHARED=$(comm -12 <(nets_of "$MANAGER") <(cat <(nets_of "$PROXY_ID") <(nets_of "$CONNECTOR_ID") | sort -u) | wc -l | tr -d ' ')
expect "manager shares no network with dockerproxy or connector" 0 "$SHARED"
SHARED=$(comm -12 <(nets_of "$EXECUTOR") <(cat <(nets_of "$PROXY_ID") <(nets_of "$CONNECTOR_ID") | sort -u) | wc -l | tr -d ' ')
expect "executor shares no network with dockerproxy or connector" 0 "$SHARED"

# The fake token is the only secret; it may appear in the manager environment and nowhere else.
echo "== token confinement"
HOLDERS=0
for c in $(docker ps -aq); do
  if docker inspect "$c" | grep -q "$TOKEN_VALUE"; then
    HOLDERS=$((HOLDERS + 1))
    expect "token holder is the manager" "$MANAGER" "$(docker inspect -f '{{.Name}}' "$c" | tr -d /)"
  fi
done
expect "exactly one container carries the token" 1 "$HOLDERS"
BODY=$(docker inspect "$MANAGER")
jq_ok "the token sits in the manager environment" ".[0].Config.Env | any(. == \"CITE_GITHUB_TOKEN=$TOKEN_VALUE\")"
jq_ok "the token is not in the manager labels" ".[0].Config.Labels | tostring | contains(\"$TOKEN_VALUE\") | not"
expect "no network or volume carries the token" 0 "$(resource_dump | grep -c "$TOKEN_VALUE" || true)"

echo "== connector survives a manager that cannot reach GitHub"
sleep 5
expect "connector never restarted" 0 "$(docker inspect -f '{{.RestartCount}}' "$CONNECTOR_ID")"
truthy "connector is still running" container_running "$CONNECTOR_ID"
api GET /api/v1/healthz "" ""
code_is "connector API still answers" 200

# Names below match the cite pattern on purpose, so the body checks rather than the name check must refuse them.
echo "== proxy attacks"
BEFORE=$(docker_state)
proxy GET /_ping
expect "proxy forwards _ping (control, HTTP 200)" 200 "$PCODE"
proxy GET '/v1.45/containers/json?filters=%7B%22label%22%3A%5B%22cite.managed%3Dtrue%22%5D%7D'
expect "proxy forwards the labelled container list (control, HTTP 200)" 200 "$PCODE"
EVIL=cite-evil-blue-manager
evil_body() {
  jq -nc --argjson host "$1" '{Image: "ghcr.io/seggys116/cite-manager:0.0.1-node22", HostConfig: $host}'
}
denied "privileged container create" POST "/v1.45/containers/create?name=$EVIL" "$(evil_body '{"Privileged":true}')"
denied "create with a root bind mount" POST "/v1.45/containers/create?name=$EVIL" "$(evil_body '{"Binds":["/:/host"]}')"
denied "create with a docker socket mount" POST "/v1.45/containers/create?name=$EVIL" "$(evil_body '{"Mounts":[{"Type":"bind","Source":"/var/run/docker.sock","Target":"/s"}]}')"
denied "create with host pid" POST "/v1.45/containers/create?name=$EVIL" "$(evil_body '{"PidMode":"host"}')"
denied "create with host network" POST "/v1.45/containers/create?name=$EVIL" "$(evil_body '{"NetworkMode":"host"}')"
denied "create with a foreign image" POST "/v1.45/containers/create?name=$EVIL" '{"Image":"docker.io/library/alpine:latest","HostConfig":{}}'
denied "create under a name outside the cite pattern" POST "/v1.45/containers/create?name=evil" "$(evil_body '{}')"
denied "duplicate-key HostConfig body" POST "/v1.45/containers/create?name=$EVIL" \
  '{"Image":"ghcr.io/seggys116/cite-manager:0.0.1-node22","HostConfig":{"Privileged":false,"Privileged":true}}'
denied "duplicate top-level Image key" POST "/v1.45/containers/create?name=$EVIL" \
  '{"Image":"ghcr.io/seggys116/cite-manager:0.0.1-node22","Image":"docker.io/library/alpine:latest"}'
denied "exec in HAProxy" POST "/v1.45/containers/$HAPROXY/exec" '{"Cmd":["sh"],"AttachStdin":true}'
denied "exec in a stack container" POST "/v1.45/containers/$MANAGER/exec" '{"Cmd":["sh"]}'
denied "container list without the label filter" GET /v1.45/containers/json
denied "container list with a different filter" GET '/v1.45/containers/json?all=1'
denied "image pull of alpine" POST '/v1.45/images/create?fromImage=alpine&tag=latest'
denied "image pull from a foreign registry" POST '/v1.45/images/create?fromImage=docker.io%2Flibrary%2Falpine&tag=3'
denied "volume with bind driver options" POST /v1.45/volumes/create \
  '{"Name":"cite-evil-blue-data","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/"}}'
denied "volume with a hostile name" POST /v1.45/volumes/create '{"Name":"evil","Labels":{}}'
denied "stopping HAProxy" POST "/v1.45/containers/$HAPROXY/stop"
denied "removing HAProxy" DELETE "/v1.45/containers/$HAPROXY?force=1"
denied "stopping the connector" POST "/v1.45/containers/$CONNECTOR_ID/stop"
denied "attaching HAProxy to the shared edge network" POST "/v1.45/networks/cite_edge/connect" "{\"Container\":\"$HAPROXY\"}"
denied "attaching the connector to a stack network" POST "/v1.45/networks/$NET/connect" "{\"Container\":\"$CONNECTOR_ID\"}"
denied "network create with a host driver" POST /v1.45/networks/create '{"Name":"cite-evil-blue-net","Driver":"host","Internal":true}'
denied "system info" GET /v1.45/info
denied "events stream" GET /v1.45/events
denied "image build" POST /v1.45/build
denied "unsupported API version" GET /v1.10/containers/json
AFTER=$(docker_state)
expect "docker state is unchanged by every denied request" "$BEFORE" "$AFTER"

# The manager cannot reach GitHub, so the idle slot never gets a release: a 409 with active unchanged is the documented outcome.
echo "== deploy of a ref to the idle slot"
API_TIMEOUT=240 api POST "/api/v1/sites/$SITE/deploy" '{"git_ref":"release","note":"e2e ref deploy"}'
case $CODE in
  200 | 409) pass "deploy answers with a documented status (HTTP $CODE)" ;;
  *) fail "deploy: unexpected HTTP $CODE: $BODY" ;;
esac
GREEN_MANAGER=cite-$SITE-green-manager
truthy "green manager was created" docker inspect "$GREEN_MANAGER"
BODY=$(docker inspect "$GREEN_MANAGER")
jq_ok "green manager builds the requested ref" '.[0].Config.Env | any(. == "CITE_BRANCH=release")'
jq_ok "green manager is hardened" "$HARDENED"
expect "green executor is only on its own network" "$GREEN_NET" "$(nets_of "cite-$SITE-green-executor")"
api GET "/api/v1/sites/$SITE"
if printf '%s' "$BODY" | jq -e '.active == "blue"' >/dev/null; then
  jq_ok "failed deploy kept blue active and was recorded" '(.history | last | .action) == "failed" and .active == "blue"'
  wait_for "failed idle stack is stopped" 30 test "$(docker inspect -f '{{.State.Running}}' "cite-$SITE-green-executor")" = false
  wait_for "HAProxy is cut off from the stopped green network" 30 haproxy_off "$GREEN_NET"
  truthy "the blue network keeps HAProxy attached" haproxy_on "$NET"
else
  jq_ok "deploy promoted green" '.active == "green"'
  API_TIMEOUT=240 api POST "/api/v1/sites/$SITE/rollback"
  code_is "rollback to blue" 200
  jq_ok "rollback recorded" '.action == "rollback" and .slot == "blue"'
fi

# A recreated HAProxy has no stack networks; the connector must reattach it after a restart even though the site is unhealthy meanwhile.
echo "== HAProxy recreation and connector restart"
compose up -d --no-deps --force-recreate haproxy >"$WORK/up.log" 2>&1 || fail "haproxy recreate failed: $(<"$WORK/up.log")"
truthy "recreated HAProxy lost the stack network" haproxy_off "$NET"
compose restart connector >"$WORK/restart.log" 2>&1 || fail "connector restart failed: $(<"$WORK/restart.log")"
wait_api
wait_for "reconcile reattached HAProxy to the stack network" 90 haproxy_on "$NET"
login
api GET "/api/v1/sites/$SITE"
jq_ok "site persisted across the restart" '.id == "e2eshop" and .active == "blue"'
api GET /api/v1/node
jq_ok "orchestrator reachable again after the restart" '.orchestrator.enabled == true and .orchestrator.reachable == true'

# Delete must remove every container, volume and network of the site plus the stored secret.
echo "== delete"
api DELETE "/api/v1/sites/$SITE"
code_is "delete site" 200
expect "no container of the site remains" 0 "$(docker ps -aq --filter "label=cite.site=$SITE" | wc -l | tr -d ' ')"
expect "no volume of the site remains" 0 "$(docker volume ls -q --filter "name=cite-$SITE-" | wc -l | tr -d ' ')"
expect "no network of the site remains" 0 "$(docker network ls -q --filter "name=cite-$SITE-" | wc -l | tr -d ' ')"
truthy "HAProxy is no longer on the stack network" haproxy_off "$NET"
SECRETS=$(docker run --rm --entrypoint cat -v "${PROJECT}_cite_conf:/conf:ro" "$REGISTRY/cite-connector:$CITE_VERSION" /conf/secrets.json)
expect "the stored token is gone" 0 "$(printf '%s' "$SECRETS" | grep -c "$TOKEN_VALUE" || true)"
api GET /api/v1/sites
jq_ok "site list is empty" 'length == 0'

# The live phase points the proxy and connector at a mock GitHub and expects the manager to build the site and HAProxy to serve it.
echo "== live: mock GitHub and the API URL passthrough"
mock_endpoint
docker run -d --name "$MOCK_NAME" -p "$MOCK_BIND:$MOCK_PORT:8080" "$MOCK_IMAGE" >/dev/null || fail "mock GitHub did not start"
wait_for "mock GitHub answers" 30 curl -fsS --max-time 3 -H "Authorization: Bearer $MOCK_TOKEN" "http://$MOCK_BIND:$MOCK_PORT/repos/acme/live"
mock_push main e2e-live-v1
export CITE_GITHUB_API_URL=$MOCK_API_URL
compose up -d >"$WORK/up.log" 2>&1 || fail "compose up with the mock URL failed: $(<"$WORK/up.log")"
wait_api
wait_for "dockerproxy is healthy with the mock URL" 60 test "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q dockerproxy)")" = healthy
wait_for "HAProxy stopped restarting" 90 haproxy_settled
PROXY_ID=$(compose ps -q dockerproxy)
CONNECTOR_ID=$(compose ps -q connector)
BODY=$(docker inspect "$PROXY_ID")
jq_ok "dockerproxy carries the operator URL" ".[0].Config.Env | any(. == \"CITE_PROXY_GITHUB_API_URL=$MOCK_API_URL\")"
BODY=$(docker inspect "$CONNECTOR_ID")
jq_ok "connector carries the same URL" ".[0].Config.Env | any(. == \"CITE_STACK_GITHUB_API_URL=$MOCK_API_URL\")"
login
api GET /api/v1/node
jq_ok "orchestrator is reachable after the restart" '.orchestrator.enabled == true and .orchestrator.reachable == true'

echo "== live: create a static site from the mock repository"
LIVE_BLUE_NET="cite-$LIVE_SITE-blue-net"
LIVE_EGRESS="cite-$LIVE_SITE-blue-egress"
LIVE_MANAGER=cite-$LIVE_SITE-blue-manager
LIVE_EXECUTOR=cite-$LIVE_SITE-blue-executor
live_json=$(jq -nc --arg token "$MOCK_TOKEN" --arg repo "$LIVE_REPO" --arg host "$LIVE_HOST" '{
  id: "e2elive", name: "E2E Live", hosts: [$host], active: "blue",
  blue: {targets: []}, green: {targets: []},
  source: {repo: $repo, branch: "main", runtime: "static", poll_interval: "off"},
  github_token: $token
}')
API_TIMEOUT=240 api POST /api/v1/sites "$live_json"
code_is "create live site from source" 200
jq_ok "live site is active on blue with the static executor target" \
  ".id == \"$LIVE_SITE\" and .active == \"blue\" and .blue.targets[0].addr == \"$LIVE_EXECUTOR:8080\""
BODY=$(docker inspect "$LIVE_MANAGER")
jq_ok "manager image is the node22 manager" '.[0].Config.Image | endswith("/cite-manager:'"$CITE_STACK_VERSION"'-node22")'
jq_ok "manager reports the mock as its GitHub API" ".[0].Config.Env | any(. == \"CITE_GITHUB_API_URL=$MOCK_API_URL\")"
BODY=$(docker inspect "$LIVE_EXECUTOR")
jq_ok "executor image is the static executor" '.[0].Config.Image | endswith("/cite-executor-static:'"$CITE_STACK_VERSION"'")'
jq_ok "executor does not see the API URL or the token" '.[0].Config.Env | any(test("GITHUB")) | not'
jq_ok "executor publishes no port" '((.[0].HostConfig.PortBindings // {}) | length) == 0'

echo "== live: the manager builds and HAProxy serves"
wait_for "site is served through HAProxy with the v1 build" 180 live_serves e2e-live-v1
expect "HTTP status of the served site" 200 "$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -H "Host: $LIVE_HOST" "http://127.0.0.1:$CITE_HTTP_PORT/")"
NOHOST=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -H 'Host: other.e2e.test' "http://127.0.0.1:$CITE_HTTP_PORT/")
[ "$NOHOST" != 200 ] || fail "an unknown host was served"
pass "an unknown host is not served (HTTP $NOHOST)"
api GET "/api/v1/sites/$LIVE_SITE"
code_is "live site status" 200
jq_ok "HAProxy reports the executor UP" '.live.blue[0].status == "UP"'
for name in "$LIVE_MANAGER" "$LIVE_EXECUTOR"; do
  BODY=$(docker inspect "$name")
  jq_ok "$name is hardened after the build" "$HARDENED"
done
expect "live executor is only on its own internal network" "$LIVE_BLUE_NET" "$(nets_of "$LIVE_EXECUTOR")"
expect "live manager is only on its egress network" "$LIVE_EGRESS" "$(nets_of "$LIVE_MANAGER")"
BODY=$(docker network inspect "$LIVE_BLUE_NET")
jq_ok "live stack network is internal and holds only the executor and HAProxy" \
  ".[0].Internal == true and ([.[0].Containers[].Name] | sort == [\"$LIVE_EXECUTOR\", \"$HAPROXY\"])"
BODY=$(docker network inspect "$LIVE_EGRESS")
jq_ok "live egress network is not internal and holds only the manager" ".[0].Internal == false and ([.[0].Containers[].Name] == [\"$LIVE_MANAGER\"])"
HOLDERS=0
for c in $(docker ps -aq); do
  if docker inspect "$c" | grep -q "$MOCK_TOKEN"; then
    HOLDERS=$((HOLDERS + 1))
    expect "mock token holder is the live manager" "$LIVE_MANAGER" "$(docker inspect -f '{{.Name}}' "$c" | tr -d /)"
  fi
done
expect "exactly one container carries the mock token" 1 "$HOLDERS"
expect "no network or volume carries the mock token" 0 "$(resource_dump | grep -c "$MOCK_TOKEN" || true)"

echo "== live: deploy a second commit from a git ref"
mock_push release e2e-live-v2
API_TIMEOUT=240 api POST "/api/v1/sites/$LIVE_SITE/deploy" '{"git_ref":"release","note":"e2e live ref deploy"}'
code_is "deploy of the release ref" 200
jq_ok "deploy promoted green" '.action == "promote" and .slot == "green"'
BODY=$(docker inspect "cite-$LIVE_SITE-green-manager")
jq_ok "green manager builds the release ref" '.[0].Config.Env | any(. == "CITE_BRANCH=release")'
jq_ok "green manager is hardened" "$HARDENED"
wait_for "site is served with the v2 build" 60 live_serves e2e-live-v2
if live_serves e2e-live-v1; then fail "the v1 build is still served after the promote"; fi
pass "the v1 build is no longer served"
api GET "/api/v1/sites/$LIVE_SITE"
jq_ok "site is active on green and the deploy is in the history" '.active == "green" and (.history | last | .action) == "promote"'
wait_for "drained blue executor is stopped" 90 container_stopped "$LIVE_EXECUTOR"
wait_for "site still serves v2 after the drain" 30 live_serves e2e-live-v2

echo "== live: rollback restarts the drained slot on its own ref"
API_TIMEOUT=240 api POST "/api/v1/sites/$LIVE_SITE/rollback"
code_is "rollback to blue" 200
jq_ok "rollback recorded" '.action == "rollback" and .slot == "blue"'
wait_for "rolled back site serves the v1 build again" 120 live_serves e2e-live-v1
BODY=$(docker inspect "$LIVE_MANAGER")
jq_ok "blue manager still builds main" '.[0].Config.Env | any(. == "CITE_BRANCH=main")'

echo "== live: delete"
api DELETE "/api/v1/sites/$LIVE_SITE"
code_is "delete live site" 200
expect "no container of the live site remains" 0 "$(docker ps -aq --filter "label=cite.site=$LIVE_SITE" | wc -l | tr -d ' ')"
expect "no volume of the live site remains" 0 "$(docker volume ls -q --filter "name=cite-$LIVE_SITE-" | wc -l | tr -d ' ')"
expect "no network of the live site remains" 0 "$(docker network ls -q --filter "name=cite-$LIVE_SITE-" | wc -l | tr -d ' ')"
truthy "HAProxy is no longer on the live stack network" haproxy_off "$LIVE_BLUE_NET"
if live_serves e2e-live; then fail "the deleted site is still served"; fi
pass "the deleted site is no longer served"
SECRETS=$(docker run --rm --entrypoint cat -v "${PROJECT}_cite_conf:/conf:ro" "$REGISTRY/cite-connector:$CITE_VERSION" /conf/secrets.json)
expect "the stored mock token is gone" 0 "$(printf '%s' "$SECRETS" | grep -c "$MOCK_TOKEN" || true)"

echo "== teardown"
if [ "${E2E_KEEP:-0}" = 1 ]; then
  echo "e2e-orchestrator: E2E_KEEP=1, leaving the stack up"
else
  remove_stack
  expect "no cite.managed container remains" 0 "$(docker ps -aq --filter label=cite.managed=true | wc -l | tr -d ' ')"
  expect "no cite.managed volume remains" 0 "$(docker volume ls -q --filter label=cite.managed=true | wc -l | tr -d ' ')"
  expect "no cite.managed network remains" 0 "$(docker network ls -q --filter label=cite.managed=true | wc -l | tr -d ' ')"
  expect "no cite-e2e container remains" 0 "$(docker ps -aq --filter name=cite-e2e | wc -l | tr -d ' ')"
  expect "no cite-e2e volume remains" 0 "$(docker volume ls -q --filter name=cite-e2e | wc -l | tr -d ' ')"
  expect "no cite-e2e network remains" 0 "$(docker network ls -q --filter name=cite-e2e | wc -l | tr -d ' ')"
fi

echo "e2e-orchestrator: all checks passed"
