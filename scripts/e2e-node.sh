#!/usr/bin/env bash
# End to end check of the node stack (HAProxy plus connector) against a throwaway compose project.
# Needs a connector image tagged ghcr.io/seggys116/cite-connector:${CITE_VERSION:-e2e}. E2E_KEEP=1 skips teardown.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT=cite-e2e
HTTP_PORT=18080
API_PORT=17443
SITE_HOST=app.e2e.test
UPSTREAMS=(e2e-blue e2e-green e2e-blue2)

export CITE_VERSION="${CITE_VERSION:-e2e}"
export CITE_PUBLIC_BIND=127.0.0.1
export CITE_HTTP_PORT=$HTTP_PORT
export CITE_HTTPS_PORT=18443
export CITE_CONNECTOR_BIND=127.0.0.1
export CITE_CONNECTOR_PORT=$API_PORT
export CITE_CONNECTOR_ALLOW=allow-all

for tool in docker jq curl python3 openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "e2e-node: $tool is required" >&2; exit 2; }
done

WORK="$(mktemp -d)"
CA="$WORK/ca.pem"
TOKEN=""
LAST_STEP=0
LOOP_PID=""
CODE=""
BODY=""

compose() {
  docker compose -p "$PROJECT" -f "$ROOT/docker-compose.node.yml" "$@" </dev/null
}

remove_stack() {
  docker rm -f "${UPSTREAMS[@]}" >/dev/null 2>&1 || true
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  [ -z "$LOOP_PID" ] || kill "$LOOP_PID" 2>/dev/null || true
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
  echo "e2e-node FAIL: $*" >&2
  compose logs --no-color --tail 30 connector haproxy >&2 2>/dev/null || true
  exit 1
}

pass() {
  echo "ok   $*"
}

expect() {
  [ "$2" = "$3" ] || fail "$1: expected '$2', got '$3'"
  pass "$1"
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
  expect "$1 (HTTP $2)" "$2" "$CODE"
}

jq_ok() {
  printf '%s' "$BODY" | jq -e "$2" >/dev/null || fail "$1: jq '$2' failed on: $BODY"
  pass "$1"
}

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

login_body() {
  jq -nc --arg u "$1" --arg p "$2" --arg t "$3" '{username:$u,password:$p,totp:$t}'
}

login() {
  local step code
  while :; do
    read -r step code < <(totp "$TOTP_SECRET")
    [ "$step" -gt "$LAST_STEP" ] && break
    sleep 1
  done
  LAST_STEP=$step
  api POST /api/v1/auth/login "$(login_body "$USERNAME" "$PASSWORD" "$code")" ""
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

edge() {
  local path=$1
  shift
  curl -sS --max-time 5 -H "Host: ${EDGE_HOST:-$SITE_HOST}" "$@" "http://127.0.0.1:$HTTP_PORT$path"
}

edge_code() {
  edge "$1" -o /dev/null -w '%{http_code}'
}

edge_is() {
  local what=$1 want=$2 tries=${3:-1} got=""
  for _ in $(seq 1 "$tries"); do
    got=$(edge / 2>/dev/null || true)
    [ "$got" = "$want" ] && break
    sleep 1
  done
  expect "$what" "$want" "$got"
}

edge_dropped() {
  local out rc=0
  out=$(edge "$1" --max-time 3 -o /dev/null -w '%{http_code}') || rc=$?
  case $rc in
    28 | 52 | 56) ;;
    *) fail "$2: expected a silent drop, curl exit $rc, code ${out:-none}" ;;
  esac
  expect "$2 (no HTTP status, curl exit $rc)" "000" "$out"
}

traffic() {
  local out=$1 count=$2 body
  : >"$out"
  for _ in $(seq 1 "$count"); do
    [ ! -e "$WORK/stop" ] || break
    body=$(curl -s --max-time 5 -H "Host: $SITE_HOST" -w ' %{http_code}' "http://127.0.0.1:$HTTP_PORT/" || true)
    printf '%s\n' "$body" >>"$out"
    sleep 0.03
  done
}

traffic_failures() {
  local n
  n=$(grep -vc ' 200$' "$1" || true)
  echo "$n"
}

start_upstream() {
  docker run -d --name "$1" --network cite_edge --network-alias "$1" --entrypoint sh docker.io/library/nginx:alpine \
    -c "printf %s '$2' > /usr/share/nginx/html/index.html && exec nginx -g 'daemon off;'" >/dev/null
}

site_json() {
  jq -nc --arg host "$SITE_HOST" '{
    id: "app", name: "App", hosts: [$host], active: "blue",
    blue: {targets: [{addr: "e2e-blue:80"}]},
    green: {targets: [{addr: "e2e-green:80"}]}
  }'
}

cd "$ROOT"
remove_stack
docker pull -q docker.io/curlimages/curl:latest >/dev/null
docker pull -q docker.io/library/nginx:alpine >/dev/null

echo "== onboarding"
compose run --rm --no-deps -T init >"$WORK/init.log" 2>&1 || fail "volume init failed: $(<"$WORK/init.log")"
compose run --rm --no-deps -T connector init --non-interactive --json >"$WORK/creds.json" 2>"$WORK/init.err" ||
  fail "connector init failed: $(<"$WORK/init.err")"
USERNAME=$(jq -er .username "$WORK/creds.json")
PASSWORD=$(jq -er .password "$WORK/creds.json")
TOTP_SECRET=$(jq -er .totp_secret "$WORK/creds.json")
FINGERPRINT=$(jq -er .ca_fingerprint "$WORK/creds.json")
pass "init --json printed credentials for $USERNAME"
compose run --rm --no-deps -T --entrypoint cat connector /conf/tls/ca.pem >"$CA" || fail "could not read ca.pem"
SEEN=$(openssl x509 -in "$CA" -noout -fingerprint -sha256 | sed 's/^.*=//' | tr a-f A-F)
expect "CA fingerprint from init matches ca.pem" "$FINGERPRINT" "$SEEN"
compose run --rm --no-deps -T connector init --non-interactive --json >/dev/null 2>&1 &&
  fail "a second init without --force must refuse"
pass "second init refuses to overwrite"

echo "== start and detect the dashboard source address"
compose up -d >"$WORK/up.log" 2>&1 || fail "compose up failed: $(<"$WORK/up.log")"
wait_api
login
api GET "/api/v1/audit?limit=50"
code_is "audit readable" 200
PEER=$(printf '%s' "$BODY" | jq -er '[.[] | select(.action == "login.success")] | last | .detail | sub("^peer="; "")')
[ -n "$PEER" ] || fail "no peer address in the audit log"
pass "connector sees the host as $PEER"
export CITE_CONNECTOR_ALLOW=$PEER
compose up -d connector >"$WORK/up.log" 2>&1 || fail "connector recreate failed: $(<"$WORK/up.log")"
wait_api
pass "connector restarted with the allowlist limited to $PEER"
compose ps --format '{{.Service}} {{.State}} {{.Health}}' >"$WORK/ps.txt"
grep -q '^connector running' "$WORK/ps.txt" || fail "connector is not running: $(<"$WORK/ps.txt")"

echo "== api access"
api GET /api/v1/healthz "" ""
code_is "healthz" 200
jq_ok "healthz reports ok" '.ok == true'
CONNECTOR_ID=$(compose ps -q connector)
CONNECTOR_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${PROJECT}_public\").IPAddress}}" "$CONNECTOR_ID")
rc=0
out=$(docker run --rm --network "${PROJECT}_public" docker.io/curlimages/curl:latest -sk --max-time 5 \
  -o /dev/null -w '%{http_code}' "https://$CONNECTOR_IP:7443/api/v1/healthz") || rc=$?
case $rc in
  35 | 52 | 56) pass "non-allowlisted source is closed (curl exit $rc)" ;;
  *) fail "non-allowlisted source got curl exit $rc, code ${out:-none}" ;;
esac
expect "non-allowlisted source got no HTTP status" "000" "$out"

read -r _ GOOD_CODE < <(totp "$TOTP_SECRET")
WRONG_CODE=$(printf '%06d' $(((10#$GOOD_CODE + 1) % 1000000)))
api POST /api/v1/auth/login "$(login_body "$USERNAME" "$PASSWORD" "$WRONG_CODE")" ""
code_is "wrong TOTP rejected" 401
WRONG_TOTP_BODY=$BODY
api POST /api/v1/auth/login "$(login_body "$USERNAME" "wrong-password-value" "$GOOD_CODE")" ""
code_is "wrong password rejected" 401
expect "wrong password and wrong TOTP answer identically" "$WRONG_TOTP_BODY" "$BODY"
api POST /api/v1/auth/login "$(login_body nobody "$PASSWORD" "$GOOD_CODE")" ""
code_is "unknown user rejected" 401
expect "unknown user answers identically" "$WRONG_TOTP_BODY" "$BODY"
api GET /api/v1/sites "" ""
code_is "unauthenticated request rejected" 401
login
api GET /api/v1/auth/me
jq_ok "session identifies the user" ".username == \"$USERNAME\""

echo "== sites and traffic"
start_upstream e2e-blue blue-v1
start_upstream e2e-green green-v2
start_upstream e2e-blue2 blue-v2
api POST /api/v1/sites "$(site_json)"
code_is "create site" 200
jq_ok "site active slot is blue" '.active == "blue" and .id == "app"'
edge_is "blue serves through HAProxy" blue-v1 10
expect "unknown host gets 404" 404 "$(EDGE_HOST=unknown.e2e.test edge_code /)"

traffic "$WORK/switch.out" 200 &
LOOP_PID=$!
sleep 1
api POST /api/v1/sites/app/switch '{"slot":"green"}'
code_is "switch to green" 200
jq_ok "switch recorded" '.action == "switch" and .slot == "green"'
wait "$LOOP_PID"
LOOP_PID=""
expect "requests recorded during the switch" 200 "$(wc -l <"$WORK/switch.out" | tr -d ' ')"
expect "failed requests during the switch" 0 "$(traffic_failures "$WORK/switch.out")"
[ "$(grep -c '^blue-v1 200$' "$WORK/switch.out" || true)" -gt 0 ] || fail "no request was served by blue before the switch"
[ "$(grep -c '^green-v2 200$' "$WORK/switch.out" || true)" -gt 0 ] || fail "no request was served by green after the switch"
pass "loop saw both slots, zero failures"
edge_is "green serves after the switch" green-v2

API_TIMEOUT=120 api POST /api/v1/sites/app/deploy '{"targets":[{"addr":"e2e-blue2:80"}],"note":"e2e deploy"}'
code_is "deploy to the idle slot" 200
jq_ok "deploy promoted blue" '.action == "promote" and .slot == "blue"'
edge_is "new deploy serves" blue-v2
api POST /api/v1/sites/app/rollback
code_is "rollback" 200
jq_ok "rollback recorded" '.action == "rollback" and .slot == "green"'
edge_is "rollback serves the previous slot" green-v2

API_TIMEOUT=150 api POST /api/v1/sites/app/deploy '{"targets":[{"addr":"e2e-blue:9"}],"note":"dead targets"}'
code_is "deploy with dead targets fails health" 409
edge_is "active slot untouched after the failed deploy" green-v2
api GET /api/v1/sites/app
jq_ok "failed deploy recorded, active unchanged" '.active == "green" and (.history | last | .action) == "failed"'

echo "== firewall"
api POST /api/v1/firewall/presets/sensitive-files/apply
code_is "apply sensitive-files preset" 200
jq_ok "preset added rules" 'length > 0'
edge_dropped /.env "dotfile request"
edge_dropped /backup.sql "database dump request"
expect "root still served" 200 "$(edge_code /)"
api POST /api/v1/firewall/rules '{"id":"e2e-deny","name":"e2e deny","enabled":true,"action":"deny","matchers":{"path_prefix":"/forbidden"}}'
code_is "create deny rule" 200
expect "deny rule returns 403" 403 "$(edge_code /forbidden/page)"
expect "root still served after deny rule" 200 "$(edge_code /)"

echo "== maintenance"
api POST /api/v1/pages '{"id":"down","name":"Down","html":"<h1>maintenance-e2e</h1>","status":503}'
code_is "create maintenance page" 200
api POST /api/v1/sites/app/maintenance '{"enabled":true,"page_id":"down"}'
code_is "enable maintenance" 200
expect "maintenance status" 503 "$(edge_code /)"
case $(edge /) in
  *maintenance-e2e*) pass "maintenance page body served" ;;
  *) fail "maintenance body missing" ;;
esac
api POST /api/v1/sites/app/maintenance '{"enabled":false}'
code_is "disable maintenance" 200
edge_is "service restored after maintenance" green-v2

echo "== analytics"
SUMMARY_OK=""
for _ in $(seq 1 30); do
  api GET "/api/v1/analytics/summary?window=15m"
  if printf '%s' "$BODY" | jq -e '.blocked > 0 and .requests > 200 and (.status["5xx"] // 0) > 0' >/dev/null; then
    SUMMARY_OK=1
    break
  fi
  sleep 1
done
[ -n "$SUMMARY_OK" ] || fail "analytics never showed the traffic: $BODY"
jq_ok "summary counts requests and blocked" '.requests > 200 and .blocked > 0'
jq_ok "status classes present" '.status["2xx"] > 0 and .status["4xx"] > 0 and .status["5xx"] > 0'
jq_ok "top paths include the dropped dotfile" 'any(.top_paths[]; .key == "/.env")'
jq_ok "content types recorded" '(.content_types | length) > 0'
jq_ok "top blocked names the preset rule" 'any(.top_blocked[]; .key | startswith("preset-sensitive-files"))'
api GET "/api/v1/analytics/requests?blocked=true&limit=50"
code_is "blocked requests listed" 200
jq_ok "events carry the rule id" 'any(.[]; .blocked == "preset-sensitive-files-1" and .path == "/.env")'
api GET "/api/v1/analytics/requests?limit=500"
jq_ok "events are attributed to the site and slot" 'any(.[]; .site == "app" and .backend == "be_app_green" and .status == 200)'
api GET /api/v1/analytics/timeseries?window=15m
code_is "timeseries" 200

echo "== settings and retention"
api GET /api/v1/settings
code_is "read settings" 200
SETTINGS=$(printf '%s' "$BODY" | jq -c '.retention.recent_events = 5')
api PUT /api/v1/settings "$SETTINGS"
code_is "shrink recent_events" 200
api GET "/api/v1/analytics/requests?limit=100"
jq_ok "event ring shrank to 5" 'length > 0 and length <= 5'

echo "== api tokens"
api POST /api/v1/tokens '{"name":"e2e"}'
code_is "create API token" 200
API_TOKEN=$(printf '%s' "$BODY" | jq -er .token)
TOKEN_ID=$(printf '%s' "$BODY" | jq -er .id)
api GET /api/v1/node "" "$API_TOKEN"
code_is "API token authenticates" 200
jq_ok "node reports HAProxy running" '.haproxy.running == true and .sites == 1'
api DELETE "/api/v1/tokens/$TOKEN_ID"
code_is "revoke API token" 200
api GET /api/v1/node "" "$API_TOKEN"
code_is "revoked token rejected" 401

echo "== connector restart"
api GET /api/v1/analytics/summary?window=15m
REQUESTS_BEFORE=$(printf '%s' "$BODY" | jq -r .requests)
api GET /api/v1/firewall/rules
RULES_BEFORE=$(printf '%s' "$BODY" | jq -r length)
rm -f "$WORK/stop"
traffic "$WORK/restart.out" 400 &
LOOP_PID=$!
compose restart connector >"$WORK/restart.log" 2>&1 || fail "connector restart failed: $(<"$WORK/restart.log")"
wait_api
: >"$WORK/stop"
wait "$LOOP_PID"
LOOP_PID=""
[ "$(wc -l <"$WORK/restart.out" | tr -d ' ')" -gt 20 ] || fail "too few requests sent during the connector restart"
expect "failed requests while the connector restarted" 0 "$(traffic_failures "$WORK/restart.out")"
rm -f "$WORK/stop"
login
api GET /api/v1/sites
jq_ok "site persisted" 'length == 1 and .[0].id == "app" and .[0].active == "green"'
api GET /api/v1/firewall/rules
expect "firewall rules persisted" "$RULES_BEFORE" "$(printf '%s' "$BODY" | jq -r length)"
api GET /api/v1/analytics/summary?window=15m
jq_ok "analytics snapshot persisted" ".requests >= $REQUESTS_BEFORE"
api GET /api/v1/settings
jq_ok "settings persisted" '.retention.recent_events == 5'
edge_dropped /.env "dotfile request after connector restart"

echo "== haproxy restart"
compose restart haproxy >"$WORK/restart.log" 2>&1 || fail "haproxy restart failed: $(<"$WORK/restart.log")"
edge_is "same active slot after HAProxy restart" green-v2 30
edge_dropped /.env "dotfile request after HAProxy restart"
expect "deny rule after HAProxy restart" 403 "$(edge_code /forbidden/x)"
api POST /api/v1/haproxy/reload
code_is "connector reaches the restarted HAProxy" 200
edge_is "service after reload" green-v2
api GET /api/v1/node
jq_ok "HAProxy healthy" '.haproxy.running == true and .haproxy.last_reload_ok == true'

echo "e2e-node: all checks passed"
