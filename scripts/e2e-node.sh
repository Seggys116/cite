#!/usr/bin/env bash
# End to end check of the node stack against a throwaway compose project; needs a connector image tagged ghcr.io/seggys116/cite-connector:${CITE_VERSION:-e2e}. E2E_KEEP=1 skips teardown.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT=cite-e2e
HTTP_PORT=18080
HTTPS_PORT=18443
API_PORT=17443
SITE_HOST=app.e2e.test
CERT_HOST=secure.e2e.test
CF_HOST=cf.e2e.test
UPSTREAMS=(e2e-blue e2e-green e2e-blue2 e2e-echo)

export CITE_VERSION="${CITE_VERSION:-e2e}"
export CITE_PUBLIC_BIND=127.0.0.1
export CITE_HTTP_PORT=$HTTP_PORT
export CITE_HTTPS_PORT=$HTTPS_PORT
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
  upgrade_compose down -v --remove-orphans >/dev/null 2>&1 || true
}

# A second project for the upgrade check; it shares the fixed haproxy container name, so it only runs once the main stack is gone.
upgrade_compose() {
  docker compose -p "${PROJECT}-upg" -f "$ROOT/docker-compose.node.yml" "$@" </dev/null
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
  [ "$2" = "$CODE" ] || fail "$1 (HTTP $2): expected '$2', got '$CODE' with body: $(printf '%s' "$BODY" | head -c 400)"
  pass "$1 (HTTP $2)"
}

jq_ok() {
  printf '%s' "$BODY" | jq -e "$2" >/dev/null || fail "$1: jq '$2' failed on: $BODY"
  pass "$1"
}

# Prints the 30 second step with the code so login() can wait for a fresh step instead of reusing a consumed one.
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

# A firewall drop sends no HTTP reply, so curl exits 28, 52 or 56 instead of reporting a status.
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
  if [ "$n" != 0 ]; then
    echo "non-200 responses in $1:" >&2
    grep -v ' 200$' "$1" | sort | uniq -c >&2
  fi
  echo "$n"
}

# The node serves a certificate only for the SNI name, so curl is pointed at the loopback port with --resolve and trusts the uploaded certificate as its own CA.
https_edge() {
  local cacert=$1
  shift
  curl -sS --max-time 5 --cacert "$cacert" --resolve "$CERT_HOST:$HTTPS_PORT:127.0.0.1" "$@" "https://$CERT_HOST:$HTTPS_PORT/"
}

fingerprint_of() {
  sed 's/^.*=//' | tr -d ':' | tr 'A-F' 'a-f'
}

served_fingerprint() {
  openssl s_client -connect "127.0.0.1:$HTTPS_PORT" -servername "$CERT_HOST" </dev/null 2>/dev/null |
    openssl x509 -noout -fingerprint -sha256 2>/dev/null | fingerprint_of
}

# Waits until HAProxy presents the certificate with this fingerprint on the HTTPS port.
wait_served() {
  local want=$1 got=""
  for _ in $(seq 1 20); do
    got=$(served_fingerprint || true)
    [ "$got" = "$want" ] && break
    sleep 1
  done
  expect "$2" "$want" "$got"
}

self_signed() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
    -keyout "$1.key" -out "$1.pem" -subj "/CN=$CERT_HOST" -addext "subjectAltName=DNS:$CERT_HOST" >/dev/null 2>&1 ||
    fail "openssl could not create a certificate"
}

# 24 characters from the first base64 line of a PEM key: a leak of the body shows up even when the BEGIN line is missing.
key_slice() {
  sed -n '2p' "$1" | cut -c 20-43
}

# Fails on an error document too, so an absent key cannot be a side effect of the request having failed.
no_key_material() {
  case $BODY in
    '{"error"'*) fail "$1 is an error document: $BODY" ;;
    "") fail "$1 is empty" ;;
  esac
  local slice
  for slice in "${KEY_SLICES[@]}"; do
    [ "${#slice}" -ge 20 ] || fail "could not take a slice of a key to look for"
    case $BODY in
      *"$slice"*) fail "$1 contains key material" ;;
    esac
  done
  case $BODY in
    *"PRIVATE KEY"*) fail "$1 contains a key block" ;;
  esac
  pass "$1 carries no key"
}

upload_body() {
  jq -nc --arg name "$1" --rawfile c "$2.pem" --rawfile k "$2.key" '{name:$name,certificate:$c,private_key:$k}'
}

cf_code() {
  EDGE_HOST=$CF_HOST edge "$1" -o /dev/null -w '%{http_code}' "${@:2}"
}

# Sets LOGGED to the client address the node recorded for a request path, waiting for the log pipeline to deliver it.
logged_client() {
  LOGGED=""
  for _ in $(seq 1 20); do
    api GET "/api/v1/analytics/requests?limit=200"
    LOGGED=$(printf '%s' "$BODY" | jq -r --arg p "$1" '[.[] | select(.path == $p)] | first | .client_ip // empty')
    [ -z "$LOGGED" ] || return 0
    sleep 1
  done
  fail "no analytics event for $1"
}

# Answers every request with the zone header it received, so a test can see whether the edge forwarded it.
start_echo() {
  printf '%s\n' 'server { listen 80; location / { return 200 "zone=[$http_x_cite_origin_secret]"; } }' >"$WORK/echo.conf"
  docker run -d --name e2e-echo --network cite_edge --network-alias e2e-echo \
    -v "$WORK/echo.conf:/etc/nginx/conf.d/default.conf:ro" docker.io/library/nginx:alpine >/dev/null
}

# A site body with a second slot, which every site needs; the extra argument is the access object.
plain_site() {
  local access=${4:-}
  [ -n "$access" ] || access='{}'
  jq -nc --arg id "$1" --arg host "$2" --arg target "$3" --argjson access "$access" '{
    id: $id, name: $id, hosts: [$host], active: "blue",
    blue: {targets: [{addr: $target}]},
    green: {targets: [{addr: "e2e-green:80"}]},
    access: $access
  }'
}

zone_code() {
  EDGE_HOST=zone.e2e.test edge / -o /dev/null -w '%{http_code}' -H 'CF-Connecting-IP: 203.0.113.9' "$@"
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

echo "== first boot before the connector writes anything"
compose run --rm --no-deps -T --entrypoint cat connector /conf/haproxy/haproxy.cfg >"$WORK/boot.cfg" ||
  fail "init left no haproxy.cfg"
grep -q 'frontend fe_boot' "$WORK/boot.cfg" || fail "init did not write the bootstrap config: $(<"$WORK/boot.cfg")"
pass "init wrote the bootstrap haproxy.cfg"
compose up -d --no-deps haproxy >"$WORK/up.log" 2>&1 || fail "haproxy start failed: $(<"$WORK/up.log")"
sleep 5
expect "haproxy runs on the bootstrap config without a restart" "true 0" \
  "$(docker inspect -f '{{.State.Running}} {{.RestartCount}}' "$(compose ps -q haproxy)")"
expect "the bootstrap answers 404 on port 80" 404 "$(EDGE_HOST=anything.e2e.test edge_code /)"

echo "== start and detect the dashboard source address"
compose up -d >"$WORK/up.log" 2>&1 || fail "compose up failed: $(<"$WORK/up.log")"
wait_api
login
api GET "/api/v1/audit?limit=50"
code_is "audit readable" 200
PEER=$(printf '%s' "$BODY" | jq -er '[.[] | select(.action == "login.success")] | last | .detail | sub("^peer="; "")')
[ -n "$PEER" ] || fail "no peer address in the audit log"
pass "connector sees the host as $PEER"
# allow-all was only needed to learn the source address; restrict to it so the allowlist is exercised.
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
# A source outside the allowlist must be cut off during the connection, so a curl error rather than an HTTP status is the pass condition.
rc=0
out=$(docker run --rm --network "${PROJECT}_public" docker.io/curlimages/curl:latest -sk --max-time 5 \
  -o /dev/null -w '%{http_code}' "https://$CONNECTOR_IP:7443/api/v1/healthz") || rc=$?
case $rc in
  35 | 52 | 56) pass "non-allowlisted source is closed (curl exit $rc)" ;;
  *) fail "non-allowlisted source got curl exit $rc, code ${out:-none}" ;;
esac
expect "non-allowlisted source got no HTTP status" "000" "$out"

# Each bad factor must produce the same response, so the API cannot be used to learn which of user, password or code was right.
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

echo "== bots, top lists, stats and export"
api GET "/api/v1/analytics/bots?window=15m"
code_is "bot summary" 200
jq_ok "bot summary counts requests and bots" '.total_requests > 200 and .bot_requests > 0 and (.classes | length) > 0'
jq_ok "curl traffic is scored as a tool or bot" 'any(.classes[]; (.key == "tool" or .key == "bot") and .count > 0)'
jq_ok "bot signals are named" '(.signals | length) > 0 and all(.signals[]; .key | test("^[a-z0-9_]+$"))'
api GET "/api/v1/analytics/top?kind=paths&window=15m&limit=10"
code_is "top paths" 200
jq_ok "top paths include the dropped dotfile" 'any(.items[]; .key == "/.env")'
api GET "/api/v1/analytics/top?kind=nonsense&window=15m"
code_is "unknown top kind is rejected" 400
api GET /api/v1/analytics/stats
code_is "store stats" 200
jq_ok "store holds the requests" '.rows > 200 and .db_bytes > 0 and .write_errors == 0'
api GET "/api/v1/analytics/requests?limit=50"
jq_ok "events carry the captured headers and bot fields" 'any(.[]; (.http_version | startswith("HTTP/")) and (.bot_class | length) > 0 and .bot_score >= 0)'
EXPORT_HEADERS="$WORK/export.headers"
curl -sS --max-time 60 --cacert "$CA" --resolve "localhost:$API_PORT:127.0.0.1" -D "$EXPORT_HEADERS" -o "$WORK/export.csv" \
  -H "Authorization: Bearer $TOKEN" "https://localhost:$API_PORT/api/v1/analytics/export?kind=requests&format=csv&limit=1000" || fail "csv export failed"
grep -qi '^content-type: text/csv' "$EXPORT_HEADERS" || fail "export is not text/csv: $(<"$EXPORT_HEADERS")"
grep -qi '^content-disposition: attachment; filename="cite-requests-' "$EXPORT_HEADERS" || fail "export has no attachment name"
pass "csv export is a named attachment"
HEADER_ROW=$(head -n 1 "$WORK/export.csv" | tr -d '\r')
case $HEADER_ROW in
  timestamp,ts_ms,*bot_score*bot_class*bot_signals*) pass "csv header lists the bot columns" ;;
  *) fail "unexpected csv header: $HEADER_ROW" ;;
esac
[ "$(wc -l <"$WORK/export.csv" | tr -d ' ')" -gt 50 ] || fail "csv export has too few rows"
pass "csv export holds the stored requests"
grep -q '/.env' "$WORK/export.csv" || fail "the dropped dotfile is missing from the csv"
pass "csv export includes the dropped request"

echo "== archives and backups"
api GET /api/v1/settings
code_is "read default settings" 200
jq_ok "retention is unlimited and archives before deleting by default" '.retention.hour_buckets_days == 0 and .retention.archive_before_delete == true'
api GET /api/v1/analytics/archives
code_is "list archives" 200
jq_ok "archive list shape" '(.items | type) == "array" and (.dir_bytes | type) == "number"'
api POST /api/v1/analytics/backup
code_is "back up the database" 200
jq_ok "backup is a checksummed copy of the stored rows" '.kind == "backup" and (.sha256 | length) == 64 and .rows > 200 and .bytes > 0'
BACKUP_NAME=$(printf '%s' "$BODY" | jq -er .name)
BACKUP_SHA=$(printf '%s' "$BODY" | jq -er .sha256)
api GET /api/v1/analytics/archives
jq_ok "backup is listed" "any(.items[]; .name == \"$BACKUP_NAME\" and .kind == \"backup\")"
BACKUP_HEADERS="$WORK/backup.headers"
curl -sS --max-time 60 --cacert "$CA" --resolve "localhost:$API_PORT:127.0.0.1" -D "$BACKUP_HEADERS" -o "$WORK/backup.db" \
  -H "Authorization: Bearer $TOKEN" "https://localhost:$API_PORT/api/v1/analytics/archives/$BACKUP_NAME" || fail "backup download failed"
BACKUP_FILE_SHA=$(python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$WORK/backup.db")
expect "downloaded backup matches its checksum" "$BACKUP_SHA" "$BACKUP_FILE_SHA"
grep -qi "^x-archive-sha256: $BACKUP_SHA" "$BACKUP_HEADERS" || fail "download has no checksum header: $(<"$BACKUP_HEADERS")"
pass "download carries the checksum header"
api GET /api/v1/analytics/stats
ROWS_BEFORE_CUT=$(printf '%s' "$BODY" | jq -r .rows)
api POST /api/v1/analytics/cut '{"before_days":1,"dry_run":true}'
code_is "cut dry run" 200
jq_ok "dry run reports and archives nothing" '.dry_run == true and .archive == true and .archived_rows == 0 and (.files | length) == 0'
api GET /api/v1/analytics/stats
expect "dry run deleted nothing" "$ROWS_BEFORE_CUT" "$(printf '%s' "$BODY" | jq -r .rows)"
api POST /api/v1/analytics/cut '{}'
code_is "cut without a cutoff is rejected" 400
api POST /api/v1/analytics/cut '{"before_days":1,"archive":"no"}'
code_is "cut with a non-boolean archive flag is rejected" 400
api GET "/api/v1/analytics/archives/..%2Fanalytics.db"
code_is "archive name traversal is rejected" 400
api DELETE "/api/v1/analytics/archives/$BACKUP_NAME"
code_is "delete the backup" 200
api GET /api/v1/analytics/archives
jq_ok "backup is gone from the list" "all(.items[]; .name != \"$BACKUP_NAME\")"

echo "== settings and retention"
api GET /api/v1/settings
code_is "read settings" 200
SETTINGS=$(printf '%s' "$BODY" | jq -c '.retention.hour_buckets_days = 30')
api PUT /api/v1/settings "$SETTINGS"
code_is "shorten retention to 30 days" 200
api GET /api/v1/analytics/stats
jq_ok "shorter retention keeps recent rows" '.rows > 200'
api GET /api/v1/settings
SETTINGS=$(printf '%s' "$BODY" | jq -c '.retention.store_client_ips = false')
api PUT /api/v1/settings "$SETTINGS"
code_is "turn off client address storage" 200
SCRUBBED=""
for _ in $(seq 1 30); do
  api GET "/api/v1/analytics/requests?limit=200"
  if printf '%s' "$BODY" | jq -e 'length > 0 and all(.[]; .client_ip == "")' >/dev/null; then
    SCRUBBED=1
    break
  fi
  sleep 1
done
[ -n "$SCRUBBED" ] || fail "stored client addresses were not erased: $BODY"
pass "turning off client addresses erased the stored ones"
api GET /api/v1/settings
SETTINGS=$(printf '%s' "$BODY" | jq -c '.retention.store_client_ips = true')
api PUT /api/v1/settings "$SETTINGS"
code_is "turn client address storage back on" 200

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
traffic "$WORK/restart.out" 2000 &
LOOP_PID=$!
for _ in 1 2 3; do
  compose restart connector >"$WORK/restart.log" 2>&1 || fail "connector restart failed: $(<"$WORK/restart.log")"
  wait_api
done
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
jq_ok "analytics survived the restart" ".requests >= $REQUESTS_BEFORE"
api GET /api/v1/settings
jq_ok "settings persisted" '.retention.hour_buckets_days == 30'
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

echo "== certificates"
api POST /api/v1/sites "$(jq -nc --arg host "$CERT_HOST" '{
  id: "secure", name: "Secure", hosts: [$host], active: "blue",
  blue: {targets: [{addr: "e2e-blue:80"}]},
  green: {targets: [{addr: "e2e-green:80"}]}
}')"
code_is "create the site the certificate is for" 200
self_signed "$WORK/cert1"
self_signed "$WORK/cert2"
KEY_SLICES=("$(key_slice "$WORK/cert1.key")" "$(key_slice "$WORK/cert2.key")")
FP1=$(openssl x509 -in "$WORK/cert1.pem" -noout -fingerprint -sha256 | fingerprint_of)
FP2=$(openssl x509 -in "$WORK/cert2.pem" -noout -fingerprint -sha256 | fingerprint_of)
api GET /api/v1/settings
jq_ok "https is off by default" '.https_port == null'
api POST /api/v1/certificates "$(upload_body "e2e cert" "$WORK/cert1")"
code_is "upload a certificate" 201
jq_ok "certificate is described and covers the site" ".name == \"e2e cert\" and .sans == [\"$CERT_HOST\"] and .covers == [\"$CERT_HOST\"] and .days_left >= 29 and .key_type == \"ecdsa-p256\" and .fingerprint_sha256 == \"$FP1\""
jq_ok "upload warns that https is not enabled" '.warning | type == "string"'
no_key_material "the upload response"
CERT_ID=$(printf '%s' "$BODY" | jq -er .id)
api GET /api/v1/certificates
jq_ok "list shows the certificate, the unset port and the uncovered site" ".items | length == 1 and .[0].id == \"$CERT_ID\""
jq_ok "list reports https state and uncovered hosts" ".https_port == null and .dir_ready == true and (.uncovered_hosts | index(\"$SITE_HOST\")) != null"
no_key_material "the list response"
api GET /api/v1/settings
api PUT /api/v1/settings "$(printf '%s' "$BODY" | jq -c '.https_port = 443')"
code_is "enable https on port 443" 200
wait_served "$FP1" "HAProxy serves the uploaded certificate by SNI"
expect "https reaches the site through HAProxy" blue-v1 "$(https_edge "$WORK/cert1.pem")"
expect "http keeps serving the same host" 200 "$(EDGE_HOST=$CERT_HOST edge_code /)"

api PUT "/api/v1/certificates/$CERT_ID" "$(upload_body "e2e cert" "$WORK/cert2")"
code_is "replace the certificate in place" 200
jq_ok "replacement keeps the id and changes the fingerprint" ".id == \"$CERT_ID\" and .fingerprint_sha256 == \"$FP2\" and (has(\"warning\") | not)"
wait_served "$FP2" "HAProxy serves the replacement certificate"
expect "https works with the replacement" blue-v1 "$(https_edge "$WORK/cert2.pem")"
api POST /api/v1/certificates "$(upload_body "again" "$WORK/cert2")"
code_is "the same certificate twice is a conflict" 409
api POST /api/v1/certificates "$(jq -nc --rawfile c "$WORK/cert1.pem" --rawfile k "$WORK/cert2.key" '{name:"mismatch",certificate:$c,private_key:$k}')"
code_is "a key that does not match is refused" 400
api GET "/api/v1/certificates/$CERT_ID"
code_is "fetch one certificate" 200
api GET /api/v1/audit?limit=100
code_is "read the audit log" 200
no_key_material "the audit log"
jq_ok "uploads and replacements are audited without key material" 'any(.[]; .action == "certificates.create") and any(.[]; .action == "certificates.replace") and all(.[]; (.detail | contains("PRIVATE KEY") | not))'

api DELETE "/api/v1/certificates/$CERT_ID"
code_is "delete the last certificate" 204
rc=0
https_edge "$WORK/cert2.pem" -o /dev/null || rc=$?
[ "$rc" != 0 ] || fail "https still answers after the last certificate was deleted"
pass "https stops answering once no certificate is left (curl exit $rc)"
expect "http keeps serving after the delete" 200 "$(EDGE_HOST=$CERT_HOST edge_code /)"
api GET /api/v1/certificates
jq_ok "list is empty and https_port is untouched" '.items == [] and .https_port == 443'
api GET "/api/v1/certificates/$CERT_ID"
code_is "deleted certificate is gone" 404
api DELETE /api/v1/sites/secure
code_is "remove the certificate site" 200

echo "== cloudflare access"
api POST /api/v1/sites "$(jq -nc --arg host "$CF_HOST" '{
  id: "cf", name: "Cloudflare only", hosts: [$host], active: "blue",
  blue: {targets: [{addr: "e2e-green:80"}]},
  green: {targets: [{addr: "e2e-blue:80"}]},
  access: {cloudflare_only: true, tls: "flexible"}
}')"
code_is "create a cloudflare-only site" 200
jq_ok "site keeps its access settings" '.access.cloudflare_only == true and .access.tls == "flexible"'
api GET /api/v1/cloudflare/ranges
code_is "read the cloudflare ranges" 200
jq_ok "built-in ranges are reported with their date" '.source == "builtin" and (.ranges | length) > 0 and (.updated | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$"))'
# The upstream only has an index page, so a 404 on any other path proves the request reached it.
expect "an ordinary site passes the probe to its origin" 404 "$(edge_code /client-addr-probe)"
logged_client /client-addr-probe
EDGE_CLIENT=$LOGGED
pass "HAProxy sees the test client as $EDGE_CLIENT"
expect "a client outside the cloudflare ranges is refused" 403 "$(cf_code /cf-blocked -H 'CF-Connecting-IP: 203.0.113.9')"

api GET /api/v1/settings
api PUT /api/v1/settings "$(printf '%s' "$BODY" | jq -c --arg ip "$EDGE_CLIENT" '.cloudflare_ranges = [$ip]')"
code_is "trust the test client as a cloudflare address" 200
api GET /api/v1/cloudflare/ranges
jq_ok "custom ranges are reported" ".source == \"custom\" and .ranges == [\"$EDGE_CLIENT/32\"]"
expect "a listed peer reaches the origin" green-v2 "$(EDGE_HOST=$CF_HOST edge / -H 'CF-Connecting-IP: 203.0.113.9')"
expect "a listed peer is not refused" 404 "$(cf_code /cf-real-ip -H 'CF-Connecting-IP: 203.0.113.9')"
logged_client /cf-real-ip
expect "the backend logs the CF-Connecting-IP value as the client" 203.0.113.9 "$LOGGED"

api GET /api/v1/settings
api PUT /api/v1/settings "$(printf '%s' "$BODY" | jq -c '.cloudflare_ranges = []')"
code_is "return to the built-in ranges" 200
expect "an unlisted peer is refused again" 403 "$(cf_code /cf-forged -H 'CF-Connecting-IP: 198.51.100.77')"
logged_client /cf-forged
expect "a forged header from an unlisted peer does not change the logged address" "$EDGE_CLIENT" "$LOGGED"
expect "the forged header is ignored on an ordinary site" 404 "$(edge /plain-forged -H 'CF-Connecting-IP: 198.51.100.78' -o /dev/null -w '%{http_code}')"
logged_client /plain-forged
expect "the logged address of an ordinary site is the peer" "$EDGE_CLIENT" "$LOGGED"
api DELETE /api/v1/sites/cf
code_is "remove the cloudflare-only site" 200

echo "== zone lock, redirects, cors and bot policy"
start_echo
api POST /api/v1/sites "$(plain_site zone zone.e2e.test e2e-echo:80 '{"cloudflare_only":true,"zone_lock":true}')"
code_is "create a zone-locked site" 200
api GET /api/v1/sites/zone/zone-secret
code_is "read the zone secret status" 200
jq_ok "a secret was generated and is not returned" '.configured == true and .header == "X-Cite-Origin-Secret" and (.fingerprint | length) == 8 and (has("secret") | not)'
api POST /api/v1/sites/zone/zone-secret
code_is "rotate the zone secret" 200
jq_ok "the new secret is shown once with its fingerprint" '(.secret | length) == 43 and (.fingerprint | length) == 8'
ZONE_SECRET=$(printf '%s' "$BODY" | jq -er .secret)
api GET /api/v1/sites/zone/zone-secret
code_is "read the zone secret status again" 200
jq_ok "the status never returns the secret" "has(\"configured\") and (has(\"secret\") | not) and (tostring | contains(\"$ZONE_SECRET\") | not)"
api GET /api/v1/haproxy/config
code_is "read the rendered config" 200
case $BODY in
  *"frontend fe_main"*) ;;
  *) fail "the config endpoint did not return a config: $BODY" ;;
esac
case $BODY in
  *"$ZONE_SECRET"*) fail "the rendered config shown by the API contains the zone secret" ;;
esac
pass "the config shown by the API has no secret"
api GET /api/v1/settings
api PUT /api/v1/settings "$(printf '%s' "$BODY" | jq -c --arg ip "$EDGE_CLIENT" '.cloudflare_ranges = [$ip]')"
code_is "trust the test client as a cloudflare address again" 200
expect "no zone header is refused" 403 "$(zone_code)"
expect "a wrong zone secret is refused" 403 "$(zone_code -H 'X-Cite-Origin-Secret: wrong-secret-value-0123456789abcdef')"
expect "the right zone secret is served" 200 "$(zone_code -H "X-Cite-Origin-Secret: $ZONE_SECRET")"
expect "the origin does not receive the zone header" "zone=[]" "$(EDGE_HOST=zone.e2e.test edge / -H 'CF-Connecting-IP: 203.0.113.9' -H "X-Cite-Origin-Secret: $ZONE_SECRET")"
api POST /api/v1/sites/zone/zone-secret
code_is "rotate the zone secret again" 200
NEW_ZONE_SECRET=$(printf '%s' "$BODY" | jq -er .secret)
expect "the old zone secret stops working" 403 "$(zone_code -H "X-Cite-Origin-Secret: $ZONE_SECRET")"
expect "the new zone secret works" 200 "$(zone_code -H "X-Cite-Origin-Secret: $NEW_ZONE_SECRET")"
api GET "/api/v1/audit?limit=100"
jq_ok "rotation is audited without the secret" "any(.[]; .action == \"zone_secret.rotate\") and (tostring | contains(\"$NEW_ZONE_SECRET\") | not)"
api GET /api/v1/firewall/rules
jq_ok "the zone rule is not stored with the firewall rules" 'all(.[]; .id != "zone-zone")'

api POST /api/v1/sites "$(plain_site redir redir.e2e.test e2e-green:80)"
code_is "create a site for redirects" 200
api POST /api/v1/firewall/rules '{"id":"e2e-www","name":"add www","enabled":true,"site":"redir","redirect":{"to":"{scheme}://{www_host}{path}{query}"}}'
code_is "create a redirect-to-www rule" 200
expect "the bare host is redirected with a 301 to www" "301 http://www.redir.e2e.test/page?x=1" \
  "$(EDGE_HOST=redir.e2e.test edge '/page?x=1' -o /dev/null -w '%{http_code} %{redirect_url}')"

api POST /api/v1/sites "$(plain_site cors cors.e2e.test e2e-green:80)"
code_is "create a site for cors" 200
api POST /api/v1/firewall/rules '{"id":"e2e-cors","name":"cors","enabled":true,"site":"cors","cors":{"origins":["https://app.example.com"],"methods":["GET"],"allow_headers":["Content-Type"],"max_age_secs":600}}'
code_is "create a cors rule" 200
expect "a preflight from a listed origin is answered 204 by the edge" 204 \
  "$(EDGE_HOST=cors.e2e.test edge /api -X OPTIONS -H 'Origin: https://app.example.com' -H 'Access-Control-Request-Method: GET' -D "$WORK/preflight.h" -o /dev/null -w '%{http_code}')"
grep -qi '^access-control-allow-origin: https://app.example.com' "$WORK/preflight.h" || fail "the preflight has no allow-origin header: $(<"$WORK/preflight.h")"
pass "the preflight names the allowed origin"

api POST /api/v1/sites "$(plain_site bots bots.e2e.test e2e-green:80 '{"bots":"block_bad"}')"
code_is "create a site with the block_bad bot policy" 200
expect "a tool user agent is refused" 403 "$(EDGE_HOST=bots.e2e.test edge / -A 'curl/8.5.0' -o /dev/null -w '%{http_code}')"
expect "a browser user agent is served" green-v2 "$(EDGE_HOST=bots.e2e.test edge / -A 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0')"
api GET /api/v1/firewall/presets
jq_ok "the redirect and force-https presets are listed" 'map(.name) as $n | all(["redirect-to-www","redirect-to-apex","force-https"][]; . as $w | $n | index($w) != null)'

api DELETE /api/v1/firewall/rules/e2e-www
code_is "remove the redirect rule" 200
api DELETE /api/v1/firewall/rules/e2e-cors
code_is "remove the cors rule" 200
for site in zone redir cors bots; do
  api DELETE "/api/v1/sites/$site"
  code_is "remove site $site" 200
done
api GET /api/v1/settings
api PUT /api/v1/settings "$(printf '%s' "$BODY" | jq -c '.cloudflare_ranges = []')"
code_is "restore the built-in cloudflare ranges" 200

echo "== upgrade from a volume that has only /conf/haproxy"
remove_stack
export CITE_HTTP_PORT=$((HTTP_PORT + 1)) CITE_HTTPS_PORT=$((HTTPS_PORT + 1)) CITE_CONNECTOR_PORT=$((API_PORT + 1))
upgrade_compose run --rm --no-deps -T --entrypoint /bin/sh init -c \
  'mkdir -p /conf/haproxy && chown 10001:10001 /conf /conf/haproxy && chmod 0750 /conf /conf/haproxy' >"$WORK/old.log" 2>&1 ||
  fail "could not build the old-style volume: $(<"$WORK/old.log")"
upgrade_compose run --rm --no-deps -T init >"$WORK/init.log" 2>&1 || fail "init on the old volume failed: $(<"$WORK/init.log")"
upgrade_compose run --rm --no-deps -T --entrypoint /bin/sh connector -c \
  'test -d /conf/certs && test -d /conf/state && grep -q fe_boot /conf/haproxy/haproxy.cfg' >"$WORK/old.log" 2>&1 ||
  fail "init did not complete the old volume: $(<"$WORK/old.log")"
pass "init created certs and state and the bootstrap config on the old volume"
upgrade_compose up -d --no-deps haproxy >"$WORK/up.log" 2>&1 || fail "haproxy could not start on the old volume: $(<"$WORK/up.log")"
sleep 5
expect "haproxy runs on the upgraded volume without a restart" "true 0" \
  "$(docker inspect -f '{{.State.Running}} {{.RestartCount}}' "$(upgrade_compose ps -q haproxy)")"
remove_stack

echo "e2e-node: all checks passed"
