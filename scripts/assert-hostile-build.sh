#!/usr/bin/env bash
# Run the hostile fixture inside the live manager and require containment, including no PAT in the build env.
set -euo pipefail

PROJECT="${1:-cite-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JOB="/var/lib/cite/work/job-tst26"
mkdir -p "$ROOT/target"

fail() {
  echo "assert-hostile-build FAIL: $*" >&2
  exit 1
}

mgr_id="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1)"
[[ -n "$mgr_id" ]] || fail "manager container not running for project ${PROJECT}"

docker exec -u 10002:10002 "$mgr_id" cite-manager __clean "$JOB" >/dev/null 2>&1 || true
docker exec "$mgr_id" sh -c "chown -R 0:0 '$JOB' 2>/dev/null || true; rm -rf '$JOB' /tmp/cite-hostile /etc/cite-hostile /var/lib/cite/releases/cite-hostile /var/lib/cite/state/cite-hostile /var/lib/cite/cache/cite-hostile"
docker exec "$mgr_id" mkdir -p "$JOB/src" "$JOB/home" "$JOB/out"
docker cp "$ROOT/tests/fixtures/hostile/." "$mgr_id:$JOB/src"

docker exec "$mgr_id" node -e '
const fs = require("fs");
const job = {
  job_id: "tst26",
  src: "/var/lib/cite/work/job-tst26/src",
  home: "/var/lib/cite/work/job-tst26/home",
  out: "/var/lib/cite/work/job-tst26/out",
  install_command: "true",
  build_command: "node build.js",
  prune_command: null,
  env: {
    PATH: "/usr/local/bin:/usr/bin:/bin",
    HOME: "/var/lib/cite/work/job-tst26/home",
    TMPDIR: "/var/lib/cite/work/job-tst26/home",
    TMP: "/var/lib/cite/work/job-tst26/home",
    TEMP: "/var/lib/cite/work/job-tst26/home"
  },
  cache_dir: null,
  timeout_s: 12
};
fs.writeFileSync("/var/lib/cite/work/job-tst26/out/job.json", JSON.stringify(job));
'
docker exec "$mgr_id" chown -R 10002:10002 "$JOB"

set +e
docker exec "$mgr_id" cite-manager __supervise "$JOB/out/job.json" >"$ROOT/target/hostile-supervise.log" 2>&1
supervise_status=$?
set -e
results="$(docker exec "$mgr_id" cat "$JOB/home/results.txt")"
printf '%s\n' "$results" >"$ROOT/target/hostile-results.txt"
grep -q "timed out" "$ROOT/target/hostile-supervise.log" || fail "supervise did not report a timeout"

need() {
  printf '%s\n' "$results" | grep -q "$1" || fail "missing result: $1"
}
need "token DENIED"
need "proc1 DENIED"
need "mem DENIED"
need "socket DENIED"
need "ptrace DENIED"
need "write /etc/cite-hostile DENIED"
need "write /tmp/cite-hostile DENIED"
need "write /var/lib/cite/releases/cite-hostile DENIED"
need "write /var/lib/cite/state/cite-hostile DENIED"
need "hardlink DENIED"
need "metadata "
need "nproc 512"
need "fsize 2147483648"
need "results-ready"
if grep -E 'ghp_|github_pat_' "$ROOT/target/hostile-supervise.log" "$ROOT/target/hostile-results.txt"; then
  fail "PAT appeared in the build log"
fi
printf '%s\n' "$results" | grep -q "metadata CONNECTED" && fail "metadata endpoint was reachable"
printf '%s\n' "$results" | grep -q "fork STARTED" && fail "fork storm was not limited"

straggler="$(printf '%s\n' "$results" | sed -n 's/^straggler //p' | head -n1)"
[[ -n "$straggler" && "$straggler" != "none" ]] || fail "no straggler pid"

[[ "$supervise_status" -ne 0 ]] || fail "supervise exited 0; build did not hit the timeout"

docker exec -u 10002:10002 "$mgr_id" cite-manager __clean "$JOB" >/dev/null 2>&1 || true
if docker exec "$mgr_id" sh -c "test -d /proc/$straggler"; then
  fail "straggler $straggler still alive after __clean"
fi
docker exec "$mgr_id" sh -c "chown -R 0:0 '$JOB' 2>/dev/null || true; rm -rf '$JOB'"
if docker exec "$mgr_id" sh -c "test -d $JOB"; then
  fail "job directory was not removed"
fi
if docker exec "$mgr_id" sh -c 'find /var/lib/cite/releases -name index.html -o -name cite-hostile | grep -q .'; then
  fail "hostile output landed in releases"
fi

echo "assert-hostile-build OK"
