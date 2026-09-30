# shellcheck shell=bash disable=SC2034

start_layout_watch() {
  local name="${PROJECT}-layout"
  if docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -q true; then
    return 0
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --entrypoint node \
    -v "${PROJECT}_cite_data:/data:ro" \
    -v "${ROOT}/scripts/layout-watch.js:/layout-watch.js:ro" \
    cite-manager:dev /layout-watch.js >/dev/null
  sleep 0.3
  docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -q true \
    || fail "layout watcher exited: $(docker logs "$name" 2>&1 | tail -n 20)"
}

harvest_layout_watch() {
  local name="${PROJECT}-layout" samples violations
  samples="$(docker exec "$name" node -e 'const fs=require("fs"); process.stdout.write(fs.existsSync("/tmp/cite-layout-samples")?fs.readFileSync("/tmp/cite-layout-samples","utf8"):"0");')" \
    || fail "layout watcher is not running"
  violations="$(docker exec "$name" node -e 'const fs=require("fs"); process.stdout.write(fs.existsSync("/tmp/cite-layout-violations")?fs.readFileSync("/tmp/cite-layout-violations","utf8"):"");')" \
    || fail "layout watcher is not running"
  [[ "$samples" =~ ^[0-9]+$ ]] || samples=0
  LAYOUT_SAMPLES="$samples"
  if [[ -n "$violations" ]]; then
    printf '%s\n' "$violations" > target/e2e-layout-violations
  else
    rm -f target/e2e-layout-violations
  fi
}

stop_layout_watch() {
  docker rm -f "${PROJECT}-layout" >/dev/null 2>&1 || true
}
