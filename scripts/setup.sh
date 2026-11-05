#!/bin/sh
# Cite node installer: sets up the connector node and the dashboard with Docker Compose.
set -eu
umask 077

RAW_BASE="https://raw.githubusercontent.com/seggys116/cite"
IMAGE_REPO="ghcr.io/seggys116/cite-connector"
DEFAULT_VERSION="0.2.0"
DEFAULT_REF="main"
WAIT_SECS=90
TOTAL_STEPS=6

CMD="install"
MODE=""
DIR=""
ALLOW=""
BIND=""
PORT=""
HTTP_PORT=""
HTTPS_PORT=""
DASH_BIND=""
DASH_PORT=""
ORCH=""
VERSION=""
REF=""
TARGET=""
YES=0
NOSTART=0
PURGE=0
STEP=0
SRC_DIR=""
WORK=""
ENV_TMP=""
ENV_FILE=""
OS=""
ARCH=""
ANSWER=""
CA_COPIED=0
FORCE_REMOTE=0

setup_colors() {
  TTY_OUT=0
  if [ -t 1 ]; then
    TTY_OUT=1
  fi
  if [ "$TTY_OUT" = 1 ] && [ -z "${NO_COLOR:-}" ]; then
    ESC=$(printf '\033')
    BOLD="${ESC}[1m"
    DIM="${ESC}[2m"
    RED="${ESC}[31m"
    GREEN="${ESC}[32m"
    YELLOW="${ESC}[33m"
    CYAN="${ESC}[36m"
    RESET="${ESC}[0m"
  else
    ESC=$(printf '\033')
    BOLD=""
    DIM=""
    RED=""
    GREEN=""
    YELLOW=""
    CYAN=""
    RESET=""
  fi
}

say() {
  printf '%s\n' "$*"
}

ok() {
  printf '  %sok%s  %s\n' "$GREEN" "$RESET" "$*"
}

warn() {
  printf '  %swarn%s  %s\n' "$YELLOW" "$RESET" "$*" >&2
}

die() {
  printf '%serror%s  %s\n' "$RED" "$RESET" "$*" >&2
  exit 1
}

step() {
  STEP=$((STEP + 1))
  printf '\n%s[%s/%s]%s %s%s%s\n' "$CYAN" "$STEP" "$TOTAL_STEPS" "$RESET" "$BOLD" "$*" "$RESET"
}

px_row() {
  printf '  %s%s%s\n' "$CYAN" "$(printf '%s' "$1.$2.$3.$4" | sed -e 's/#/██/g' -e 's/\./  /g')" "$RESET"
}

banner() {
  say ""
  px_row '.##' '.#.' '.#.' '###'
  px_row '#..' '...' '###' '#.#'
  px_row '#..' '.#.' '.#.' '###'
  px_row '#..' '.#.' '.#.' '#..'
  px_row '.##' '.#.' '.##' '###'
  say "  ${DIM}node installer${RESET}"
}

usage() {
  cat <<EOF
Usage: setup.sh [command] [options]

Commands:
  install     Install and start a Cite node and/or dashboard (default)
  status      Show the state of the installed stacks
  update      Pull new images and recreate containers, keeping volumes
  logs        Follow logs (optionally: logs node | logs dashboard)
  uninstall   Remove containers and networks (volumes only with --purge)
  help        Show this help

Options:
  --mode node|dashboard|both   What to install (prompted when omitted)
  --dir PATH                   Install directory (default ~/cite, /opt/cite as root)
  --allow LIST                 Comma separated IPs or CIDRs allowed to connect
                               ('allow-all' opens it to everyone)
  --bind IP                    Address the connector is exposed on
  --port PORT                  Connector port (default 7443)
  --http-port PORT             Public HTTP port (default 80)
  --https-port PORT            Public HTTPS port (default 443)
  --dashboard-bind IP          Address the dashboard is exposed on (default 127.0.0.1)
  --dashboard-port PORT        Dashboard port (default 8088)
  --orchestrator               Enable the Docker socket proxy so the connector can start sites
  --version X.Y.Z              Image version (default $DEFAULT_VERSION)
  --ref GIT_REF                Git ref to fetch compose files from (default $DEFAULT_REF)
  --yes                        Never prompt; accept defaults and confirmations
  --no-start                   Write the files and stop before pulling and starting
  --purge                      With uninstall: also remove volumes and installed files

Examples:
  curl -fsSL $RAW_BASE/$DEFAULT_REF/scripts/setup.sh | sh
  curl -fsSL $RAW_BASE/$DEFAULT_REF/scripts/setup.sh | sh -s -- --mode node --allow 203.0.113.7 --yes
EOF
}

cleanup() {
  if [ -n "$ENV_TMP" ]; then
    rm -f "$ENV_TMP"
  fi
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf "$WORK"
  fi
}

need_value() {
  [ $# -ge 2 ] || die "$1 needs a value"
}

is_interactive() {
  [ "$YES" != 1 ] || return 1
  ( : </dev/tty ) 2>/dev/null
}

ask() {
  printf '%s' "$1" >/dev/tty
  ANSWER=""
  IFS= read -r ANSWER </dev/tty || die "no input available; rerun with --yes and explicit options"
  if [ -z "$ANSWER" ]; then
    ANSWER=$2
  fi
}

confirm() {
  [ "$YES" != 1 ] || return 0
  is_interactive || return 1
  ask "$1 [y/N] " ""
  case $ANSWER in
    y|Y|yes|YES) return 0 ;;
  esac
  return 1
}

valid_ip4() {
  case $1 in
    ''|*[!0-9.]*|.*|*.|*..*|*.*.*.*.*) return 1 ;;
    *.*.*.*) ;;
    *) return 1 ;;
  esac
  _a=${1%%.*}
  _r=${1#*.}
  _b=${_r%%.*}
  _r=${_r#*.}
  _c=${_r%%.*}
  _d=${_r#*.}
  for _o in "$_a" "$_b" "$_c" "$_d"; do
    case $_o in
      ''|*[!0-9]*) return 1 ;;
    esac
    [ "${#_o}" -le 3 ] || return 1
    [ "$_o" -le 255 ] || return 1
  done
  return 0
}

valid_ip6() {
  case $1 in
    ''|*[!0-9A-Fa-f:.]*|*:::*) return 1 ;;
    *:*:*) ;;
    *) return 1 ;;
  esac
  [ "${#1}" -le 45 ]
}

valid_ip() {
  valid_ip4 "$1" || valid_ip6 "$1"
}

valid_cidr() {
  _has_len=0
  _ip=$1
  _len=""
  case $1 in
    */*)
      _has_len=1
      _ip=${1%/*}
      _len=${1#*/}
      ;;
  esac
  if valid_ip4 "$_ip"; then
    _max=32
  elif valid_ip6 "$_ip"; then
    _max=128
  else
    return 1
  fi
  if [ "$_has_len" = 1 ]; then
    case $_len in
      ''|*[!0-9]*) return 1 ;;
    esac
    [ "${#_len}" -le 3 ] || return 1
    [ "$_len" -le "$_max" ] || return 1
  fi
  return 0
}

valid_port() {
  case $1 in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "${#1}" -le 5 ] || return 1
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_version() {
  case $1 in
    [0-9]*) ;;
    *) return 1 ;;
  esac
  case $1 in
    *[!0-9A-Za-z.+-]*) return 1 ;;
  esac
  return 0
}

valid_ref() {
  case $1 in
    ''|*[!A-Za-z0-9._/-]*|*..*|/*) return 1 ;;
  esac
  return 0
}

valid_dir() {
  _nl=$(printf '\n_')
  _nl=${_nl%_}
  case $1 in
    ''|*[\"\'\$\`\\]*|*"$_nl"*) return 1 ;;
  esac
  return 0
}

check_allow() {
  [ -n "$1" ] || { warn "the allow list is empty"; return 1; }
  _rest=$1
  while [ -n "$_rest" ]; do
    _item=${_rest%%,*}
    case $_rest in
      *,*) _rest=${_rest#*,} ;;
      *) _rest="" ;;
    esac
    valid_cidr "$_item" || { warn "not an IP address or CIDR: $_item"; return 1; }
    case $_item in
      */0|0.0.0.0|::)
        warn "$_item allows everyone; type allow-all if you really mean that"
        return 1
        ;;
    esac
  done
  return 0
}

resolve_allow() {
  if [ "$1" = allow-all ]; then
    if confirm "Allow ANY address to reach this service? Only the credentials will protect it."; then
      ALLOW="0.0.0.0/0,::/0,allow-all"
      warn "open to every address; make sure a firewall restricts the exposed ports"
      return 0
    fi
    warn "allow-all was not confirmed"
    return 1
  fi
  check_allow "$1" || return 1
  ALLOW=$1
}

check_mode() {
  case $MODE in
    node|dashboard|both) ;;
    *) die "invalid mode: $MODE (use node, dashboard or both)" ;;
  esac
}

stack_enabled() {
  case "$1:$MODE" in
    node:node|node:both|dashboard:dashboard|dashboard:both) return 0 ;;
  esac
  return 1
}

dc_node() {
  if [ "$ORCH" = 1 ]; then
    docker compose --project-directory "$DIR" -f "$DIR/docker-compose.node.yml" -f "$DIR/docker-compose.orchestrator.yml" "$@" </dev/null
  else
    docker compose --project-directory "$DIR" -f "$DIR/docker-compose.node.yml" "$@" </dev/null
  fi
}

dc_dash() {
  docker compose --project-directory "$DIR" -f "$DIR/docker-compose.dashboard.yml" "$@" </dev/null
}

dc_stack() {
  _ds=$1
  shift
  case $_ds in
    node) dc_node "$@" ;;
    *) dc_dash "$@" ;;
  esac
}

node_file_args() {
  _args="-f docker-compose.node.yml"
  if [ "$ORCH" = 1 ]; then
    _args="$_args -f docker-compose.orchestrator.yml"
  fi
  printf '%s' "$_args"
}

env_get() {
  [ -f "$ENV_FILE" ] || return 0
  sed -n "s/^$1=//p" "$ENV_FILE" | sed -n 1p
}

set_env_key() {
  ENV_TMP=$(mktemp "$DIR/.env.XXXXXX")
  awk -v k="$1" -v v="$2" 'BEGIN { FS = OFS = "="; done = 0 }
    $1 == k { print k "=" v; done = 1; next }
    { print }
    END { if (!done) print k "=" v }' "$ENV_FILE" >"$ENV_TMP"
  cp -p "$ENV_FILE" "$ENV_FILE.bak"
  mv "$ENV_TMP" "$ENV_FILE"
  ENV_TMP=""
}

port_busy() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk -v p="$1" '{ n = split($4, a, ":"); if (a[n] == p) f = 1 } END { exit (f ? 0 : 1) }'
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  else
    return 1
  fi
}

detect_ip() {
  _ip=""
  if [ "$OS" = Darwin ]; then
    _if=$(route -n get default 2>/dev/null | awk '/interface:/ { print $2; exit }' || true)
    if [ -z "$_if" ]; then
      _if=en0
    fi
    _ip=$(ipconfig getifaddr "$_if" 2>/dev/null || true)
  else
    _ip=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | sed -n 1p || true)
    if [ -z "$_ip" ]; then
      _all=$(hostname -I 2>/dev/null || true)
      _ip=${_all%% *}
    fi
  fi
  case $_ip in
    127.*) _ip="" ;;
  esac
  if valid_ip4 "$_ip"; then
    printf '%s' "$_ip"
  fi
}

ver_ok() {
  _v=$(printf '%s' "$1" | sed 's/^v//; s/[^0-9.].*$//')
  case $_v in
    *.*) ;;
    *) _v="$_v.0" ;;
  esac
  _maj=${_v%%.*}
  _rest=${_v#*.}
  _min=${_rest%%.*}
  case "$_maj$_min" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ -n "$_maj" ] && [ -n "$_min" ] || return 1
  [ "$_maj" -gt "$2" ] && return 0
  [ "$_maj" -eq "$2" ] && [ "$_min" -ge "$3" ]
}

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1" </dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$2" "$1"
  else
    die "curl or wget is required to download files"
  fi
}

find_checkout() {
  [ "$FORCE_REMOTE" != 1 ] || return 0
  case $0 in
    */*|*.sh) ;;
    *) return 0 ;;
  esac
  _sd=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || return 0
  if [ "$(basename "$_sd")" = scripts ] && [ -f "$_sd/../docker-compose.node.yml" ]; then
    SRC_DIR=$(cd "$_sd/.." && pwd)
  fi
}

get_file() {
  if [ -n "$SRC_DIR" ]; then
    [ -f "$SRC_DIR/$1" ] || die "$1 is missing from the checkout at $SRC_DIR"
    if [ "$SRC_DIR" != "$DIR" ]; then
      cp "$SRC_DIR/$1" "$DIR/$1"
    fi
  else
    fetch "$RAW_BASE/$REF/$1" "$WORK/$1" || die "could not download $1 at ref $REF"
    mv "$WORK/$1" "$DIR/$1"
  fi
}

fetch_files() {
  if stack_enabled node; then
    get_file docker-compose.node.yml
    if [ "$ORCH" = 1 ]; then
      get_file docker-compose.orchestrator.yml
    fi
  fi
  if stack_enabled dashboard; then
    get_file docker-compose.dashboard.yml
  fi
}

install_self() {
  if [ -n "$SRC_DIR" ]; then
    cp "$SRC_DIR/scripts/setup.sh" "$DIR/cite-setup.sh" 2>/dev/null || warn "could not keep a copy of the installer"
  elif fetch "$RAW_BASE/$REF/scripts/setup.sh" "$WORK/cite-setup.sh" 2>/dev/null; then
    mv "$WORK/cite-setup.sh" "$DIR/cite-setup.sh"
  else
    warn "could not keep a copy of the installer"
  fi
  chmod 700 "$DIR/cite-setup.sh" 2>/dev/null || true
}

spin() {
  [ "$TTY_OUT" = 1 ] || return 0
  case $(($1 % 4)) in
    0) _f='|' ;;
    1) _f='/' ;;
    2) _f='-' ;;
    *) _f="\\" ;;
  esac
  printf '\r%s%s%s %s' "$CYAN" "$_f" "$RESET" "$2"
}

spin_done() {
  [ "$TTY_OUT" = 1 ] || return 0
  printf '\r%s[K' "$ESC"
}

container_ok() {
  _info=$(docker inspect -f '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$1" 2>/dev/null) || return 1
  case $_info in
    'running|'|'running|healthy') return 0 ;;
  esac
  return 1
}

stack_ready() {
  if [ "$1" = node ]; then
    _c=$(dc_node ps -q connector 2>/dev/null || true)
    _h=$(dc_node ps -q haproxy 2>/dev/null || true)
    [ -n "$_c" ] && [ -n "$_h" ] || return 1
    container_ok "$_c" && container_ok "$_h"
  else
    _ids=$(dc_dash ps -q 2>/dev/null || true)
    [ -n "$_ids" ] || return 1
    for _id in $_ids; do
      container_ok "$_id" || return 1
    done
    return 0
  fi
}

wait_ready() {
  _i=0
  while [ "$_i" -lt "$WAIT_SECS" ]; do
    if stack_ready "$1"; then
      spin_done
      return 0
    fi
    spin "$_i" "waiting for the $1 stack (up to ${WAIT_SECS}s)"
    sleep 1
    _i=$((_i + 1))
  done
  spin_done
  return 1
}

detect_platform() {
  case $(uname -s) in
    Linux) OS=Linux ;;
    Darwin) OS=Darwin ;;
    *) die "unsupported OS: $(uname -s) (Linux and macOS are supported)" ;;
  esac
  case $(uname -m) in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported architecture: $(uname -m) (amd64 and arm64 images are published)" ;;
  esac
}

preflight() {
  detect_platform
  ok "platform $OS/$ARCH"
  if [ "$(id -u)" -eq 0 ]; then
    warn "running as root; a regular user in the docker group is preferred"
  fi
  if ! command -v docker >/dev/null 2>&1; then
    if [ "$OS" = Darwin ]; then
      die "docker was not found. Install Docker Desktop: https://docs.docker.com/desktop/setup/install/mac-install/"
    fi
    die "docker was not found. Install Docker Engine: https://docs.docker.com/engine/install/"
  fi
  _cv=$(docker compose version --short 2>/dev/null || true)
  [ -n "$_cv" ] || die "docker compose v2 was not found. See https://docs.docker.com/compose/install/"
  ver_ok "$_cv" 2 26 || die "docker compose $_cv is too old; v2.26 or newer is required. See https://docs.docker.com/compose/install/"
  ok "docker compose $_cv"
  docker info >/dev/null 2>&1 </dev/null || die "cannot reach the Docker daemon. Start Docker, or add your user to the docker group and log in again"
  _ev=$(docker version --format '{{.Server.Version}}' 2>/dev/null </dev/null || true)
  [ -n "$_ev" ] || die "could not read the Docker Engine version"
  ver_ok "$_ev" 26 0 || die "Docker Engine $_ev is too old; 26 or newer is required. See https://docs.docker.com/engine/install/"
  ok "docker engine $_ev"
  if [ "$OS" = Darwin ]; then
    say "  ${DIM}macOS: published ports bind through Docker Desktop's forwarder${RESET}"
  fi
}

check_ports() {
  _running=$(docker ps -q --filter label=com.docker.compose.project=cite-node </dev/null 2>/dev/null || true)
  if [ -n "$_running" ]; then
    return 0
  fi
  _busy=""
  if stack_enabled node; then
    for _p in "$PORT" "$HTTP_PORT" "$HTTPS_PORT"; do
      if port_busy "$_p"; then
        _busy="$_busy $_p"
      fi
    done
  fi
  if stack_enabled dashboard && port_busy "$DASH_PORT"; then
    _busy="$_busy $DASH_PORT"
  fi
  if [ -n "$_busy" ]; then
    die "port(s) already in use:$_busy. Free them or choose others with --port, --http-port, --https-port, --dashboard-port"
  fi
}

default_dir() {
  if [ -z "$DIR" ]; then
    case $0 in
      */cite-setup.sh)
        _d=$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)
        if [ -n "$_d" ] && [ -f "$_d/.env" ]; then
          DIR=$_d
        fi
        ;;
    esac
  fi
  if [ -z "$DIR" ]; then
    if [ "$(id -u)" -eq 0 ]; then
      DIR=/opt/cite
    else
      DIR=${HOME:-.}/cite
    fi
  fi
  # shellcheck disable=SC2088
  case $DIR in
    '~') DIR=${HOME:-.} ;;
    '~/'*) DIR=${HOME:-.}/${DIR#'~/'} ;;
  esac
  valid_dir "$DIR" || die "the install directory contains characters that are not allowed: $DIR"
}

load_installed() {
  default_dir
  [ -d "$DIR" ] || die "no Cite install found in $DIR (use --dir)"
  DIR=$(cd "$DIR" && pwd)
  ENV_FILE=$DIR/.env
  [ -f "$ENV_FILE" ] || die "no Cite install found in $DIR (use --dir)"
  if [ -z "$MODE" ]; then
    MODE=$(env_get CITE_SETUP_MODE)
  fi
  if [ -z "$MODE" ]; then
    MODE=node
  fi
  check_mode
  if [ -z "$ORCH" ]; then
    ORCH=$(env_get CITE_SETUP_ORCHESTRATOR)
  fi
  if [ "$ORCH" != 1 ]; then
    ORCH=0
  fi
  if [ -z "$VERSION" ]; then
    VERSION=$(env_get CITE_VERSION)
  fi
  if [ -z "$VERSION" ]; then
    VERSION=$DEFAULT_VERSION
  fi
  [ -n "$BIND" ] || BIND=$(env_get CITE_CONNECTOR_BIND)
  [ -n "$PORT" ] || PORT=$(env_get CITE_CONNECTOR_PORT)
  [ -n "$DASH_BIND" ] || DASH_BIND=$(env_get CITE_DASHBOARD_BIND)
  [ -n "$DASH_PORT" ] || DASH_PORT=$(env_get CITE_DASHBOARD_PORT)
  return 0
}

choose_mode() {
  if [ -n "$MODE" ]; then
    check_mode
    return 0
  fi
  if ! is_interactive; then
    MODE=node
    return 0
  fi
  while :; do
    ask "What do you want to install? node, dashboard or both [node]: " node
    MODE=$ANSWER
    case $MODE in
      node|dashboard|both) break ;;
    esac
    warn "enter node, dashboard or both"
  done
}

choose_allow() {
  if [ -n "$ALLOW" ]; then
    resolve_allow "$ALLOW" || die "invalid --allow value"
    return 0
  fi
  _def=""
  if [ -n "${SSH_CONNECTION:-}" ]; then
    _def=${SSH_CONNECTION%% *}
  fi
  valid_ip "$_def" || _def=""
  if is_interactive; then
    while :; do
      ask "Which IP or CIDR may connect (comma separated)${_def:+ [$_def]}: " "$_def"
      if resolve_allow "$ANSWER"; then
        break
      fi
    done
    return 0
  fi
  [ -n "$_def" ] || die "--allow is required when not prompting (an IP, a CIDR list, or allow-all)"
  ALLOW=$_def
  ok "allowing the SSH client address $_def"
}

choose_bind() {
  if ! stack_enabled node; then
    return 0
  fi
  if [ -z "$BIND" ]; then
    _def=$(detect_ip)
    if [ -z "$_def" ]; then
      _def=0.0.0.0
    fi
    BIND=$_def
    if is_interactive; then
      while :; do
        ask "Which local IP should the connector listen on [$_def]: " "$_def"
        if valid_ip "$ANSWER"; then
          BIND=$ANSWER
          break
        fi
        warn "not an IP address: $ANSWER"
      done
    fi
  fi
  valid_ip "$BIND" || die "invalid --bind address: $BIND"
  if [ "$BIND" = 0.0.0.0 ]; then
    warn "the connector will listen on every interface; the allowlist is the only gate"
  fi
}

choose_dash_bind() {
  if ! stack_enabled dashboard; then
    return 0
  fi
  if [ -z "$DASH_BIND" ]; then
    DASH_BIND=127.0.0.1
    if is_interactive; then
      while :; do
        ask "Which local IP should the dashboard listen on [127.0.0.1]: " "127.0.0.1"
        if valid_ip "$ANSWER"; then
          DASH_BIND=$ANSWER
          break
        fi
        warn "not an IP address: $ANSWER"
      done
    fi
  fi
  valid_ip "$DASH_BIND" || die "invalid --dashboard-bind address: $DASH_BIND"
}

choose_orch() {
  if ! stack_enabled node; then
    ORCH=0
    return 0
  fi
  if [ -z "$ORCH" ]; then
    ORCH=0
    if is_interactive; then
      say "The orchestrator lets the connector start site containers through a filtering Docker API proxy."
      say "The proxy only allows cite site containers, but it holds the Docker socket, so keep this node dedicated."
      if confirm "Enable the orchestrator?"; then
        ORCH=1
      fi
    fi
  fi
}

collect_config() {
  choose_mode
  [ -n "$VERSION" ] || VERSION=$DEFAULT_VERSION
  [ -n "$PORT" ] || PORT=7443
  [ -n "$HTTP_PORT" ] || HTTP_PORT=80
  [ -n "$HTTPS_PORT" ] || HTTPS_PORT=443
  [ -n "$DASH_PORT" ] || DASH_PORT=8088
  valid_version "$VERSION" || die "invalid --version: $VERSION"
  for _p in "$PORT" "$HTTP_PORT" "$HTTPS_PORT" "$DASH_PORT"; do
    valid_port "$_p" || die "invalid port: $_p"
  done
  choose_allow
  choose_bind
  choose_dash_bind
  choose_orch
  return 0
}

# Group that owns the Docker socket; Docker Desktop shows it as root inside its VM, so fall back to 0 there.
docker_socket_gid() {
  _gid=$(stat -c %g /var/run/docker.sock 2>/dev/null || stat -f %g /var/run/docker.sock 2>/dev/null || echo 0)
  case $(uname -s) in
    Darwin) _gid=0 ;;
  esac
  case $_gid in
    '' | *[!0-9]*) _gid=0 ;;
  esac
  printf '%s' "$_gid"
}

write_env() {
  if [ -f "$ENV_FILE" ]; then
    confirm "$ENV_FILE already exists. Replace it (a copy is kept as .env.bak)?" \
      || die "$ENV_FILE exists; keeping it. Use the update command to upgrade, or pass --yes to rewrite it"
    cp -p "$ENV_FILE" "$ENV_FILE.bak"
  fi
  ENV_TMP=$(mktemp "$DIR/.env.XXXXXX")
  {
    printf '# written by cite setup.sh on %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'CITE_VERSION=%s\n' "$VERSION"
    printf 'CITE_SETUP_MODE=%s\n' "$MODE"
    printf 'CITE_SETUP_ORCHESTRATOR=%s\n' "$ORCH"
    if [ "$ORCH" = 1 ]; then
      printf 'DOCKER_GID=%s\n' "$(docker_socket_gid)"
    fi
    if stack_enabled node; then
      printf 'CITE_CONNECTOR_ALLOW=%s\n' "$ALLOW"
      printf 'CITE_CONNECTOR_BIND=%s\n' "$BIND"
      printf 'CITE_CONNECTOR_PORT=%s\n' "$PORT"
      printf 'CITE_HTTP_PORT=%s\n' "$HTTP_PORT"
      printf 'CITE_HTTPS_PORT=%s\n' "$HTTPS_PORT"
    fi
    if stack_enabled dashboard; then
      printf 'CITE_DASHBOARD_ALLOW=%s\n' "$ALLOW"
      printf 'CITE_DASHBOARD_BIND=%s\n' "$DASH_BIND"
      printf 'CITE_DASHBOARD_PORT=%s\n' "$DASH_PORT"
    fi
  } >"$ENV_TMP"
  chmod 600 "$ENV_TMP"
  mv "$ENV_TMP" "$ENV_FILE"
  ENV_TMP=""
}

connector_host() {
  if [ "$BIND" = 0.0.0.0 ]; then
    _h=$(detect_ip)
    printf '%s' "${_h:-<this-host>}"
  else
    printf '%s' "$BIND"
  fi
}

copy_ca() {
  rm -f "$DIR/cite-ca.pem"
  if dc_node cp connector:/conf/tls/ca.pem "$DIR/cite-ca.pem" >/dev/null 2>&1; then
    chmod 644 "$DIR/cite-ca.pem"
    CA_COPIED=1
  fi
}

summary() {
  say ""
  say "${BOLD}Cite is running.${RESET}"
  say ""
  if stack_enabled node; then
    say "${BOLD}Connector${RESET}"
    say "  URL             https://$(connector_host):$PORT"
    say "  Allowed         $ALLOW"
    if [ "$CA_COPIED" = 1 ]; then
      say "  CA certificate  $DIR/cite-ca.pem"
      if command -v openssl >/dev/null 2>&1; then
        _fp=$(openssl x509 -in "$DIR/cite-ca.pem" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//' || true)
        if [ -n "$_fp" ]; then
          say "  CA SHA-256      $_fp"
        fi
      fi
    fi
    say "  Copy the CA out again with either command:"
    say "    cd \"$DIR\" && docker compose $(node_file_args) cp connector:/conf/tls/ca.pem ./cite-ca.pem"
    say "    docker run --rm -v cite-node_cite_conf:/conf:ro --entrypoint cat $IMAGE_REPO:$VERSION /conf/tls/ca.pem > cite-ca.pem"
    say "  Add the node in the dashboard under Nodes: give it a name, the URL above, a connector API token,"
    say "  and the CA certificate. Compare the fingerprint above with the one shown by init."
    say ""
  fi
  if stack_enabled dashboard; then
    say "${BOLD}Dashboard${RESET}"
    say "  URL             http://$DASH_BIND:$DASH_PORT"
    say "  Onboarding      open the URL in a browser and create the first account there"
    if [ "$MODE" = both ]; then
      say "  Same host       the dashboard reaches the connector from a Docker address;"
      say "                  include it in the connector allowlist if the node shows as unreachable"
    fi
    say ""
  fi
  say "${BOLD}Manage${RESET}"
  say "  $DIR/cite-setup.sh status"
  say "  $DIR/cite-setup.sh update"
  say "  $DIR/cite-setup.sh logs"
  say "  $DIR/cite-setup.sh uninstall"
  say ""
}

do_install() {
  find_checkout
  step "checking docker"
  preflight

  step "choosing settings"
  default_dir
  collect_config
  check_ports
  ok "mode $MODE, version $VERSION"

  step "writing files"
  mkdir -p "$DIR"
  chmod 700 "$DIR"
  DIR=$(cd "$DIR" && pwd)
  ENV_FILE=$DIR/.env
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/cite-setup.XXXXXX")
  fetch_files
  write_env
  install_self
  ok "wrote $ENV_FILE (mode 600) and the compose files"
  for _s in node dashboard; do
    if stack_enabled "$_s"; then
      dc_stack "$_s" config -q || die "the $_s compose file did not validate; see the message above"
    fi
  done
  ok "compose files validate"

  if [ "$NOSTART" = 1 ]; then
    say ""
    say "Files are in place. To start:"
    for _s in node dashboard; do
      if stack_enabled "$_s"; then
        if [ "$_s" = node ]; then
          say "  cd \"$DIR\" && docker compose $(node_file_args) pull && docker compose $(node_file_args) run --rm --no-deps init && docker compose $(node_file_args) run --rm --no-deps connector init && docker compose $(node_file_args) up -d"
        else
          say "  cd \"$DIR\" && docker compose -f docker-compose.dashboard.yml up -d"
        fi
      fi
    done
    return 0
  fi

  step "pulling images"
  for _s in node dashboard; do
    if stack_enabled "$_s"; then
      dc_stack "$_s" pull || die "could not pull the $_s images"
    fi
  done
  ok "images pulled"

  step "preparing credentials"
  if stack_enabled node; then
    dc_node run --rm -T --no-deps init || die "could not prepare the connector volume"
    say ""
    say "${BOLD}Save the credentials below now.${RESET} They are shown once; rerunning init prints nothing new."
    say ""
    dc_node run --rm -T --no-deps connector init || die "connector init failed"
    say ""
  else
    ok "dashboard onboarding happens in the browser; nothing to initialise"
  fi

  step "starting"
  for _s in node dashboard; do
    if stack_enabled "$_s"; then
      dc_stack "$_s" up -d || die "could not start the $_s stack"
      if wait_ready "$_s"; then
        ok "$_s stack is up"
      else
        warn "the $_s stack is not healthy after ${WAIT_SECS}s; check: $DIR/cite-setup.sh logs $_s"
      fi
    fi
  done
  if stack_enabled node; then
    copy_ca
    if [ "$CA_COPIED" != 1 ]; then
      warn "could not copy the CA certificate yet; use one of the commands below once the connector is healthy"
    fi
  fi
  summary
}

do_status() {
  load_installed
  say "install dir  $DIR"
  say "version      $VERSION"
  say "mode         $MODE (orchestrator: $([ "$ORCH" = 1 ] && echo on || echo off))"
  for _s in node dashboard; do
    if stack_enabled "$_s"; then
      say ""
      say "${BOLD}$_s${RESET}"
      dc_stack "$_s" ps
    fi
  done
  if stack_enabled node && [ -n "$BIND" ]; then
    say ""
    say "connector    https://$(connector_host):${PORT:-7443}"
  fi
  if stack_enabled dashboard && [ -n "$DASH_BIND" ]; then
    say "dashboard    http://$DASH_BIND:${DASH_PORT:-8088}"
  fi
}

do_update() {
  load_installed
  find_checkout
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/cite-setup.XXXXXX")
  valid_version "$VERSION" || die "invalid version: $VERSION"
  TOTAL_STEPS=3
  step "updating files"
  set_env_key CITE_VERSION "$VERSION"
  set_env_key CITE_SETUP_ORCHESTRATOR "$ORCH"
  fetch_files
  for _s in node dashboard; do
    if stack_enabled "$_s"; then
      dc_stack "$_s" config -q || die "the $_s compose file did not validate; see the message above"
    fi
  done
  ok "version $VERSION"
  step "pulling images"
  for _s in node dashboard; do
    if stack_enabled "$_s"; then
      dc_stack "$_s" pull || die "could not pull the $_s images"
    fi
  done
  step "recreating containers"
  for _s in node dashboard; do
    if stack_enabled "$_s"; then
      dc_stack "$_s" up -d --remove-orphans || die "could not start the $_s stack"
      if wait_ready "$_s"; then
        ok "$_s stack is up"
      else
        warn "the $_s stack is not healthy after ${WAIT_SECS}s; check: $DIR/cite-setup.sh logs $_s"
      fi
    fi
  done
  say ""
  say "Volumes were kept; credentials and certificates are unchanged."
}

do_logs() {
  load_installed
  _t=$TARGET
  if [ -z "$_t" ]; then
    if stack_enabled node; then
      _t=node
    else
      _t=dashboard
    fi
  fi
  stack_enabled "$_t" || die "the $_t stack is not part of this install"
  dc_stack "$_t" logs -f --tail 100
}

do_uninstall() {
  load_installed
  say "This will remove:"
  for _s in node dashboard; do
    if stack_enabled "$_s"; then
      say "  containers and networks of the $_s stack"
    fi
  done
  if [ "$PURGE" = 1 ]; then
    say "  all volumes of those stacks (CA, TLS keys, credentials, state); this cannot be undone"
    say "  files in $DIR: .env, .env.bak, compose files, cite-ca.pem, cite-setup.sh"
  else
    say "Volumes and the files in $DIR are kept; add --purge to remove them."
  fi
  say "Site containers started by the connector are not compose-managed and are left in place."
  confirm "Continue?" || die "aborted; nothing was removed (use --yes to skip the prompt)"
  for _s in node dashboard; do
    if stack_enabled "$_s"; then
      if [ "$PURGE" = 1 ]; then
        dc_stack "$_s" down --remove-orphans --volumes || die "could not remove the $_s stack"
      else
        dc_stack "$_s" down --remove-orphans || die "could not remove the $_s stack"
      fi
      ok "removed the $_s stack"
    fi
  done
  if [ "$PURGE" = 1 ]; then
    for _f in .env .env.bak docker-compose.node.yml docker-compose.orchestrator.yml docker-compose.dashboard.yml cite-ca.pem cite-setup.sh; do
      rm -f "$DIR/$_f"
    done
    rmdir "$DIR" 2>/dev/null || true
    ok "removed volumes and installed files"
  fi
}

parse_args() {
  while [ $# -gt 0 ]; do
    case $1 in
      --mode) need_value "$@"; MODE=$2; shift 2 ;;
      --dir) need_value "$@"; DIR=$2; shift 2 ;;
      --allow) need_value "$@"; ALLOW=$2; shift 2 ;;
      --bind) need_value "$@"; BIND=$2; shift 2 ;;
      --port) need_value "$@"; PORT=$2; shift 2 ;;
      --http-port) need_value "$@"; HTTP_PORT=$2; shift 2 ;;
      --https-port) need_value "$@"; HTTPS_PORT=$2; shift 2 ;;
      --dashboard-bind) need_value "$@"; DASH_BIND=$2; shift 2 ;;
      --dashboard-port) need_value "$@"; DASH_PORT=$2; shift 2 ;;
      --version) need_value "$@"; VERSION=$2; shift 2 ;;
      --ref) need_value "$@"; REF=$2; shift 2 ;;
      --orchestrator) ORCH=1; shift ;;
      --yes|-y) YES=1; shift ;;
      --no-start) NOSTART=1; shift ;;
      --purge) PURGE=1; shift ;;
      -h|--help) CMD=help; shift ;;
      node|dashboard) TARGET=$1; shift ;;
      *) die "unknown option: $1 (see: setup.sh help)" ;;
    esac
  done
}

validate_flags() {
  if [ -n "$REF" ]; then
    valid_ref "$REF" || die "invalid --ref: $REF"
    SRC_DIR=""
    FORCE_REMOTE=1
  fi
  if [ -n "$VERSION" ]; then
    valid_version "$VERSION" || die "invalid --version: $VERSION"
  fi
  [ -z "$PORT" ] || valid_port "$PORT" || die "invalid --port: $PORT"
  [ -z "$HTTP_PORT" ] || valid_port "$HTTP_PORT" || die "invalid --http-port: $HTTP_PORT"
  [ -z "$HTTPS_PORT" ] || valid_port "$HTTPS_PORT" || die "invalid --https-port: $HTTPS_PORT"
  [ -z "$DASH_PORT" ] || valid_port "$DASH_PORT" || die "invalid --dashboard-port: $DASH_PORT"
  [ -z "$BIND" ] || valid_ip "$BIND" || die "invalid --bind: $BIND"
  [ -z "$DASH_BIND" ] || valid_ip "$DASH_BIND" || die "invalid --dashboard-bind: $DASH_BIND"
  return 0
}

main() {
  setup_colors
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if [ $# -gt 0 ]; then
    case $1 in
      install|status|update|logs|uninstall|help) CMD=$1; shift ;;
    esac
  fi
  parse_args "$@"
  if [ "$CMD" = help ]; then
    usage
    exit 0
  fi
  validate_flags
  if [ "$CMD" = install ]; then
    banner
  fi
  if [ -z "$REF" ]; then
    REF=$DEFAULT_REF
  fi
  case $CMD in
    install) do_install ;;
    status) do_status ;;
    update) do_update ;;
    logs) do_logs ;;
    uninstall) do_uninstall ;;
  esac
}

main "$@"
