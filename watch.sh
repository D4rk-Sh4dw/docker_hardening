#!/usr/bin/env bash
# =================================================================
# Docker Security Analyzer - WATCH/DAEMON mode
# Repeatedly traces a running container in time windows and keeps a
# merged profile up to date across container restarts.
#
# Usage:
#   ./watch.sh <container_name_or_id> <runtime_seconds> [--retry-seconds N] [--detach]
#
# Examples:
#   sudo ./watch.sh immich-server 300
#   sudo ./watch.sh immich-server 300 --retry-seconds 10 --detach
# =================================================================
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <container_name_or_id> <runtime_seconds> [--retry-seconds N] [--detach]"
    exit 1
fi

CONTAINER="$1"
RUNTIME="$2"
shift 2

RETRY_SECONDS=5
DETACH=0

while [ $# -gt 0 ]; do
    case "$1" in
        --retry-seconds)
            [ $# -ge 2 ] || { echo "Error: --retry-seconds needs a value"; exit 1; }
            RETRY_SECONDS="$2"
            shift 2
            ;;
        --detach)
            DETACH=1
            shift
            ;;
        *)
            echo "Error: Unknown argument '$1'"
            exit 1
            ;;
    esac
done

if ! [[ "$RUNTIME" =~ ^[0-9]+$ ]] || [ "$RUNTIME" -lt 1 ]; then
    echo "Error: runtime_seconds must be a positive integer"
    exit 1
fi

if ! [[ "$RETRY_SECONDS" =~ ^[0-9]+$ ]] || [ "$RETRY_SECONDS" -lt 1 ]; then
    echo "Error: --retry-seconds must be a positive integer"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Run as root (required for eBPF tracing)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ATTACH_SCRIPT="${SCRIPT_DIR}/attach.sh"
GENERATOR_SCRIPT="${SCRIPT_DIR}/generator.py"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()  { echo -e "${BLUE}[*]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[-]${NC} $*" >&2; }

SESSION_DIR="${SCRIPT_DIR}/reports/watch_${CONTAINER}_${TIMESTAMP}"
RUNS_FILE="${SESSION_DIR}/runs.txt"
MERGE_DIR="${SESSION_DIR}/merged"
LOG_FILE="${SESSION_DIR}/watch.log"
mkdir -p "$SESSION_DIR"
touch "$RUNS_FILE" "$LOG_FILE"

if [ ! -f "$ATTACH_SCRIPT" ]; then
    log_error "attach.sh not found at: $ATTACH_SCRIPT"
    exit 1
fi

if [ ! -f "$GENERATOR_SCRIPT" ]; then
    log_error "generator.py not found at: $GENERATOR_SCRIPT"
    exit 1
fi

if [ "$DETACH" -eq 1 ] && [ -z "${WATCH_DETACHED:-}" ]; then
    log_info "Starting detached watcher..."
    nohup env WATCH_DETACHED=1 "$0" "$CONTAINER" "$RUNTIME" --retry-seconds "$RETRY_SECONDS" \
        > "$LOG_FILE" 2>&1 &
    PID="$!"
    echo ""
    log_ok "Detached watcher started"
    echo "  PID: $PID"
    echo "  Log: $LOG_FILE"
    echo "  Session: $SESSION_DIR"
    exit 0
fi

wait_for_container_running() {
    while true; do
        if docker inspect "$CONTAINER" &>/dev/null; then
            local running
            running="$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || echo false)"
            if [ "$running" = "true" ]; then
                return 0
            fi
        fi
        log_warn "Container '$CONTAINER' not running - retry in ${RETRY_SECONDS}s"
        sleep "$RETRY_SECONDS"
    done
}

resolve_image_name() {
    docker inspect -f '{{.Config.Image}}' "$CONTAINER" 2>/dev/null || echo "unknown:image"
}

refresh_merge() {
    mapfile -t report_dirs < "$RUNS_FILE"
    if [ ${#report_dirs[@]} -eq 0 ]; then
        return 0
    fi

    local image_name
    image_name="$(resolve_image_name)"

    python3 "$GENERATOR_SCRIPT" merge "$MERGE_DIR" "$image_name" "${report_dirs[@]}" >> "$LOG_FILE" 2>&1 || {
        log_warn "Merge refresh failed; will retry after next run"
        return 1
    }

    log_ok "Merged profile refreshed: $MERGE_DIR"
}

log_info "Watch session started"
log_info "Container: $CONTAINER"
log_info "Per-run trace window: ${RUNTIME}s"
log_info "Session dir: $SESSION_DIR"

while true; do
    wait_for_container_running

    log_info "Starting new trace run for '$CONTAINER'"
    run_output="$(bash "$ATTACH_SCRIPT" "$CONTAINER" "$RUNTIME" 2>&1 | tee -a "$LOG_FILE")" || {
        log_warn "attach.sh failed (container may have restarted); retrying"
        sleep "$RETRY_SECONDS"
        continue
    }

    report_dir="$(printf '%s\n' "$run_output" | sed -n 's/.*Report: \(.*\)$/\1/p' | tail -1)"
    if [ -z "$report_dir" ] || [ ! -d "$report_dir" ]; then
        log_warn "Could not detect report dir from attach output; retrying"
        sleep "$RETRY_SECONDS"
        continue
    fi

    if ! grep -Fxq "$report_dir" "$RUNS_FILE"; then
        echo "$report_dir" >> "$RUNS_FILE"
    fi

    refresh_merge || true
done
