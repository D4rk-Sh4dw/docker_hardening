#!/usr/bin/env bash
# =================================================================
# Docker Security Profile Analyzer - ATTACH MODE
# Attaches to an already-running container (e.g. from docker-compose)
# and traces its actual production workload.
#
# Usage: ./attach.sh <container_name_or_id> <runtime_seconds>
# Example: ./attach.sh myapp-web-1 300
#          ./attach.sh $(docker compose ps -q web) 120
# Requires: root (eBPF needs kernel privileges)
# =================================================================
set -euo pipefail

CONTAINER="${1:?'Error: Container name/ID required. Usage: ./attach.sh <container> <runtime>'}"
RUNTIME_RAW="${2:?'Error: Runtime required (e.g. 60, 60s, 5m, 1h).'}"

# Normalize runtime: accept plain seconds or Ns / Nm / Nh suffix
case "$RUNTIME_RAW" in
    *h) RUNTIME=$(( ${RUNTIME_RAW%h} * 3600 )) ;;
    *m) RUNTIME=$(( ${RUNTIME_RAW%m} * 60 )) ;;
    *s) RUNTIME="${RUNTIME_RAW%s}" ;;
    *)  RUNTIME="$RUNTIME_RAW" ;;
esac
if ! [[ "$RUNTIME" =~ ^[0-9]+$ ]] || [ "$RUNTIME" -lt 1 ]; then
    echo "Error: Invalid runtime '$RUNTIME_RAW'. Use e.g. 60, 60s, 5m, 1h."
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: Run as root (required for eBPF tracing)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ---- Colors ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()  { echo -e "${BLUE}[*]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[-]${NC} $*" >&2; }

TRACER_PID=""

collect_descendant_pids() {
    local root_pid="$1"
    local -a queue=("$root_pid")
    local -a out=()
    local pid child
    declare -A seen=()

    while [ ${#queue[@]} -gt 0 ]; do
        pid="${queue[0]}"
        queue=("${queue[@]:1}")

        [ -n "${seen[$pid]:-}" ] && continue
        seen[$pid]=1
        out+=("$pid")

        while IFS= read -r child; do
            [ -n "$child" ] && queue+=("$child")
        done < <(pgrep -P "$pid" 2>/dev/null || true)
    done

    echo "${out[*]}"
}

cleanup() {
    [ -n "$TRACER_PID" ] && kill "$TRACER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# ================================================================
# 1. DEPENDENCIES (idempotent)
# ================================================================
install_deps() {
    log_info "Checking dependencies..."
    command -v docker &>/dev/null || { log_error "Docker not found."; exit 1; }

    local pkgs=()
    command -v bpftrace &>/dev/null || pkgs+=("bpftrace")
    command -v python3  &>/dev/null || pkgs+=("python3")

    if [ ${#pkgs[@]} -gt 0 ]; then
        log_info "Installing: ${pkgs[*]}"
        if   command -v apt-get &>/dev/null; then apt-get update -qq && apt-get install -y -qq "${pkgs[@]}"
        elif command -v dnf     &>/dev/null; then dnf install -y -q "${pkgs[@]}"
        elif command -v yum     &>/dev/null; then yum install -y -q "${pkgs[@]}"
        else log_error "No supported package manager found."; exit 1; fi
    fi

    # Best-effort: improves syscall ID -> name mapping in generator.py.
    if ! command -v ausyscall &>/dev/null; then
        log_warn "ausyscall not found, trying to install audit tooling"
        if   command -v apt-get &>/dev/null; then apt-get install -y -qq auditd || true
        elif command -v dnf     &>/dev/null; then dnf install -y -q audit || true
        elif command -v yum     &>/dev/null; then yum install -y -q audit || true
        fi
    fi
    command -v ausyscall &>/dev/null || log_warn "ausyscall still missing - unknown syscall IDs may remain"

    if ! bpftrace -l 'tracepoint:syscalls:sys_enter_read' &>/dev/null; then
        log_error "bpftrace cannot access syscall tracepoints."
        exit 1
    fi
    log_ok "Dependencies OK"
}

# ================================================================
# 2. DISCOVER CONTAINER
# ================================================================
discover_container() {
    if ! docker inspect "$CONTAINER" &>/dev/null; then
        log_error "Container '$CONTAINER' not found."
        log_info "Running containers:"
        docker ps --format 'table {{.ID}}\t{{.Names}}\t{{.Image}}'
        exit 1
    fi

    local state
    state=$(docker inspect -f '{{.State.Status}}' "$CONTAINER")
    if [ "$state" != "running" ]; then
        log_error "Container is '$state', not 'running'. Start it first."
        exit 1
    fi

    ROOT_PID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")
    IMAGE=$(docker inspect -f '{{.Config.Image}}' "$CONTAINER")
    CONTAINER_NAME=$(docker inspect -f '{{.Name}}' "$CONTAINER" | sed 's|^/||')

    if [ "$ROOT_PID" -eq 0 ]; then
        log_error "Container root PID is 0 (not really running?)"
        exit 1
    fi

    log_ok "Container: $CONTAINER_NAME"
    log_ok "Image:     $IMAGE"
    log_ok "Root PID:  $ROOT_PID"
}

# ================================================================
# 3. CAPABILITIES SNAPSHOT
# ================================================================
collect_capabilities() {
    local cap_file="${REPORT_DIR}/capabilities-granted-raw.txt"
    mkdir -p "$REPORT_DIR"
    : > "$cap_file"
    grep "^Cap" /proc/"$ROOT_PID"/status >> "$cap_file" 2>/dev/null || true
    log_ok "Granted capabilities snapshot recorded"
}

# ================================================================
# 4. eBPF TRACER
# ================================================================
start_tracer() {
    local raw_file="${REPORT_DIR}/trace-raw.txt"
    mkdir -p "$REPORT_DIR"

    log_info "eBPF filter: PID subtree of $ROOT_PID (all container procs + future forks)"

    # Seed with the full current descendant tree, not only direct children.
    # This closes gaps for already-running worker processes.
    local seed_pids
    seed_pids=$(collect_descendant_pids "$ROOT_PID")
    seed_pids="${seed_pids:-$ROOT_PID}"

    # Build BPF BEGIN block with all seed PIDs
    local begin_block="BEGIN {"
    for pid in $seed_pids; do
        begin_block+=" @tracked[${pid}] = 1;"
    done
    begin_block+=" }"

    local bpf_script
    bpf_script=$(cat <<BPF
${begin_block}
tracepoint:sched:sched_process_fork
/@tracked[args->parent_pid]/
{
  @tracked[args->child_pid] = 1;
}
tracepoint:sched:sched_process_exit
/@tracked[pid]/
{
  delete(@tracked[pid]);
}
tracepoint:raw_syscalls:sys_enter
/@tracked[pid]/
{
  @syscall_id[args->id] = count();
}
kprobe:cap_capable
/@tracked[pid]/
{
  @cap_used[arg2] = count();
}
interval:s:${RUNTIME}
{
  print(@syscall_id);
  print(@cap_used);
  clear(@tracked);
  exit();
}
BPF
)

    bpftrace -e "$bpf_script" > "$raw_file" 2>&1 &
    TRACER_PID=$!
    log_ok "eBPF tracer started (PID: $TRACER_PID, seeded with $(echo $seed_pids | wc -w) PIDs)"
}

# ================================================================
# MAIN
# ================================================================
echo ""
echo "============================================"
echo "   Docker Security Analyzer - ATTACH mode"
echo "============================================"
echo ""

install_deps
discover_container

# Now that we know the container name, set up the report dir
IMAGE_SLUG=$(echo "$IMAGE" | tr '/.:' '_')
REPORT_DIR="${SCRIPT_DIR}/reports/attach_${CONTAINER_NAME}_${IMAGE_SLUG}_${TIMESTAMP}"

collect_capabilities
start_tracer

log_info "Tracing ${RUNTIME}s - use the app normally to generate real workload..."
echo ""

for ((i=1; i<=RUNTIME; i++)); do
    printf "\r  Progress: %d/%ds" "$i" "$RUNTIME"
    sleep 1
    # Bail if container disappeared
    if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
        echo ""
        log_warn "Container stopped during trace"
        break
    fi
done
echo ""; echo ""

wait "$TRACER_PID" 2>/dev/null || true
TRACER_PID=""

RAW_LINES=$(grep -cE "@syscall_id|@cap_used" "${REPORT_DIR}/trace-raw.txt" 2>/dev/null | head -1)
RAW_LINES="${RAW_LINES:-0}"
if [ "$RAW_LINES" -eq 0 ]; then
    log_warn "No trace data captured! Raw output:"
    cat "${REPORT_DIR}/trace-raw.txt"
fi

log_info "Generating security profiles..."
python3 "${SCRIPT_DIR}/generator.py" "$REPORT_DIR" "$IMAGE" "$RUNTIME"

echo ""
echo "============================================"
echo "   Analysis Complete!"
echo "============================================"
echo ""
log_ok "Report: $REPORT_DIR"
echo "  |-- seccomp.json"
echo "  |-- docker-compose-snippet.yml"
echo "  |-- report.md"
echo "  |-- trace-raw.txt"
echo "  \`-- capabilities-granted-raw.txt"
echo ""
log_info "Container '$CONTAINER_NAME' continues running - no changes were made to it."
