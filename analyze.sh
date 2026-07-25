#!/usr/bin/env bash
# =================================================================
# Docker Security Profile Analyzer
# Usage: ./analyze.sh <image> <runtime_seconds> [-- docker_args...]
# Example: ./analyze.sh nginx:latest 60
#          ./analyze.sh myapp:1.0 120 -- -e APP_ENV=prod
# Requires: root (eBPF needs kernel privileges)
# =================================================================
set -euo pipefail

# ---- Argument parsing ----
IMAGE="${1:?'Error: Image required. Usage: ./analyze.sh <image> <runtime>'}"
RUNTIME_RAW="${2:?'Error: Runtime required (e.g. 60, 60s, 5m, 1h).'}"
shift 2
DOCKER_ARGS=()
if [[ "${1:-}" == "--" ]]; then shift; DOCKER_ARGS=("$@"); fi

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
IMAGE_SLUG=$(echo "$IMAGE" | tr '/.:' '_')
REPORT_DIR="${SCRIPT_DIR}/reports/${IMAGE_SLUG}_${TIMESTAMP}"

# ---- Colors ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()  { echo -e "${BLUE}[*]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[-]${NC} $*" >&2; }

CONTAINER_ID=""
TRACER_PID=""
ROOT_PID=""

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
    if [ -n "$CONTAINER_ID" ]; then
        docker stop "$CONTAINER_ID" >/dev/null 2>&1 || true
        docker rm   "$CONTAINER_ID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# ================================================================
# 1. DEPENDENCIES
# ================================================================
install_deps() {
    log_info "Checking dependencies..."

    command -v docker &>/dev/null || { log_error "Docker not found."; exit 1; }

    local pkgs=()
    command -v bpftrace  &>/dev/null || pkgs+=("bpftrace")
    command -v python3   &>/dev/null || pkgs+=("python3")
    command -v capsh     &>/dev/null || pkgs+=("libcap2-bin")

    if [ ${#pkgs[@]} -gt 0 ]; then
        log_info "Installing: ${pkgs[*]}"
        if   command -v apt-get &>/dev/null; then apt-get update -qq && apt-get install -y -qq "${pkgs[@]}"
        elif command -v dnf     &>/dev/null; then dnf install -y -q "${pkgs[@]}"
        elif command -v yum     &>/dev/null; then yum install -y -q "${pkgs[@]}"
        else log_error "No supported package manager found. Install manually: ${pkgs[*]}"; exit 1; fi
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

    # Verify bpftrace can access syscall tracepoints
    if ! bpftrace -l 'tracepoint:syscalls:sys_enter_read' &>/dev/null; then
        log_error "bpftrace cannot access syscall tracepoints. Check kernel config (CONFIG_FTRACE_SYSCALLS)."
        exit 1
    fi

    log_ok "All dependencies OK"
}

# ================================================================
# 2. CONTAINER START
# ================================================================
start_container() {
    log_info "Pulling $IMAGE..."
    docker pull "$IMAGE" -q

    log_info "Starting analysis container (seccomp=unconfined, cap=ALL)..."
    CONTAINER_ID=$(docker run -d \
        --security-opt seccomp=unconfined \
        --cap-add ALL \
        --name "sec-analyze-$$" \
        "${DOCKER_ARGS[@]+"${DOCKER_ARGS[@]}"}" \
        "$IMAGE")

    log_ok "Container: ${CONTAINER_ID:0:12}"

    if ! docker ps -q --no-trunc 2>/dev/null | grep -q "^${CONTAINER_ID}$"; then
        log_error "Container exited immediately. Logs:"
        docker logs "$CONTAINER_ID" 2>&1 | tail -20
        exit 1
    fi

    ROOT_PID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER_ID")
    log_ok "Container root PID on host: $ROOT_PID"
}

# ================================================================
# 3. eBPF TRACER — tracks PID subtree + syscalls + capability checks
# ================================================================
start_tracer() {
    local raw_file="${REPORT_DIR}/trace-raw.txt"
    mkdir -p "$REPORT_DIR"

    log_info "eBPF filter: PID subtree of container root PID ($ROOT_PID)"

    # Strategy:
    #  - BEGIN: seed tracked PIDs with the full current descendant tree
    #  - sched_process_fork: propagate tracking to every child process
    #  - sched_process_exit: clean up (optional but keeps map small)
    #  - sys_enter_*: count syscalls for tracked PIDs
    #  - cap_capable: count capability checks for tracked PIDs (arg2 = cap num)
    local seed_pids
    seed_pids=$(collect_descendant_pids "$ROOT_PID")
    seed_pids="${seed_pids:-$ROOT_PID}"

    local begin_block="BEGIN {"
    local pid
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
    log_ok "eBPF tracer started (PID: $TRACER_PID, seeded with $(echo "$seed_pids" | wc -w) PIDs)"
}

# ================================================================
# 4. CAPABILITIES SNAPSHOT (fallback / reference)
# ================================================================
collect_capabilities() {
    # Note: This only records the *granted* CapEff (max privilege the process
    # has). The actually *used* capabilities are captured via eBPF cap_capable.
    local cap_file="${REPORT_DIR}/capabilities-granted-raw.txt"
    mkdir -p "$REPORT_DIR"
    : > "$cap_file"
    grep "^Cap" /proc/"$ROOT_PID"/status >> "$cap_file" 2>/dev/null || true
    log_ok "Recorded granted capabilities snapshot"
}

# ================================================================
# MAIN
# ================================================================
echo ""
echo "============================================"
echo "   Docker Security Profile Analyzer"
echo "============================================"
echo ""

install_deps
start_container

collect_capabilities
start_tracer

log_info "Tracing ${RUNTIME}s — trigger container workload now..."
echo ""

for ((i=1; i<=RUNTIME; i++)); do
    printf "\r  Progress: %d/%ds" "$i" "$RUNTIME"
    sleep 1
    docker ps -q --no-trunc 2>/dev/null | grep -q "^${CONTAINER_ID}$" || \
        { echo ""; log_warn "Container exited early"; break; }
done
echo ""
echo ""

wait "$TRACER_PID" 2>/dev/null || true
TRACER_PID=""

# Sanity check
RAW_LINES=$(grep -cE "@syscall_id|@cap_used" "${REPORT_DIR}/trace-raw.txt" 2>/dev/null | head -1)
RAW_LINES="${RAW_LINES:-0}"
if [ "$RAW_LINES" -eq 0 ]; then
    log_warn "No trace data captured! Raw output:"
    cat "${REPORT_DIR}/trace-raw.txt"
fi

log_info "Stopping container..."
docker stop "$CONTAINER_ID" >/dev/null
docker rm   "$CONTAINER_ID" >/dev/null
CONTAINER_ID=""

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
