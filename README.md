# Docker Hardening Analyzer

Automatically detects the **syscalls** and **Linux capabilities** a container actually needs, then generates a hardened seccomp profile and a docker-compose security snippet.

## What it does

1. Installs dependencies (`bpftrace`, `python3`, `libcap2-bin`)
2. Starts your target image with `seccomp=unconfined` + `cap_add=ALL` (maximum permissions)
3. Attaches an **eBPF tracer** that records every syscall the container makes
4. Reads effective capabilities from `/proc/<PID>/status`
5. After the configured runtime, generates:
   - `seccomp.json` — OCI seccomp allowlist profile
   - `docker-compose-snippet.yml` — drop-in security config
   - `report.md` — human-readable summary
   - `syscalls-raw.txt` / `capabilities-raw.txt` — raw data

## Requirements

| Component | Minimum |
|---|---|
| Linux kernel | 5.4+ (5.8+ recommended for BTF) |
| Docker | 20.10+ |
| Root privileges | required (eBPF) |
| `CONFIG_FTRACE_SYSCALLS` | must be enabled in kernel |

## Usage

```bash
chmod +x analyze.sh

# Basic
sudo ./analyze.sh nginx:latest 60

# With extra docker args (ports, env vars, etc.)
sudo ./analyze.sh myapp:1.0 120 -- -p 8080:80 -e APP_ENV=prod

# Longer trace for production-like coverage
sudo ./analyze.sh postgres:16 300 -- -e POSTGRES_PASSWORD=test
```

Arguments:
- `<image>` — Docker image to analyze
- `<runtime_seconds>` — how long to trace
- `-- <docker_args>` — optional passthrough args for `docker run`

## Output

Reports land in `reports/<image>_<timestamp>/`:

```
reports/nginx_latest_20260724_143000/
├── seccomp.json
├── docker-compose-snippet.yml
├── report.md
├── syscalls-raw.txt
└── capabilities-raw.txt
```

## Applying the results

```yaml
services:
  myapp:
    image: myapp:1.0
    security_opt:
      - no-new-privileges:true
      - seccomp:./seccomp.json
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE   # only what the report shows as non-default
```

## Tips for accurate profiles

- **Exercise the app** during tracing (HTTP requests, DB writes, background jobs)
- **Trace longer** for apps with lazy/on-demand code paths
- **Trace multiple scenarios** and merge the resulting syscall lists
- **Re-run after updates** — new library versions may need new syscalls

## Notes

- Runs only on Linux (native or VM). WSL2 eBPF support is limited.
- Uses the maximum observed `CapEff` from all container processes.
- Docker's default cap set is filtered out — you only see caps that require explicit `cap_add`.
