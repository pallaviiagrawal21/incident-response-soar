# Running ir-soar in Docker

## Build

From the repository root:

```bash
docker compose -f docker/docker-compose.yml build
```

(equivalently: `docker build -f docker/Dockerfile -t ir-soar:latest .`)

## First-time setup

```bash
cp .env.example .env   # only needed if you have real connector credentials to set;
                        # safe to skip entirely for lab/home dry-run/simulated use
```

## Run

`ir-soar` is a one-shot CLI tool, not a long-running service — use
`run --rm`, not `up`:

```bash
# List available playbooks
docker compose -f docker/docker-compose.yml run --rm ir-soar list-playbooks

# List registered actions
docker compose -f docker/docker-compose.yml run --rm ir-soar list-actions

# Dry-run a playbook (no incident file needed to just see it load)
docker compose -f docker/docker-compose.yml run --rm ir-soar \
  validate-playbook phishing_lateral_movement

# A real dry-run against an incident, mounting a local incident file in
docker compose -f docker/docker-compose.yml run --rm \
  -v "$(pwd)/incident.json:/app/incident.json:ro" \
  ir-soar run --playbook phishing_lateral_movement --dry-run \
  --incident-file /app/incident.json --non-interactive
```

## What's mounted vs. baked in

| Path | Source | Why |
|---|---|---|
| `/app/config` | host `config/`, read-only | edit config/playbook YAML without rebuilding |
| `/app/playbooks` | host `playbooks/`, read-only | edit Markdown playbooks without rebuilding |
| `/app/logs` | named volume `ir-soar-logs` | persists the audit trail across container runs |
| `/app/evidence` | named volume `ir-soar-evidence` | persists collected forensic artifacts |

## Notes

- The container runs as a **non-root user** (`irsoar`, uid 1000) — this is
  enforced in the image itself, independent of how you invoke it.
- The image ships with `mode: dry-run` as the effective default
  (`IR_SOAR_MODE` environment variable in `docker-compose.yml`) —
  override with `-e IR_SOAR_MODE=live` (and everything else `run --help`
  documents) only once you're intentionally ready to.
- Requires Docker Compose v2.24+ for the `env_file: [{path, required}]`
  syntax used in `docker-compose.yml`. If your Compose is older, either
  upgrade or simplify that block to a plain `env_file: [../.env]` and
  make sure `.env` exists first (`cp .env.example .env`).
