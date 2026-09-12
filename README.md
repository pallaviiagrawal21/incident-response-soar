# Incident Response Playbook + Lightweight SOAR Automation Framework

A production-quality, portfolio-grade incident response automation framework: realistic, MITRE-mapped IR playbooks paired with a small, safety-first SOAR-style execution engine.

Built for two real scenarios — **phishing → credential harvesting → lateral movement** and **ransomware (initial access → encryption → lateral movement)** — on an engine that needs **zero code changes** to support a third.

---

## Why this exists

Most "SOAR demo" projects either hardcode a scenario into the engine, skip the human-approval story entirely, or fake dry-run mode. This project is built the other way around:

- **Playbooks are data, not code.** The engine (`src/ir_soar/engine/`) has no idea what phishing or ransomware are — it only knows how to load, validate, and execute a `Playbook` object. Both included playbooks prove this: same schema, same loader, same executor, zero engine changes between them.
- **Nothing dangerous happens by accident.** Dry-run by default, containment actions require human approval by default, full-auto requires an explicit, loudly-warned acknowledgement, every input is strictly validated, every action is timeout-bounded and retry-bounded, and the whole run is capped by a hard action ceiling — see [Safety Model](#safety-model).
- **Every decision is audited.** A hash-chained, append-only audit log records every decision (approved/denied/auto-approved) and every action attempt/result. Tampering with a historical line is detectable by replaying the chain.

---

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # or: pip install -e .

# See what's available
ir-soar list-playbooks
ir-soar list-actions

# Validate a playbook (schema + condition-reference checks)
ir-soar validate-playbook phishing_lateral_movement

# Dry-run it against a sample incident (no real side effects, ever)
cat > incident.json << 'EOF'
{
  "sender_domain": "phish-example.com",
  "malicious_link_domain": "creds-harvest.example.net",
  "affected_user": "jdoe",
  "affected_host": "ws-jdoe-01",
  "lateral_movement_host": "srv-file01"
}
EOF

ir-soar run --playbook phishing_lateral_movement --dry-run \
  --incident-file incident.json --non-interactive
```

Or with Docker — see [`docker/README.md`](docker/README.md):

```bash
docker compose -f docker/docker-compose.yml build
docker compose -f docker/docker-compose.yml run --rm ir-soar list-playbooks
```

---

## What's included

| Scenario | Machine-readable | Human-readable |
|---|---|---|
| Phishing → Credential Harvesting → Lateral Movement | [`config/playbooks/phishing_lateral_movement.yaml`](config/playbooks/phishing_lateral_movement.yaml) | [`playbooks/phishing_lateral_movement.md`](playbooks/phishing_lateral_movement.md) |
| Ransomware (Initial Access → Encryption → Lateral Movement) | [`config/playbooks/ransomware.yaml`](config/playbooks/ransomware.yaml) | [`playbooks/ransomware.md`](playbooks/ransomware.md) |

Each Markdown playbook covers Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned, roles/RACI, a Mermaid decision tree, a communication plan, evidence-handling guidance, a full MITRE ATT&CK mapping, and a step-id-matched **Automation Cross-Reference** table showing exactly what the engine automates vs. what stays manual.

**8 built-in actions**, each with strict input validation, dry-run support, and timeout/retry bounds:

| Enrichment (read-only) | Containment (state-changing, approval-gated by default) |
|---|---|
| `ip_domain_reputation` | `isolate_host` |
| `hash_reputation` | `disable_account` |
| `whois_dns` | `block_ip_domain` |
| `log_correlation` | `collect_forensics` |

---

## Architecture

```
CLI (cli.py)
   |
Config Layer (config.yaml + env vars + CLI args -> AppConfig)
   |
Playbook Loader (YAML -> validated Playbook model)
   |
Executor --> Decision Engine (condition + approval gate)
   |     --> Action Registry --> Connectors (simulated | real)
   |
Audit Trail (hash-chained JSONL)
```

Full detail, including the precedence rules for configuration and the exact execution sequence for a single step, is in [`docs/architecture.md`](docs/architecture.md).

---

## Safety Model

| Control | What it guarantees |
|---|---|
| Dry-run by default | `mode: dry-run` unless explicitly overridden; nothing has a real side effect |
| Human approval gate | Containment actions require interactive approval by default; **denied by default when non-interactive**, never silently executed or hung waiting on input |
| Full-auto acknowledgement | `--full-auto` prints a loud warning and requires typing an exact confirmation phrase (interactive) or `IR_SOAR_FULL_AUTO_ACK=true` (non-interactive) — verified live, both paths |
| Strict input validation | Every IP/domain/hash/hostname/username is validated before it reaches an action; shell-metacharacter check as defense-in-depth |
| Bounded everything | Hard `max_actions_per_run` ceiling, bounded retries with backoff, per-attempt timeout — no code path in the engine can loop or hang indefinitely |
| Hash-chained audit trail | Every decision and result is recorded; tampering with a historical line is detectable by replaying the chain |
| No secrets in code | Config only ever stores the *name* of an environment variable holding a credential, never the value |
| Fail-safe unimplemented connectors | Setting a real (not-yet-built) connector type raises `NotImplementedError` in live mode rather than silently faking success |

---

## Configuration

Layered, fully overridable, no hardcoded paths or hosts:

```
CLI arguments  >  environment variables  >  config.yaml + environment overlay  >  built-in defaults
```

```bash
ir-soar run --playbook ransomware --env production-like --mode live \
  --incident-file incident.json --log-level DEBUG
```

Three environment overlays ship out of the box — `lab` (verbose, permissive), `home` (interactive, tighter ceilings), `production-like` (strict — approval required even for enrichment, smallest action ceiling). See [`config/config.yaml`](config/config.yaml) and the `config/config.*.yaml` overlays.

---

## Extending

Adding a new playbook, action, or real connector integration requires **zero engine changes** — see [`docs/extending.md`](docs/extending.md) for a worked example of each.

---

## Project Structure

```
incident-response-soar/
├── config/                  # config.yaml + environment overlays + playbook YAML
├── playbooks/                # human-readable Markdown playbooks
├── src/ir_soar/
│   ├── cli.py                 # ir-soar command-line interface
│   ├── config/                 # AppConfig schema + layered loader
│   ├── engine/                 # playbook loader, decision engine, executor
│   ├── actions/                 # enrichment/ + containment/ + base.py (the extension point)
│   ├── connectors/               # simulated (default) + real-integration interfaces
│   ├── models/                    # Playbook, ActionResult, AuditEvent (Pydantic)
│   └── utils/                      # logging (incl. audit trail), validation, safety
├── docs/                     # architecture.md, extending.md, mitre_attack_mapping.md
├── tests/                    # pytest suite
└── docker/                   # Dockerfile + docker-compose.yml
```

---

## Status

All 12 planned build steps are complete: skeleton + config, logging/validation/safety, playbook loader, base action system, enrichment actions, containment actions, core execution engine, CLI, both full example playbooks, Docker support, this documentation, and the test suite.

Built as an actively-maintained portfolio project — see `docs/extending.md` for the intended path to real EDR/IAM/firewall/threat-intel integrations.

## License

MIT — see [`LICENSE`](LICENSE).
