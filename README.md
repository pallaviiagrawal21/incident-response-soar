# Incident Response Playbook + Lightweight SOAR Automation Framework

> **Status: under active build.** This README is a placeholder for Phase 2,
> Step 1 (project skeleton + configuration system). The full professional
> README, with architecture diagrams, quickstart, and usage examples, is
> delivered in build Step 11.

## What's here so far

- `pyproject.toml` / `requirements.txt` — dependencies and packaging
- `.env.example` — every environment variable the system supports
- `config/` — layered YAML configuration (base + environment overlays)
- `src/ir_soar/config/` — the configuration schema (Pydantic) and loader
  (merges defaults → `config.yaml` → environment overlay → env vars → CLI args)

## Quick check (configuration system only, for now)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -c "from ir_soar.config.loader import load_config; c = load_config(); print(c.model_dump_json(indent=2))"
```

More to come as each build step lands.
