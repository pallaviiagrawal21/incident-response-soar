# Architecture

## Design philosophy

The engine (`src/ir_soar/engine/`) is a **generic playbook interpreter**. It contains zero knowledge of phishing, ransomware, or any other scenario — all of that lives in data (`config/playbooks/*.yaml`). This is deliberate and verified: both included playbooks run through the exact same `PlaybookLoader`, `Executor`, and `Decision` code with no branching on playbook identity anywhere in the engine.

## Layers

```
CLI (cli.py)
   parses args -> builds AppConfig -> invokes Executor
        |
Config Layer (config/loader.py)
   config.yaml + env overlay + env vars + CLI args -> AppConfig
        |
Playbook Loader (engine/playbook_loader.py)
   loads YAML -> validates schema -> returns a Playbook model
        |
Executor (engine/executor.py)
   for each phase, for each step:
     resolve action_type -> Action class (actions/base.py registry)
     evaluate condition + approval (engine/decision.py)
     render {{ incident.* }} inputs (engine/templating.py)
     consume RunGuard slot (utils/safety.py)
     run action with bounded retries + per-attempt timeout
     record every decision + result to the audit trail
        |
        +--> Decision Engine (engine/decision.py)
        |      condition evaluator: no eval(), regex-based, safe by design
        |
        +--> Action Registry (actions/base.py)
               enrichment/*  and  containment/*
                    |
                    +--> Connectors (connectors/)
                           simulated (default) or a real integration

Cross-cutting: utils/logging.py (app log + hash-chained audit trail),
               utils/validation.py (strict input validators),
               utils/safety.py (RunGuard, full-auto gate, approval prompt)
```

## Configuration precedence

```
CLI arguments  >  environment variables  >  config.yaml + environment overlay  >  built-in AppConfig defaults
```

Implemented in `config/loader.py::load_config()`:

1. Start from `AppConfig()` built-in defaults.
2. Deep-merge `config.yaml`.
3. Deep-merge the environment overlay (`config.<environment>.yaml`), where `<environment>` comes from `--env`, then `IR_SOAR_ENV`, then the base file's own `environment:` key.
4. Resolve every `${VAR:-default}` placeholder against the real process environment.
5. Apply the narrow, explicit set of named environment variable overrides (`IR_SOAR_MODE`, `IR_SOAR_LOG_LEVEL`, etc. — see `_ENV_VAR_OVERRIDES` in `loader.py`).
6. Apply CLI overrides (dotted keys, e.g. `{"logging.level": "DEBUG"}`).
7. Validate the fully merged dict against `AppConfig` (Pydantic, `extra="forbid"`) — any typo or invalid value fails loudly here, before any playbook runs.

## Execution sequence for a single step

1. Resolve `step.action_type` to an `Action` class via `get_action_class()`. Unknown action type -> immediate `failure` outcome, not a crash.
2. `warn_if_dangerous()` logs a WARNING if the step's risk meets `config.safety.dangerous_action_risk_floor`.
3. `decide()` evaluates:
   - `step.condition` (if any) against prior step results — `steps.<id>.result.<field>` — regex-parsed, no `eval()`.
   - Whether approval is required: `step.requires_approval OR config.approval.require_for_<category>`, reduced by `config.approval.auto_approve_risk_below`.
   - If approval is required: `--full-auto` (with its own acknowledgement gate) bypasses the prompt; otherwise prompts interactively; **denies by default if not running in an interactive terminal.**
4. If approved: `RunGuard.consume()` — raises if `max_actions_per_run` is exceeded, which aborts the whole run immediately (not just the current step).
5. `render_inputs()` resolves `{{ incident.* }}` placeholders via Jinja2 with `StrictUndefined` — an undefined incident field fails the step cleanly rather than silently rendering empty.
6. The action runs via `BaseAction.run()`: `validate_inputs()` -> (dry-run short-circuit, no side effects) -> `execute()` inside a single-attempt, thread-based timeout.
7. On failure (live mode only), the executor retries up to `1 + max(step.retries, config.execution.max_retries)` attempts total, sleeping `retry_backoff_seconds` between attempts.
8. Every decision and every attempt's result is written to the hash-chained audit trail (`utils/logging.py::AuditLogger`).
9. `step.on_success` / `step.on_failure` (`continue` / `continue_with_warning` / `abort_run`) determines whether the run continues, warns, or aborts.

## Why dry-run and condition branching interact the way they do

In dry-run mode, an action's `execute()` is **never called** — only `dry_run_preview()` is, which returns a generic "would execute X" description, not real computed data. Since `condition` guards read `steps.<id>.result.<field>`, and dry-run's preview data doesn't contain fields like `suspicious`, condition-gated downstream steps always evaluate to "skip" during a pure dry-run. This is correct dry-run semantics — a true dry-run has no real data to branch on — but it does mean dry-run cannot preview which containment branch a live run would actually take. A `--mode interactive` run against simulated (not dry-run) connectors is the way to preview real branching behavior without touching real infrastructure.

## Why there's no `eval()` anywhere

`condition` strings in playbook YAML are treated as semi-trusted configuration, not code, on principle — even though in this project's threat model the playbook author and the operator are typically the same person. `engine/decision.py::evaluate_condition()` is a small regex-based parser supporting exactly the grammar the two example playbooks need: `steps.<id>.result.<field>` optionally compared with `==`/`!=` against a literal. Extending the grammar (e.g. `and`/`or`) would mean extending this parser, not introducing `eval()`.

## Extension points

See [`extending.md`](extending.md) for worked examples. In summary:

| To add | Touch | Don't touch |
|---|---|---|
| A new playbook | `config/playbooks/*.yaml` + `playbooks/*.md` | engine, actions, connectors |
| A new action | One file in `actions/enrichment/` or `actions/containment/`, `@register_action` | engine, executor, CLI |
| A new real connector | `connectors/base_connector.py` interface implementation + one `elif` in `connectors/__init__.py` resolver | actions, engine |
