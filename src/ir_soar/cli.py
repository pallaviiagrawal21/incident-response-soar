"""
ir-soar command-line interface.

Commands:
    ir-soar run <playbook_id> [options]        execute a playbook
    ir-soar list-playbooks                      list available playbooks
    ir-soar list-actions                        list registered actions
    ir-soar validate-playbook <playbook_id>     load + validate, show warnings
    ir-soar show-playbook <playbook_id>         print the human-readable Markdown

Every option here can also be set via config.yaml or an environment
variable — see docs/architecture.md for the full precedence order
(CLI args > env vars > config.yaml+overlay > built-in defaults). CLI
arguments always win.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import ir_soar.actions  # noqa: F401 - importing this triggers action registration
from ir_soar.actions.base import ACTION_REGISTRY
from ir_soar.config.loader import ConfigError, load_config
from ir_soar.config.schema import AppConfig
from ir_soar.engine.executor import Executor, RunResult
from ir_soar.engine.playbook_loader import (
    PlaybookLoadError,
    list_available_playbooks,
    load_playbook_by_id,
    load_playbook_markdown,
)
from ir_soar.utils.logging import AuditLogger, setup_logging
from ir_soar.utils.safety import SafetyError, enforce_full_auto_safety

app = typer.Typer(
    name="ir-soar",
    help="Lightweight Incident Response Playbook + SOAR-style automation framework.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)

DEFAULT_CONFIG_PATH = "config/config.yaml"
DEFAULT_PLAYBOOKS_DIR = "config/playbooks"
DEFAULT_MARKDOWN_DIR = "playbooks"

_STATUS_STYLE = {"success": "green", "failure": "red", "skipped": "yellow"}


def _build_config(
    config_path: str,
    env: Optional[str],
    mode: Optional[str],
    full_auto: bool,
    log_level: Optional[str],
    max_actions: Optional[int],
) -> AppConfig:
    cli_overrides: dict[str, Any] = {}
    if mode is not None:
        cli_overrides["mode"] = mode
    if full_auto:
        cli_overrides["full_auto"] = True
    if log_level is not None:
        cli_overrides["logging.level"] = log_level
    if max_actions is not None:
        cli_overrides["execution.max_actions_per_run"] = max_actions
    try:
        return load_config(config_path=config_path, env=env, cli_overrides=cli_overrides)
    except ConfigError as exc:
        err_console.print(Panel(str(exc), title="Configuration Error", style="bold red"))
        raise typer.Exit(code=2)


def _load_incident_context(incident_file: Optional[str], set_fields: list[str]) -> dict[str, Any]:
    context: dict[str, Any] = {}

    if incident_file:
        path = Path(incident_file)
        if not path.exists():
            err_console.print(f"[bold red]Incident file not found:[/bold red] {path}")
            raise typer.Exit(code=2)
        text = path.read_text(encoding="utf-8")
        try:
            loaded = yaml.safe_load(text) if path.suffix.lower() in (".yaml", ".yml") else json.loads(text)
        except (yaml.YAMLError, json.JSONDecodeError) as exc:
            err_console.print(f"[bold red]Failed to parse incident file {path}:[/bold red] {exc}")
            raise typer.Exit(code=2)
        if not isinstance(loaded, dict):
            err_console.print(f"[bold red]Incident file {path} must contain a mapping at the top level[/bold red]")
            raise typer.Exit(code=2)
        context.update(loaded)

    for item in set_fields:
        if "=" not in item:
            err_console.print(f"[bold red]--set value must be KEY=VALUE, got:[/bold red] {item}")
            raise typer.Exit(code=2)
        key, _, value = item.partition("=")
        context[key.strip()] = value.strip()

    return context


@app.command("run")
def run_playbook(
    playbook: str = typer.Option(..., "--playbook", "-p", help="Playbook id (matches config/playbooks/<id>.yaml)"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Force dry-run mode regardless of config/env (shortcut for --mode dry-run)"
    ),
    mode: Optional[str] = typer.Option(None, "--mode", help="dry-run | interactive | live (overrides config)"),
    env: Optional[str] = typer.Option(None, "--env", help="lab | home | production-like (selects the config overlay)"),
    config_path: str = typer.Option(DEFAULT_CONFIG_PATH, "--config", help="Path to base config.yaml"),
    incident_file: Optional[str] = typer.Option(None, "--incident-file", help="Path to a JSON/YAML incident context file"),
    set_fields: list[str] = typer.Option([], "--set", help="Override/add an incident field: KEY=VALUE (repeatable)"),
    full_auto: bool = typer.Option(
        False, "--full-auto", help="Skip interactive approval prompts (requires explicit acknowledgement)"
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Never prompt, even if attached to a TTY (containment steps needing approval will be denied, not hung)",
    ),
    log_level: Optional[str] = typer.Option(None, "--log-level", help="DEBUG | INFO | WARNING | ERROR"),
    max_actions: Optional[int] = typer.Option(None, "--max-actions", help="Override execution.max_actions_per_run"),
    report_file: Optional[str] = typer.Option(None, "--report-file", help="Write a JSON run summary to this path"),
    playbooks_dir: str = typer.Option(DEFAULT_PLAYBOOKS_DIR, "--playbooks-dir", help="Directory containing playbook YAML files"),
) -> None:
    """Execute a playbook against an incident context."""
    effective_mode = "dry-run" if dry_run else mode
    config = _build_config(config_path, env, effective_mode, full_auto, log_level, max_actions)
    logger = setup_logging(config)
    audit = AuditLogger(config.logging.audit_log_path)

    try:
        pb = load_playbook_by_id(playbook, playbooks_dir)
    except PlaybookLoadError as exc:
        err_console.print(Panel(str(exc), title="Playbook Load Error", style="bold red"))
        raise typer.Exit(code=2)

    for warning in pb.validate_step_references():
        console.print(f"[yellow]Warning:[/yellow] {warning}")

    incident_context = _load_incident_context(incident_file, set_fields)

    # Never prompt when stdin isn't actually an interactive terminal — a
    # scripted/CI invocation must never silently block waiting for input.
    interactive = (not non_interactive) and sys.stdin.isatty()

    try:
        enforce_full_auto_safety(config, interactive=interactive, console=err_console)
    except SafetyError as exc:
        err_console.print(Panel(str(exc), title="Full-Auto Safety Gate", style="bold red"))
        raise typer.Exit(code=3)

    console.print(
        Panel(
            f"Playbook: [bold]{pb.name}[/bold] ([cyan]{pb.id}[/cyan])\n"
            f"Mode: [bold]{config.mode}[/bold]  |  Environment: [bold]{config.environment}[/bold]  |  "
            f"Full-auto: [bold]{config.full_auto}[/bold]  |  Interactive: [bold]{interactive}[/bold]",
            title="ir-soar run",
        )
    )

    executor = Executor(config, audit, interactive=interactive, logger=logger)
    result = executor.run(pb, incident_context)

    _print_run_summary(result)

    if report_file:
        _write_report(result, report_file)
        console.print(f"Report written to [bold]{report_file}[/bold]")

    console.print(f"Audit trail: [bold]{audit.path}[/bold] (chain verifies: {audit.verify_chain()})")

    if result.aborted or result.failed_steps:
        raise typer.Exit(code=1)


def _print_run_summary(result: RunResult) -> None:
    table = Table(title=f"Run Summary: {result.playbook_id} (mode={result.mode})")
    table.add_column("Phase")
    table.add_column("Step")
    table.add_column("Ran")
    table.add_column("Status")
    table.add_column("Reason / Error")

    for outcome in result.outcomes:
        status = outcome.result.status if outcome.result else "-"
        style = _STATUS_STYLE.get(status, "white")
        reason = outcome.decision_reason
        if outcome.result and outcome.result.error:
            reason = outcome.result.error
        table.add_row(
            outcome.phase,
            outcome.step_id,
            "yes" if outcome.ran else "no",
            f"[{style}]{status}[/{style}]",
            reason,
        )
    console.print(table)

    if result.aborted:
        console.print(Panel(result.abort_reason or "Run aborted", title="RUN ABORTED", style="bold red"))
    else:
        console.print(
            f"[bold]Done.[/bold] succeeded={len(result.succeeded_steps)} "
            f"failed={len(result.failed_steps)} skipped={len(result.skipped_steps)}"
        )


def _write_report(result: RunResult, path: str) -> None:
    report = {
        "playbook_id": result.playbook_id,
        "mode": result.mode,
        "dry_run": result.dry_run,
        "aborted": result.aborted,
        "abort_reason": result.abort_reason,
        "outcomes": [
            {
                "step_id": o.step_id,
                "phase": o.phase,
                "action_type": o.action_type,
                "ran": o.ran,
                "decision_reason": o.decision_reason,
                "attempts": o.attempts,
                "result": o.result.model_dump() if o.result else None,
            }
            for o in result.outcomes
        ],
    }
    Path(path).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")


@app.command("list-playbooks")
def list_playbooks_cmd(
    playbooks_dir: str = typer.Option(DEFAULT_PLAYBOOKS_DIR, "--playbooks-dir"),
) -> None:
    """List available playbook ids."""
    ids = list_available_playbooks(playbooks_dir)
    if not ids:
        console.print("[yellow]No playbooks found.[/yellow]")
        raise typer.Exit(code=0)
    table = Table(title="Available Playbooks")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Steps")
    for pb_id in ids:
        pb = load_playbook_by_id(pb_id, playbooks_dir)
        table.add_row(pb.id, pb.name, pb.version, str(len(pb.all_steps())))
    console.print(table)


@app.command("list-actions")
def list_actions_cmd() -> None:
    """List every registered action (enrichment + containment)."""
    table = Table(title="Registered Actions")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Default Risk")
    table.add_column("Description")
    for name in sorted(ACTION_REGISTRY):
        cls = ACTION_REGISTRY[name]
        table.add_row(name, cls.category, cls.default_risk, cls.description)
    console.print(table)


@app.command("validate-playbook")
def validate_playbook_cmd(
    playbook: str = typer.Argument(..., help="Playbook id"),
    playbooks_dir: str = typer.Option(DEFAULT_PLAYBOOKS_DIR, "--playbooks-dir"),
) -> None:
    """Load and validate a playbook, reporting any consistency warnings."""
    try:
        pb = load_playbook_by_id(playbook, playbooks_dir)
    except PlaybookLoadError as exc:
        err_console.print(Panel(str(exc), title="Validation Failed", style="bold red"))
        raise typer.Exit(code=1)

    console.print(
        f"[green]OK[/green] — '{pb.id}' loaded and validated "
        f"({len(pb.all_steps())} steps across {len(pb.phases)} phases)"
    )

    unknown_actions = sorted({s.action_type for s in pb.all_steps() if s.action_type not in ACTION_REGISTRY})
    if unknown_actions:
        console.print(f"[red]Unknown action_type(s) referenced (not registered):[/red] {', '.join(unknown_actions)}")

    warnings = pb.validate_step_references()
    if warnings:
        for w in warnings:
            console.print(f"[yellow]Warning:[/yellow] {w}")
    else:
        console.print("[green]No condition-reference warnings.[/green]")

    if unknown_actions:
        raise typer.Exit(code=1)


@app.command("show-playbook")
def show_playbook_cmd(
    playbook: str = typer.Argument(..., help="Playbook id"),
    markdown_dir: str = typer.Option(DEFAULT_MARKDOWN_DIR, "--markdown-dir"),
) -> None:
    """Print the human-readable Markdown playbook to the terminal."""
    try:
        text = load_playbook_markdown(playbook, markdown_dir)
    except PlaybookLoadError as exc:
        err_console.print(Panel(str(exc), title="Not Found", style="bold red"))
        raise typer.Exit(code=1)
    console.print(text)


if __name__ == "__main__":
    app()
