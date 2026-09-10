"""
Base action class and the action registry — the primary extension point of
ir_soar.

To add a brand-new action:
    1. Subclass `BaseAction`.
    2. Implement `validate_inputs()` and `execute()`.
    3. Decorate the class with `@register_action("your_action_name")`.
    4. Nothing else changes — the executor resolves actions purely by the
       `action_type` string in a playbook step, via `get_action_class()`.

Design (template method pattern): every action is invoked through
`BaseAction.run()`, never through `execute()` directly. `run()` always:

    validate_inputs()  ->  dry-run short-circuit (no side effects)
                       ->  execute() with a single-attempt timeout
                       ->  wrapped in an ActionResult

`run()` never raises — every exception, at every stage, is caught and
turned into a `status="failure"` ActionResult. This is deliberate: one
broken or misbehaving action must never crash an entire incident response
run. Retry logic across multiple attempts (using `config.execution.
max_retries`) is intentionally NOT here — it belongs to the executor (a
later build step), which needs playbook-level and audit-log context that
individual actions shouldn't need to know about. This class only guarantees
that a single attempt cannot hang forever.
"""

from __future__ import annotations

import concurrent.futures
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Callable, ClassVar

from ir_soar.config.schema import AppConfig
from ir_soar.models.action_result import ActionResult
from ir_soar.utils.validation import ValidationError

#: name -> BaseAction subclass. Populated exclusively via @register_action.
ACTION_REGISTRY: dict[str, type["BaseAction"]] = {}


class ActionTimeoutError(RuntimeError):
    """Raised when a single execution attempt exceeds its configured timeout."""


def register_action(name: str) -> Callable[[type["BaseAction"]], type["BaseAction"]]:
    """Class decorator that registers an action class under `name`.

    Raises ValueError at import time (not at run time) if `name` is already
    registered — a duplicate action name is a programming error that
    should fail loudly and immediately, not surface as a confusing runtime
    resolution bug hours into a build.
    """

    def _decorator(cls: type["BaseAction"]) -> type["BaseAction"]:
        if name in ACTION_REGISTRY:
            raise ValueError(
                f"Action name '{name}' is already registered to "
                f"{ACTION_REGISTRY[name].__module__}.{ACTION_REGISTRY[name].__name__}"
            )
        cls.action_name = name
        ACTION_REGISTRY[name] = cls
        return cls

    return _decorator


def get_action_class(name: str) -> type["BaseAction"]:
    """Resolve an `action_type` string (from a playbook step) to its class.

    Raises:
        KeyError: if no action is registered under `name`, listing every
            action name that IS available so the error is actionable.
    """
    try:
        return ACTION_REGISTRY[name]
    except KeyError as exc:
        available = ", ".join(sorted(ACTION_REGISTRY)) or "(none registered — did you import the actions package?)"
        raise KeyError(f"Unknown action_type '{name}'. Registered actions: {available}") from exc


def _run_with_timeout(fn: Callable[..., dict[str, Any]], *args: Any, timeout_seconds: float, **kwargs: Any) -> dict[str, Any]:
    """Run `fn` in a worker thread, bounded by `timeout_seconds`.

    Deliberately does NOT use the executor as a context manager: `with
    ThreadPoolExecutor() as executor:` blocks on `__exit__` until the
    worker thread finishes, which would silently defeat the timeout (the
    caller would still be blocked for the full runaway duration even
    though `future.result(timeout=...)` raised promptly). Calling
    `executor.shutdown(wait=False)` instead lets this function — and
    therefore `BaseAction.run()` — return to the caller within
    `timeout_seconds`, full stop.

    Python threads cannot be forcibly killed, so a genuinely hung
    `execute()` implementation continues running in the background,
    detached, after this raises ActionTimeoutError. That's an accepted
    trade-off: the safety property this project actually requires is "no
    step can block the run past its timeout," not "no thread anywhere may
    ever keep running." Real connectors that make network calls should
    additionally set their own request-level timeout as defense in depth.
    """
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(fn, *args, **kwargs)
    try:
        return future.result(timeout=timeout_seconds)
    except concurrent.futures.TimeoutError as exc:
        raise ActionTimeoutError(f"Action exceeded timeout of {timeout_seconds}s") from exc
    finally:
        executor.shutdown(wait=False)


class BaseAction(ABC):
    """Template-method base class for every enrichment/containment action."""

    #: set automatically by @register_action — do not set manually
    action_name: ClassVar[str] = ""

    #: short human description shown by `ir-soar list-actions`
    description: ClassVar[str] = ""

    #: informational default only — the AUTHORITATIVE risk for a given run
    #: always comes from the playbook Step, never from this class attribute
    default_risk: ClassVar[str] = "low"

    #: "enrichment" (read-only, no side effects) or "containment"
    #: (state-changing). Used by the decision engine to apply
    #: config.approval.require_for_containment / require_for_enrichment.
    category: ClassVar[str] = "enrichment"

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger(
            f"ir_soar.actions.{self.action_name or self.__class__.__name__}"
        )

    # -- subclasses implement these two -------------------------------------

    @abstractmethod
    def validate_inputs(self, inputs: dict[str, Any]) -> dict[str, Any]:
        """Validate and normalize `inputs`.

        Raise `ir_soar.utils.validation.ValidationError` (or a subclass) on
        anything invalid. Return the normalized inputs dict (e.g. IPs
        lowercased/stripped, whitespace trimmed) for use by `execute()` /
        `dry_run_preview()`.
        """
        raise NotImplementedError

    @abstractmethod
    def execute(self, inputs: dict[str, Any], config: AppConfig) -> dict[str, Any]:
        """Perform the real action. Only ever called when NOT in dry-run mode.

        Must return a plain, JSON-serializable dict of result data. Should
        raise on failure rather than returning an ambiguous "maybe it
        worked" result — `run()` turns any exception into a clean
        `status="failure"` ActionResult.
        """
        raise NotImplementedError

    # -- subclasses may override this ---------------------------------------

    def dry_run_preview(self, inputs: dict[str, Any]) -> dict[str, Any]:
        """Describe what WOULD happen, with no side effects. Default is generic;
        override for a more informative preview (e.g. containment actions
        should say exactly what would be isolated/disabled/blocked)."""
        return {"would_execute": self.action_name, "with_inputs": inputs}

    # -- the only method callers should invoke -------------------------------

    def run(
        self,
        inputs: dict[str, Any],
        config: AppConfig,
        *,
        dry_run: bool,
        timeout_seconds: float | None = None,
    ) -> ActionResult:
        """Validate -> (dry-run short-circuit) -> execute (single attempt,
        timeout-bounded) -> ActionResult. Never raises."""
        start = time.monotonic()

        try:
            normalized_inputs = self.validate_inputs(inputs)
        except ValidationError as exc:
            return self._failure(f"Validation failed: {exc}", start, dry_run)
        except Exception as exc:  # noqa: BLE001 - a broken validator must not crash the run
            self._logger.exception("Unexpected error validating inputs for action '%s'", self.action_name)
            return self._failure(f"Unexpected validation error: {exc}", start, dry_run)

        if dry_run:
            try:
                preview = self.dry_run_preview(normalized_inputs)
            except Exception as exc:  # noqa: BLE001
                self._logger.exception("Unexpected error building dry-run preview for '%s'", self.action_name)
                return self._failure(f"Dry-run preview error: {exc}", start, dry_run=True)
            self._logger.info(
                "[DRY-RUN] would execute action '%s'",
                self.action_name,
                extra={"extra_fields": {"action": self.action_name, "inputs": normalized_inputs, "dry_run": True}},
            )
            return ActionResult(status="success", data=preview, duration_ms=self._elapsed_ms(start), dry_run=True)

        effective_timeout = timeout_seconds or config.execution.default_timeout_seconds
        try:
            data = _run_with_timeout(self.execute, normalized_inputs, config, timeout_seconds=effective_timeout)
            self._logger.info(
                "Action '%s' completed successfully",
                self.action_name,
                extra={"extra_fields": {"action": self.action_name, "dry_run": False}},
            )
            return ActionResult(status="success", data=data, duration_ms=self._elapsed_ms(start), dry_run=False)
        except ActionTimeoutError as exc:
            self._logger.error("Action '%s' timed out: %s", self.action_name, exc)
            return self._failure(str(exc), start, dry_run=False)
        except Exception as exc:  # noqa: BLE001 - never let one action crash the whole run
            self._logger.exception("Action '%s' failed during execution", self.action_name)
            return self._failure(str(exc), start, dry_run=False)

    def _failure(self, message: str, start: float, dry_run: bool) -> ActionResult:
        return ActionResult(status="failure", error=message, duration_ms=self._elapsed_ms(start), dry_run=dry_run)

    @staticmethod
    def _elapsed_ms(start: float) -> float:
        return round((time.monotonic() - start) * 1000, 2)
