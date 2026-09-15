"""Tests for the core executor (engine/executor.py), using synthetic
test-only actions registered in conftest.py so these tests don't depend on
timing-sensitive real connector behavior."""

from __future__ import annotations

from ir_soar.engine.executor import Executor
from ir_soar.models.playbook import Phase, Playbook, Step
from ir_soar.utils.logging import AuditLogger


def _make_playbook(steps: list[Step], phase_name: str = "identification") -> Playbook:
    return Playbook(id="test_pb", name="Test Playbook", version="1.0", phases=[Phase(name=phase_name, steps=steps)])


def test_executor_runs_simple_success_path(test_config, audit_logger: AuditLogger) -> None:
    pb = _make_playbook([Step(id="s1", action_type="test_noop", requires_approval=False, risk="low")])
    executor = Executor(test_config, audit_logger, interactive=False)
    result = executor.run(pb, {})

    assert not result.aborted
    assert len(result.succeeded_steps) == 1
    assert audit_logger.verify_chain() is True


def test_executor_skips_step_when_condition_false(test_config, audit_logger: AuditLogger) -> None:
    steps = [
        Step(id="s1", action_type="test_noop", requires_approval=False, risk="low"),
        Step(
            id="s2", action_type="test_noop", requires_approval=False, risk="low",
            condition="steps.s1.result.nonexistent_field == true",
        ),
    ]
    pb = _make_playbook(steps)
    executor = Executor(test_config, audit_logger, interactive=False)
    result = executor.run(pb, {})

    assert len(result.succeeded_steps) == 1
    assert len(result.skipped_steps) == 1
    assert result.skipped_steps[0].step_id == "s2"


def test_executor_retries_then_succeeds(test_config, audit_logger: AuditLogger) -> None:
    cfg = test_config.model_copy(
        update={"mode": "live", "execution": test_config.execution.model_copy(update={"retry_backoff_seconds": 0})}
    )
    step = Step(
        id="flaky", action_type="test_flaky", requires_approval=False, risk="low", retries=3,
        inputs={"key": "unique-retry-test-key", "fail_until_attempt": 3},
    )
    pb = _make_playbook([step])
    executor = Executor(cfg, audit_logger, interactive=False)
    result = executor.run(pb, {})

    outcome = result.outcomes[0]
    assert outcome.attempts == 3
    assert outcome.result.succeeded


def test_executor_exhausts_retries_and_fails(test_config, audit_logger: AuditLogger) -> None:
    cfg = test_config.model_copy(
        update={"mode": "live", "execution": test_config.execution.model_copy(update={"retry_backoff_seconds": 0})}
    )
    step = Step(id="always_fails", action_type="test_always_fails", requires_approval=False, risk="low", retries=2)
    pb = _make_playbook([step])
    executor = Executor(cfg, audit_logger, interactive=False)
    result = executor.run(pb, {})

    outcome = result.outcomes[0]
    assert outcome.attempts == 3  # 1 + 2 retries
    assert outcome.result.status == "failure"


def test_executor_on_failure_abort_run_stops_the_run(test_config, audit_logger: AuditLogger) -> None:
    cfg = test_config.model_copy(update={"mode": "live"})
    steps = [
        Step(
            id="fails", action_type="test_always_fails", requires_approval=False, risk="low",
            retries=0, on_failure="abort_run",
        ),
        Step(id="never_reached", action_type="test_noop", requires_approval=False, risk="low"),
    ]
    pb = _make_playbook(steps)
    executor = Executor(cfg, audit_logger, interactive=False)
    result = executor.run(pb, {})

    assert result.aborted is True
    assert len(result.outcomes) == 1  # the second step must never run


def test_executor_max_actions_per_run_aborts_immediately(test_config, audit_logger: AuditLogger) -> None:
    cfg = test_config.model_copy(
        update={"mode": "live", "execution": test_config.execution.model_copy(update={"max_actions_per_run": 2})}
    )
    steps = [Step(id=f"s{i}", action_type="test_noop", requires_approval=False, risk="low") for i in range(5)]
    pb = _make_playbook(steps)
    executor = Executor(cfg, audit_logger, interactive=False)
    result = executor.run(pb, {})

    assert result.aborted is True
    assert len(result.outcomes) == 3  # 2 succeed, the 3rd hits the ceiling and aborts
    assert len(result.succeeded_steps) == 2


def test_executor_denies_containment_when_non_interactive(test_config, audit_logger: AuditLogger) -> None:
    cfg = test_config.model_copy(update={"mode": "live"})
    step = Step(
        id="isolate_x", action_type="isolate_host", requires_approval=True, risk="high",
        inputs={"hostname": "ws1"}, on_failure="continue_with_warning",
    )
    pb = _make_playbook(steps=[step], phase_name="containment")
    executor = Executor(cfg, audit_logger, interactive=False)
    result = executor.run(pb, {})

    outcome = result.outcomes[0]
    assert outcome.ran is False
    assert outcome.result.status == "skipped"


def test_executor_renders_incident_template_variables(test_config, audit_logger: AuditLogger) -> None:
    step = Step(
        id="isolate_x", action_type="isolate_host", requires_approval=False, risk="low",
        inputs={"hostname": "{{ incident.affected_host }}"},
    )
    pb = _make_playbook([step], phase_name="containment")
    executor = Executor(test_config, audit_logger, interactive=False)
    result = executor.run(pb, {"affected_host": "ws-rendered-01"})

    outcome = result.outcomes[0]
    assert outcome.result.succeeded
    assert outcome.result.data["hostname"] == "ws-rendered-01"


def test_executor_fails_cleanly_on_missing_incident_field(test_config, audit_logger: AuditLogger) -> None:
    step = Step(
        id="isolate_x", action_type="isolate_host", requires_approval=False, risk="low",
        inputs={"hostname": "{{ incident.undefined_field }}"},
    )
    pb = _make_playbook([step], phase_name="containment")
    executor = Executor(test_config, audit_logger, interactive=False)
    result = executor.run(pb, {})  # incident context missing the referenced field

    outcome = result.outcomes[0]
    assert outcome.result.status == "failure"
    assert "undefined" in outcome.result.error.lower()


def test_full_real_playbooks_run_cleanly_end_to_end(
    test_config, audit_logger: AuditLogger, playbooks_dir, sample_incident_context
) -> None:
    from ir_soar.engine.playbook_loader import load_playbook_by_id

    for playbook_id in ("phishing_lateral_movement", "ransomware"):
        pb = load_playbook_by_id(playbook_id, playbooks_dir)
        executor = Executor(test_config, audit_logger, interactive=False)
        result = executor.run(pb, sample_incident_context)
        assert len(result.failed_steps) == 0
        assert audit_logger.verify_chain() is True
