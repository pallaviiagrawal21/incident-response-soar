"""
Renders `{{ incident.* }}` placeholders in a playbook step's `inputs`,
using the incident context supplied for this run (via `--incident-file` or
CLI overrides — see cli.py, a later build step).

`StrictUndefined` is used deliberately: a playbook referencing an incident
field that was never supplied fails loudly and immediately, rather than
silently rendering as an empty string that then sails through action input
validation as some technically-valid-but-wrong value (e.g. isolating a host
named `""`).
"""

from __future__ import annotations

from typing import Any

from jinja2 import Environment, StrictUndefined, UndefinedError

_ENV = Environment(undefined=StrictUndefined, autoescape=False)


class TemplateRenderError(RuntimeError):
    """Raised when a step input references an undefined incident field, or otherwise fails to render."""


def render_inputs(inputs: dict[str, Any], incident_context: dict[str, Any]) -> dict[str, Any]:
    """Render every string value in `inputs` as a Jinja template with `incident` in scope.

    Non-string values pass through unchanged. Strings with no `{{` are
    passed through without invoking the template engine at all (a cheap,
    correct fast path for the common case of literal values).
    """
    rendered: dict[str, Any] = {}
    for key, value in inputs.items():
        if isinstance(value, str) and "{{" in value:
            try:
                template = _ENV.from_string(value)
                rendered[key] = template.render(incident=incident_context)
            except UndefinedError as exc:
                raise TemplateRenderError(
                    f"Input '{key}' = '{value}' references an undefined incident field: {exc}"
                ) from exc
            except Exception as exc:  # noqa: BLE001 - any Jinja error becomes a clean, catchable failure
                raise TemplateRenderError(f"Failed to render input '{key}' = '{value}': {exc}") from exc
        else:
            rendered[key] = value
    return rendered
