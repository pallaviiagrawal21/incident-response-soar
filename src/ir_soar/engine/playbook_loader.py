"""
Playbook loader — the boundary between playbook files on disk and the
validated, typed `Playbook` objects the rest of the engine consumes.

Two file families are supported, kept in sync by a shared `id`:
  - config/playbooks/<id>.yaml   machine-readable, consumed by the executor
  - playbooks/<id>.md            human-readable, for analysts during a
                                  real incident; the loader can fetch this
                                  raw text for the CLI's `show` command but
                                  never parses or validates its structure
                                  (that's not this project's job — the MD
                                  is authored and reviewed by humans).

This module never imports anything from `actions/` — the loader does not
need to know which action types are actually implemented. That check (does
this playbook reference an action_type the engine can actually run?) is a
concern for the executor at run time, not for loading/validating structure.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from ir_soar.models.playbook import Playbook


class PlaybookLoadError(RuntimeError):
    """Raised when a playbook file is missing, malformed, or fails schema validation."""


def load_playbook_yaml(path: str | Path) -> Playbook:
    """Load and validate a single playbook YAML file into a `Playbook`.

    Raises:
        PlaybookLoadError: file missing, not valid YAML, not a mapping at
            the top level, or fails Playbook schema validation.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise PlaybookLoadError(f"Playbook file not found: {file_path}")

    try:
        with file_path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise PlaybookLoadError(f"Failed to parse YAML in {file_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise PlaybookLoadError(f"Playbook file {file_path} must contain a YAML mapping at the top level")

    try:
        playbook = Playbook.model_validate(raw)
    except ValidationError as exc:
        raise PlaybookLoadError(f"Playbook {file_path} failed schema validation:\n{exc}") from exc

    return playbook


def list_available_playbooks(playbooks_dir: str | Path) -> list[str]:
    """Return the sorted list of playbook ids available in `playbooks_dir`.

    An id is considered available if `<playbooks_dir>/<id>.yaml` exists and
    loads/validates successfully. Files that fail to load are skipped
    rather than raising, so one broken draft file doesn't take down
    `list-playbooks` for every other playbook.
    """
    directory = Path(playbooks_dir)
    if not directory.exists():
        return []
    ids: list[str] = []
    for yaml_path in sorted(directory.glob("*.yaml")):
        try:
            playbook = load_playbook_yaml(yaml_path)
        except PlaybookLoadError:
            continue
        ids.append(playbook.id)
    return ids


def load_playbook_by_id(playbook_id: str, playbooks_dir: str | Path) -> Playbook:
    """Load `<playbooks_dir>/<playbook_id>.yaml` and validate its `id` field matches."""
    directory = Path(playbooks_dir)
    file_path = directory / f"{playbook_id}.yaml"
    playbook = load_playbook_yaml(file_path)
    if playbook.id != playbook_id:
        raise PlaybookLoadError(
            f"Playbook file {file_path} declares id '{playbook.id}', "
            f"but was loaded by filename-derived id '{playbook_id}'. "
            "The filename (without .yaml) and the internal 'id' field must match."
        )
    return playbook


def get_playbook_markdown_path(playbook_id: str, markdown_dir: str | Path) -> Path:
    """Return the expected Markdown path for `playbook_id` (may not exist)."""
    return Path(markdown_dir) / f"{playbook_id}.md"


def load_playbook_markdown(playbook_id: str, markdown_dir: str | Path) -> str:
    """Return the raw Markdown text for `playbook_id`.

    Raises:
        PlaybookLoadError: if the file does not exist.
    """
    path = get_playbook_markdown_path(playbook_id, markdown_dir)
    if not path.exists():
        raise PlaybookLoadError(f"Markdown playbook not found: {path}")
    return path.read_text(encoding="utf-8")
