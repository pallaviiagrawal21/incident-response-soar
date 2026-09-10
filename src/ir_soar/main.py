"""
Thin process entrypoint. Both `python -m ir_soar.main` and the installed
`ir-soar` console script (see pyproject.toml [project.scripts]) land here;
all real logic lives in `cli.py`.
"""

from __future__ import annotations

from ir_soar.cli import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()
