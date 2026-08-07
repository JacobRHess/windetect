from __future__ import annotations

from pathlib import Path

import pytest

from helpers import DEFAULT_RULE, DEFAULT_YAML, build_root

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_CAPTURE = Path(__file__).resolve().parent / "data" / "capture_stage03.xml"


@pytest.fixture
def make_root(tmp_path: Path):
    def _make(
        *,
        yaml_text: str | None = None,
        rule: str | None = DEFAULT_RULE,
        write_rule: bool = True,
    ) -> Path:
        return build_root(
            tmp_path, yaml_text=yaml_text or DEFAULT_YAML, rule=rule, write_rule=write_rule
        )

    return _make


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def sample_capture() -> Path:
    return SAMPLE_CAPTURE
