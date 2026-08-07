"""Shared builders for offline tests; importable as `helpers` from any test module."""

from __future__ import annotations

from pathlib import Path

DETECTION_ID = "lsass-access-untrusted-caller"

DEFAULT_RULE = 'EventCode=10 TargetImage="C:\\Windows\\System32\\lsass.exe"'

DEFAULT_YAML = f"""\
version: 1

stages:
  - id: 03-credential-access
    techniques: [T1003.001]

detections:
  - id: {DETECTION_ID}
    title: LSASS process access by an untrusted caller
    rule: rules/{DETECTION_ID}.spl
    stage: 03-credential-access
    attack: [T1003.001]
    slice:
      sysmon: [10, 1]
      security: [4688]
    fixtures:
      - events: fixtures/{DETECTION_ID}.attack.json
        expect: attack
      - events: fixtures/{DETECTION_ID}.benign.json
        expect: benign
"""

EMPTY_YAML = """\
version: 1

stages:
  - id: 03-credential-access
    techniques: [T1003.001]

detections: []
"""


def build_root(
    root: Path,
    *,
    yaml_text: str | None = None,
    rule: str | None = DEFAULT_RULE,
    write_rule: bool = True,
) -> Path:
    (root / "rules").mkdir(exist_ok=True)
    (root / "fixtures").mkdir(exist_ok=True)
    (root / "detections.yaml").write_text(yaml_text or DEFAULT_YAML, encoding="utf-8")
    if write_rule:
        (root / "rules" / f"{DETECTION_ID}.spl").write_text(rule or DEFAULT_RULE, encoding="utf-8")
    return root
