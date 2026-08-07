from __future__ import annotations

import json

from helpers import DEFAULT_YAML, DETECTION_ID, build_root
from windetect.model import load_model
from windetect.report import coverage_markdown, coverage_text
from windetect.schema import SYSMON

EMPTY_YAML_TEXT = (
    "version: 1\n\nstages:\n  - id: 03-credential-access\n"
    "    techniques: [T1003.001]\n\ndetections: []\n"
)


def _event() -> dict:
    return {
        "sourcetype": SYSMON,
        "_time": "2026-08-03T20:24:09.000000+00:00",
        "Computer": "WINDETECT-01",
        "EventCode": 10,
        "SourceImage": "C:\\Temp\\rundll32.exe",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x1fffff",
    }


def with_fixtures(root):
    (root / "fixtures").mkdir(exist_ok=True)
    for suffix in ("attack", "benign"):
        (root / f"fixtures/{DETECTION_ID}.{suffix}.json").write_text(
            json.dumps([_event()]), encoding="utf-8"
        )
    return root


def test_coverage_text_with_detection(tmp_path):
    root = with_fixtures(build_root(tmp_path))
    model = load_model(root)
    text = coverage_text(model)
    assert DETECTION_ID in text
    assert "03-credential-access" in text
    assert "T1003.001" in text
    assert "Techniques proven: 1/1" in text
    assert "MISSING" not in text
    assert "attack:yes" in text.replace(" ", "")


def test_coverage_text_missing_assets(tmp_path):
    root = build_root(tmp_path, write_rule=False)
    model = load_model(root)
    text = coverage_text(model)
    assert "MISSING" in text


def test_coverage_text_no_detections(tmp_path):
    root = build_root(tmp_path, yaml_text=EMPTY_YAML_TEXT)
    model = load_model(root)
    text = coverage_text(model)
    assert "No detections yet" in text
    assert "0 detection(s)" in text


def test_coverage_markdown(tmp_path):
    root = build_root(tmp_path)
    model = load_model(root)
    md = coverage_markdown(model)
    assert md.startswith("| Stage")
    assert "---" in md
    assert DETECTION_ID in md
    assert "```" in md


def test_coverage_markdown_no_detections(tmp_path):
    root = build_root(tmp_path, yaml_text=EMPTY_YAML_TEXT)
    model = load_model(root)
    assert "no detections yet" in coverage_markdown(model)


def test_summary_counts_multiple_stages(tmp_path):
    yaml_text = DEFAULT_YAML.replace(
        "stages:",
        "stages:\n  - id: 04-discovery\n    techniques: [T1087.002, T1069.002]",
        1,
    )
    root = build_root(tmp_path, yaml_text=yaml_text)
    model = load_model(root)
    text = coverage_text(model)
    assert "Techniques proven: 1/3" in text
    assert "04-discovery: 0 detection(s)" in text
