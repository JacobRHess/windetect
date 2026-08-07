from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers import DEFAULT_RULE, DEFAULT_YAML, DETECTION_ID, build_root
from windetect import schema
from windetect.capture import SliceError, run_capture, slice_events, write_fixture
from windetect.model import load_model

TWO_STAGE_YAML = DEFAULT_YAML.replace(
    "stages:",
    "stages:\n  - id: 02-defense-evasion\n    techniques: [T1070.001]",
    1,
)

NO_SLICE_YAML = DEFAULT_YAML.replace(
    "    slice:\n      sysmon: [10, 1]\n      security: [4688]\n", ""
)

EMPTY_SLICE_YAML = DEFAULT_YAML.replace(
    "      sysmon: [10, 1]\n      security: [4688]",
    "      sysmon: [22]\n      security: [9999]",
)


def test_slice_events_filters_by_channel_and_code():
    events = [
        {"sourcetype": schema.SYSMON, "EventCode": 10},
        {"sourcetype": schema.SYSMON, "EventCode": 1},
        {"sourcetype": schema.SYSMON, "EventCode": 3},
        {"sourcetype": schema.SECURITY, "EventCode": 4688},
        {"sourcetype": schema.SECURITY, "EventCode": 4624},
    ]
    kept = slice_events(events, {"sysmon": (10, 1), "security": (4688,)})
    assert [e["EventCode"] for e in kept] == [10, 1, 4688]
    assert slice_events(events, {}) == events


def test_attack_capture_slices_fixtures(make_root, sample_capture):
    root = make_root()
    model = load_model(root)
    outcomes = run_capture(root, model, [sample_capture], expect="attack")

    (outcome,) = outcomes
    assert outcome.detection_id == DETECTION_ID
    assert outcome.expect == "attack"
    assert outcome.events == 3

    fixture = root / f"fixtures/{DETECTION_ID}.attack.json"
    events = json.loads(fixture.read_text(encoding="utf-8"))
    assert [e["EventCode"] for e in events] == [1, 10, 4688]
    times = [e["_time"] for e in events]
    assert times == sorted(times)
    schema.validate_events(events, "attack")


def test_attack_capture_explicit_stage(make_root, sample_capture):
    root = make_root()
    model = load_model(root)
    for ref in ("03", "03-credential-access"):
        outcomes = run_capture(root, model, [sample_capture], expect="attack", stage_ref=ref)
        assert outcomes


def test_attack_capture_stage_mismatch(make_root, sample_capture):
    root = make_root(yaml_text=TWO_STAGE_YAML)
    model = load_model(root)
    with pytest.raises(SliceError, match="but --stage selected"):
        run_capture(root, model, [sample_capture], expect="attack", stage_ref="02")


def test_attack_capture_stage_with_no_detections(make_root, sample_capture, tmp_path):
    root = make_root(yaml_text=TWO_STAGE_YAML)
    model = load_model(root)
    other = tmp_path / "stage02.xml"
    other.write_text(
        sample_capture.read_text(encoding="utf-8").replace('stage="03"', 'stage="02"', 1),
        encoding="utf-8",
    )
    with pytest.raises(SliceError, match="has no detections"):
        run_capture(root, model, [other], expect="attack")


def test_attack_capture_unknown_stage_attr(make_root, sample_capture, tmp_path):
    root = make_root()
    model = load_model(root)
    other = tmp_path / "stage99.xml"
    other.write_text(
        sample_capture.read_text(encoding="utf-8").replace('stage="03"', 'stage="99"', 1),
        encoding="utf-8",
    )
    with pytest.raises(SliceError, match="does not define"):
        run_capture(root, model, [other], expect="attack")


def test_empty_slice_fails_loudly(make_root, sample_capture):
    root = make_root(yaml_text=EMPTY_SLICE_YAML)
    model = load_model(root)
    with pytest.raises(SliceError, match="matched no events"):
        run_capture(root, model, [sample_capture], expect="attack")


def test_benign_capture_ignores_stage_and_covers_all_detections(make_root, sample_capture):
    root = make_root()
    model = load_model(root)
    outcomes = run_capture(root, model, [sample_capture], expect="benign")
    (outcome,) = outcomes
    assert outcome.expect == "benign"
    fixture = root / f"fixtures/{DETECTION_ID}.benign.json"
    assert fixture.is_file()
    schema.validate_events(json.loads(fixture.read_text(encoding="utf-8")), "benign")


def test_detection_without_slice_gets_whole_capture(make_root, sample_capture):
    root = make_root(yaml_text=NO_SLICE_YAML)
    model = load_model(root)
    outcomes = run_capture(root, model, [sample_capture], expect="attack")
    assert outcomes[0].events == 7


def test_no_exports_given(make_root):
    root = make_root()
    model = load_model(root)
    with pytest.raises(SliceError, match="no capture exports"):
        run_capture(root, model, [], expect="attack")


def test_multiple_exports_merge(tmp_path, sample_capture):
    root = build_root(tmp_path, yaml_text=NO_SLICE_YAML)
    model = load_model(root)
    second = tmp_path / "copy.xml"
    second.write_text(sample_capture.read_text(encoding="utf-8"), encoding="utf-8")
    outcomes = run_capture(root, model, [sample_capture, second], expect="attack")
    assert outcomes[0].events == 14


def test_write_fixture_creates_parents(tmp_path):
    path = write_fixture(
        tmp_path, Path("fixtures/deep/nested/x.json"), [{"sourcetype": schema.SECURITY}]
    )
    assert json.loads(path.read_text(encoding="utf-8")) == [{"sourcetype": schema.SECURITY}]


def test_schema_violation_in_capture_fails(tmp_path, sample_capture):
    yaml_text = DEFAULT_YAML.replace("      sysmon: [10, 1]", "      sysmon: [3]")
    root = build_root(tmp_path, yaml_text=yaml_text)
    model = load_model(root)
    degraded = tmp_path / "degraded.xml"
    degraded.write_text(
        sample_capture.read_text(encoding="utf-8").replace(
            '<Data Name="DestinationPort">443</Data>', "", 1
        ),
        encoding="utf-8",
    )
    with pytest.raises(schema.SchemaError, match="DestinationPort"):
        run_capture(root, model, [degraded], expect="attack")


def test_rule_written_alongside(make_root):
    root = make_root(rule=DEFAULT_RULE)
    assert (root / "rules" / f"{DETECTION_ID}.spl").read_text(encoding="utf-8") == DEFAULT_RULE
