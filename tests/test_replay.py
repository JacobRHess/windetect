from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers import DEFAULT_RULE, DETECTION_ID, build_root
from windetect.model import load_model
from windetect.replay import (
    ReplayError,
    check_model_for_replay,
    format_outcome,
    load_fixture,
    replay_detection,
    run_replay,
)
from windetect.schema import SYSMON, SchemaError
from windetect.splunk import SplunkConfig


def _event(offset: int = 0) -> dict:
    return {
        "sourcetype": SYSMON,
        "_time": f"2026-08-03T20:24:{9 + offset:02d}.000000+00:00",
        "Computer": "WINDETECT-01",
        "EventCode": 10,
        "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x1fffff",
    }


def write_fixtures(root: Path, *, attack=None, benign=None) -> None:
    (root / "fixtures").mkdir(exist_ok=True)
    attack = attack if attack is not None else [_event()]
    benign = benign if benign is not None else [_event(30)]
    (root / f"fixtures/{DETECTION_ID}.attack.json").write_text(json.dumps(attack), encoding="utf-8")
    (root / f"fixtures/{DETECTION_ID}.benign.json").write_text(json.dumps(benign), encoding="utf-8")


class FakeClient:
    index = SplunkConfig().index

    def __init__(self, *, attack_rows: int = 1, benign_rows: int = 0):
        self.bootstrap_called = False
        self.sent: list[tuple[str, str, int]] = []
        self.searches: list[tuple[str, str | None, str | None]] = []
        self._attack_rows = attack_rows
        self._benign_rows = benign_rows

    def bootstrap(self) -> None:
        self.bootstrap_called = True

    def send_events(self, events, *, run_tag: str, source: str) -> int:
        self.sent.append((run_tag, source, len(events)))
        return len(events)

    def wait_indexed(self, run_tag: str, expected: int, *, timeout: float = 90.0) -> None:
        return None

    def oneshot_search(self, spl, *, earliest=None, latest=None):
        self.searches.append((spl, earliest, latest))
        rows = self._attack_rows if "attack" in spl else self._benign_rows
        return [{"row": i} for i in range(rows)]


@pytest.fixture
def loaded_model(tmp_path):
    root = build_root(tmp_path)
    write_fixtures(root)
    return load_model(root)


def test_run_replay_all_pass(loaded_model):
    client = FakeClient(attack_rows=2, benign_rows=0)
    outcomes = run_replay(loaded_model, client, run_id="run1")
    assert client.bootstrap_called
    (outcome,) = outcomes
    assert outcome.passed
    attack, benign = outcome.outcomes
    assert attack.expect == "attack"
    assert attack.rows == 2
    assert benign.expect == "benign"
    assert benign.rows == 0
    tags = [sent[0] for sent in client.sent]
    assert f"run1-{DETECTION_ID}-attack" in tags
    assert f"run1-{DETECTION_ID}-benign" in tags


@pytest.mark.parametrize("bad", ['x" OR wd_run="*', "spaced run", "a" * 65, ""])
def test_run_replay_rejects_unsafe_run_id(loaded_model, bad):
    client = FakeClient()
    with pytest.raises(ReplayError, match="run id"):
        run_replay(loaded_model, client, run_id=bad)
    assert not client.sent


def test_run_replay_generates_run_id(loaded_model):
    client = FakeClient()
    run_replay(loaded_model, client)
    tag = client.sent[0][0]
    assert tag.endswith(f"-{DETECTION_ID}-attack")


def test_replay_attack_silent_fails(loaded_model):
    client = FakeClient(attack_rows=0, benign_rows=0)
    outcomes = run_replay(loaded_model, client)
    assert not outcomes[0].passed
    assert "attack: 0 row(s)" in format_outcome(outcomes[0])


def test_replay_benign_fires_fails(loaded_model):
    client = FakeClient(attack_rows=1, benign_rows=3)
    outcomes = run_replay(loaded_model, client)
    assert not outcomes[0].passed


def test_run_replay_no_detections(tmp_path):
    yaml_text = (
        "version: 1\n\nstages:\n  - id: 03-credential-access\n"
        "    techniques: [T1003.001]\n\ndetections: []\n"
    )
    root = build_root(tmp_path, yaml_text=yaml_text)
    model = load_model(root)
    assert run_replay(model, FakeClient()) == []


def test_replay_detection_directly(loaded_model):
    client = FakeClient(attack_rows=1, benign_rows=0)
    detection = loaded_model.detections[0]
    outcome = replay_detection(client, loaded_model, detection, DEFAULT_RULE, "fixed")
    assert outcome.passed
    assert client.sent[0][0] == f"fixed-{DETECTION_ID}-attack"


def test_time_bounds_passed_to_search(loaded_model):
    client = FakeClient()
    run_replay(loaded_model, client)
    for spl, earliest, latest in client.searches:
        assert earliest is not None
        assert latest is not None
        assert earliest < latest
        assert DEFAULT_RULE in spl


def test_load_fixture_missing(tmp_path):
    with pytest.raises(ReplayError, match="missing fixture"):
        load_fixture(tmp_path, Path("fixtures/nope.json"))


def test_load_fixture_invalid_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ReplayError, match="not valid JSON"):
        load_fixture(tmp_path, Path("bad.json"))


def test_load_fixture_not_a_list(tmp_path):
    path = tmp_path / "obj.json"
    path.write_text('{"a": 1}', encoding="utf-8")
    with pytest.raises(ReplayError, match="JSON array"):
        load_fixture(tmp_path, Path("obj.json"))


def test_load_fixture_schema_violation(tmp_path):
    path = tmp_path / "bad-event.json"
    path.write_text(
        json.dumps(
            [
                {
                    "sourcetype": "syslog",
                    "_time": "2026-01-01T00:00:00+00:00",
                    "Computer": "X",
                    "EventCode": 1,
                }
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(SchemaError):
        load_fixture(tmp_path, Path("bad-event.json"))


def test_load_fixture_ok(tmp_path):
    path = tmp_path / "good.json"
    path.write_text(json.dumps([_event()]), encoding="utf-8")
    assert len(load_fixture(tmp_path, Path("good.json"))) == 1


def test_check_model_for_replay_missing_fixture(tmp_path):
    root = build_root(tmp_path)
    model = load_model(root)
    with pytest.raises(ReplayError, match="missing fixture"):
        check_model_for_replay(model)


def test_check_model_for_replay_bad_rule(tmp_path):
    root = build_root(tmp_path, rule="index=hardcoded")
    write_fixtures(root)
    model = load_model(root)
    with pytest.raises(ReplayError, match="index"):
        check_model_for_replay(model)


def test_check_model_for_replay_ok(loaded_model):
    check_model_for_replay(loaded_model)


def test_format_outcome(loaded_model):
    client = FakeClient(attack_rows=1, benign_rows=0)
    (outcome,) = run_replay(loaded_model, client)
    text = format_outcome(outcome)
    assert text.startswith("PASS")
    assert DETECTION_ID in text
