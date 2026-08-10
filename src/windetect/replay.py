"""The proof step: replay captured fixtures through Splunk and assert.

For every detection the engine loads the two fixtures sliced from real
captures, validates them against the schema, ingests them over HEC tagged
with a unique per-replay marker (``wd_run``), and runs the rule scoped to
that marker over the captured timeline. The assertions are the project's
whole promise:

- the attack fixture must produce at least one result row
- the benign fixture must produce none

Everything runs against a live lab Splunk; there is no offline simulation
of search semantics, so this module only touches real behavior.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from windetect import schema
from windetect.model import EXPECT_ATTACK, EXPECT_BENIGN, Detection, Model, ModelError, check_rules
from windetect.splunk import SplunkClient

_TIME_PAD = timedelta(seconds=60)

# The run id is interpolated into the replay search inside wd_run="..."; keep
# it to characters that cannot alter the SPL.
_RUN_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class ReplayError(RuntimeError):
    """A fixture could not be loaded for replay."""


@dataclass(frozen=True)
class FixtureOutcome:
    expect: str
    path: Path
    events: int
    rows: int

    @property
    def passed(self) -> bool:
        return (self.rows > 0) if self.expect == EXPECT_ATTACK else (self.rows == 0)


@dataclass(frozen=True)
class DetectionOutcome:
    detection_id: str
    outcomes: tuple[FixtureOutcome, ...]

    @property
    def passed(self) -> bool:
        return all(outcome.passed for outcome in self.outcomes)


def load_fixture(root: Path, path: Path) -> list[dict[str, Any]]:
    full = root / path
    try:
        raw = json.loads(full.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReplayError(f"missing fixture {full}") from exc
    except json.JSONDecodeError as exc:
        raise ReplayError(f"fixture {full} is not valid JSON: {exc}") from exc
    if not isinstance(raw, list):
        raise ReplayError(f"fixture {full} must be a JSON array of events")
    schema.validate_events(raw, str(path))
    return raw


def _time_bounds(events: list[dict[str, Any]]) -> tuple[str, str]:
    times = sorted(datetime.fromisoformat(e["_time"]) for e in events)
    earliest = (times[0] - _TIME_PAD).astimezone(UTC)
    latest = (times[-1] + _TIME_PAD).astimezone(UTC)
    return earliest.isoformat(), latest.isoformat()


def replay_detection(
    client: SplunkClient, model: Model, detection: Detection, rule_text: str, run_id: str
) -> DetectionOutcome:
    outcomes: list[FixtureOutcome] = []
    for expect in (EXPECT_ATTACK, EXPECT_BENIGN):
        ref = detection.fixture_for(expect)
        events = load_fixture(model.root, ref.events)
        tag = f"{run_id}-{detection.id}-{expect}"
        client.send_events(events, run_tag=tag, source=ref.events.as_posix())
        client.wait_indexed(tag, len(events))

        earliest, latest = _time_bounds(events)
        spl = f'index={client.index} wd_run="{tag}" {rule_text}'
        rows = client.oneshot_search(spl, earliest=earliest, latest=latest)
        outcomes.append(
            FixtureOutcome(expect=expect, path=ref.events, events=len(events), rows=len(rows))
        )
    return DetectionOutcome(detection.id, tuple(outcomes))


def run_replay(
    model: Model, client: SplunkClient, *, run_id: str | None = None
) -> list[DetectionOutcome]:
    if not model.detections:
        return []
    rules = check_rules(model)
    client.bootstrap()
    if run_id is None:
        run_id = uuid.uuid4().hex[:12]
    elif not _RUN_ID.match(run_id):
        raise ReplayError(f"run id {run_id!r} must match [A-Za-z0-9._-]{{1,64}}")
    return [
        replay_detection(client, model, detection, rules[detection.id], run_id)
        for detection in model.detections
    ]


def format_outcome(outcome: DetectionOutcome) -> str:
    status = "PASS" if outcome.passed else "FAIL"
    details = ", ".join(
        f"{o.expect}: {o.rows} row(s)/{o.events} event(s)" for o in outcome.outcomes
    )
    return f"{status} {outcome.detection_id} ({details})"


def load_replay_targets(model: Model) -> None:
    """Fail fast if any fixture referenced by a detection is unreadable."""
    for detection in model.detections:
        for ref in detection.fixtures:
            load_fixture(model.root, ref.events)


def check_model_for_replay(model: Model) -> None:
    try:
        check_rules(model)
    except ModelError as exc:
        raise ReplayError(str(exc)) from exc
    load_replay_targets(model)
