"""Live-lab tests, excluded from the offline gate by pytest addopts.

Run with the lab Splunk up (``docker compose -f lab/docker-compose.yml up -d``)
via ``uv run pytest -m replay``; the CI validate job runs them against a
service container. The smoke test ingests clearly-synthetic canary events to
prove the ingest/extract/search path end to end - it never touches detection
fixtures, which by contract come only from real captures.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from windetect.model import load_model
from windetect.replay import format_outcome, run_replay
from windetect.schema import SECURITY
from windetect.splunk import SplunkClient, config_from_env

pytestmark = pytest.mark.replay


def _client() -> SplunkClient:
    return SplunkClient(config_from_env())


def test_live_bootstrap_ingest_search() -> None:
    client = _client()
    client.bootstrap()

    run_tag = f"smoke-{uuid.uuid4().hex[:8]}"
    now = datetime.now(UTC)
    events = [
        {
            "sourcetype": SECURITY,
            "_time": (now - timedelta(seconds=i)).isoformat(timespec="microseconds"),
            "Computer": "WINDETECT-CANARY",
            "EventCode": 9999,
            "wd_canary": "yes",
        }
        for i in range(3)
    ]
    client.send_events(events, run_tag=run_tag, source="replay-smoke")
    client.wait_indexed(run_tag, len(events))

    rows = client.oneshot_search(f'{client.index} wd_run="{run_tag}" EventCode=9999')
    assert len(rows) == 3
    assert all(row.get("wd_canary") == "yes" for row in rows), (
        "KV_MODE=json props are not applied; fixture fields would be unsearchable"
    )


def test_live_replay_all_detections(repo_root) -> None:
    model = load_model(repo_root)
    if not model.detections:
        pytest.skip("no detections committed yet; replay becomes real with the first capture")
    outcomes = run_replay(model, _client())
    failures = [format_outcome(outcome) for outcome in outcomes if not outcome.passed]
    assert not failures, "\n".join(failures)
