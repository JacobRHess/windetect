from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import pytest

from windetect import splunk as splunk_mod
from windetect.schema import SYSMON
from windetect.splunk import (
    DEFAULT_HEC_URL,
    DEFAULT_PASSWORD,
    DEFAULT_REST_URL,
    SplunkClient,
    SplunkConfig,
    SplunkError,
    config_from_env,
    hec_batch,
    parse_search_export,
)


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: Any = None, text: str | None = None):
        self.status_code = status_code
        self.text = text if text is not None else json.dumps(payload if payload is not None else {})


class FakeSession:
    def __init__(self, responses: list[FakeResponse]):
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def _take(self, method: str, url: str, kwargs: dict[str, Any]) -> FakeResponse:
        self.calls.append((method, url, kwargs))
        assert self.responses, f"unexpected call {method} {url}"
        return self.responses.pop(0)

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        return self._take(method, url, kwargs)

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        return self._take("POST", url, kwargs)


def make_client(responses: list[FakeResponse]) -> tuple[SplunkClient, FakeSession]:
    client = SplunkClient(SplunkConfig())
    session = FakeSession(responses)
    client._session = session
    return client, session


TOKEN_RESPONSE = {"entry": [{"content": {"token": "tok-123"}}]}
EXISTING_PROPS = {"entry": [{"content": {"KV_MODE": "json"}}]}


def bootstrap_ok_responses() -> list[FakeResponse]:
    responses = [FakeResponse(200, {"entry": []})]
    for _ in range(3):
        responses.append(FakeResponse(200, EXISTING_PROPS))
        responses.append(FakeResponse(200, {"entry": []}))
    responses.append(FakeResponse(200, TOKEN_RESPONSE))
    return responses


def test_config_defaults():
    config = config_from_env()
    assert config.rest_url == DEFAULT_REST_URL
    assert config.hec_url == DEFAULT_HEC_URL
    assert config.password == DEFAULT_PASSWORD


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("WD_SPLUNK_URL", "https://splunk.example:8089")
    monkeypatch.setenv("WD_SPLUNK_HEC_URL", "https://splunk.example:8088")
    monkeypatch.setenv("WD_SPLUNK_USER", "root")
    monkeypatch.setenv("WD_SPLUNK_PASSWORD", "hunter2")
    monkeypatch.setenv("WD_SPLUNK_INDEX", "other")
    config = config_from_env()
    assert config == SplunkConfig(
        rest_url="https://splunk.example:8089",
        hec_url="https://splunk.example:8088",
        username="root",
        password="hunter2",
        index="other",
    )


def make_event() -> dict[str, Any]:
    return {
        "sourcetype": SYSMON,
        "_time": "2026-08-03T20:24:09.123456+00:00",
        "Computer": "WINDETECT-01",
        "EventCode": 10,
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
    }


def test_hec_batch_shape():
    body = hec_batch(
        [make_event()], run_tag="abc-det-attack", index="windetect", source="fixture.json"
    )
    (line,) = body.splitlines()
    record = json.loads(line)
    assert record["index"] == "windetect"
    assert record["source"] == "fixture.json"
    assert record["sourcetype"] == SYSMON
    assert record["host"] == "WINDETECT-01"
    expected_epoch = datetime.fromisoformat("2026-08-03T20:24:09.123456+00:00").timestamp()
    assert record["time"] == pytest.approx(expected_epoch)
    assert record["event"]["wd_run"] == "abc-det-attack"
    assert record["event"]["EventCode"] == 10


def test_hec_batch_multiple_events():
    body = hec_batch([make_event(), make_event()], run_tag="t", index="i", source="s")
    assert len(body.splitlines()) == 2


def test_parse_search_export():
    assert parse_search_export({"results": [{"a": "1"}]}) == [{"a": "1"}]
    assert parse_search_export({"preview": False}) == []
    with pytest.raises(SplunkError, match="malformed"):
        parse_search_export({"results": "nope"})


def test_bootstrap_adopts_existing_objects():
    client, session = make_client(bootstrap_ok_responses())
    client.bootstrap()
    assert client._hec_token == "tok-123"
    gets = [call for call in session.calls if call[0] == "GET"]
    posts = [call for call in session.calls if call[0] == "POST"]
    assert len(gets) == 5
    assert len(posts) == 3
    assert all(call[2]["data"]["KV_MODE"] == "json" for call in posts)


def test_bootstrap_creates_missing_objects():
    responses = [
        FakeResponse(404),
        FakeResponse(200, {"entry": [{"name": "windetect"}]}),
        FakeResponse(404),
        FakeResponse(200, {"entry": [{}]}),
        FakeResponse(404),
        FakeResponse(200, {"entry": [{}]}),
        FakeResponse(404),
        FakeResponse(200, {"entry": [{}]}),
        FakeResponse(404),
        FakeResponse(200, TOKEN_RESPONSE),
    ]
    client, session = make_client(responses)
    client.bootstrap()
    assert client._hec_token == "tok-123"
    created = [call[1] for call in session.calls if call[0] == "POST"]
    assert any(url.endswith("/services/data/indexes") for url in created)
    assert any(url.endswith("/configs/conf-props") for url in created)
    assert any(url.endswith("/data/inputs/http") for url in created)


def test_send_events_requires_bootstrap():
    client, _ = make_client([])
    with pytest.raises(SplunkError, match="bootstrap"):
        client.send_events([make_event()], run_tag="t", source="s")


def event_fixture(count: int = 1) -> list[dict[str, Any]]:
    return [make_event() for _ in range(count)]


def test_send_events_happy_path_and_batching():
    responses = [
        *bootstrap_ok_responses(),
        FakeResponse(200, {"text": "Success", "code": 0}),
        FakeResponse(200, {"text": "Success", "code": 0}),
    ]
    client, session = make_client(responses)
    client.bootstrap()
    sent = client.send_events(event_fixture(501), run_tag="tag", source="f.json")
    assert sent == 501
    hec_calls = [call for call in session.calls if "collector" in call[1]]
    assert len(hec_calls) == 2
    first_body = hec_calls[0][2]["data"].decode("utf-8")
    assert len(first_body.splitlines()) == 500
    assert hec_calls[0][2]["headers"]["Authorization"] == "Splunk tok-123"


def test_send_events_http_failure():
    client, _ = make_client([*bootstrap_ok_responses(), FakeResponse(503, text="unavailable")])
    client.bootstrap()
    with pytest.raises(SplunkError, match="HEC ingest failed"):
        client.send_events(event_fixture(1), run_tag="t", source="s")


def test_send_events_rejected_ack():
    client, _ = make_client(
        [*bootstrap_ok_responses(), FakeResponse(200, {"code": 5, "text": "bad"})]
    )
    client.bootstrap()
    with pytest.raises(SplunkError, match="rejected"):
        client.send_events(event_fixture(1), run_tag="t", source="s")


def test_send_events_non_json_ack():
    client, _ = make_client([*bootstrap_ok_responses(), FakeResponse(200, text="<html>")])
    client.bootstrap()
    with pytest.raises(SplunkError, match="non-JSON ack"):
        client.send_events(event_fixture(1), run_tag="t", source="s")


def test_oneshot_search_parses_rows():
    client, session = make_client(
        [*bootstrap_ok_responses(), FakeResponse(200, {"results": [{"count": "2"}]})]
    )
    client.bootstrap()
    rows = client.oneshot_search("windetect | stats count", earliest="a", latest="b")
    assert rows == [{"count": "2"}]
    search_call = session.calls[-1]
    assert search_call[2]["data"]["earliest_time"] == "a"
    assert search_call[2]["data"]["latest_time"] == "b"


def test_oneshot_search_error_payload():
    payload = {"messages": [{"type": "ERROR", "text": "Unknown search command 'bogus'"}]}
    client, _ = make_client([*bootstrap_ok_responses(), FakeResponse(400, payload)])
    client.bootstrap()
    with pytest.raises(SplunkError, match="Unknown search command"):
        client.oneshot_search("bogus")


def test_oneshot_search_error_without_messages():
    client, _ = make_client([*bootstrap_ok_responses(), FakeResponse(400, {})])
    client.bootstrap()
    with pytest.raises(SplunkError, match="400"):
        client.oneshot_search("bogus")


def test_oneshot_search_non_json():
    client, _ = make_client([*bootstrap_ok_responses(), FakeResponse(500, text="boom")])
    client.bootstrap()
    with pytest.raises(SplunkError, match="non-JSON"):
        client.oneshot_search("whatever")


def test_count_events_and_wait_indexed(monkeypatch):
    monkeypatch.setattr(splunk_mod.time, "sleep", lambda _: None)
    client, _ = make_client(
        [
            *bootstrap_ok_responses(),
            FakeResponse(200, {"results": [{"count": "1"}]}),
            FakeResponse(200, {"results": [{"count": "2"}]}),
        ]
    )
    client.bootstrap()
    client.wait_indexed("tag", 2)


def test_wait_indexed_times_out():
    client, _ = make_client(
        [
            *bootstrap_ok_responses(),
            FakeResponse(200, {"results": [{"count": "0"}]}),
            FakeResponse(200, {"results": [{"count": "0"}]}),
        ]
    )
    client.bootstrap()
    with pytest.raises(SplunkError, match="became searchable"):
        client.wait_indexed("tag", 5, timeout=0.0001)


def test_count_events_zero_when_no_rows():
    client, _ = make_client([*bootstrap_ok_responses(), FakeResponse(200, {})])
    client.bootstrap()
    assert client.count_events("tag") == 0


def test_index_creation_failure():
    client, _ = make_client([FakeResponse(404), FakeResponse(404)])
    with pytest.raises(SplunkError, match="could not create index"):
        client.bootstrap()


def test_props_creation_failure():
    client, _ = make_client([FakeResponse(200, {}), FakeResponse(404), FakeResponse(404)])
    with pytest.raises(SplunkError, match="props stanza"):
        client.bootstrap()


def test_hec_creation_failure():
    responses = [
        FakeResponse(200, {}),
        FakeResponse(200, {}),
        FakeResponse(200, {}),
        FakeResponse(200, {}),
        FakeResponse(200, {}),
        FakeResponse(200, {}),
        FakeResponse(200, {}),
        FakeResponse(404),
        FakeResponse(404),
    ]
    client, _ = make_client(responses)
    with pytest.raises(SplunkError, match="could not create HEC input"):
        client.bootstrap()


def test_token_missing_from_payload():
    responses = [*bootstrap_ok_responses()[:-1], FakeResponse(200, {})]
    client, _ = make_client(responses)
    with pytest.raises(SplunkError, match="no HEC token"):
        client.bootstrap()


def test_rest_non_json():
    client, _ = make_client([FakeResponse(200, text="not json at all")])
    with pytest.raises(SplunkError, match="non-JSON"):
        client.bootstrap()


def test_index_property():
    client, _ = make_client([])
    assert client.index == "windetect"
