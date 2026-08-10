from __future__ import annotations

import pytest

from windetect.schema import (
    POWERSHELL,
    SECURITY,
    SYSMON,
    SchemaError,
    validate_event,
    validate_events,
)

VALID = {
    "sourcetype": SYSMON,
    "_time": "2026-08-03T20:24:09.123456+00:00",
    "Computer": "WINDETECT-01",
    "EventCode": 10,
    "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
    "GrantedAccess": "0x1fffff",
}


def make_event(**overrides):
    event = dict(VALID)
    event.update(overrides)
    return event


@pytest.mark.parametrize("missing", ["sourcetype", "_time", "Computer", "EventCode"])
def test_missing_common_field_fails(missing):
    event = make_event()
    del event[missing]
    with pytest.raises(SchemaError, match="missing required field"):
        validate_event(event, "ctx")


def test_unknown_sourcetype_fails():
    with pytest.raises(SchemaError, match="unknown sourcetype"):
        validate_event(make_event(sourcetype="syslog"), "ctx")


@pytest.mark.parametrize("bad", [True, "10", 10.5, None])
def test_non_int_event_code_fails(bad):
    with pytest.raises(SchemaError, match="EventCode must be an int"):
        validate_event(make_event(EventCode=bad), "ctx")


def test_non_string_time_fails():
    with pytest.raises(SchemaError, match="_time must be an ISO-8601 string"):
        validate_event(make_event(_time=1754252649), "ctx")


def test_naive_time_fails():
    with pytest.raises(SchemaError, match="UTC offset"):
        validate_event(make_event(_time="2026-08-03T20:24:09.123456"), "ctx")


def test_non_object_event_fails():
    with pytest.raises(SchemaError, match="JSON object"):
        validate_events([5], "ctx")


def test_unparseable_time_fails():
    with pytest.raises(SchemaError, match="does not parse as ISO-8601"):
        validate_event(make_event(_time="not-a-date"), "ctx")


def test_event_code_specific_required_fields():
    event = make_event()
    del event["TargetImage"]
    with pytest.raises(SchemaError, match="missing required field 'TargetImage'"):
        validate_event(event, "ctx")


def test_unpaired_sourcetype_and_code_needs_only_common_fields():
    validate_event(make_event(sourcetype=SECURITY, EventCode=9999), "ctx")


def test_security_4624_required_fields():
    event = {
        "sourcetype": SECURITY,
        "_time": "2026-08-03T20:25:59.500000+00:00",
        "Computer": "WINDETECT-01",
        "EventCode": 4624,
        "TargetUserName": "alice",
        "TargetDomainName": "WORKGROUP",
        "LogonType": "3",
        "IpAddress": "192.168.10.44",
    }
    validate_event(event, "ctx")


def test_powershell_4104_required_fields():
    event = {
        "sourcetype": POWERSHELL,
        "_time": "2026-08-03T20:26:40+00:00",
        "Computer": "WINDETECT-01",
        "EventCode": 4104,
        "ScriptBlockText": "whoami",
        "ScriptBlockId": "abc",
    }
    validate_event(event, "ctx")
    del event["ScriptBlockText"]
    with pytest.raises(SchemaError, match="missing required field 'ScriptBlockText'"):
        validate_event(event, "ctx")


def test_validate_events_empty_fails():
    with pytest.raises(SchemaError, match="no events"):
        validate_events([], "ctx")


def test_validate_events_indexes_failures():
    with pytest.raises(SchemaError, match=r"ctx\[1\]"):
        validate_events([VALID, make_event(EventCode="x")], "ctx")
