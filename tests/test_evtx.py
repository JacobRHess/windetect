from __future__ import annotations

from pathlib import Path

import pytest

from windetect.evtx import CaptureError, normalize_timestamp, parse_capture
from windetect.schema import POWERSHELL, SECURITY, SYSMON


def test_parse_sample_capture(sample_capture: Path):
    attrs, events = parse_capture(sample_capture)

    assert attrs.stage == "03"
    assert attrs.host == "WINDETECT-01"
    assert attrs.start.startswith("2026-08-03T20:00:00")
    assert attrs.end.startswith("2026-08-03T20:30:00")

    assert len(events) == 7
    times = [e["_time"] for e in events]
    assert times == sorted(times)

    codes = [(e["sourcetype"], e["EventCode"]) for e in events]
    assert codes == [
        (SYSMON, 1),
        (SECURITY, 1102),
        (SYSMON, 10),
        (SECURITY, 4688),
        (SYSMON, 3),
        (SECURITY, 4624),
        (POWERSHELL, 4104),
    ]

    lsass = next(e for e in events if e["EventCode"] == 10)
    assert lsass["TargetImage"] == "C:\\Windows\\System32\\lsass.exe"
    assert lsass["GrantedAccess"] == "0x1fffff"
    assert lsass["_time"] == "2026-08-03T20:24:09.123456+00:00"

    e4104 = next(e for e in events if e["EventCode"] == 4104)
    assert "MiniDump" in e4104["ScriptBlockText"]

    e1102 = next(e for e in events if e["EventCode"] == 1102)
    assert "unnamed-positional-element" not in e1102.values()

    empty_field = next(e for e in events if e["EventCode"] == 3)
    assert empty_field["SourcePortName"] == ""


def test_unknown_channel_fails(tmp_path: Path):
    xml = (
        '<windetect-capture stage="01" host="H" start="s" end="e">\n'
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>1</EventID>"
        '<TimeCreated SystemTime="2026-08-03T20:00:00.0000000Z"/>'
        "<Channel>Application</Channel><Computer>H</Computer></System>"
        "</Event>\n</windetect-capture>\n"
    )
    path = tmp_path / "bad.xml"
    path.write_text(xml, encoding="utf-8")
    with pytest.raises(CaptureError, match="unmapped channel"):
        parse_capture(path)


def test_wrong_root_element_fails(tmp_path: Path):
    path = tmp_path / "bad.xml"
    path.write_text("<Events></Events>", encoding="utf-8")
    with pytest.raises(CaptureError, match="windetect-capture"):
        parse_capture(path)


def test_missing_root_attributes_fail(tmp_path: Path):
    path = tmp_path / "bad.xml"
    path.write_text('<windetect-capture stage="01"></windetect-capture>', encoding="utf-8")
    with pytest.raises(CaptureError, match="missing attribute"):
        parse_capture(path)


def test_missing_system_child_fails(tmp_path: Path):
    xml = (
        '<windetect-capture stage="01" host="H" start="s" end="e">\n'
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4624</EventID>"
        "<Channel>Security</Channel><Computer>H</Computer></System>"
        "</Event>\n</windetect-capture>\n"
    )
    path = tmp_path / "bad.xml"
    path.write_text(xml, encoding="utf-8")
    with pytest.raises(CaptureError, match="missing System/TimeCreated"):
        parse_capture(path)


def test_invalid_event_id_fails(tmp_path: Path):
    xml = (
        '<windetect-capture stage="01" host="H" start="s" end="e">\n'
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>abc</EventID>"
        '<TimeCreated SystemTime="2026-08-03T20:00:00Z"/>'
        "<Channel>Security</Channel><Computer>H</Computer></System>"
        "</Event>\n</windetect-capture>\n"
    )
    path = tmp_path / "bad.xml"
    path.write_text(xml, encoding="utf-8")
    with pytest.raises(CaptureError, match="invalid EventID"):
        parse_capture(path)


def test_missing_system_time_fails(tmp_path: Path):
    xml = (
        '<windetect-capture stage="01" host="H" start="s" end="e">\n'
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4624</EventID><TimeCreated/>"
        "<Channel>Security</Channel><Computer>H</Computer></System>"
        "</Event>\n</windetect-capture>\n"
    )
    path = tmp_path / "bad.xml"
    path.write_text(xml, encoding="utf-8")
    with pytest.raises(CaptureError, match="TimeCreated without SystemTime"):
        parse_capture(path)


def test_empty_file_fails(tmp_path: Path):
    path = tmp_path / "empty.xml"
    path.write_text("", encoding="utf-8")
    with pytest.raises(CaptureError, match="invalid capture XML"):
        parse_capture(path)


def test_unnamed_positional_wrapper_fails(tmp_path: Path):
    path = tmp_path / "noattrs.xml"
    path.write_text("<windetect-capture/>", encoding="utf-8")
    with pytest.raises(CaptureError, match="missing attribute"):
        parse_capture(path)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-08-03T20:24:09.1234567Z", "2026-08-03T20:24:09.123456+00:00"),
        ("2026-08-03T20:24:09Z", "2026-08-03T20:24:09.000000+00:00"),
        ("2026-08-03T22:24:09.5+02:00", "2026-08-03T20:24:09.500000+00:00"),
    ],
)
def test_normalize_timestamp(raw: str, expected: str):
    assert normalize_timestamp(raw, ctx="t") == expected


def test_normalize_timestamp_malformed():
    with pytest.raises(CaptureError, match="unparseable SystemTime"):
        normalize_timestamp("garbage", ctx="t")
