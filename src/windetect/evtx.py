"""Parse VM capture exports into schema-conformant events.

``vm/Export-Stage.ps1`` writes a ``<windetect-capture>`` wrapper around the
raw EVTX XML of every event in the window (``Get-WinEvent ... .ToXml()``),
newest first, across all three channels. This module turns that file back
into the flat event dicts the schema describes:

- ``Channel`` maps to the production ``sourcetype`` (an unmapped channel is
  an error, not a silent drop)
- ``EventID`` becomes ``EventCode`` (int), ``Computer`` is copied through
- ``TimeCreated/@SystemTime`` is normalized to ISO-8601 UTC (EVTX carries
  100ns precision and a ``Z`` suffix; fixtures carry microseconds)
- ``EventData/Data/@Name`` become the event fields - the real Windows field
  names the rules search

Events are returned oldest-first regardless of export order.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element

from defusedxml.ElementTree import ParseError, iterparse

from windetect.schema import POWERSHELL, SECURITY, SYSMON

CHANNEL_SOURCETYPES = {
    "Security": SECURITY,
    "Microsoft-Windows-Sysmon/Operational": SYSMON,
    "Microsoft-Windows-PowerShell/Operational": POWERSHELL,
}

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_SYSTEM_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$")


class CaptureError(ValueError):
    """A capture export (or a timestamp inside it) cannot be parsed."""


@dataclass(frozen=True)
class CaptureAttrs:
    stage: str
    host: str
    start: str
    end: str


def normalize_timestamp(raw: str, *, ctx: str) -> str:
    match = _SYSTEM_TIME.match(raw.strip())
    if not match:
        raise CaptureError(f"{ctx}: unparseable SystemTime {raw!r}")
    base, frac, tz = match.groups()
    micros = (frac or "").ljust(6, "0")[:6]
    offset = "+00:00" if tz == "Z" else tz
    parsed = datetime.fromisoformat(f"{base}.{micros}{offset}")
    return parsed.astimezone(UTC).isoformat(timespec="microseconds")


def parse_capture(path: Path) -> tuple[CaptureAttrs, list[dict[str, Any]]]:
    attrs: CaptureAttrs | None = None
    events: list[dict[str, Any]] = []
    try:
        for action, element in iterparse(path, events=("start", "end")):
            if action == "start" and attrs is None:
                attrs = _root_attrs(element, path)
            elif action == "end" and element.tag == f"{_NS}Event":
                events.append(_parse_event(element, path))
                element.clear()
    except ParseError as exc:
        raise CaptureError(f"{path}: invalid capture XML: {exc}") from exc

    if attrs is None:
        raise CaptureError(f"{path}: empty capture file")
    events.sort(key=lambda e: e["_time"])
    return attrs, events


def _root_attrs(element: Element, path: Path) -> CaptureAttrs:
    if element.tag != "windetect-capture":
        raise CaptureError(
            f"{path}: expected a <windetect-capture> root, got <{element.tag}>; "
            "is this a vm/Export-Stage.ps1 export?"
        )
    missing = [name for name in ("stage", "host", "start", "end") if name not in element.attrib]
    if missing:
        raise CaptureError(f"{path}: capture root is missing attribute(s) {', '.join(missing)}")
    return CaptureAttrs(
        stage=element.attrib["stage"],
        host=element.attrib["host"],
        start=element.attrib["start"],
        end=element.attrib["end"],
    )


def _parse_event(element: Element, path: Path) -> dict[str, Any]:
    ctx = f"{path}: event"

    def child(tag: str) -> Element:
        found = element.find(f"{_NS}System/{_NS}{tag}")
        if found is None:
            raise CaptureError(f"{ctx}: missing System/{tag}")
        return found

    channel = child("Channel").text or ""
    sourcetype = CHANNEL_SOURCETYPES.get(channel)
    if sourcetype is None:
        raise CaptureError(f"{ctx}: unmapped channel {channel!r}")

    event_id = child("EventID").text or ""
    if not event_id.isdigit():
        raise CaptureError(f"{ctx}: invalid EventID {event_id!r}")

    created = child("TimeCreated")
    system_time = created.get("SystemTime")
    if not system_time:
        raise CaptureError(f"{ctx}: TimeCreated without SystemTime")
    computer = child("Computer").text or ""
    if not computer:
        raise CaptureError(f"{ctx}: missing Computer")

    event: dict[str, Any] = {
        "sourcetype": sourcetype,
        "_time": normalize_timestamp(system_time, ctx=ctx),
        "Computer": computer,
        "EventCode": int(event_id),
    }
    event_data = element.find(f"{_NS}EventData")
    if event_data is not None:
        for data in event_data.findall(f"{_NS}Data"):
            name = data.get("Name")
            if name:
                event[name] = data.text or ""
    return event
