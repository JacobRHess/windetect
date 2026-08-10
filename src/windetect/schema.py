"""The fixture event contract: real Windows field names, nothing bespoke.

windetect fixtures are slices of genuine captures (Sysmon, Security,
PowerShell operational channels exported as EVTX from the capture VM), and
they carry the field names a production Splunk deployment extracts via the
standard add-ons: ``EventCode``, ``Image``, ``CommandLine``,
``TargetUserName``. The rules in ``rules/`` search those names directly, so a
detection that passes the replay here runs unmodified in a real deployment.

Every event carries ``sourcetype`` (one of the three channels this project
captures) and ``_time`` (ISO-8601 UTC, normalized from the EVTX SystemTime).
The harness sets each event's Splunk ``_time`` from this value, so windowed
searches measure the captured timeline rather than ingest time.

``validate_event`` is run over every fixture in the test suite, so a fixture
that drifts from a capture export fails loudly instead of silently never
matching a rule.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

SYSMON = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
SECURITY = "WinEventLog:Security"
POWERSHELL = "WinEventLog:Microsoft-Windows-PowerShell/Operational"

SOURCETYPES = (SYSMON, SECURITY, POWERSHELL)

_COMMON = ("sourcetype", "_time", "Computer", "EventCode")

# Additional fields each (sourcetype, EventCode) pair must carry. These are
# the fields the rules actually search; a capture export that lost one of them
# (channel misconfiguration, EVTX truncation) must not reach the fixtures.
_REQUIRED: dict[tuple[str, int], tuple[str, ...]] = {
    (SYSMON, 1): ("Image", "CommandLine", "ParentImage", "User", "ProcessId"),
    (SYSMON, 3): ("Image", "DestinationIp", "DestinationPort", "User"),
    (SYSMON, 10): ("SourceImage", "TargetImage", "GrantedAccess"),
    (SYSMON, 11): ("TargetFilename", "Image"),
    (SYSMON, 13): ("TargetObject", "Details", "Image"),
    (SYSMON, 22): ("QueryName", "Image"),
    (SYSMON, 23): ("TargetFilename", "Image", "User"),
    (SECURITY, 4624): ("TargetUserName", "TargetDomainName", "LogonType", "IpAddress"),
    (SECURITY, 4625): ("TargetUserName", "LogonType", "IpAddress"),
    (SECURITY, 4672): ("SubjectUserName", "SubjectDomainName"),
    (SECURITY, 4688): ("NewProcessName", "NewProcessId", "SubjectUserName"),
    (SECURITY, 4697): ("ServiceName", "ServiceFileName", "SubjectUserName"),
    (SECURITY, 4698): ("TaskName", "SubjectUserName"),
    (SECURITY, 1102): (),
    (POWERSHELL, 4104): ("ScriptBlockText", "ScriptBlockId"),
}


class SchemaError(ValueError):
    """A fixture event does not conform to the windetect schema."""


def validate_event(event: dict[str, Any], ctx: str) -> None:
    if not isinstance(event, dict):
        raise SchemaError(f"{ctx}: event must be a JSON object, got {type(event).__name__}")
    for field in _COMMON:
        if field not in event:
            raise SchemaError(f"{ctx}: missing required field {field!r}")

    sourcetype = event["sourcetype"]
    if sourcetype not in SOURCETYPES:
        raise SchemaError(f"{ctx}: unknown sourcetype {sourcetype!r}")

    event_code = event["EventCode"]
    if isinstance(event_code, bool) or not isinstance(event_code, int):
        raise SchemaError(f"{ctx}: EventCode must be an int, got {event_code!r}")

    timestamp = event["_time"]
    if not isinstance(timestamp, str):
        raise SchemaError(f"{ctx}: _time must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise SchemaError(f"{ctx}: _time does not parse as ISO-8601: {timestamp!r}") from exc
    # Naive timestamps would be read in the local machine timezone at replay,
    # indexing the same fixture at different times on different hosts.
    if parsed.tzinfo is None:
        raise SchemaError(f"{ctx}: _time must carry a UTC offset: {timestamp!r}")

    for field in _REQUIRED.get((sourcetype, event_code), ()):
        if field not in event:
            raise SchemaError(
                f"{ctx}: {sourcetype} event {event_code} is missing required field {field!r}"
            )


def validate_events(events: list[dict[str, Any]], ctx: str) -> None:
    if not events:
        raise SchemaError(f"{ctx}: fixture contains no events")
    for i, event in enumerate(events):
        validate_event(event, f"{ctx}[{i}]")
