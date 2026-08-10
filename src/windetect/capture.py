"""Slice a capture export into per-detection fixtures.

One capture export feeds many detections. Each detection declares a ``slice``
(channel -> event codes) in detections.yaml; the slicer applies it to the
parsed export and writes the result to the detection's fixture. Slicing is
event-code level only - every matching event lands verbatim, so the rule
still has to earn its matches on real field values.

Attack slices must come from an export whose ``stage`` attribute matches the
detection's stage; benign slices come from scripted normal-usage windows and
are cut for every detection at once. An empty slice is an error: a fixture
that contains none of the events its rule searches proves nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from windetect import schema
from windetect.evtx import CaptureAttrs, parse_capture
from windetect.model import EXPECT_ATTACK, Model, ModelError

_SOURCE_TO_SOURCETYPE = {
    "sysmon": schema.SYSMON,
    "security": schema.SECURITY,
    "powershell": schema.POWERSHELL,
}


class SliceError(ValueError):
    """A slice produced nothing usable; the capture or the spec is wrong."""


@dataclass(frozen=True)
class SliceOutcome:
    detection_id: str
    expect: Literal["attack", "benign"]
    path: Path
    events: int


def slice_events(
    events: list[dict[str, Any]], slice_spec: dict[str, tuple[int, ...]]
) -> list[dict[str, Any]]:
    if not slice_spec:
        return list(events)
    wanted = {
        (_SOURCE_TO_SOURCETYPE[source], code)
        for source, codes in slice_spec.items()
        for code in codes
    }
    return [event for event in events if (event["sourcetype"], event["EventCode"]) in wanted]


def write_fixture(root: Path, rel_path: Path, events: list[dict[str, Any]]) -> Path:
    path = root / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")
    return path


def run_capture(
    root: Path,
    model: Model,
    xml_paths: list[Path],
    *,
    expect: Literal["attack", "benign"],
    stage_ref: str | None = None,
) -> list[SliceOutcome]:
    if not xml_paths:
        raise SliceError("no capture exports given")
    parsed = [parse_capture(path) for path in xml_paths]
    events: list[dict[str, Any]] = []
    for _, parsed_events in parsed:
        events.extend(parsed_events)
    events.sort(key=lambda e: e["_time"])

    if expect == EXPECT_ATTACK:
        resolved = [
            (path, attrs, _resolve_capture_stage(model, attrs))
            for path, (attrs, _) in zip(xml_paths, parsed, strict=True)
        ]
        detected_stage = resolved[0][2]
        mismatched = [
            f"{path}: {stage.id}" for path, _, stage in resolved if stage.id != detected_stage.id
        ]
        if mismatched:
            raise SliceError(
                f"exports declare different stages ({resolved[0][0]}: {detected_stage.id}; "
                + "; ".join(mismatched)
                + "); slice one stage at a time"
            )
        chosen = model.stage(stage_ref) if stage_ref is not None else detected_stage
        if chosen.id != detected_stage.id:
            raise SliceError(
                f"capture declares stage {resolved[0][1].stage!r} ({detected_stage.id}) "
                f"but --stage selected {chosen.id}"
            )
        targets = model.stage_detections(chosen.id)
        if not targets:
            raise SliceError(f"stage {chosen.id} has no detections in detections.yaml")
    else:
        targets = model.detections

    outcomes: list[SliceOutcome] = []
    for detection in targets:
        ref = detection.fixture_for(expect)
        sliced = slice_events(events, detection.slice)
        if not sliced:
            raise SliceError(
                f"detection {detection.id!r}: slice matched no events in the capture; "
                "check the slice spec or widen the capture window"
            )
        schema.validate_events(sliced, f"{detection.id}.{expect}")
        path = write_fixture(root, ref.events, sliced)
        outcomes.append(SliceOutcome(detection.id, expect, path, len(sliced)))
    return outcomes


def _resolve_capture_stage(model: Model, attrs: CaptureAttrs) -> Any:
    try:
        return model.stage(attrs.stage)
    except ModelError as exc:
        raise SliceError(
            f"capture declares stage {attrs.stage!r}, which detections.yaml does not define"
        ) from exc
