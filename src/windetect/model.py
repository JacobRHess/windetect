"""The detections.yaml contract, loaded and proven correct before anything runs.

``detections.yaml`` is the single source of truth: stages, and for each
detection its rule path, MITRE techniques, the capture slice that produces
its fixtures, and the fixture pair itself. Everything downstream - the
capture slicer, the replay engine, the coverage report, the CI gate - is
derived from this file, so it is validated hard at load time:

- stage ids are unique and shaped ``NN-slug``; techniques are MITRE ids
- detection ids are unique kebab-case; each detection references a stage
  defined in the same file
- each detection carries exactly one ``attack`` and one ``benign`` fixture
  at ``fixtures/<id>.<expect>.json``
- the slice, when present, names only captured channels and integer event
  codes

Rules get a contract of their own (``check_rule``): the replay harness
prepends an index + run scope to the rule text, so a rule must start with
bare search terms (no leading command), and must not pin its own index or
time window - that binding belongs to the deployment, not the rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

VERSION = 1

Expect = Literal["attack", "benign"]
EXPECT_ATTACK: Expect = "attack"
EXPECT_BENIGN: Expect = "benign"
EXPECTS: tuple[Expect, ...] = (EXPECT_ATTACK, EXPECT_BENIGN)

SOURCE_SYSMON = "sysmon"
SOURCE_SECURITY = "security"
SOURCE_POWERSHELL = "powershell"
SOURCES = (SOURCE_SYSMON, SOURCE_SECURITY, SOURCE_POWERSHELL)

_STAGE_ID = re.compile(r"^\d{2}-[a-z0-9]+(-[a-z0-9]+)*$")
_DETECTION_ID = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_SLICE_CODE = re.compile(r"^\d{1,5}$")

# Commands that must never open a rule: the harness prepends bare search
# terms, and these forms do not combine with a bare-term prefix.
_LEADING_COMMANDS = (
    "search",
    "from",
    "datamodel",
    "eventcount",
    "loadjob",
    "inputlookup",
    "tstats",
)

_NO_TIME_OR_INDEX = re.compile(r"\b(index|earliest|latest)\s*=")


class ModelError(ValueError):
    """detections.yaml (or a referenced rule/fixture) violates the contract."""


@dataclass(frozen=True)
class Stage:
    id: str
    techniques: tuple[str, ...]


@dataclass(frozen=True)
class FixtureRef:
    events: Path
    expect: Expect


@dataclass(frozen=True)
class Detection:
    id: str
    title: str
    rule: Path
    stage: str
    attack: tuple[str, ...]
    slice: dict[str, tuple[int, ...]]
    fixtures: tuple[FixtureRef, ...]

    def fixture_for(self, expect: str) -> FixtureRef:
        for ref in self.fixtures:
            if ref.expect == expect:
                return ref
        raise ModelError(f"detection {self.id!r} has no {expect} fixture")


@dataclass(frozen=True)
class Model:
    root: Path
    version: int
    stages: tuple[Stage, ...]
    detections: tuple[Detection, ...]

    def stage(self, ref: str) -> Stage:
        """Resolve a stage by full id or by numeric prefix ("03")."""
        matches = [s for s in self.stages if s.id == ref or s.id.startswith(f"{ref}-")]
        if not matches:
            raise ModelError(f"unknown stage {ref!r}")
        if len(matches) > 1:
            ids = ", ".join(s.id for s in matches)
            raise ModelError(f"stage reference {ref!r} is ambiguous: {ids}")
        return matches[0]

    def stage_detections(self, stage_id: str) -> tuple[Detection, ...]:
        return tuple(d for d in self.detections if d.stage == stage_id)


def load_model(root: Path) -> Model:
    path = root / "detections.yaml"
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ModelError(f"no detections.yaml under {root}") from exc
    except yaml.YAMLError as exc:
        raise ModelError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ModelError(f"{path}: top level must be a mapping")

    version = raw.get("version")
    if version != VERSION:
        raise ModelError(f"{path}: unsupported version {version!r}, expected {VERSION}")

    stages = _parse_stages(path, raw.get("stages"))
    detections = _parse_detections(path, raw.get("detections"), stages)
    return Model(root=root, version=version, stages=stages, detections=detections)


def _parse_stages(path: Path, raw: Any) -> tuple[Stage, ...]:
    if not isinstance(raw, list) or not raw:
        raise ModelError(f"{path}: stages must be a non-empty list")
    seen: set[str] = set()
    stages: list[Stage] = []
    for entry in raw:
        stage = _parse_stage(path, entry)
        if stage.id in seen:
            raise ModelError(f"{path}: duplicate stage id {stage.id!r}")
        seen.add(stage.id)
        stages.append(stage)
    return tuple(stages)


def _parse_stage(path: Path, entry: Any) -> Stage:
    if not isinstance(entry, dict):
        raise ModelError(f"{path}: each stage must be a mapping, got {entry!r}")
    stage_id, techniques = entry.get("id"), entry.get("techniques")
    if not isinstance(stage_id, str) or not _STAGE_ID.match(stage_id):
        raise ModelError(f"{path}: stage id must match NN-slug, got {stage_id!r}")
    if not isinstance(techniques, list) or not techniques:
        raise ModelError(f"{path}: stage {stage_id} must list techniques")
    for technique in techniques:
        if not isinstance(technique, str) or not _TECHNIQUE_ID.match(technique):
            raise ModelError(f"{path}: stage {stage_id} has invalid technique {technique!r}")
    return Stage(id=stage_id, techniques=tuple(techniques))


def _parse_detections(path: Path, raw: Any, stages: tuple[Stage, ...]) -> tuple[Detection, ...]:
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise ModelError(f"{path}: detections must be a list")
    stage_techniques = {s.id: frozenset(s.techniques) for s in stages}
    seen: set[str] = set()
    detections: list[Detection] = []
    for entry in raw:
        detection = _parse_detection(path, entry, stage_techniques)
        if detection.id in seen:
            raise ModelError(f"{path}: duplicate detection id {detection.id!r}")
        seen.add(detection.id)
        detections.append(detection)
    return tuple(detections)


def _parse_detection(
    path: Path, entry: Any, stage_techniques: dict[str, frozenset[str]]
) -> Detection:
    if not isinstance(entry, dict):
        raise ModelError(f"{path}: each detection must be a mapping, got {entry!r}")

    detection_id = entry.get("id")
    if not isinstance(detection_id, str) or not _DETECTION_ID.match(detection_id):
        raise ModelError(f"{path}: detection id must be kebab-case, got {detection_id!r}")

    title = entry.get("title")
    if not isinstance(title, str) or not title.strip():
        raise ModelError(f"{path}: detection {detection_id} needs a non-empty title")

    rule = entry.get("rule")
    if not isinstance(rule, str) or rule != f"rules/{detection_id}.spl":
        raise ModelError(f"{path}: detection {detection_id} rule must be rules/{detection_id}.spl")

    stage = entry.get("stage")
    if not isinstance(stage, str) or stage not in stage_techniques:
        raise ModelError(f"{path}: detection {detection_id} references unknown stage {stage!r}")

    attack = entry.get("attack")
    if not isinstance(attack, list) or not attack:
        raise ModelError(f"{path}: detection {detection_id} must list attack techniques")
    for technique in attack:
        if not isinstance(technique, str) or not _TECHNIQUE_ID.match(technique):
            raise ModelError(
                f"{path}: detection {detection_id} has invalid technique {technique!r}"
            )
    # Keep the coverage report and the Navigator layer in agreement: every
    # technique a detection claims must be one its stage declares.
    unclaimed = [t for t in attack if t not in stage_techniques[stage]]
    if unclaimed:
        raise ModelError(
            f"{path}: detection {detection_id} claims technique(s) "
            f"{', '.join(unclaimed)} not listed for stage {stage}"
        )

    slice_spec = _parse_slice(path, detection_id, entry.get("slice"))
    fixtures = _parse_fixtures(path, detection_id, entry.get("fixtures"))
    return Detection(
        id=detection_id,
        title=title.strip(),
        rule=Path(rule),
        stage=stage,
        attack=tuple(attack),
        slice=slice_spec,
        fixtures=fixtures,
    )


def _parse_slice(path: Path, detection_id: str, raw: Any) -> dict[str, tuple[int, ...]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict) or not raw:
        raise ModelError(f"{path}: detection {detection_id} slice must be a non-empty mapping")
    parsed: dict[str, tuple[int, ...]] = {}
    for source, codes in raw.items():
        if source not in SOURCES:
            raise ModelError(
                f"{path}: detection {detection_id} slice source {source!r} "
                f"must be one of {', '.join(SOURCES)}"
            )
        if not isinstance(codes, list) or not codes:
            raise ModelError(
                f"{path}: detection {detection_id} slice {source} must list event codes"
            )
        ints: list[int] = []
        for code in codes:
            if isinstance(code, bool) or not isinstance(code, int) or code <= 0:
                raise ModelError(
                    f"{path}: detection {detection_id} slice {source} has invalid code {code!r}"
                )
            ints.append(code)
        parsed[source] = tuple(ints)
    return parsed


def _parse_fixtures(path: Path, detection_id: str, raw: Any) -> tuple[FixtureRef, ...]:
    if not isinstance(raw, list) or not raw:
        raise ModelError(f"{path}: detection {detection_id} must list fixtures")
    refs: list[FixtureRef] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ModelError(f"{path}: detection {detection_id} fixture entries must be mappings")
        events, expect = entry.get("events"), entry.get("expect")
        if expect not in EXPECTS:
            raise ModelError(
                f"{path}: detection {detection_id} fixture expect must be one of {EXPECTS}, "
                f"got {expect!r}"
            )
        expected_path = f"fixtures/{detection_id}.{expect}.json"
        if not isinstance(events, str) or events != expected_path:
            raise ModelError(
                f"{path}: detection {detection_id} {expect} fixture must be {expected_path}"
            )
        refs.append(FixtureRef(events=Path(events), expect=expect))

    kinds = [ref.expect for ref in refs]
    for expect in EXPECTS:
        if kinds.count(expect) != 1:
            raise ModelError(
                f"{path}: detection {detection_id} must have exactly one {expect} fixture"
            )
    return tuple(refs)


def _strip_strings(text: str) -> str:
    return re.sub(r'"[^"]*"|\'[^\']*\'', '""', text)


def check_rule(rule_path: Path) -> str:
    """Load a rule and enforce the replay contract; return its text."""
    try:
        text = rule_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ModelError(f"missing rule file {rule_path}") from exc
    stripped = text.strip()
    if not stripped:
        raise ModelError(f"{rule_path}: rule is empty")

    if text.count('"') % 2 != 0:
        raise ModelError(f"{rule_path}: unbalanced quotes")
    for ch_open, ch_close in (("(", ")"), ("[", "]")):
        if text.count(ch_open) != text.count(ch_close):
            raise ModelError(f"{rule_path}: unbalanced {ch_open}{ch_close} pairs")

    if stripped.startswith("|"):
        raise ModelError(
            f"{rule_path}: rule must not start with a pipeline command; "
            "the replay harness prepends its scope"
        )
    first_token = _strip_strings(stripped).split(None, 1)[0].lower().rstrip(",")
    if first_token in _LEADING_COMMANDS:
        raise ModelError(
            f"{rule_path}: rule must start with bare search terms, not {first_token!r}; "
            "the replay harness prepends its scope"
        )

    scanned = _strip_strings(stripped)
    match = _NO_TIME_OR_INDEX.search(scanned)
    if match:
        raise ModelError(
            f"{rule_path}: rule must not bind {match.group(1)!r}; "
            "index and time binding belong to the deployment, not the rule"
        )
    return stripped


def check_rules(model: Model) -> dict[str, str]:
    """Check every detection's rule file; return {detection id: rule text}."""
    rules: dict[str, str] = {}
    errors: list[str] = []
    for detection in model.detections:
        try:
            rules[detection.id] = check_rule(model.root / detection.rule)
        except ModelError as exc:
            errors.append(str(exc))
    if errors:
        raise ModelError("; ".join(errors))
    return rules
