"""The windetect command line.

Subcommands:

- ``capture``   slice a VM capture export into per-detection fixtures
- ``validate``  prove detections.yaml, every rule file, and every fixture
                that already exists conform to the contract
- ``replay``    replay every fixture through a live lab Splunk and assert
                attack fixtures fire while benign fixtures stay silent
- ``report``    coverage table across the kill chain; ``--layer`` emits an
                ATT&CK Navigator layer
- ``build-app`` generate an installable Splunk app from the detections
- ``new``       scaffold a detection entry in detections.yaml
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from windetect import app as app_mod
from windetect import capture as capture_mod
from windetect import report as report_mod
from windetect import schema
from windetect.evtx import CaptureError
from windetect.model import (
    EXPECT_ATTACK,
    EXPECT_BENIGN,
    SOURCES,
    Model,
    ModelError,
    check_rules,
    load_model,
)
from windetect.replay import ReplayError, check_model_for_replay, format_outcome, run_replay
from windetect.splunk import SplunkClient, SplunkError, config_from_env


class CommandError(Exception):
    """User-facing failure; text goes to stderr, exit code is 1."""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="windetect", description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="project root (default: cwd)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    cap = subparsers.add_parser("capture", help="slice capture exports into fixtures")
    cap.add_argument("exports", nargs="+", type=Path, help="stage-NN-*.windetect.xml files")
    cap.add_argument("--stage", help="stage id or numeric prefix (attack only)")
    cap.add_argument(
        "--benign", action="store_true", help="slice benign fixtures for all detections"
    )

    subparsers.add_parser("validate", help="validate detections.yaml, rules, and existing fixtures")

    rep = subparsers.add_parser("replay", help="replay fixtures through a live Splunk")
    rep.add_argument("--url", help="Splunk REST url ($WD_SPLUNK_URL)")
    rep.add_argument("--hec-url", help="Splunk HEC url ($WD_SPLUNK_HEC_URL)")
    rep.add_argument("--user", help="admin username ($WD_SPLUNK_USER)")
    rep.add_argument("--password", help="admin password ($WD_SPLUNK_PASSWORD)")
    rep.add_argument("--index", help="target index ($WD_SPLUNK_INDEX)")
    rep.add_argument("--run-id", help="replay marker (default: random)")

    cov = subparsers.add_parser("report", help="kill-chain coverage report")
    cov.add_argument("--markdown", action="store_true")
    cov.add_argument("--layer", type=Path, metavar="PATH", help="write an ATT&CK Navigator layer")

    bld = subparsers.add_parser("build-app", help="generate an installable Splunk app")
    bld.add_argument("--out", type=Path, required=True, help="output directory for the app")
    bld.add_argument("--index", help="deployment index the saved searches scope to")

    new = subparsers.add_parser("new", help="scaffold a detection entry")
    new.add_argument("id")
    new.add_argument("--stage", required=True, help="stage id or numeric prefix")
    new.add_argument("--title", required=True)
    new.add_argument("--technique", action="append", required=True, dest="techniques")
    new.add_argument(
        "--slice",
        action="append",
        default=[],
        dest="slices",
        metavar="SOURCE=CODE[,CODE]",
        help="e.g. sysmon=10,3 (repeatable)",
    )
    return parser


def _command_capture(model: Model, args: argparse.Namespace) -> int:
    expect = EXPECT_BENIGN if args.benign else EXPECT_ATTACK
    if args.benign and args.stage:
        raise CommandError("--benign and --stage are mutually exclusive")
    outcomes = capture_mod.run_capture(
        model.root, model, args.exports, expect=expect, stage_ref=args.stage
    )
    for outcome in outcomes:
        print(f"wrote {outcome.path} ({outcome.events} events) for {outcome.detection_id}")
    return 0


def _command_validate(model: Model) -> int:
    problems: list[str] = []
    try:
        check_rules(model)
    except ModelError as exc:
        problems.extend(str(exc).split("; "))

    for detection in model.detections:
        for ref in detection.fixtures:
            path = model.root / ref.events
            if not path.is_file():
                print(f"note: {ref.events} not sliced yet")
                continue
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                problems.append(f"{ref.events}: not valid JSON: {exc}")
                continue
            except OSError as exc:
                problems.append(f"{ref.events}: unreadable: {exc}")
                continue
            if not isinstance(raw, list):
                problems.append(f"{ref.events}: must be a JSON array of events")
                continue
            try:
                schema.validate_events(raw, str(ref.events))
            except schema.SchemaError as exc:
                problems.append(f"{ref.events}: {exc}")

    if not model.detections:
        print("no detections yet; stages load clean")

    if problems:
        raise CommandError("\n".join(problems))
    print(f"valid: {len(model.stages)} stages, {len(model.detections)} detections")
    return 0


def _command_replay(model: Model, args: argparse.Namespace) -> int:
    base = config_from_env()
    overrides = {
        "rest_url": args.url,
        "hec_url": args.hec_url,
        "username": args.user,
        "password": args.password,
        "index": args.index,
    }
    config = dataclasses.replace(base, **{k: v for k, v in overrides.items() if v is not None})
    if not model.detections:
        print("no detections to replay yet; fixtures land as captures are recorded")
        return 0
    check_model_for_replay(model)
    client = SplunkClient(config)
    outcomes = run_replay(model, client, run_id=args.run_id)
    for outcome in outcomes:
        print(format_outcome(outcome))
    failed = [outcome for outcome in outcomes if not outcome.passed]
    if failed:
        raise CommandError(f"{len(failed)}/{len(outcomes)} detection(s) failed replay")
    print(f"all {len(outcomes)} detection(s) passed replay")
    return 0


def _command_report(model: Model, args: argparse.Namespace) -> int:
    if args.layer:
        args.layer.write_text(report_mod.coverage_layer_json(model), encoding="utf-8")
        print(f"wrote {args.layer}")
        return 0
    if args.markdown:
        print(report_mod.coverage_markdown(model))
    else:
        print(report_mod.coverage_text(model))
    return 0


def _command_build_app(model: Model, args: argparse.Namespace) -> int:
    index = args.index or config_from_env().index
    out = app_mod.build_app(model, args.out, index=index)
    print(
        f"built Splunk app with {len(model.detections)} saved search(es) at {out}; "
        "install it under $SPLUNK_HOME/etc/apps/"
    )
    return 0


def _command_new(model: Model, args: argparse.Namespace) -> int:
    stage = model.stage(args.stage)
    slice_spec: dict[str, list[int]] = {}
    for chunk in args.slices:
        source, _, codes_raw = chunk.partition("=")
        if source not in SOURCES or not codes_raw:
            raise CommandError(f"--slice must look like sysmon=10,3, got {chunk!r}")
        try:
            codes = [int(code) for code in codes_raw.split(",")]
        except ValueError as exc:
            raise CommandError(f"--slice codes must be integers in {chunk!r}") from exc
        slice_spec.setdefault(source, []).extend(codes)

    if any(detection.id == args.id for detection in model.detections):
        raise CommandError(f"detection id {args.id!r} already exists")

    entry_lines = [
        f"  - id: {args.id}",
        f"    title: {args.title}",
        f"    rule: rules/{args.id}.spl",
        f"    stage: {stage.id}",
        f"    attack: [{', '.join(args.techniques)}]",
    ]
    if slice_spec:
        entry_lines.append("    slice:")
        for source, codes in slice_spec.items():
            entry_lines.append(f"      {source}: [{', '.join(str(c) for c in codes)}]")
    entry_lines += [
        "    fixtures:",
        f"      - events: fixtures/{args.id}.attack.json",
        "        expect: attack",
        f"      - events: fixtures/{args.id}.benign.json",
        "        expect: benign",
    ]
    _append_detection(model.root / "detections.yaml", entry_lines)
    print(f"added {args.id} to detections.yaml")
    print(f"next: write rules/{args.id}.spl, then slice fixtures with 'windetect capture'")
    return 0


def _append_detection(yaml_path: Path, entry_lines: list[str]) -> None:
    text = yaml_path.read_text(encoding="utf-8")
    lines = text.splitlines()

    for i, line in enumerate(lines):
        if line.strip() == "detections: []":
            lines[i : i + 1] = ["detections:", *entry_lines]
            yaml_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return

    for i, line in enumerate(lines):
        if line.rstrip() == "detections:":
            j = i + 1
            while j < len(lines) and (lines[j].startswith("  ") or not lines[j].strip()):
                j += 1
            lines[j:j] = entry_lines
            yaml_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return

    raise CommandError(
        "could not find a 'detections:' section in detections.yaml; add the entry by hand"
    )


_HANDLERS = {
    "capture": lambda model, args: _command_capture(model, args),
    "validate": lambda model, args: _command_validate(model),
    "replay": lambda model, args: _command_replay(model, args),
    "report": lambda model, args: _command_report(model, args),
    "build-app": lambda model, args: _command_build_app(model, args),
    "new": lambda model, args: _command_new(model, args),
}


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        model = load_model(args.root)
        return _HANDLERS[args.command](model, args)
    except (
        CommandError,
        ModelError,
        CaptureError,
        ReplayError,
        SplunkError,
        schema.SchemaError,
        capture_mod.SliceError,
    ) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
