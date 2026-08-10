from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers import DEFAULT_YAML, DETECTION_ID, build_root
from windetect.cli import main
from windetect.model import load_model


def run_cli(*argv: str) -> int:
    return main(list(argv))


def test_validate_repo(repo_root: Path, capsys):
    assert run_cli("--root", str(repo_root), "validate") == 0
    assert "0 detections" in capsys.readouterr().out


def test_report_repo(repo_root: Path, capsys):
    assert run_cli("--root", str(repo_root), "report") == 0
    assert "No detections yet" in capsys.readouterr().out


def test_report_repo_markdown(repo_root: Path, capsys):
    assert run_cli("--root", str(repo_root), "report", "--markdown") == 0
    assert capsys.readouterr().out.startswith("| Stage")


def test_capture_attack_via_cli(make_root, sample_capture: Path, capsys):
    root = make_root()
    assert run_cli("--root", str(root), "capture", str(sample_capture), "--stage", "03") == 0
    out = capsys.readouterr().out
    assert DETECTION_ID in out
    fixture = root / f"fixtures/{DETECTION_ID}.attack.json"
    assert json.loads(fixture.read_text(encoding="utf-8"))


def test_capture_infers_stage(make_root, sample_capture: Path):
    root = make_root()
    assert run_cli("--root", str(root), "capture", str(sample_capture)) == 0
    assert (root / f"fixtures/{DETECTION_ID}.attack.json").is_file()


def test_capture_benign_via_cli(make_root, sample_capture: Path):
    root = make_root()
    assert run_cli("--root", str(root), "capture", str(sample_capture), "--benign") == 0
    assert (root / f"fixtures/{DETECTION_ID}.benign.json").is_file()


def test_capture_benign_and_stage_conflict(make_root, sample_capture: Path, capsys):
    root = make_root()
    rc = run_cli("--root", str(root), "capture", str(sample_capture), "--benign", "--stage", "03")
    assert rc == 1
    assert "mutually exclusive" in capsys.readouterr().err


def test_capture_stage_mismatch(make_root, sample_capture: Path, capsys):
    root = make_root(
        yaml_text=DEFAULT_YAML.replace(
            "stages:",
            "stages:\n  - id: 04-discovery\n    techniques: [T1087.002]",
            1,
        )
    )
    rc = run_cli("--root", str(root), "capture", str(sample_capture), "--stage", "04")
    assert rc == 1
    assert "--stage selected" in capsys.readouterr().err


def test_validate_missing_rule_fails(make_root, capsys):
    root = make_root(write_rule=False)
    assert run_cli("--root", str(root), "validate") == 1
    assert "missing rule file" in capsys.readouterr().err


def test_validate_notes_unsliced_fixtures(make_root, capsys):
    root = make_root()
    assert run_cli("--root", str(root), "validate") == 0
    assert "not sliced yet" in capsys.readouterr().out


def test_validate_corrupt_fixture_fails(make_root, capsys):
    root = make_root()
    fixture = root / f"fixtures/{DETECTION_ID}.attack.json"
    fixture.write_text("{oops", encoding="utf-8")
    assert run_cli("--root", str(root), "validate") == 1
    assert "not valid JSON" in capsys.readouterr().err


def test_validate_fixture_with_schema_violation_fails(make_root, capsys):
    root = make_root()
    fixture = root / f"fixtures/{DETECTION_ID}.attack.json"
    fixture.write_text('[{"sourcetype": "syslog"}]', encoding="utf-8")
    assert run_cli("--root", str(root), "validate") == 1
    assert "missing required field" in capsys.readouterr().err


def test_replay_no_detections(tmp_path, capsys):
    root = build_root(
        tmp_path,
        yaml_text="version: 1\n\nstages:\n  - id: 03-credential-access\n"
        "    techniques: [T1003.001]\n\ndetections: []\n",
    )
    assert run_cli("--root", str(root), "replay") == 0
    assert "no detections to replay" in capsys.readouterr().out


def test_replay_missing_fixture_fails_without_network(make_root, capsys):
    root = make_root()
    assert run_cli("--root", str(root), "replay") == 1
    assert "missing fixture" in capsys.readouterr().err


def test_new_scaffolds_detection(make_root, capsys):
    root = make_root()
    rc = run_cli(
        "--root",
        str(root),
        "new",
        "lsass-dump-lineage",
        "--stage",
        "03",
        "--title",
        "LSASS dump process lineage",
        "--technique",
        "T1003.001",
        "--slice",
        "sysmon=1",
        "--slice",
        "security=4688",
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "added lsass-dump-lineage" in out

    model = load_model(root)
    (detection,) = [d for d in model.detections if d.id == "lsass-dump-lineage"]
    assert detection.slice == {"sysmon": (1,), "security": (4688,)}
    assert detection.attack == ("T1003.001",)

    assert run_cli("--root", str(root), "validate") == 1
    (root / "rules" / "lsass-dump-lineage.spl").write_text(
        'EventCode=1 ParentImage="C:\\Windows\\System32\\rundll32.exe"', encoding="utf-8"
    )
    assert run_cli("--root", str(root), "validate") == 0


def test_new_appends_to_existing_block(make_root):
    root = make_root()
    for new_id in ("second-detection", "third-detection"):
        assert (
            run_cli(
                "--root",
                str(root),
                "new",
                new_id,
                "--stage",
                "03",
                "--title",
                f"title {new_id}",
                "--technique",
                "T1003.001",
            )
            == 0
        )
    model = load_model(root)
    assert [d.id for d in model.detections] == [DETECTION_ID, "second-detection", "third-detection"]


def test_new_duplicate_id_fails(make_root, capsys):
    root = make_root()
    rc = run_cli(
        "--root",
        str(root),
        "new",
        DETECTION_ID,
        "--stage",
        "03",
        "--title",
        "dup",
        "--technique",
        "T1003.001",
    )
    assert rc == 1
    assert "already exists" in capsys.readouterr().err


def test_new_unknown_stage_fails(make_root, capsys):
    root = make_root()
    rc = run_cli(
        "--root",
        str(root),
        "new",
        "x",
        "--stage",
        "99",
        "--title",
        "t",
        "--technique",
        "T1003.001",
    )
    assert rc == 1
    assert "unknown stage" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("bad_args", "message"),
    [
        (("Bad_Id", "--title", "t", "--technique", "T1003.001"), "kebab-case"),
        (("x", "--title", "t", "--technique", "t1003"), "T1003.001"),
        (("x", "--title", "t", "--technique", "T1548.002"), "not listed for stage"),
        (("x", "--title", "  ", "--technique", "T1003.001"), "must not be empty"),
        (("x", "--title", "colon: title", "--technique", "T1003.001"), "YAML"),
        (("x", "--title", "[flow]", "--technique", "T1003.001"), "YAML"),
    ],
)
def test_new_invalid_input_rejected_before_write(make_root, capsys, bad_args, message):
    root = make_root()
    before = (root / "detections.yaml").read_text(encoding="utf-8")
    rc = run_cli("--root", str(root), "new", bad_args[0], "--stage", "03", *bad_args[1:])
    assert rc == 1
    assert message in capsys.readouterr().err
    # The file the tool would have corrupted is untouched and still loads.
    assert (root / "detections.yaml").read_text(encoding="utf-8") == before
    load_model(root)


@pytest.mark.parametrize("bad_slice", ["netflow=10", "sysmon=", "sysmon=x"])
def test_new_bad_slice_fails(make_root, capsys, bad_slice):
    root = make_root()
    rc = run_cli(
        "--root",
        str(root),
        "new",
        "x",
        "--stage",
        "03",
        "--title",
        "t",
        "--technique",
        "T1003.001",
        "--slice",
        bad_slice,
    )
    assert rc == 1
    assert "slice" in capsys.readouterr().err


def test_new_without_detections_marker_fails(tmp_path, capsys):
    root = build_root(
        tmp_path,
        yaml_text="version: 1\n\nstages:\n  - id: 03-credential-access\n"
        "    techniques: [T1003.001]\n",
    )
    rc = run_cli(
        "--root",
        str(root),
        "new",
        "x",
        "--stage",
        "03",
        "--title",
        "t",
        "--technique",
        "T1003.001",
    )
    assert rc == 1
    assert "by hand" in capsys.readouterr().err


def test_missing_root_fails(capsys):
    assert run_cli("--root", "/nonexistent-windetect", "validate") == 1
    assert "no detections.yaml" in capsys.readouterr().err


def test_build_app_via_cli(make_root, tmp_path, capsys):
    root = make_root()
    out = tmp_path / "app"
    assert run_cli("--root", str(root), "build-app", "--out", str(out)) == 0
    assert "1 saved search(es)" in capsys.readouterr().out
    assert (out / "default" / "savedsearches.conf").is_file()


def test_build_app_requires_out(repo_root, capsys):
    with pytest.raises(SystemExit):
        run_cli("--root", str(repo_root), "build-app")


def test_report_layer_via_cli(make_root, tmp_path, capsys):
    root = make_root()
    layer = tmp_path / "layer.json"
    assert run_cli("--root", str(root), "report", "--layer", str(layer)) == 0
    assert str(layer) in capsys.readouterr().out
    parsed = json.loads(layer.read_text(encoding="utf-8"))
    assert parsed["techniques"][0]["techniqueID"] == "T1003.001"
