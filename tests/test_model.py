from __future__ import annotations

from pathlib import Path

import pytest

from helpers import DEFAULT_YAML, DETECTION_ID
from windetect.model import (
    EXPECT_ATTACK,
    EXPECT_BENIGN,
    ModelError,
    check_rule,
    check_rules,
    load_model,
)


def test_repo_detections_yaml_loads(repo_root: Path):
    model = load_model(repo_root)
    assert model.version == 1
    assert len(model.stages) == 8
    assert model.stage("03").id == "03-credential-access"
    detection = model.detections[0]
    assert detection.id == "lsass-dump-command-line"
    assert detection.stage == "03-credential-access"
    assert detection.attack == ("T1003.001",)


def test_full_model_loads(make_root):
    model = load_model(make_root())
    (detection,) = model.detections
    assert detection.id == DETECTION_ID
    assert detection.stage == "03-credential-access"
    assert detection.title == "LSASS process access by an untrusted caller"
    assert detection.attack == ("T1003.001",)
    assert detection.slice == {"sysmon": (10, 1), "security": (4688,)}
    assert detection.fixture_for(EXPECT_ATTACK).events == Path(
        f"fixtures/{DETECTION_ID}.attack.json"
    )
    assert detection.fixture_for(EXPECT_BENIGN).expect == EXPECT_BENIGN
    assert len(model.stage_detections("03-credential-access")) == 1


def test_fixture_for_unknown_expect(make_root):
    model = load_model(make_root())
    with pytest.raises(ModelError, match="no hostile fixture"):
        model.detections[0].fixture_for("hostile")


def test_stage_resolution(make_root):
    model = load_model(make_root())
    assert model.stage("03-credential-access").id == "03-credential-access"
    assert model.stage("03").id == "03-credential-access"
    with pytest.raises(ModelError, match="unknown stage"):
        model.stage("99")


def test_missing_yaml(tmp_path: Path):
    with pytest.raises(ModelError, match=r"no detections\.yaml"):
        load_model(tmp_path)


def _block_replacement(text: str, header: str, replacement: str) -> str:
    head, rest = text.split(header, 1)
    kept = "".join(
        line for line in rest.splitlines(keepends=True) if line and not line.startswith(" ")
    )
    return head + replacement + kept


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda t: t.replace("version: 1", "version: 2"), "unsupported version"),
        (lambda t: t.replace("version: 1", ""), "unsupported version"),
        (
            lambda t: _block_replacement(t, "detections:", "detections: {}\n"),
            "detections must be a list",
        ),
        (lambda t: t.replace("- id: 03-credential-access", "- id: bad slug"), "stage id"),
        (lambda t: t.replace("techniques: [T1003.001]", "techniques: []"), "must list techniques"),
        (
            lambda t: t.replace("techniques: [T1003.001]", "techniques: [X1003]"),
            "invalid technique",
        ),
        (
            lambda t: t.replace(
                "stages:", "stages:\n  - id: 03-credential-access\n    techniques: [T1059]\n", 1
            ),
            "duplicate stage",
        ),
        (
            lambda t: t.replace(
                f"  - id: {DETECTION_ID}", f"  - id: Bad_Case\n  - id: {DETECTION_ID}", 1
            ),
            "kebab-case",
        ),
        (
            lambda t: t.replace("title: LSASS process access by an untrusted caller", "title: ''"),
            "title",
        ),
        (
            lambda t: t.replace(f"rule: rules/{DETECTION_ID}.spl", "rule: rules/other.spl"),
            "rule must be rules/",
        ),
        (
            lambda t: t.replace("stage: 03-credential-access", "stage: 99-nowhere"),
            "unknown stage",
        ),
        (lambda t: t.replace("attack: [T1003.001]", "attack: []"), "attack techniques"),
        (lambda t: t.replace("attack: [T1003.001]", "attack: [nope]"), "invalid technique"),
        (lambda t: t.replace("      sysmon: [10, 1]", "      sysmon: [true]"), "invalid code"),
        (lambda t: t.replace("      sysmon: [10, 1]", "      sysmon: []"), "must list event codes"),
        (
            lambda t: t.replace("      sysmon: [10, 1]", "      netflow: [10]"),
            "slice source",
        ),
        (
            lambda t: _block_replacement(t, "    slice:", "    slice: []\n"),
            "non-empty mapping",
        ),
        (
            lambda t: t.replace(
                f"      - events: fixtures/{DETECTION_ID}.attack.json",
                "      - events: fixtures/elsewhere.json",
            ),
            "attack fixture must be",
        ),
        (
            lambda t: t.replace("        expect: attack", "        expect: hostile"),
            "expect must be one of",
        ),
        (
            lambda t: t.replace(
                f"      - events: fixtures/{DETECTION_ID}.benign.json\n        expect: benign",
                f"      - events: fixtures/{DETECTION_ID}.attack.json\n        expect: attack",
            ),
            "exactly one attack",
        ),
        (
            lambda t: _block_replacement(t, "    fixtures:", "    fixtures: []\n"),
            "must list fixtures",
        ),
    ],
)
def test_invalid_models_fail(make_root, mutate, match):
    root = make_root(yaml_text=mutate(DEFAULT_YAML))
    with pytest.raises(ModelError, match=match):
        load_model(root)


def test_stage_entry_not_a_mapping(make_root):
    yaml_text = _block_replacement(DEFAULT_YAML, "stages:", "stages:\n  - 42\n")
    with pytest.raises(ModelError, match="each stage must be a mapping"):
        load_model(make_root(yaml_text=yaml_text))


def test_detection_entry_not_a_mapping(make_root):
    yaml_text = _block_replacement(DEFAULT_YAML, "detections:", "detections:\n  - 42\n")
    with pytest.raises(ModelError, match="each detection must be a mapping"):
        load_model(make_root(yaml_text=yaml_text))


def test_invalid_yaml_text_fails(make_root):
    with pytest.raises(ModelError, match="invalid YAML"):
        load_model(make_root(yaml_text="version: [unclosed"))


def test_non_mapping_top_level_fails(make_root):
    with pytest.raises(ModelError, match="top level must be a mapping"):
        load_model(make_root(yaml_text="- just\n- a\n- list\n"))


def test_stage_prefix_ambiguity(make_root):
    yaml_text = DEFAULT_YAML.replace(
        "stages:", "stages:\n  - id: 03-other-stage\n    techniques: [T1059]", 1
    )
    model = load_model(make_root(yaml_text=yaml_text))
    with pytest.raises(ModelError, match="ambiguous"):
        model.stage("03")


def test_check_rule_contract(make_root):
    root = make_root()
    rule_path = root / "rules" / f"{DETECTION_ID}.spl"

    rule_path.write_text("| stats count by Image", encoding="utf-8")
    with pytest.raises(ModelError, match="must not start with a pipeline"):
        check_rule(rule_path)

    rule_path.write_text("search EventCode=10", encoding="utf-8")
    with pytest.raises(ModelError, match="bare search terms"):
        check_rule(rule_path)

    rule_path.write_text("EventCode=10 index=windows", encoding="utf-8")
    with pytest.raises(ModelError, match="'index'"):
        check_rule(rule_path)

    rule_path.write_text("EventCode=10 earliest=-30m", encoding="utf-8")
    with pytest.raises(ModelError, match="'earliest'"):
        check_rule(rule_path)

    rule_path.write_text('EventCode=10 CommandLine="unbalanced', encoding="utf-8")
    with pytest.raises(ModelError, match="unbalanced"):
        check_rule(rule_path)

    rule_path.write_text("   \n", encoding="utf-8")
    with pytest.raises(ModelError, match="empty"):
        check_rule(rule_path)

    with pytest.raises(ModelError, match="missing rule file"):
        check_rule(root / "rules" / "absent.spl")

    rule_path.write_text(
        'EventCode=10 note="talks about index= and earliest=" | top Image', encoding="utf-8"
    )
    assert check_rule(rule_path).startswith("EventCode=10")


def test_check_rules_aggregates(make_root):
    root = make_root(rule="| stats count")
    with pytest.raises(ModelError, match="pipeline"):
        check_rules(load_model(root))
    rules = check_rules(load_model(make_root()))
    assert DETECTION_ID in rules
