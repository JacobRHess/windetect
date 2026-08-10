from __future__ import annotations

import pytest

from helpers import DEFAULT_RULE, DETECTION_ID, EMPTY_YAML, build_root
from windetect.app import build_app, render_savedsearches
from windetect.model import ModelError, check_rules, load_model


def test_build_app_empty_model(tmp_path):
    root = build_root(tmp_path, yaml_text=EMPTY_YAML, write_rule=False)
    out = build_app(load_model(root), tmp_path / "out")
    assert (out / "default" / "app.conf").is_file()
    assert (out / "metadata" / "default.meta").is_file()
    assert (out / "default" / "savedsearches.conf").read_text(encoding="utf-8") == ""
    assert (out / "default" / "data" / "ui" / "views" / "windetect_coverage.xml").is_file()


def test_build_app_renders_saved_search(tmp_path):
    root = build_root(tmp_path)
    build_app(load_model(root), tmp_path / "out")
    conf = (tmp_path / "out" / "default" / "savedsearches.conf").read_text(encoding="utf-8")
    assert f"[windetect - {DETECTION_ID}]" in conf
    assert f"search = index=windetect {DEFAULT_RULE}" in conf
    assert 'mitre_technique="T1003.001"' in conf
    assert 'windetect_stage="03-credential-access"' in conf
    assert "cron_schedule = */10 * * * *" in conf


def test_build_app_index_override(tmp_path):
    root = build_root(tmp_path)
    model = load_model(root)
    build_app(model, tmp_path / "out", index="prod_windows")
    conf = (tmp_path / "out" / "default" / "savedsearches.conf").read_text(encoding="utf-8")
    assert "index=prod_windows" in conf
    dashboard = (
        tmp_path / "out" / "default" / "data" / "ui" / "views" / "windetect_coverage.xml"
    ).read_text(encoding="utf-8")
    assert "index=prod_windows" in dashboard
    assert "index=windetect" not in dashboard


def test_saved_search_window_matches_cron_period(tmp_path):
    root = build_root(tmp_path)
    model = load_model(root)
    conf = render_savedsearches(model, check_rules(model))
    assert "dispatch.earliest_time = -10m@m" in conf
    assert "dispatch.latest_time = @m" in conf


def test_saved_search_title_whitespace_collapsed(tmp_path):
    yaml_text = (
        "version: 1\n\nstages:\n  - id: 03-credential-access\n"
        "    techniques: [T1003.001]\n\ndetections:\n"
        f"  - id: {DETECTION_ID}\n"
        '    title: "Two\\nline title"\n'
        f"    rule: rules/{DETECTION_ID}.spl\n"
        "    stage: 03-credential-access\n"
        "    attack: [T1003.001]\n"
        "    fixtures:\n"
        f"      - events: fixtures/{DETECTION_ID}.attack.json\n"
        "        expect: attack\n"
        f"      - events: fixtures/{DETECTION_ID}.benign.json\n"
        "        expect: benign\n"
    )
    root = build_root(tmp_path, yaml_text=yaml_text)
    model = load_model(root)
    conf = render_savedsearches(model, check_rules(model))
    description = next(line for line in conf.splitlines() if line.startswith("description"))
    assert description == "description = Two line title"


def test_build_app_missing_rule_fails(tmp_path):
    root = build_root(tmp_path, write_rule=False)
    with pytest.raises(ModelError, match="missing rule file"):
        build_app(load_model(root), tmp_path / "out")


def test_app_conf_shape(tmp_path):
    root = build_root(tmp_path, yaml_text=EMPTY_YAML, write_rule=False)
    build_app(load_model(root), tmp_path / "out")
    conf = (tmp_path / "out" / "default" / "app.conf").read_text(encoding="utf-8")
    assert "label = windetect" in conf
    assert "is_configured = 0" in conf
