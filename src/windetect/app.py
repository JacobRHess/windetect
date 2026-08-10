"""Generate an installable Splunk app from the detections.

Each detection becomes a scheduled saved search that alerts when it returns
results, scoped to the deployment index the way the replay harness scopes it,
and enriched with the ATT&CK technique and kill-chain stage. The app also
ships a coverage dashboard. The rules deployed here are the same rule files
CI replays against a real Splunk. Build with ``windetect build-app --out
<dir>`` and drop the result in ``$SPLUNK_HOME/etc/apps/``.
"""

from __future__ import annotations

from pathlib import Path

from windetect.model import Detection, Model, check_rules
from windetect.splunk import DEFAULT_INDEX

_APP_CONF = """\
[install]
is_configured = 0

[ui]
is_visible = 1
label = windetect

[launcher]
author = Jacob Hess
description = Windows detections proven against a real intrusion capture, as scheduled alerts
version = 0.1.0
"""

_DEFAULT_META = """\
[]
access = read : [ * ], write : [ admin ]
export = system
"""

_DASHBOARD = """\
<dashboard version="1.1">
  <label>windetect coverage</label>
  <description>windetect detections and what they have caught recently.</description>
  <row>
    <panel>
      <title>Telemetry by sourcetype (last 24h)</title>
      <chart>
        <search>
          <query>| tstats count where index={index} by sourcetype</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
    <panel>
      <title>Triggered detections (last 24h)</title>
      <table>
        <search>
          <query>index=_audit action=alert_fired ss_name="windetect - *"
| stats count by ss_name | rename ss_name as detection, count as fires</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Installed detection alerts</title>
      <table>
        <search>
          <query>| rest /services/saved/searches | search title="windetect - *"
| table title description cron_schedule | rename title as detection</query>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
"""


def _enriched_search(index: str, rule_text: str, detection: Detection) -> str:
    one_line = " ".join(rule_text.split())
    techniques = ", ".join(detection.attack)
    return (
        f"index={index} {one_line} "
        f'| eval mitre_technique="{techniques}", windetect_stage="{detection.stage}"'
    )


def _saved_search(detection: Detection, search: str) -> str:
    # Collapse whitespace so a newline in a detection title cannot inject a
    # second conf key. Ids are already kebab-case constrained by the loader.
    title = " ".join(detection.title.split())
    return (
        f"[windetect - {detection.id}]\n"
        f"search = {search}\n"
        f"description = {title}\n"
        "cron_schedule = */10 * * * *\n"
        "enableSched = 1\n"
        # Minute-aligned window matching the cron period, so consecutive runs
        # neither overlap (double alerts) nor leave gaps.
        "dispatch.earliest_time = -10m@m\n"
        "dispatch.latest_time = @m\n"
        "counttype = number of events\n"
        "relation = greater than\n"
        "quantity = 0\n"
        "alert.track = 1\n"
        "alert.severity = 4\n"
    )


def render_savedsearches(model: Model, rules: dict[str, str], *, index: str = DEFAULT_INDEX) -> str:
    stanzas = [
        _saved_search(detection, _enriched_search(index, rules[detection.id], detection))
        for detection in model.detections
    ]
    return "\n".join(stanzas)


def build_app(model: Model, out_dir: Path, *, index: str = DEFAULT_INDEX) -> Path:
    rules = check_rules(model)
    default = out_dir / "default"
    views = default / "data" / "ui" / "views"
    views.mkdir(parents=True, exist_ok=True)
    (out_dir / "metadata").mkdir(parents=True, exist_ok=True)
    (default / "app.conf").write_text(_APP_CONF, encoding="utf-8")
    (out_dir / "metadata" / "default.meta").write_text(_DEFAULT_META, encoding="utf-8")
    (default / "savedsearches.conf").write_text(
        render_savedsearches(model, rules, index=index), encoding="utf-8"
    )
    (views / "windetect_coverage.xml").write_text(_DASHBOARD.format(index=index), encoding="utf-8")
    return out_dir
