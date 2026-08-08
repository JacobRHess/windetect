# windetect

**A Windows intrusion captured on real telemetry, and the Splunk detections that proved themselves against it.**

Most detection writeups ship rules with synthetic fixtures, or fixtures with no rules. This one ships neither synthetic data nor untested rules: one adversary walks a full kill chain across a real Windows host, every stage is recorded by the same sensors a SOC already runs (Sysmon, Windows Security, PowerShell script-block logging), and every detection must fire on the captured attack trace and stay silent on a captured benign day through the same host, asserted in CI against a live Splunk container.

## The contract

```
detections.yaml            single source of truth (id, title, rule, attack, slice, fixtures)
rules/<id>.spl             native SPL, written against real Windows field names
fixtures/<id>.attack.json  sliced from a genuine capture of the attack stage
fixtures/<id>.benign.json  sliced from a genuine capture of normal activity
captures/                  raw capture exports (gitignored; slices stay out of git)
vm/                        telemetry bootstrap + capture export scripts (run inside the VM)
lab/                       single-node Splunk in Docker, same as the CI validate job
src/windetect/             the slicer, the replay engine, the coverage report
```

Adding a detection means adding an entry to `detections.yaml`, one `.spl` rule, and the two fixtures sliced from real captures. CI replays both through Splunk and asserts `attack` fires and `benign` stays clean.

## The CLI

```powershell
uv run windetect validate                      # detections.yaml + rules + fixtures conform
uv run windetect capture captures/stage-03-*.xml --stage 03   # slice attack fixtures
uv run windetect capture captures/benign-*.xml --benign       # slice benign fixtures
uv run windetect replay                        # live Splunk: attack must fire, benign must not
uv run windetect report [--markdown]           # kill-chain coverage
uv run windetect report --layer coverage.json  # ATT&CK Navigator layer of proven techniques
uv run windetect build-app --out build/windetect_app  # deployable Splunk app
uv run windetect new <id> --stage 03 --title ... --technique T1003.001 --slice sysmon=10
```

`capture` applies each detection's `slice` spec (channel → event codes) to the export and writes the matching events verbatim into the fixture — event-code level only, so rules still earn their matches on real field values. Slicing is loud: an empty slice aborts, and every written fixture is schema-validated before it lands.

Splunk connection defaults to the local lab (`https://localhost:8089`/`:8088`, `admin`/`windetect_dev_2026`, index `windetect`); override with `WD_SPLUNK_URL`, `WD_SPLUNK_HEC_URL`, `WD_SPLUNK_USER`, `WD_SPLUNK_PASSWORD`, `WD_SPLUNK_INDEX` or the matching `--flags`. The client bootstraps the index, `KV_MODE=json` props, and the HEC input over REST, so it works identically against the docker lab and the CI service container.

## The rule contract

Rules are plain SPL searching the production field names, and the replay harness prepends its scope (`index=windetect wd_run="<run>"`) to them. Therefore a rule:

- starts with bare search terms (no leading `|` or `search`)
- never binds `index=`, `earliest=`, or `latest=` — index/time binding belongs to the deployment
- outputs one row per detection (zero rows = no detection); windowed logic operates on `_time`, which the harness sets from each captured event's own timestamp

`windetect validate` enforces all of this before any replay runs.

## Deploying the detections

`windetect build-app` renders the same rule files CI replays into an installable Splunk app:
one scheduled saved search per detection, scoped to the deployment index and enriched with its
ATT&CK technique and kill-chain stage, plus a coverage dashboard. Drop the output directory in
`$SPLUNK_HOME/etc/apps/`. The CI validate job installs the generated app into the container on
every push and asserts every detection landed as a saved search, so what deploys is what was
proven.

## The kill chain

| Stage | Techniques | Key signals |
|---|---|---|
| 01 Initial access + execution | T1566.001, T1204.002, T1059.001 | Office/script host spawning shell, encoded PowerShell download cradle |
| 02 Defense evasion | T1070.001, T1036.003 | Security event log cleared (1102), masqueraded binary |
| 03 Credential access | T1003.001 | LSASS process access (Sysmon EID 10), comsvcs dump |
| 04 Discovery | T1087.002, T1069.002 | Domain user/group enumeration |
| 05 Persistence | T1547.001, T1053.005, T1543.003 | Run key, scheduled task, service creation (4697/4698) |
| 06 Privilege escalation | T1548.002 | UAC bypass process lineage, 4672 anomaly |
| 07 Lateral movement | T1021.002 | Remote service creation over SMB |
| 08 C2 + exfiltration | T1071.001, T1560.001 | Beacon cadence, staged archive |

Attack stages are executed with Atomic Red Team inside an isolated Hyper-V VM; the telemetry is exported as raw EVTX XML, sliced into JSON fixtures with real field names, and replayed through Splunk with `sourcetype` values that match a production deployment (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `WinEventLog:Security`, PowerShell operational). The rules written here are the rules you deploy there: no field renaming, no bespoke schema.

## Capture runbook

```powershell
# inside the VM (one-time)
vm\Install-Telemetry.ps1

# run the attack stage (Atomic Red Team), then from the VM:
vm\Export-Stage.ps1 -Stage 03 -WindowMinutes 30

# on the host, slice the export into per-detection fixtures:
uv run windetect capture captures/stage-03-*.windetect.xml --stage 03
```

Benign captures use the same export path over a scripted normal-usage window (browsing, installs, updates) and slice into the `<id>.benign.json` halves with `--benign`.

## Local development

```powershell
uv sync --extra dev
docker compose -f lab/docker-compose.yml up -d   # Splunk on :8000, HEC :8088
uv run pytest                                    # offline gate
uv run pytest -m replay                          # needs the lab Splunk up
```

## CI

Two jobs: `gate` (ruff, ruff format, mypy strict, offline pytest at ≥90% branch coverage, bandit, pip-audit) and `validate` (builds the deployable app, boots `splunk/splunk:9.4.2`, installs the app, and runs the replay-marked tests — a synthetic canary smoke proving ingest→extract→search end to end today, every committed detection once captures land — then asserts the detections installed as saved searches). A separate `security` workflow audits the CI workflows with zizmor and scans history for secrets with gitleaks.

## Status

Scaffolding and engine. Telemetry bootstrap, capture slicer, replay engine, and the live CI gate are in place; detections land one at a time as captures are recorded.
