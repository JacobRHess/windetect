# Capture VM runbook

The attack stages run inside an isolated Hyper-V VM, never on the host. Telemetry
installed by `Install-Telemetry.ps1` records each stage; `Export-Stage.ps1`
exports the window as raw event XML for the host-side slicing tool.

## 1. Create the VM

Hyper-V on the host (Windows 11 Pro has it as an optional feature):

- Generation 2, Windows 11 eval ISO, 4 GB RAM minimum
- Rename the guest to `WINDETECT-01` (the name lands in every fixture's
  `Computer` field and in the article screenshots)
- Take a checkpoint before every stage so a noisy stage can be replayed clean

## 2. Install telemetry (once, as Administrator)

Copy this `vm/` directory to the guest (shared folder or `Copy-VMFile`), then:

```powershell
.\Install-Telemetry.ps1
```

Installs Sysmon (`C:\windetect\Sysmon64.exe`, config alongside), enables
PowerShell script-block logging, and sets the audit subcategories the Security
EID detections need (4624/4625, 4672, 4688 with command line, 4697/4698, 1102).

## 3. Install the emulator

```powershell
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name Invoke-AtomicRedTeam -Scope AllUsers -Force
Import-Module Invoke-AtomicRedTeam
Install-AtomicRedTeam
```

## 4. Run a stage

Checkpoint first, then run the stage's atomics (the detections table in the
project README maps stages to techniques; each stage lists its atomic test IDs
in `captures/<stage>/`). Example for stage 03 (credential access):

```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 5   # comsvcs dump, no real malware
```

Defender stays enabled. If it eats a stage's payload before telemetry lands,
add a *lab-only* exclusion for the Atomic install directory and note it in the
stage's capture metadata. The product here is telemetry, not successful malware.
Observed case: in the first stage-03 capture, real-time protection let the dump
commands start (4688/4104 recorded) but blocked and quarantined the tools
mid-stage, so Sysmon EID10 never saw a dumper open LSASS and no dump files
landed - any detection that needs ProcessAccess or dump artifacts requires the
exclusion (or a real-time-protection pause) across the attack window.

## 5. Export the window

```powershell
.\Export-Stage.ps1 -Stage 03 -WindowMinutes 30
```

Copy the resulting `captures/stage-03-*.windetect.xml` to the host, then slice
it into per-detection fixtures:

```powershell
uv run windetect capture captures/stage-03-*.windetect.xml --stage 03-credential-access
```

## Benign captures

Same export path over a scripted normal-usage window (browsing, app installs,
Windows Update). Those slices fill the `<id>.benign.json` halves.

A benign capture is only as strong as the near-misses it contains. Background
noise (svchost, RuntimeBroker, remoting) proves a rule ignores unrelated events;
it does **not** prove a low false-positive rate against the activity that
actually looks like the attack. For the LSASS detections that means a benign
window should include the legitimate dump-adjacent activity a real host
produces - Task Manager's *Create dump file*, a WER/crash dump landing in
`%LOCALAPPDATA%\CrashDumps`, an admin or EDR running procdump against a service
they own. Script those into the normal-usage window so the benign slice exercises
the rule's decision boundary, not just quiet background. Until it does, treat the
low-FP claim as "ignores background noise", not "survives realistic near-misses".

## Ingest field names (renderXml)

Fixtures carry the raw EVTX element names (`CommandLine`, `NewProcessName`,
`ScriptBlockText`) because `Export-Stage.ps1` serializes each event with
`.ToXml()`. For the deployed rules to match those same names, a production
forwarder must ingest all three channels with `renderXml = true` in `inputs.conf`
(sourcetypes `XmlWinEventLog:Security`, `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`,
and the Sysmon XML sourcetype). Under the classic non-XML Security extraction the
Splunk Add-on for Windows renames these fields (`CommandLine` becomes
`Process_Command_Line`), and the rules would silently never match on 4688. This
is the single ingest assumption the "runs unmodified in production" claim rests
on, and it is stated so a reader can check it.
