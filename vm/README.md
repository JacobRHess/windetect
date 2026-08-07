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
Windows Update). Those slices fill the `<id>.benign.json` halves and are the
false-positive proof the article leans on.
