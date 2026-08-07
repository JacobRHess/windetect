# windetect capture export - run INSIDE the capture VM after executing a stage.
# Exports the last N minutes of Security, Sysmon and PowerShell operational
# events as raw EVTX XML into captures/. The host-side slicing tool converts
# this file into per-detection fixtures.

param(
    [Parameter(Mandatory)][string]$Stage,
    [int]$WindowMinutes = 30,
    [string]$OutDir = (Join-Path $PSScriptRoot '..\captures')
)
$ErrorActionPreference = 'Stop'

$Channels = @(
    'Security',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational'
)

$end = Get-Date
$start = $end.AddMinutes(-$WindowMinutes)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = Join-Path $OutDir ("stage-$Stage-" + $end.ToString('yyyyMMdd-HHmmss') + '.windetect.xml')

$writer = [System.IO.StreamWriter]::new($out, $false, [System.Text.Encoding]::UTF8)
try {
    $writer.WriteLine(
        "<windetect-capture stage=`"$Stage`" host=`"$env:COMPUTERNAME`" " +
        "start=`"$($start.ToUniversalTime().ToString('o'))`" " +
        "end=`"$($end.ToUniversalTime().ToString('o'))`">"
    )

    $total = 0
    foreach ($ch in $Channels) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $ch
                StartTime = $start
                EndTime   = $end
            } -ErrorAction Stop
        } catch {
            if ($_.FullyQualifiedErrorId -eq 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand') {
                Write-Warning "no events in window for $ch"
                continue
            }
            throw
        }
        foreach ($e in $events) {
            $writer.WriteLine($e.ToXml())
            $total++
        }
        Write-Host ("{0}: {1} events" -f $ch, $events.Count)
    }

    if ($total -eq 0) { throw 'capture window is empty; widen -WindowMinutes or check telemetry install' }
    $writer.WriteLine('</windetect-capture>')
} finally {
    $writer.Close()
}

Write-Host "Wrote $total events to $out"
