# windetect telemetry bootstrap - run INSIDE the capture VM, as Administrator.
# Installs Sysmon with the project config, enables PowerShell script-block
# logging, and turns on the Security audit subcategories the detections need.

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Tools = 'C:\windetect'
New-Item -ItemType Directory -Force -Path $Tools | Out-Null

$Sysmon = Join-Path $Tools 'Sysmon64.exe'
if (-not (Test-Path $Sysmon)) {
    Write-Host 'Downloading Sysmon from live.sysinternals.com'
    Invoke-WebRequest -Uri 'https://live.sysinternals.com/Sysmon64.exe' -OutFile $Sysmon
}

$Config = Join-Path $PSScriptRoot 'sysmon-config.xml'
if (-not (Test-Path $Config)) { throw "missing $Config" }

Write-Host 'Installing Sysmon with windetect config'
& $Sysmon -accepteula -i $Config
if ($LASTEXITCODE -ne 0) { throw "Sysmon install exited $LASTEXITCODE" }

Write-Host 'Enabling PowerShell script-block logging'
$sbKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -ItemType Directory -Force -Path $sbKey | Out-Null
New-ItemProperty -Path $sbKey -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force | Out-Null
$modKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -ItemType Directory -Force -Path $modKey | Out-Null
New-ItemProperty -Path $modKey -Name EnableModuleLogging -PropertyType DWord -Value 1 -Force | Out-Null
New-Item -ItemType Directory -Force -Path "$modKey\ModuleNames" | Out-Null
New-ItemProperty -Path "$modKey\ModuleNames" -Name '*' -PropertyType String -Value '*' -Force | Out-Null

Write-Host 'Setting audit policy'
$policies = @(
    # subcategory, success, failure -> covers the Security EIDs the rules search
    @('Logon', 'enable', 'enable'),                          # 4624, 4625
    @('Special Logon', 'enable', 'disable'),                # 4672
    @('Process Creation', 'enable', 'disable'),             # 4688
    @('Other Object Access Events', 'enable', 'disable'),   # 4697, 4698
    @('Log Deletion', 'enable', 'disable')                  # 1102 (Security log cleared)
)
foreach ($p in $policies) {
    & auditpol /set /subcategory:$p[0] /success:$p[1] /failure:$p[2]
    if ($LASTEXITCODE -ne 0) {
        throw ("auditpol failed for '{0}'; run 'auditpol /list /subcategory:*' and fix the name" -f $p[0])
    }
}

Write-Host 'Including command line in 4688 events'
$auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -ItemType Directory -Force -Path $auditKey | Out-Null
New-ItemProperty -Path $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force | Out-Null

Write-Host 'Done. Verify with:'
Write-Host '  Get-Service Sysmon64'
Write-Host "  auditpol /get /subcategory:'Logon'"
