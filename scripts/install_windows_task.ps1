param(
    [string]$InstallDir = (Resolve-Path "$PSScriptRoot\..").Path,
    [string]$TaskName = "PythonEDRPoCAgent"
)

$ErrorActionPreference = "Stop"

$Python = Get-Command python -ErrorAction Stop
$VenvPython = Join-Path $InstallDir ".venv\Scripts\python.exe"
$AgentPath = Join-Path $InstallDir "edr_agent.py"
$ConfigPath = Join-Path $InstallDir "config\watch_config.json"
$RequirementsPath = Join-Path $InstallDir "requirements.txt"

if (-not (Test-Path $AgentPath)) {
    throw "Agent not found at $AgentPath"
}

if (-not (Test-Path $VenvPython)) {
    & $Python.Source -m venv (Join-Path $InstallDir ".venv")
}

& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -r $RequirementsPath

$Action = New-ScheduledTaskAction -Execute $VenvPython -Argument "`"$AgentPath`" --config `"$ConfigPath`"" -WorkingDirectory $InstallDir
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "Installed and started scheduled task '$TaskName' from $InstallDir"
