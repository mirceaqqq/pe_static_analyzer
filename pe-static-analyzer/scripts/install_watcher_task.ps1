<#
.SYNOPSIS
  Creeaza un task programat care porneste watcher-ul AV la boot.

.DESCRIPTION
  Ruleaza watcher-ul (python main.py watch ...) la startup folosind Scheduled Tasks.
  Necesita rulare ca Administrator. Nu cere parola daca se foloseste contul SYSTEM.

.PARAMETER Paths
  Liste de cai de monitorizat (default: C:\Users).

.PARAMETER IntervalMinutes
  Interval pentru auto-update YARA (minute). Default 60.

.PARAMETER DisableYaraUpdate
  Dezactiveaza update-ul automat YARA in watcher.

.PARAMETER NoRecursive
  Dezactiveaza monitorizarea recursiva.

.PARAMETER TaskName
  Numele task-ului programat (default: PEStaticAnalyzerWatcher).

.EXAMPLE
  .\install_watcher_task.ps1

.EXAMPLE
  .\install_watcher_task.ps1 -Paths "C:\Samples","C:\Users" -IntervalMinutes 120
#>
[CmdletBinding()]
param(
    [string[]] $Paths = @("C:\Users"),
    [int] $IntervalMinutes = 60,
    [switch] $DisableYaraUpdate,
    [switch] $NoRecursive,
    [string] $TaskName = "PEStaticAnalyzerWatcher"
)

function Ensure-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
        Write-Error "Rulati scriptul dintr-o sesiune PowerShell cu drepturi de Administrator."
        exit 1
    }
}

Ensure-Admin

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = "python.exe"
$WorkDir = $Root
$PathArgs = $Paths -join " "

$argsList = @("main.py", "watch")
if ($NoRecursive) { $argsList += "--no-recursive" }
if ($DisableYaraUpdate) { $argsList += "--no-yara-update" }
$argsList += @("--interval-min", $IntervalMinutes)
$argsList += $PathArgs
$Arguments = $argsList -join " "

Write-Host "Configurez task-ul '$TaskName' cu args: $Arguments"

$action = New-ScheduledTaskAction -Execute $Python -Argument $Arguments -WorkingDirectory $WorkDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

Write-Host "Task-ul '$TaskName' a fost creat. Va porni watcher-ul la boot."
Write-Host "Pentru a sterge: Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false"
