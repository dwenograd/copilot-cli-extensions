[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TaskPath,
    [Parameter(Mandatory = $true)][string]$TaskName,
    [Parameter(Mandatory = $true)][string]$Description,
    [Parameter(Mandatory = $true)][string]$Execute,
    [Parameter(Mandatory = $true)][string]$Arguments,
    [Parameter(Mandatory = $true)][string]$WorkingDirectory,
    [Parameter(Mandatory = $true)][string]$UserId,
    [Parameter(Mandatory = $true)][string]$UserSid,
    [Parameter(Mandatory = $true)][string]$LauncherSha256,
    [Parameter(Mandatory = $true)][string]$NodePath,
    [Parameter(Mandatory = $true)][string]$NodeSha256,
    [Parameter(Mandatory = $true)][string]$DaemonSha256,
    [Parameter(Mandatory = $true)][string]$DaemonPath
)

$ErrorActionPreference = "Stop"

function Normalize-Path([string]$Value) {
    return [System.IO.Path]::GetFullPath($Value).TrimEnd("\")
}

function Test-ExpectedUserId([string]$Observed) {
    $shortUserId = if ($UserId.Contains("\")) {
        ($UserId -split "\\")[-1]
    }
    elseif ($UserId.Contains("@")) {
        ($UserId -split "@")[0]
    }
    else {
        $UserId
    }
    return $Observed -ieq $UserId `
        -or $Observed -ieq $UserSid `
        -or $Observed -ieq $shortUserId
}

function Get-Sha256([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString(
            $algorithm.ComputeHash($stream)
        ) -replace "-", "").ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function Test-ExactTask($Task) {
    if ($null -eq $Task) { return $false }
    $Actions = @($Task.Actions)
    $Triggers = @($Task.Triggers)
    if ($Actions.Count -ne 1 -or $Triggers.Count -ne 1) {
        return $false
    }
    $Action = $Actions[0]
    $Trigger = $Triggers[0]
    return $Task.Description -ceq $Description `
        -and (Normalize-Path $Action.Execute) -ieq (Normalize-Path $Execute) `
        -and $Action.Arguments -ceq $Arguments `
        -and (Normalize-Path $Action.WorkingDirectory) -ieq (Normalize-Path $WorkingDirectory) `
        -and (Test-ExpectedUserId $Task.Principal.UserId) `
        -and [string]$Task.Principal.LogonType -eq "Interactive" `
        -and [string]$Task.Principal.RunLevel -eq "Limited" `
        -and $Trigger.CimClass.CimClassName -eq "MSFT_TaskLogonTrigger" `
        -and (Test-ExpectedUserId $Trigger.UserId) `
        -and [bool]$Task.Settings.Hidden `
        -and [bool]$Task.Settings.StartWhenAvailable `
        -and [int]$Task.Settings.RestartCount -eq 999 `
        -and $Task.Settings.RestartInterval -eq "PT1M" `
        -and [string]$Task.Settings.MultipleInstances -eq "IgnoreNew" `
        -and $Task.Settings.ExecutionTimeLimit -eq "PT0S" `
        -and -not [bool]$Task.Settings.DisallowStartIfOnBatteries `
        -and -not [bool]$Task.Settings.StopIfGoingOnBatteries
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.Name -ine $UserId -or $identity.User.Value -cne $UserSid) {
    throw "The requested task principal is not the current interactive user"
}

$launcherHash = "sha256:$(Get-Sha256 $Execute)"
$nodeHash = "sha256:$(Get-Sha256 $NodePath)"
$daemonHash = "sha256:$(Get-Sha256 $DaemonPath)"
if ($launcherHash -cne $LauncherSha256 `
    -or $nodeHash -cne $NodeSha256 `
    -or $daemonHash -cne $DaemonSha256) {
    throw "Launcher, Node, or recovery daemon bytes changed after configuration"
}

$existing = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName `
    -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    if (-not (Test-ExactTask $existing)) {
        throw "A task with this deterministic name has a different action"
    }
    [ordered]@{ installed = $false; unchanged = $true } |
        ConvertTo-Json -Compress
    exit 0
}

$service = New-Object -ComObject "Schedule.Service"
$service.Connect()
$root = $service.GetFolder("\")
$folderName = $TaskPath.Trim("\")
if (-not [string]::IsNullOrWhiteSpace($folderName)) {
    try {
        $null = $service.GetFolder("\$folderName")
    }
    catch {
        $null = $root.CreateFolder($folderName)
    }
}

$action = New-ScheduledTaskAction -Execute $Execute -Argument $Arguments `
    -WorkingDirectory $WorkingDirectory
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $UserId
$principal = New-ScheduledTaskPrincipal -UserId $UserId `
    -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -Hidden -StartWhenAvailable `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$definition = New-ScheduledTask -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Description $Description

$null = Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName `
    -InputObject $definition
$installed = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
if (-not (Test-ExactTask $installed)) {
    throw "Task Scheduler did not preserve the exact recovery action"
}

[ordered]@{ installed = $true; unchanged = $false } |
    ConvertTo-Json -Compress
