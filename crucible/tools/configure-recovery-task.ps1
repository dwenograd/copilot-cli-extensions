[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Identity", "Inspect")]
    [string]$Mode,
    [string]$TaskPath = "\Crucible\",
    [string]$TaskName = ""
)

$ErrorActionPreference = "Stop"
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

if ($Mode -eq "Identity") {
    [ordered]@{
        userId = $identity.Name
        userSid = $identity.User.Value
    } | ConvertTo-Json -Compress
    exit 0
}

if ([string]::IsNullOrWhiteSpace($TaskName)) {
    throw "TaskName is required for Inspect"
}

$task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName `
    -ErrorAction SilentlyContinue
if ($null -eq $task) {
    [ordered]@{
        exists = $false
        taskPath = $TaskPath
        taskName = $TaskName
    } | ConvertTo-Json -Compress
    exit 0
}

$actions = @($task.Actions)
$triggers = @($task.Triggers)
if ($actions.Count -ne 1 -or $triggers.Count -ne 1) {
    throw "Crucible recovery task must contain exactly one action and one trigger"
}
$action = $actions[0]
$trigger = $triggers[0]
function Resolve-TaskSid([string]$Identity) {
    if ($Identity -match '^S-1-') { return $Identity }
    return (
        New-Object System.Security.Principal.NTAccount($Identity)
    ).Translate([System.Security.Principal.SecurityIdentifier]).Value
}
$principalSid = Resolve-TaskSid $task.Principal.UserId
$triggerSid = Resolve-TaskSid $trigger.UserId
$logonType = if ([string]$task.Principal.LogonType -eq "Interactive") {
    "InteractiveToken"
}
else {
    [string]$task.Principal.LogonType
}
$runLevel = if ([string]$task.Principal.RunLevel -eq "Limited") {
    "LeastPrivilege"
}
else {
    [string]$task.Principal.RunLevel
}
[ordered]@{
    exists = $true
    taskPath = $task.TaskPath
    taskName = $task.TaskName
    description = $task.Description
    action = [ordered]@{
        execute = $action.Execute
        arguments = $action.Arguments
        workingDirectory = $action.WorkingDirectory
    }
    principal = [ordered]@{
        userId = $task.Principal.UserId
        userSid = $principalSid
        logonType = $logonType
        runLevel = $runLevel
    }
    trigger = [ordered]@{
        type = if ($trigger.CimClass.CimClassName -eq "MSFT_TaskLogonTrigger") {
            "logon"
        }
        else {
            $trigger.CimClass.CimClassName
        }
        userId = $trigger.UserId
        userSid = $triggerSid
    }
    settings = [ordered]@{
        hidden = [bool]$task.Settings.Hidden
        startWhenAvailable = [bool]$task.Settings.StartWhenAvailable
        restartCount = [int]$task.Settings.RestartCount
        restartIntervalMinutes = if ($task.Settings.RestartInterval -eq "PT1M") {
            1
        }
        else {
            -1
        }
        multipleInstances = [string]$task.Settings.MultipleInstances
        executionTimeLimitSeconds = if ($task.Settings.ExecutionTimeLimit -eq "PT0S") {
            0
        }
        else {
            -1
        }
        allowStartOnBatteries = -not [bool]$task.Settings.DisallowStartIfOnBatteries
        stopOnBatteryTransition = [bool]$task.Settings.StopIfGoingOnBatteries
    }
} | ConvertTo-Json -Depth 5 -Compress
