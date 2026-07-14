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

$action = @($task.Actions)[0]
$trigger = @($task.Triggers)[0]
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
    }
} | ConvertTo-Json -Depth 5 -Compress
