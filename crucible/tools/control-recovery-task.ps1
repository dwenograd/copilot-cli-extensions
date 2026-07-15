[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Start", "Stop", "Runtime")]
    [string]$Mode,
    [Parameter(Mandatory = $true)][string]$TaskPath,
    [Parameter(Mandatory = $true)][string]$TaskName
)

$ErrorActionPreference = "Stop"

$task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName `
    -ErrorAction SilentlyContinue
if ($null -eq $task) {
    [ordered]@{
        exists = $false
        state = "Absent"
    } | ConvertTo-Json -Compress
    exit 0
}

if ($Mode -eq "Start") {
    Start-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
}
elseif ($Mode -eq "Stop" -and [string]$task.State -eq "Running") {
    Stop-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
}

$task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
$info = Get-ScheduledTaskInfo -TaskPath $TaskPath -TaskName $TaskName
[ordered]@{
    exists = $true
    state = [string]$task.State
    lastTaskResult = [int]$info.LastTaskResult
    lastRunTime = $info.LastRunTime.ToUniversalTime().ToString("o")
} | ConvertTo-Json -Compress
