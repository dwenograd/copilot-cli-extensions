[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TaskPath,
    [Parameter(Mandatory = $true)][string]$TaskName,
    [Parameter(Mandatory = $true)][string]$Description,
    [Parameter(Mandatory = $true)][string]$Execute,
    [Parameter(Mandatory = $true)][string]$Arguments,
    [Parameter(Mandatory = $true)][string]$WorkingDirectory,
    [Parameter(Mandatory = $true)][string]$UserId,
    [Parameter(Mandatory = $true)][string]$UserSid
)

$ErrorActionPreference = "Stop"

function Normalize-Path([string]$Value) {
    return [System.IO.Path]::GetFullPath($Value).TrimEnd("\")
}

$task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName `
    -ErrorAction SilentlyContinue
if ($null -eq $task) {
    [ordered]@{ removed = $false; absent = $true } |
        ConvertTo-Json -Compress
    exit 0
}

$action = @($task.Actions)[0]
$matches = $task.Description -ceq $Description `
    -and (Normalize-Path $action.Execute) -ieq (Normalize-Path $Execute) `
    -and $action.Arguments -ceq $Arguments `
    -and (Normalize-Path $action.WorkingDirectory) -ieq (Normalize-Path $WorkingDirectory) `
    -and ($task.Principal.UserId -ieq $UserId `
        -or $task.Principal.UserId -ieq $UserSid)
if (-not $matches) {
    throw "Refusing to remove a task whose action does not exactly match"
}

Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName `
    -Confirm:$false
$after = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName `
    -ErrorAction SilentlyContinue
if ($null -ne $after) {
    throw "Task still exists after unregister"
}

[ordered]@{ removed = $true; absent = $false } |
    ConvertTo-Json -Compress
