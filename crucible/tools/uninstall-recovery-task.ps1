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

$task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName `
    -ErrorAction SilentlyContinue
if ($null -eq $task) {
    [ordered]@{ removed = $false; absent = $true } |
        ConvertTo-Json -Compress
    exit 0
}

$actions = @($task.Actions)
$triggers = @($task.Triggers)
if ($actions.Count -ne 1 -or $triggers.Count -ne 1) {
    throw "Refusing to remove a task with extra actions or triggers"
}
$action = $actions[0]
$matches = $task.Description -ceq $Description `
    -and (Normalize-Path $action.Execute) -ieq (Normalize-Path $Execute) `
    -and $action.Arguments -ceq $Arguments `
    -and (Normalize-Path $action.WorkingDirectory) -ieq (Normalize-Path $WorkingDirectory) `
    -and (Test-ExpectedUserId $task.Principal.UserId)
if (-not $matches) {
    throw "Refusing to remove a task whose action does not exactly match"
}

if ([string]$task.State -eq "Running") {
    Stop-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        Start-Sleep -Milliseconds 100
        $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName `
            -ErrorAction SilentlyContinue
    } while ($null -ne $task `
        -and [string]$task.State -eq "Running" `
        -and [DateTime]::UtcNow -lt $deadline)
    if ($null -ne $task -and [string]$task.State -eq "Running") {
        throw "Recovery task did not stop before unregister"
    }
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
