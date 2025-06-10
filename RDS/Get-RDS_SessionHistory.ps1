# Usage:
# Run the script to get past 10 days of RDP sessions and save to custom path
#.\Get-RDS_SessionHistory.ps1 -DaysBack 10 -OutputPath "C:\Reports\RDS_SessionHistory.csv"

# Below will default to the last 7 days and save to the script's directory
#.\Get-RDS_SessionHistory.ps1

param (
    [int]$DaysBack = 7,
    [string]$OutputPath = "$PSScriptRoot\RDS_SessionHistory.csv"
)

$startTime = (Get-Date).AddDays(-$DaysBack)
Write-Host "`n[+] Collecting RDP session history from the last $DaysBack days..." -ForegroundColor Cyan

# Get 4624 logons (RDP)
$logons = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624
    StartTime = $startTime
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Properties[8].Value -like "RDP-Tcp*"
} | ForEach-Object {
    [PSCustomObject]@{
        EventType   = "Logon"
        TimeCreated = $_.TimeCreated
        Username    = $_.Properties[5].Value
        Domain      = $_.Properties[6].Value
        LogonID     = $_.Properties[7].Value
        IPAddress   = $_.Properties[18].Value
        SessionName = $_.Properties[8].Value
    }
}

# Get 4634 logoffs
$logoffs = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4634
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        EventType   = "Logoff"
        TimeCreated = $_.TimeCreated
        LogonID     = $_.Properties[0].Value
    }
}

# Join by LogonID to calculate session duration
$sessions = foreach ($logon in $logons) {
    $matchingLogoff = $logoffs | Where-Object { $_.LogonID -eq $logon.LogonID } | Sort-Object TimeCreated | Select-Object -First 1
    $duration = if ($matchingLogoff) {
        [math]::Round(($matchingLogoff.TimeCreated - $logon.TimeCreated).TotalMinutes, 2)
    }
    else {
        $null
    }

    [PSCustomObject]@{
        Username              = "$($logon.Domain)\$($logon.Username)"
        IPAddress             = $logon.IPAddress
        SessionName           = $logon.SessionName
        LogonTime             = $logon.TimeCreated
        LogoffTime            = $matchingLogoff?.TimeCreated
        SessionLength_Minutes = $duration
        LogonID               = $logon.LogonID
    }
}

if ($sessions.Count -gt 0) {
    $sessions | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "[✓] Exported session history to: $OutputPath`n" -ForegroundColor Green
}
else {
    Write-Warning "No RDP sessions found in the past $DaysBack days."
}