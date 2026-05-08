#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

<#
.NAME
    SetLitigationHold.ps1
.SYNOPSIS
    Enables Litigation Hold on mailboxes listed in a CSV file and logs results.
.DESCRIPTION
    Reads a CSV file containing UserPrincipalName entries, enables Litigation Hold on
    each mailbox via Exchange Online, verifies the setting was applied after a brief
    settle delay, and exports a timestamped CSV log of all results.
    Mailboxes with Litigation Hold already enabled are skipped (idempotent).
.PARAMETER CsvPath
    Path to the input CSV file. Must contain a 'UserPrincipalName' column.
    Defaults to 'users.csv' in the same directory as this script.
.PARAMETER LogPath
    Path for the output log CSV.
    Defaults to 'LitigationHold_Log_<timestamp>.csv' alongside this script.
.DEPENDENCIES
    ExchangeOnlineManagement (Install-Module ExchangeOnlineManagement)
.PLATFORM
    Windows, PowerShell 5.1+
.USAGE_EXAMPLE
    .\SetLitigationHold.ps1
    .\SetLitigationHold.ps1 -CsvPath "C:\Data\users.csv" -LogPath "C:\Logs\hold.csv"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CsvPath = (Join-Path $PSScriptRoot "users.csv"),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LogPath = (Join-Path $PSScriptRoot ("LitigationHold_Log_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss")))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------- Functions ----------

function Write-Log {
    param(
        [ValidateSet("INFO", "WARN", "ERROR", "FATAL")]
        [string]$Severity,
        [string]$Message
    )
    switch ($Severity) {
        "WARN"  { Write-Warning "[$Severity] $Message" }
        "ERROR" { Write-Output  "[$Severity] $Message" }   # Write-Output avoids re-throw under Stop preference
        "FATAL" { Write-Output  "[$Severity] $Message" }
        default { Write-Output  "[$Severity] $Message" }
    }
}

# ---------- Pre-flight ----------

if (-not (Test-Path $CsvPath)) {
    Write-Log -Severity FATAL -Message "CSV file not found: $CsvPath"
    exit 1
}

try {
    Get-OrganizationConfig -ErrorAction Stop | Out-Null
    Write-Log -Severity INFO -Message "Already connected to Exchange Online."
}
catch {
    Write-Log -Severity INFO -Message "Connecting to Exchange Online..."
    Connect-ExchangeOnline
}

# ---------- Main ----------

$users      = Import-Csv $CsvPath
$totalCount   = @($users).Count
$successCount = 0
$skippedCount = 0
$failedCount  = 0

$results = foreach ($user in $users) {

    $upn = $user.UserPrincipalName

    if ([string]::IsNullOrWhiteSpace($upn)) {
        Write-Log -Severity WARN -Message "Skipping row — missing UserPrincipalName."
        $skippedCount++
        [PSCustomObject]@{
            UserPrincipalName      = $null
            Status                 = "Skipped"
            LitigationHoldEnabled  = $null
            LitigationHoldDuration = $null
            VerificationResult     = "Missing UserPrincipalName in CSV row"
            Timestamp              = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
        }
        continue
    }

    try {
        Write-Log -Severity INFO -Message "Processing $upn..."

        $mailbox = Get-Mailbox -Identity $upn -ErrorAction Stop

        # Idempotency: skip if hold is already enabled
        if ($mailbox.LitigationHoldEnabled -eq $true) {
            Write-Log -Severity INFO -Message "$upn — Litigation Hold already enabled. Skipping."
            $skippedCount++
            [PSCustomObject]@{
                UserPrincipalName      = $upn
                Status                 = "Skipped"
                LitigationHoldEnabled  = $mailbox.LitigationHoldEnabled
                LitigationHoldDuration = $mailbox.LitigationHoldDuration
                VerificationResult     = "Litigation Hold already enabled — no change made"
                Timestamp              = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
            }
            continue
        }

        Set-Mailbox -Identity $upn -LitigationHoldEnabled $true -ErrorAction Stop

        Start-Sleep -Seconds 3

        $mailbox = Get-Mailbox -Identity $upn -ErrorAction Stop

        if ($mailbox.LitigationHoldEnabled -eq $true) {
            $status       = "Success"
            $verification = "Litigation Hold verified as enabled"
            $successCount++
            Write-Log -Severity INFO -Message "$upn — $verification"
        }
        else {
            $status       = "Failed"
            $verification = "Litigation Hold was applied but verification failed"
            $failedCount++
            Write-Log -Severity WARN -Message "$upn — $verification"
        }

        [PSCustomObject]@{
            UserPrincipalName      = $upn
            Status                 = $status
            LitigationHoldEnabled  = $mailbox.LitigationHoldEnabled
            LitigationHoldDuration = $mailbox.LitigationHoldDuration
            VerificationResult     = $verification
            Timestamp              = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
        }
    }
    catch {
        $failedCount++
        Write-Log -Severity ERROR -Message "$upn — $($_.Exception.Message)"
        [PSCustomObject]@{
            UserPrincipalName      = $upn
            Status                 = "Error"
            LitigationHoldEnabled  = $null
            LitigationHoldDuration = $null
            VerificationResult     = $_.Exception.Message
            Timestamp              = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
        }
    }
}

$results | Export-Csv -Path $LogPath -NoTypeInformation

Write-Log -Severity INFO -Message "Completed. Total: $totalCount | Success: $successCount | Skipped: $skippedCount | Failed: $failedCount"
Write-Log -Severity INFO -Message "Log saved to: $LogPath"
