<#
.ABOUT
This will target the Users.csv users in which contains teh samAccountNames and remove the proxyAddress from those users containing the old domain but retain the rest.

.EXAMPLE
.\AD-ProxyAddressCleanup.ps1 -OldSuffix "oldcompany.com" -CsvPath "C:\Temp\Users.csv"

.EXAMPLE
.\AD-ProxyAddressCleanup.ps1 -OldSuffix "oldcompany.com" -CsvPath "C:\Temp\Users.csv" -UserIdColumn "UserPrincipalName"

.EXAMPLE (dry run)
.\AD-ProxyAddressCleanup.ps1 -OldSuffix "oldcompany.com" -CsvPath "C:\Temp\Users.csv" -WhatIfMode
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OldSuffix,          # e.g. "oldcompany.com"

    [Parameter(Mandatory = $true)]
    [string]$CsvPath,            # Path to CSV with user identifiers

    [Parameter(Mandatory = $false)]
    [string]$UserIdColumn = "SamAccountName",  # Column name in CSV

    [Parameter(Mandatory = $false)]
    [string]$OutputLog = ".\Removed_ProxyAddresses_$((Get-Date).ToString('yyyyMMdd_HHmmss')).csv",

    [switch]$WhatIfMode          # If specified, no actual changes are made
)

# Ensure AD module is available
if (-not (Get-Module -ListAvailable ActiveDirectory)) {
    Write-Error "ActiveDirectory module missing. Install RSAT or run on a domain controller."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found at path: $CsvPath"
    exit 1
}

Write-Host "Loading CSV from: $CsvPath" -ForegroundColor Cyan
$csv = Import-Csv -Path $CsvPath

if ($csv.Count -eq 0) {
    Write-Error "CSV file appears to be empty."
    exit 1
}

if (-not ($csv[0].PSObject.Properties.Name -contains $UserIdColumn)) {
    Write-Error "CSV does not contain a column named '$UserIdColumn'."
    exit 1
}

Write-Host "Using column '$UserIdColumn' as the user identifier (e.g., SamAccountName/UPN/DN)." -ForegroundColor Yellow
Write-Host "Old suffix being removed from proxyAddresses: $OldSuffix" -ForegroundColor Yellow

$escapedSuffix = [regex]::Escape($OldSuffix)
$log = @()

foreach ($row in $csv) {
    $id = $row.$UserIdColumn

    if ([string]::IsNullOrWhiteSpace($id)) {
        Write-Host "Row with empty '$UserIdColumn' value skipped." -ForegroundColor DarkYellow
        continue
    }

    # Try to get the user
    $user = Get-ADUser -Identity $id -Properties proxyAddresses -ErrorAction SilentlyContinue

    if (-not $user) {
        Write-Host "User not found in AD: $id" -ForegroundColor Red
        $log += [PSCustomObject]@{
            SamAccountName      = $id
            DistinguishedName   = $null
            Status              = "UserNotFound"
            RemovedAddresses    = $null
            RemainingAddresses  = $null
        }
        continue
    }

    # Normalize allProxy to a clean string array (in case it's an ADPropertyValueCollection/PSObject)
    $allProxyRaw = $user.proxyAddresses
    if (-not $allProxyRaw) {
        Write-Host "No proxyAddresses for user: $($user.SamAccountName)" -ForegroundColor DarkYellow
        $log += [PSCustomObject]@{
            SamAccountName      = $user.SamAccountName
            DistinguishedName   = $user.DistinguishedName
            Status              = "NoProxyAddresses"
            RemovedAddresses    = $null
            RemainingAddresses  = $null
        }
        continue
    }

    $allProxy = @($allProxyRaw) | ForEach-Object { [string]$_ }

    # Addresses to remove (those containing the old suffix)
    $toRemove = $allProxy | Where-Object { $_ -match $escapedSuffix }

    if (-not $toRemove -or $toRemove.Count -eq 0) {
        Write-Host "No proxyAddresses with '$OldSuffix' for user: $($user.SamAccountName)" -ForegroundColor DarkYellow
        $log += [PSCustomObject]@{
            SamAccountName      = $user.SamAccountName
            DistinguishedName   = $user.DistinguishedName
            Status              = "NoMatchingProxyAddresses"
            RemovedAddresses    = $null
            RemainingAddresses  = ($allProxy -join ';')
        }
        continue
    }

    # Remaining addresses (everything that does NOT match the old suffix) -> normalize to string[]
    $remaining = @(
        $allProxy | Where-Object { $_ -notmatch $escapedSuffix }
    ) | ForEach-Object { [string]$_ }

    Write-Host "User: $($user.SamAccountName)" -ForegroundColor Cyan
    Write-Host "  Removing:" -ForegroundColor Cyan
    $toRemove | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

    if ($WhatIfMode) {
        Write-Host "  [WhatIfMode] No change applied. Would set proxyAddresses to:" -ForegroundColor Magenta
        if ($remaining -and $remaining.Count -gt 0) {
            $remaining | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        } else
        {
            Write-Host "    <attribute would be cleared>" -ForegroundColor DarkGray
        }
        $status = "WhatIf_NoChange"
    } else {
        if ($remaining -and $remaining.Count -gt 0) {
            # Actual update: replace proxyAddresses with normalized string[]
            Set-ADUser -Identity $user.DistinguishedName -Replace @{ proxyAddresses = $remaining }
        } else {
            # No remaining addresses – clear the attribute
            Set-ADUser -Identity $user.DistinguishedName -Clear 'proxyAddresses'
        }
        $status = "Updated"
    }

    $log += [PSCustomObject]@{
        SamAccountName      = $user.SamAccountName
        DistinguishedName   = $user.DistinguishedName
        Status              = $status
        RemovedAddresses    = ($toRemove -join ';')
        RemainingAddresses  = ($remaining -join ';')
    }
}

# Write log
$log | Export-Csv -Path $OutputLog -NoTypeInformation -Encoding UTF8
Write-Host "`nProcessing complete. Log saved to: $OutputLog" -ForegroundColor Green

if ($WhatIfMode) {
    Write-Host "WhatIfMode was enabled: no changes were written to AD." -ForegroundColor Magenta
}