<#
.SYNOPSIS
Finds all AD objects that reference a given domain suffix (UPN/email suffix).

.DESCRIPTION
Searches across:
- userPrincipalName
- mail
- proxyAddresses

Outputs:
- DistinguishedName
- ObjectClass (user, group, computer, contact, etc.)
- SamAccountName
- UPN, mail, proxyAddresses
- Which attributes matched

.EXAMPLE
.\AD-Find-ObjectsUsingSuffix.ps1 -Suffix "oldcompany.com"

.EXAMPLE
.\AD-Find-ObjectsUsingSuffix.ps1  -Suffix "@oldcompany.com" -SearchBase "OU=Users,DC=oldcompany,DC=com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Suffix,                    # e.g. "oldcompany.com" or "@oldcompany.com"

    [Parameter(Mandatory = $false)]
    [string]$SearchBase,                # Optional: e.g. "OU=Users,DC=corp,DC=local"

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\AD_Objects_Using_Suffix.csv"
)

# Ensure AD module is available
if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
    Write-Error "ActiveDirectory module not found. Install RSAT or run on a domain controller."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

# Normalize suffix: strip leading "@", work with bare domain
$DomainPart = $Suffix.TrimStart('@')

if ([string]::IsNullOrWhiteSpace($DomainPart)) {
    Write-Error "Suffix '$Suffix' is not valid."
    exit 1
}

Write-Host "Searching for objects referencing domain suffix: $DomainPart" -ForegroundColor Yellow

# Patterns to match
$upnPattern   = "*@$DomainPart"
$emailPattern = "*@$DomainPart"
$proxyPattern = "*$DomainPart*"

# Build base Get-ADObject parameters
$adParams = @{
    Filter      = '*'
    Properties  = @(
        'distinguishedName',
        'objectClass',
        'sAMAccountName',
        'userPrincipalName',
        'mail',
        'proxyAddresses'
    )
}

if ($SearchBase) {
    $adParams.SearchBase = $SearchBase
}

Write-Host "Pulling AD objects... this may take a while in large environments..." -ForegroundColor Cyan

$allObjects = Get-ADObject @adParams

Write-Host ("Total objects retrieved: {0}" -f $allObjects.Count)

$results = foreach ($obj in $allObjects) {
    $matches = @()

    $upn  = $obj.userPrincipalName
    $mail = $obj.mail
    $prox = $obj.proxyAddresses

    if ($upn -and ($upn -like $upnPattern)) {
        $matches += "userPrincipalName"
    }

    if ($mail -and ($mail -like $emailPattern)) {
        $matches += "mail"
    }

    if ($prox) {
        # proxyAddresses is multi-valued
        $proxyHit = $false
        foreach ($p in $prox) {
            if ($p -like $proxyPattern) {
                $proxyHit = $true
                break
            }
        }
        if ($proxyHit) {
            $matches += "proxyAddresses"
        }
    }

    if ($matches.Count -gt 0) {
        [PSCustomObject]@{
            DistinguishedName = $obj.DistinguishedName
            ObjectClass       = $obj.ObjectClass
            SamAccountName    = $obj.SamAccountName
            UserPrincipalName = $upn
            Mail              = $mail
            ProxyAddresses    = if ($prox) { $prox -join ';' } else { $null }
            MatchOnAttributes = $matches -join ';'
        }
    }
}

if (-not $results) {
    Write-Host "No objects found that reference suffix '$DomainPart' in UPN/mail/proxyAddresses." -ForegroundColor Green
} else {
    Write-Host ("Objects found: {0}" -f $results.Count) -ForegroundColor Yellow
    Write-Host ("Exporting to: {0}" -f (Resolve-Path $OutputPath)) -ForegroundColor Cyan

    $results |
        Sort-Object ObjectClass, SamAccountName |
        Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

    Write-Host "Export complete." -ForegroundColor Green
}