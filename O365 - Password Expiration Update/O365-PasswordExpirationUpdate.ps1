# ---- Connection to O365 ----
Connect-MsolService # Comment out if you plan on running the script while already connected to MSOLService

# ---- Variables ----
# Default script is set to disable Password Expiration. If you would like to Enable it, set this to "False"
$PassExpiration = $True

# ---- Data Import ----
$UPNs = Import-Csv -Path '.\UPN-import.csv'
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$UPNsCount = $UPNs.Count - 1
Write-Host "Total Imported Accounts: $UPNsCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $UPN in $UPNs ) {
    $UPN = $UPN.UPN
    Get-MsolUser -UserPrincipalName $upn | Set-MsolUser -PasswordNeverExpires $PassExpiration
    Write-Host "Disabled Password Expiration for $UPN" -ForegroundColor Green
}  