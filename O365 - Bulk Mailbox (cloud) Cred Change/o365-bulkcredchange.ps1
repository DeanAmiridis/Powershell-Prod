# ---- Connection to O365 ----
Connect-MsolService # Comment out if you plan on running the script while already connected to MSOLService

# ---- Data Import ----
$UPNs = Import-Csv -Path '.\user-import.csv' -Delimiter '|'  -Header @("Address", "NewPass")
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$UPNsCount = $UPNs.Count - 1
Write-Host "Total Imported Accounts: $UPNsCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $UPN in $UPNs ) { 
    Set-MsolUserPassword -UserPrincipalName $UPN.Address -NewPassword $UPN.NewPass -ForceChangePassword $false
    Write-Host "Credential changed for $UPN.Address" -ForegroundColor Green
}  