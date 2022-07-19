# ---- Module Import ----
import-Module ActiveDirectory
# ---- Module Import End ----

# ---- Data Import ----
Clear-Host # Start with clean powershell
$UserAccounts = Import-Csv -Path '.\user-import.csv'
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$UserAccountsCount = $UserAccounts.Count
Write-Host "Total Imported Accounts: $UserAccountsCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $UserAccount in $UserAccounts ) {
    $Name = $UserAccount.Name
    $NewUPN = $UserAccount.NewUPN
    Get-ADUser $Name | Set-ADUser -UserPrincipalName $NewUPN
    Write-Host "Successfully adjusted UPN for $Name to $NewUPN"
} 
# ---- Action End ----