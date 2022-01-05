# ---- Module Import ----
import-Module ActiveDirectory
# ---- Module Import End ----

# ---- Data Import ----
Clear-Host # Start with clean powershell
$UserAccounts = Import-Csv -Path '.\user-import.csv' -Delimiter ','  -Header @("Name", "JobTitle")
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$UserAccountsCount = $UserAccounts.Count
Write-Host "Total Imported Accounts: $UserAccountsCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $UserAccount in $UserAccounts ) {
    Get-ADUser $UserAccount.Name | Set-ADUser -Title $UserAccount.JobTitle
    Write-Host "Successfully updated Job Title for $UserAccount.Name to $UserAccount.JobTitle"
}
# ---- Action End ----