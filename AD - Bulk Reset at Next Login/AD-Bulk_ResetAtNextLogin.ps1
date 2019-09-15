# LAST MODIFIED: 2019-09-15 13:39:54
#
#
# The user-import.csv needs to be in the same path as the ps1 file.
# each line of the csv needs to be as follows (Name|AD_Account_Name) **
# Example: 
# Joe Smith|dean.amiridis
# Mary Smith|mary.smith

# ---- Data Import ----
$ErrorActionPreference = "SilentlyContinue"
Clear-Host # Start with clean powershell
$UserAccounts = Import-Csv -Path '.\user-import.csv' -Delimiter '|'  -Header @("Name", "samAccountName")
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$UserAccountsCount = $UserAccounts.Count
Write-Host "Total Imported Accounts: $UserAccountsCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $UserAccount in $UserAccounts ) { 
    Write-Host "Target user: $UserAccount.Name" -ForegroundColor "Yellow"
    Set-ADUser -Identity $UserAccount.samAccountName -ChangePasswordAtLogon $true
    Write-Host "Successfully set password change at next login for: $UserAccount.Name" -ForegroundColor "Green"
    Write-Host " "
} 