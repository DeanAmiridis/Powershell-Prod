# LAST MODIFIED: 2019-09-13 18:48:45
#
#
# The user-import.csv needs to be in the same path as the ps1 file.
# each line of the csv needs to be as follows (Name|AD_Account_Name) **
# Example: 
# Joe Smith|dean.amiridis|temppassword
# Mary Smith|mary.smith|temppassword

# ---- Data Import ----
$ErrorActionPreference = "SilentlyContinue"
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
    $samAccountName = $UserAccount.samAccountName
    $Password = $UserAccount.Password
    Write-Host "Resetting password for $Name" -ForegroundColor "Yellow"
    Set-ADAccountPassword -Identity $samAccountName -NewPassword (ConvertTo-SecureString -AsPlainText "$Password" -Force)
    Write-Host "Successfully changed password for $Name" -ForegroundColor "Green"
    Write-Host " "
} 