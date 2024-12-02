# LAST MODIFIED: 12/01/2024
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
$logFile = "action-log.txt"
$UserAccounts = Import-Csv -Path '.\user-import.csv'
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
Add-Content -Path $logFile -Value "CSV Imported Successfully - $(Get-Date)"
$UserAccountsCount = $UserAccounts.Count
Write-Host "Total Imported Accounts: $UserAccountsCount" -ForegroundColor "yellow"
Add-Content -Path $logFile -Value "Total Imported Accounts: $UserAccountsCount - $(Get-Date)"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $UserAccount in $UserAccounts ) {
    $Name = $UserAccount.Name
    $samAccountName = $UserAccount.samAccountName
    Write-Host "Target user: $Name" -ForegroundColor "Yellow"
    try {
        Set-ADUser -Identity $samAccountName -ChangePasswordAtLogon $true
        Write-Host "Successfully set password change at next login for: $Name" -ForegroundColor "Green"
        Add-Content -Path $logFile -Value "Successfully set password change at next login for: $Name - $(Get-Date)"
    }
    catch {
        Write-Host "Failed to set password change at next login for: $Name" -ForegroundColor "Red"
        Add-Content -Path $logFile -Value "Failed to set password change at next login for: $Name - $(Get-Date)"
    }
    Write-Host " "
}