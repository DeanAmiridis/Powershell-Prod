# Last Modified Time: 2019-09-06 14:40:25
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
    Write-Host "Removing Exchange Attributes for $UserAccount.Name" -ForegroundColor "Yellow"
    Get-ADuser $UserAccount.samAccountName | set-aduser -clear msExchMailboxGuid, msexchhomeservername, legacyexchangedn, msexchmailboxsecuritydescriptor, msexchpoliciesincluded, msexchrecipientdisplaytype, msexchrecipienttypedetails, msexchumdtmfmap, msexchuseraccountcontrol, msexchversion
    Write-Host "Successfully cleared Exchange Attributes for $UserAccount" -ForegroundColor "Green"
    Write-Host " "
} 