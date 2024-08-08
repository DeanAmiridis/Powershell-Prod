# ---- Connection to O365 ----
# ** Run this first to authenticate to O365 **
#$UserCredential = Get-Credential
#$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
#Import-PSSession $Session

# ** Run this next, and re-authenticate **
#Connect-AzureAD

# ** Run this last authentication, then execute the .PS1 file **
#Connect-MsolService
# ---- DO NOT TOUCH THE ABOVE! ----

# ---- Data Import ----
$ErrorActionPreference = "SilentlyContinue"
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
    $UPN = $UserAccount.UPN
    Write-Host "Removing Licenses for $Name" -ForegroundColor "Yellow"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:VISIOCLIENT"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:POWER_BI_PRO"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:ENTERPRISEPACK"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:DESKLESSPACK"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:FLOW_FREE"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:RIGHTSMANAGEMENT"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:POWERAPPS_VIRAL"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:MS_TEAMS_IW"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:POWER_BI_STANDARD"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:OFFICESUBSCRIPTION"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:SPE_E3"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:O365_BUSINESS_ESSENTIALS"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:EXCHANGEENTERPRISE"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:SPE_F1"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:TEAMS_COMMERCIAL_TRIAL"
    Set-MsolUserLicense -UserPrincipalName $UPN -RemoveLicenses "reseller-account:STANDARDPACK"
    Write-Host "Setting mailbox for $Name to a Shared mailbox" -ForegroundColor "white"
    Set-Mailbox $UPN -Type Shared -LitigationHoldEnabled $True # Set's the mailbox to shared with Litigation Hold
    Write-Host "Disabling login access for: $Name" -ForegroundColor "Green"
    Set-AzureADUser -ObjectID $UPN -AccountEnabled $False # Disables login on account
} 
