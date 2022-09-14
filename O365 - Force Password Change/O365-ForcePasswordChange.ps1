# THIS IS FOR CLOUD ACCOUNTS ONLY! If accounts are synced with ADConnect, do not use; it will fail.
#
#---- Connection to Office365 **Uncomment to use** ----
#Connect-MsolService

# ---- Data Import Start  ----
$Accounts = Import-Csv -Path '.\account-import.csv'
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$AccountsCount = $Accounts.Count - 1
Write-Host "Total Imported Accounts: $AccountsCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Actions ----
foreach ( $Account in $Accounts ) {
    $Username = $Account.UserPrincipalName
    Set-MsolUser -UserPrincipalName $Username -StrongPasswordRequired:$true
    Write-Host "Password Reset Required for $Username" -ForegroundColor "green"
}