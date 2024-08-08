# ---- Connection to Office365 **Uncomment to use** ----
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

# ---- Variables *DO NOT TOUCH ----
$st = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
$st.RelyingParty = "*"
$st.State = "Enabled"
$sta = @($st)

# ---- Actions ----
foreach ( $Account in $Accounts ) {
    $Username = $Account.Username
    Set-MsolUser -UserPrincipalName $Username -StrongAuthenticationRequirements $sta
    write-host "Completed enabling $Username..."
}
