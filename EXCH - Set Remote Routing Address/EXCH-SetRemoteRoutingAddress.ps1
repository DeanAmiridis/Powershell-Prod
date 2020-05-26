# Variables & Data Import
Get-RemoteMailbox -ResultSize Unlimited | Where-Object { $_.RemoteRoutingAddress -notlike “*.mail.onmicrosoft.com” } | Select-Object Name, SAMAccountName | Export-Csv "RM_Import.csv" -NoTypeInformation
(Get-Content "RM_Import.csv") | % { $_ -replace ‘"‘, "” } | out-file "RM_ImportUsersConsolidated.csv" -Fo -En ascii
$RM_Accounts = Import-Csv -Path '.\RM_ImportUsersConsolidated.csv' -Delimiter ',' -Header @("Name", "SAMAccountName")
$RoutingAddressSuffix = "" # Modify to have the correct suffix address for all accounts being adjusted.
$RM_AccountsCount = $RM_Accounts.Count-1

# Confirmation pre-exec
Write-Host "Total Imported Accounts: $RM_AccountsCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }

# Actions
foreach ( $RM_Account in $RM_Accounts ) { 
    Set-RemoteMailbox -Identity "$RM_Account.Name" -RemoteRoutingAddress "$($RM_Account.SAMAccountName)$RoutingAddressSuffix"
}  