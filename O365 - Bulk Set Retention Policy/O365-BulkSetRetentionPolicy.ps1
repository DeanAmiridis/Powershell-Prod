# ---- Connection to O365 ----
Connect-ExchangeOnline # Comment out if you plan on running the script while already connected to MSOLService

# ---- Variables ----
# Default script is set to disable Password Expiration. If you would like to Enable it, set this to "False"
$RetentionPolicyName = ""

# ---- Data Import ----
$Users = Import-Csv -Path '.\user-import.csv'
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$UsersCount = $Users.Count - 1
Write-Host "Total Imported Accounts: $UsersCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $User in $Users ) {
    $UPN = $User.UPN
    Set-Mailbox -Identity $UPN -RetentionPolicy $RetentionPolicyName
    Write-Host "Retention Policy set for $UPN" -ForegroundColor Green
    Start-ManagedFolderAssistant -Identity $UPN
    Write-Host "Folder Assistant restarted for $UPN" -ForegroundColor Yellow
}