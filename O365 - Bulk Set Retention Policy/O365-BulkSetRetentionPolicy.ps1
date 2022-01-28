# ---- Connection to O365 ----
Connect-ExchangeOnline # Comment out if you plan on running the script while already connected to MSOLService

# ---- Variables ----
# Default script is set to disable Password Expiration. If you would like to Enable it, set this to "False"
$RetentionPolicyName = ""

# ---- Data Import ----
$Users = Import-Csv -Path '.\user-import.csv' -Header @("UPN")
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$UsersCount = $Users.Count - 1
Write-Host "Total Imported Accounts: $UsersCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $User in $Users ) {
    Set-Mailbox -Identity $User.UPN -RetentionPolicy $RetentionPolicyName
    Write-Host "Retention Policy set for $User.UPN" -ForegroundColor Green
    Start-ManagedFolderAssistant -Identity $User.UPN
    Write-Host "Folder Assistant restarted for $User.UPN" -ForegroundColor Yellow
}