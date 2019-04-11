# Created by Dean Amiridis
# Last Modified - 4/11/2019
#
# ---- Connection to O365 ----
#$UserCredential = Get-Credential
#$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
#Import-PSSession $Session
# ---- DO NOT TOUCH THE ABOVE! ----
#
# Above is the connection commands to run to authenticate your powershell session with the office 365 tenant. Minus the commenting "#"
# When it prompts you for credentials, be sure to enter the GA (Global Admin) Account credentials!

# ---- Import of the CSV File ----
# Example of CSV File line: Dean Amiridis|dean.amiridis@mind-shift.com
$O365UserLists = Import-Csv -Path '.\User-import.csv' -Delimiter '|'  -Header @("Name", "Alias")
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$O365UserListsCount = $O365UserLists.Count
Write-Host "Total Imported Accounts: $O365UserListsCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $O365UserList in $O365UserLists ) {
    Set-Mailbox "$O365UserList.Name" -EmailAddresses @{add="$O365UserList.Alias"}
}