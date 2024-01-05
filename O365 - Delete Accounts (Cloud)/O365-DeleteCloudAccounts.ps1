# Created by Dean Amiridis
# Last Modified - 01/05/2024
#
# ---- Connection to O365 ----
# MSOL is required for this script to run. If you do not have it installed, run the following command:
# Install-Module MSOnline
# Alternatively you can use the AzureAD Module. If you do not have it installed, run the following command:
# Install-Module AzureAD
#
# ---- Import of the CSV File ----
# Example of CSV File line: Dean Amiridis|dean.amiridis@mind-shift.com
$O365UserLists = Import-Csv -Path '.\user-import.csv'
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$O365UserListsCount = $O365UserLists.Count
Write-Host "Total Imported Accounts: $O365UserListsCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $O365UserList in $O365UserLists ) {
    $Username = $O365UserList.Username
    Remove-MsolUser -UserPrincipalName $Username -Force
    If ($?) {
        Write-Host "Account $Username Deleted Successfully" -ForegroundColor "green"
    }
    Else {
        Write-Host "Account $Username Failed to Delete" -ForegroundColor "red"
    }

}