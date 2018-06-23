import-module ActiveDirectory
#-----MODIFY ONLY THE BELOW-----
# The request ID is the request number that is provided to reference the disable request.
$RequestID = "REQ0016803"

#-----DO NOT MODIFY BELOW THIS LINE-----
$UserAccounts = Get-Content "user-list.csv" 
$UserCount = $UserAccounts.Count
Write-Host "Total Imported Accounts: $UserCount" -ForegroundColor "green"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
foreach ( $UserAccount in $UserAccounts ) { 
    Write-Host "---"
    Write-Host "Working on $UserAccount ..." -ForegroundColor "yellow"
    Write-Host "---"
    $UserDN = Get-ADUser -filter {employeeid -eq $UserAccount}
    Set-ADUser -Identity $UserDN -Add @{msExchHideFromAddressLists = "TRUE"}
    Set-ADUser -Identity $UserDN -Description "$RequestID Account Disabled"
    Get-ADUser -filter {employeeid -eq $UserAccount} | Move-ADObject -TargetPath 'OU=Disabled Objects,DC=usi,DC=X,DC=org'
    Get-ADUser -filter {employeeid -eq $UserAccount} | Disable-ADAccount
    Start-sleep -s 2
    Write-Host "---"
    Write-Host "Completed $UserAccount, Moving on to the next..." -ForegroundColor "green"
    Write-Host "---"
}  
