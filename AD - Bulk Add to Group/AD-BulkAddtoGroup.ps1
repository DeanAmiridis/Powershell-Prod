# ---- CSV Formatting ----
# Filename: user-import.csv
# CSV should look like the following:
# GroupName|samAccountName
# GroupName|samAccountName

# ---- Modules ----
import-module activedirectory #if already completed, you can comment Line2 out.

# ---- Data Import ----
Clear-Content C:\AD-AddGroupMembers-Errorlog.txt #This is for ErrorHandling.
$Users = Import-Csv -Path '.\user-import.csv'
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$UsersCount = $Users.Count
Write-Host "Total Imported Accounts: $UsersCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $User in $Users ) {
    $GroupName = $User.GroupName
    $Members = $User.Members
    Add-ADGroupMember -Identity $GroupName -Member $Members
    If ($err.count -gt 0) {
        Write-Host "ERROR: Error with account $Members" -ForegroundColor "Red"
        Add-Content C:\AD-AddGroupMembers-Errorlog.txt $User.Members
        $err.clear()
    }
    else {
        Write-Host "Added $Members to $GroupName Successfully" -ForegroundColor "Green"
    }
} 