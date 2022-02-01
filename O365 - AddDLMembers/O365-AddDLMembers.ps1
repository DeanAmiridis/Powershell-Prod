# ---- Connection to O365 ----
#$UserCredential = Get-Credential
#$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
#Import-PSSession $Session
# ---- DO NOT TOUCH THE ABOVE! ----

# ---- Data Import ----
$ErrorActionPreference = "SilentlyContinue" #This is for ErrorHandling.
Clear-Content C:\O365-AddDLMembers-Errorlog.txt #This is for ErrorHandling.
$DLs = Import-Csv -Path '.\DL-import.csv' -Delimiter '|'  -Header @("Name", "Members")
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$DLsCount = $DLs.Count
Write-Host "Total Imported Accounts: $DLsCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $DL in $DLs ) {
    Add-DistributionGroupMember -Identity $DL.Name -Member $DL.Members -ea "SilentlyContinue" -ev err
    If ($err.count -gt 0) {
        Write-Host "ERROR: Error with account $DL.Members" -ForegroundColor "Red"
        Add-Content C:\O365-AddDLMembers-Errorlog.txt $DL.name
        $err.clear()
    }
    else {
        Write-Host "Added $DL.Members to $DL.Name Successfully" -ForegroundColor "Green"
    }
} 