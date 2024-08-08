# ---- Connection to O365 ----
#$UserCredential = Get-Credential
#$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
#Import-PSSession $Session
# ---- DO NOT TOUCH THE ABOVE! ----

# ---- Data Import ----
$DLs = Import-Csv -Path '.\DL-import.csv'
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$DLsCount = $DLs.Count
Write-Host "Total Imported Accounts: $DLsCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $DL in $DLs ) {
    $Name = $DL.Name
    $PrimarySMTPAddress = $DL.PrimarySmtpAddress
    New-DistributionGroup -Name $DL.Name -DisplayName $Name -PrimarySmtpAddress $PrimarySmtpAddress -Type Distribution
}  