# Define variables
$OU = "OU=Users,DC=example,DC=com"  # Replace with your target OU
$LogFile = "C:\Logs\PasswordNeverExpiresLog_$(Get-Date -Format 'yyyyMMddHHmmss').txt"

# Ensure the log file directory exists
if (!(Test-Path -Path (Split-Path -Path $LogFile))) {
    New-Item -ItemType Directory -Path (Split-Path -Path $LogFile) -Force
}

# Write log header
"Password Never Expires Adjustment Log" | Out-File -FilePath $LogFile
"Generated: $(Get-Date)" | Out-File -FilePath $LogFile -Append
"------------------------------------------" | Out-File -FilePath $LogFile -Append

# Import the Active Directory module
Import-Module ActiveDirectory

# Search for users in the specified OU
$Users = Get-ADUser -Filter * -SearchBase $OU -Properties PasswordNeverExpires

foreach ($User in $Users) {
    if (-not $User.PasswordNeverExpires) {
        try {
            # Set PasswordNeverExpires to True
            Set-ADUser -Identity $User.DistinguishedName -PasswordNeverExpires $true

            # Log the adjustment
            "Adjusted: $($User.SamAccountName) ($($User.DistinguishedName))" | Out-File -FilePath $LogFile -Append
        }
        catch {
            # Log any errors
            "Error adjusting $($User.SamAccountName): $($_.Exception.Message)" | Out-File -FilePath $LogFile -Append
        }
    }
}

# Finish the log
"------------------------------------------" | Out-File -FilePath $LogFile -Append
"Script completed at: $(Get-Date)" | Out-File -FilePath $LogFile -Append

Write-Host "Script completed. Check the log file at $LogFile for details."