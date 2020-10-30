## <----- BEFORE YOU PROCEED ----->
# Make sure you have read the document in the link below, and obtained all variables as they are unique for your organization/DUO Account
# https://duo.com/docs/rdp#first-steps
#
# For information on flags used in this script, please reference the following URL:
# https://help.duo.com/s/article/1090?language=en_US

# <----- Required ** DO NOT TOUCH ** ----->
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
$DUOVerification = Get-WmiObject -Class Win32_Product | where-object { $_.name -Like "Duo*" }

## <----- Variables ----->
$APIHostname = "" # Enter your organizations DUO API Hostname here.
$SecretKey = "" # Enter your organizations DUO Secret Key here.
$IntegrationKey = "" # Enter your organizations DUO Integration Key here.
$DownloadURL = "" # Place the direct URL to the MSI file from your FTP here.
$TempPath = "" # This is your working directory, where the MSI will be downloaded and ran from. (ex: C:\temp\DUOInstaller.msi)

## <----- Actions ----->
Invoke-WebRequest $DownloadURL -OutFile $TempPath
Start-Sleep -s 240 # This pauses the script for 240 seconds to allow the installer to run. You can adjust this based on your environment. (Ex: 240 = 4 Minutes)

$FileCheck = Test-Path $TempPath
If ($FileCheck -eq $True) {
    Write-EventLog -LogName Application -Source "DUO-Silent-Installer" -EntryType Information -EventID 3 -Message "Successfully downloaded DUO Installer to: $TempPath"
    $TempPath /S /V /qn IKEY="$IntegrationKey" SKEY="$SecretKey" HOST="$APIHostname" AUTOPUSH="#1" FAILOPEN="#1" SMARTCARD="#0" RDPONLY="#0" FAILOPEN="#1"
    Start-Sleep -s 60 # This pauses the script for 60 seconds to allow the installer to run. You can adjust this based on your environment.
}
else {
    Write-EventLog -LogName Application -Source "DUO-Silent-Installer" -EntryType Error -EventID 3 -Message "DUO Installation file not found during installation; Script aborted."
    Get-Eventlog -LogName Application -Source DUO-Silent-Installer -Newest 25 | Format-Table -Wrap | Out-File -Append .\DUO_Silent_Installer-Log.csv
    Exit
}
If ($null -ne $DUOVerification) {
    Write-EventLog -LogName Application -Source "DUO-Silent-Installer" -EntryType Information -EventID 3 -Message "DUO Silently installed successfully"
    [System.Windows.Forms.MessageBox]::Show("DUO has been installed on your machine. Please note upon next login you will be prompted to pass multifactor authentication after your password is entered.", "DUO - ALERT!", 1, 48)
    Write-EventLog -LogName Application -Source "DUO-Silent-Installer" -EntryType Information -EventID 3 -Message "Warning message provided to user."
    $DUOVerification | Out-File -Append .\DUO_Silent_Installer-Log.csv # Pulls DUO Installed version/application information and writes to log.
    Write-EventLog -LogName Application -Source "DUO-Silent-Installer" -EntryType Information -EventID 3 -Message "DUO installation confirmation completed and exported to log."
    Get-Eventlog -LogName Application -Source DUO-Silent-Installer -Newest 10 | Format-Table -Wrap | Out-File -Append .\DUO_Silent_Installer-Log.csv
}
Else {
    Write-EventLog -LogName Application -Source "DUO-Silent-Installer" -EntryType Error -EventID 3 -Message "DUO installation failed. Please rerun script!"
}
## <----- Housekeeping/cleanup ----->
$FileCheck = Test-Path $TempPath
If ($FileCheck -eq $True) {
    Remove-Item -Recurse -Force $TempPath
    Write-EventLog -LogName Application -Source "DUO-Silent-Installer" -EntryType Information -EventID 3 -Message "DUO Installation file successfully purged."

}
else {
    Write-EventLog -LogName Application -Source "DUO-Silent-Installer" -EntryType Error -EventID 3 -Message "DUO Installation file not found during cleanup."
}

## <----- Final log output ----->
Get-Eventlog -LogName Application -Source DUO-Silent-Installer -Newest 25 | Format-Table -Wrap | Out-File -Append .\DUO_Silent_Installer-Log.csv