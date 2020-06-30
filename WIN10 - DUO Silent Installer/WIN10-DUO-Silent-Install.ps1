## <----- BEFORE YOU PROCEED ----->
# Make sure you have read the document in the link below, and obtained all variables as they are unique for your organization/DUO Account
# https://duo.com/docs/rdp#first-steps
#
# For information on flags used in this script, please reference the following URL:
# https://help.duo.com/s/article/1090?language=en_US

# <----- Required ** DO NOT TOUCH ** ----->
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

## <----- Variables ----->
$APIHostname = "" # Enter your organizations DUO API Hostname here.
$SecretKey = "" # Enter your organizations DUO Secret Key here.
$IntegrationKey = "" # Enter your organizations DUO Integration Key here.
$DownloadURL = "" # Place the direct URL to the MSI file from your FTP here.
$TempPath = "" # This is your working directory, where the MSI will be downloaded and ran from. (ex: C:\temp\DUOInstaller.msi)

## <----- Actions ----->
Invoke-WebRequest $DownloadURL -OutFile $TempPath
$TempPath /S /V /qn IKEY="$IntegrationKey" SKEY="$SecretKey" HOST="$APIHostname" AUTOPUSH="#1" FAILOPEN="#1" SMARTCARD="#0" RDPONLY="#0" FAILOPEN="#1"
Start-Sleep -s 60 # This pauses the script for 60 seconds to allow the installer to run. You can adjust this based on your environment.
[System.Windows.Forms.MessageBox]::Show("DUO has been installed on your machine. Please note upon next login you will be prompted to pass multifactor authentication after your password is entered.","DUO - ALERT!",1,48)