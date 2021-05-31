# Variables
$date = Get-Date
$date = $date.ToString("dd-MM-yyyy-hh-mm-ss")

# Encrypted Files Cleanup
$EncryptedFilesCleanup = ".\Encrypted_Files\*.*"
if (Test-Path $EncryptedFilesCleanup) {
    Remove-Item $EncryptedFilesCleanup -Force
}
$Files2EncryptCleanup = ".\Files2Encrypt.csv"
if (Test-Path $Files2EncryptCleanup) {
    Remove-Item $Files2EncryptCleanup -Force
}
$Files2EncryptHeaderCleanup = ".\Files2Encrypt-Header.csv"
if (Test-Path $Files2EncryptHeaderCleanup) {
    Remove-Item $Files2EncryptHeaderCleanup -Force
}

# Grab files in encrypt directory
$RootPath = "C:\Git\Powershell-Dev\Win4GPG - File Encryption\*.txt"
$FileList = Get-ChildItem -Path $RootPath -Name
$FileList | Out-File "Files2Encrypt.csv"
import-csv .\Files2Encrypt.csv -Header "Name" | export-csv .\Files2Encrypt-Header.csv -NoTypeInformation

# Encryption Actions
$Files = Import-Csv -Path '.\Files2Encrypt-Header.csv'
Foreach ( $File in $Files ) {
    gpg --sign $File.Name
}

# Cleanup
$OldFilesPath = New-Item -ItemType directory -Path ".\Old_Files\$date"
Move-Item -Path .\*.txt -Destination $OldFilesPath

$EncryptedFilesPath = "Encrypted_Files"
if (!(Test-Path $EncryptedFilesPath)) {
    New-Item -itemType Directory -Path .\Encrypted_Files
}
else {
    write-host "Folder already exists! Skipping.."
}
Move-Item -Path .\*.gpg -Destination $EncryptedFilesPath
