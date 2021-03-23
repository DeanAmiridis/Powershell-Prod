# This script is completely silent to the user and can be excecuted remotely without user interruption.
# 
#
$LogonServer = $Env:LOGONSERVER
$BitlockerDrive = Get-BitLockerVolume -MountPoint C
$BitRecoveryPass = $BitLockerDrive.KeyProtector | Where-Object { $_.KeyProtectorType -match 'RecoveryPassword' }
    Write-Host "KeyProtector Found:" -NoNewline -ForegroundColor "Green" ; Write-Host $BitRecoverypass.KeyProtectorID
    Write-Host "Pushing keys to active-directory server..." -ForegroundColor "Yellow"
    manage-bde -protectors -adbackup C: -id $BitRecoverypass.KeyProtectorID
    Write-Host "Pushed Recovery Key to $LogonServer." -ForegroundColor "Green"

