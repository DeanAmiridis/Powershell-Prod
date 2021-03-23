# This script requires users to confirm if they are on the VPN or on corporate network prior to proceeding.
#
#
$LogonServer = $Env:LOGONSERVER
$BitlockerDrive = Get-BitLockerVolume -MountPoint C
$BitRecoveryPass = $BitLockerDrive.KeyProtector | Where-Object { $_.KeyProtectorType -match 'RecoveryPassword' }
$confirmation = Read-Host "Be sure you are connected to VPN or Corp Network! Proceed?"
if ($confirmation -eq 'y') {
    Write-Host "KeyProtector Found:" -NoNewline -ForegroundColor "Green" ; Write-Host $BitRecoverypass.KeyProtectorID
    Write-Host "Pushing keys to active-directory server..." -ForegroundColor "Yellow"
    manage-bde -protectors -adbackup C: -id $BitRecoverypass.KeyProtectorID
    Write-Host "Pushed Recovery Key to $LogonServer." -ForegroundColor "Green"
}

