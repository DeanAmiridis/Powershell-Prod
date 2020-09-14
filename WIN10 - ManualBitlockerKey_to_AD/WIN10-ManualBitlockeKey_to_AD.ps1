# This script requires users to confirm if they are on the VPN or on corporate network prior to proceeding.
#
#
$LogonServer = $Env:LOGONSERVER
$BitRecoveryPass = (Get-BitlockerVolume).KeyProtector.KeyProtectorID
$confirmation = Read-Host "Be sure you are connected to VPN or Corp Network! Proceed?"
if ($confirmation -eq 'y') {
    Write-Host "KeyProtector Found:" -NoNewline -ForegroundColor "Green" ; Write-Host $BitRecoveryPass
    Write-Host "Pushing keys to active-directory server..." -ForegroundColor "Yellow"
    manage-bde -protectors -adbackup C: -id $BitRecoveryPass
    Write-Host "Pushed Recovery Key to $LogonServer." -ForegroundColor "Green"    
}

