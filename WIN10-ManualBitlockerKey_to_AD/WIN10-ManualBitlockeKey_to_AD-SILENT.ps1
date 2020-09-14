$LogonServer = $Env:LOGONSERVER
$BitRecoveryPass = (Get-BitlockerVolume).KeyProtector.KeyProtectorID
    Write-Host "KeyProtector Found:" -NoNewline -ForegroundColor "Green" ; Write-Host $BitRecoveryPass
    Write-Host "Pushing keys to active-directory server..." -ForegroundColor "Yellow"
    manage-bde -protectors -adbackup C: -id $BitRecoveryPass
    Write-Host "Pushed Recovery Key to $LogonServer." -ForegroundColor "Green"    

