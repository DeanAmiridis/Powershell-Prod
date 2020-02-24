
$BitStatus = Get-BitLockerVolume
$BitRecoveryKey = (Get-BitLockerVolume -MountPoint C).KeyProtector
Write-Warning "PLEASE PUT FULL PATH WITH FILENAME AND TXT EXT!! (Ex: C:\bitlocker-report.txt)"
$SaveLOC = Read-Host "Where would you like to save the report to? (full path!)"
Write-Host "Obtaining Bitlocker Recovery Status" -BackgroundColor 'Black' -ForegroundColor 'Yellow'
$BitStatus >> $SaveLOC
Write-Host "Successfully Obtained Bitlocker Recovery Status" -BackgroundColor 'Black' -ForegroundColor 'Green'
Write-Host "Obtaining Bitlocker Recovery Keys (If applicable)" -BackgroundColor 'Black' -ForegroundColor 'Yellow'
$BitRecoveryKey >> $SaveLOC
Write-Host "Successfully Obtained Bitlocker Recovery Keys (If applicable)" -BackgroundColor 'Black' -ForegroundColor 'Green'