$BitStatus = Get-BitLockerVolume
$BitRecoveryKey = (Get-BitLockerVolume -MountPoint C).KeyProtector
Write-Warning -Message 'PLEASE PUT FULL PATH WITH FILENAME AND TXT EXT!! (Ex: C:\bitlocker-report.txt)'
# To automate this script, comment out the SaveLOC Read-Host line below and UNcomment the line under it with the expected save location
$SaveLOC = Read-Host -Prompt 'Where would you like to save the report to? (full path!)'
#SaveLoc = "C:\temp\bitlocker-report.txt"
Write-Host 'Obtaining Bitlocker Recovery Status' -BackgroundColor 'Black' -ForegroundColor 'Yellow'
$BitStatus >> $SaveLOC
manage-bde.exe -status >> $SaveLOC
Write-Host 'Successfully Obtained Bitlocker Recovery Status' -BackgroundColor 'Black' -ForegroundColor 'Green'
Write-Host 'Obtaining Bitlocker Recovery Keys (If applicable)' -BackgroundColor 'Black' -ForegroundColor 'Yellow'
$BitRecoveryKey >> $SaveLOC
Write-Host 'Successfully Obtained Bitlocker Recovery Keys (If applicable)' -BackgroundColor 'Black' -ForegroundColor 'Green'