# Variables
$BitStatus = Get-BitLockerVolume
$BitRecoveryKey = (Get-BitLockerVolume -MountPoint C).KeyProtector
$TPMPresent = (Get-TPM).TpmPresent 
$TPMReady = (Get-TPM).TpmReady
$LineSplit = "--------------------------------"
$txtTPMReady = "TPM Ready:"
$txtTPMPresent = "TPM Present:"

# Warnings
Write-Warning -Message 'PLEASE PUT FULL PATH WITH FILENAME AND TXT EXT!! (Ex: C:\bitlocker-report.txt)'

# To automate this script, comment out the SaveLOC Read-Host line below and UNcomment the line under it with the expected save location
# Script:
$SaveLOC = Read-Host -Prompt 'Where would you like to save the report to? (full path!)'
#SaveLoc = "C:\temp\bitlocker-report.txt"
Write-Host 'Obtaining Bitlocker Recovery Status' -BackgroundColor 'Black' -ForegroundColor 'Yellow'
$BitStatus >> $SaveLOC
$LineSplit >> $SaveLOC
manage-bde.exe -status >> $SaveLOC
$LineSplit >> $SaveLOC
Write-Host 'Successfully Obtained Bitlocker Recovery Status' -BackgroundColor 'Black' -ForegroundColor 'Green'
Write-Host " "
Write-Host 'Obtaining Bitlocker Recovery Keys (If applicable)' -BackgroundColor 'Black' -ForegroundColor 'Yellow'
$BitRecoveryKey >> $SaveLOC
$LineSplit >> $SaveLOC
Write-Host 'Successfully Obtained Bitlocker Recovery Keys (If applicable)' -BackgroundColor 'Black' -ForegroundColor 'Green'
Write-Host " "
Write-Host 'Obtaining TPM Status & Presence' -BackgroundColor 'Black' -ForegroundColor 'Yellow'
$txtTPMPresent >> $SaveLOC
$TPMPresent >> $SaveLOC
$txtTPMReady >> $SaveLOC
$TPMReady >> $SaveLOC
Write-Verbose "TPM Status:" >> $SaveLOC
$LineSplit >> $SaveLOC
Write-Host 'Successfully Obtained TPM Status & Presence' -BackgroundColor 'Black' -ForegroundColor 'Green'
Write-Host " "
Write-Host 'Obtaining Full TPM Report' -BackgroundColor 'Black' -ForegroundColor 'Yellow'
Get-TPM >> $SaveLOC
Write-Host 'Successfully Obtained Full TPM Report' -BackgroundColor 'Black' -ForegroundColor 'Green'

