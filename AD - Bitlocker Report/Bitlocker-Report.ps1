# Important Information:
# - Export file will export file in the same directory where the ps1 is located
# - Export file will be saved as Bitlocker-Report_YEAR_date-HOUR-minute to avoid overwrites.
# - Script should be ran on a domain controller that has the Bitlocker Management roles installed
#
# Last Modified: 02-10-2021

# Required Modules
Import-Module ActiveDirectory -ErrorAction Stop
Write-Host "Imported Active Directory Module ..." -ForegroundColor Yellow
Write-Host "Running Bitlocker Report ..." -ForegroundColor Yellow

# Variables
$Computers = get-adcomputer -filter *
$CurrentDate = (Get-Date).ToString("yyyy_MM_dd-hh_mm")

# Code Execution
ForEach ($Computer in $Computers) {
    Get-ADobject -searchbase $computer -filter { objectclass -eq 'msFVE-RecoveryInformation' } -properties msFVE-RecoveryPassword, whencreated | select-object @{name = "Computer Name"; Expression = { $computer.name } }, whenCreated, msFVE-RecoveryPassword | export-csv Bitlocker-Report_$CurrentDate.csv -append -NoTypeInformation
    Write-Host "Scanning Bitlocker Data for $Computer ..." -ForegroundColor Yellow -BackgroundColor Black
}

# End Script/Identification
Write-Host "Bitlocker Report Complete & Exported ..." -ForegroundColor Green