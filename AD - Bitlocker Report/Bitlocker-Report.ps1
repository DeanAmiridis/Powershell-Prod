# Important Information:
# - Export file will export file in the same directory where the ps1 is located
# - Export file will be saved as HOSTNAME-Bitlocker-Report_YEAR_date-HOUR-minute to avoid overwrites.
# - Script should be ran on a domain controller that has the Bitlocker Management roles installed

# Required Modules
Import-Module ActiveDirectory -ErrorAction Stop
Write-Host "Imported Active Directory Module ..." -ForegroundColor Yellow
Write-Host "Running Bitlocker Report ..." -ForegroundColor Yellow

# Variables
$Computers = get-adcomputer -filter *
$CurrentDate = (Get-Date).ToString("yyyy_MM_dd-hh_mm")
$DC = Hostname
$Counter = 0

# Code Execution
ForEach ($Computer in $Computers) {
    Get-ADobject -Searchbase $computer -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -Properties msFVE-RecoveryPassword, WhenCreated | Select-Object @{name = "Computer Name"; Expression = { $computer.name } }, WhenCreated, msFVE-RecoveryPassword | Export-CSV $DC-Bitlocker-Report_$CurrentDate.csv -Append -NoTypeInformation
    $Counter++
    Write-Progress -Activity 'Scanning bitlocker data...' -CurrentOperation $Computer -PercentComplete (($counter / $Computers.count) * 100)
}

# End Script/Identification
Write-Host "Bitlocker Report Complete & Exported ..." -ForegroundColor Green