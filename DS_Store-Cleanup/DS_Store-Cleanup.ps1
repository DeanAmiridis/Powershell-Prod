# Test Comment
Clear-Host
$DriveLetter = Read-Host 'What path would you like to scan/cleanup? (ex: C:\Documents\ or  C:\)'
Write-Host " "
Write-Host -nonewline "Dry-Run cleanup of $Driveletter, Do you want to continue? (Y/N) "
$response = read-host
if ( $response -ne "Y" ) { exit }
Write-Host " "
Write-Host " "
Get-ChildItem -Path $DriveLetter -Filter .DS_Store -Recurse -ErrorAction SilentlyContinue -Force | ForEach-Object ($_) {remove-item $_.fullname  -whatif}
Write-Host " "
Write-Host "********************************************" -ForegroundColor "yellow"
Write-Host "Be sure to review the files listed above (if any) before hitting Y! This cannot be reverted!" - -ForegroundColor "red"
Write-Host "********************************************" - -ForegroundColor "yellow"
Write-Host " "
Write-Host -nonewline "Cleaning up drive $Driveletter, Do you want to continue *CHANGES CANNOT BE REVERTED!*? (Y/N) " - -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
Get-ChildItem -Path $DriveLetter -Filter .DS_Store -Recurse -ErrorAction SilentlyContinue -Force | ForEach-Object ($_) {remove-item $_.fullname}
Write-Host " "
Write-Host " "
Write-Host "All done!" -ForegroundColor "green"