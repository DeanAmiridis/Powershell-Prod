$DirPath = Import-Csv -Path '.\dir-path.csv' -Delimiter '|'  -Header @("Path")
$EmptyDir = "C:\empty\"
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$DirPathCount = $DirPath.Count
Write-Host "Total Imported Accounts: $DirPathCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $DirPath in $DirPaths ) {
robocopy $EmptyDir $DirPath /MIR
}