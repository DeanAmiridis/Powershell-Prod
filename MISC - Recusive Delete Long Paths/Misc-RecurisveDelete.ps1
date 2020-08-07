$DirPaths = Import-Csv -Path '.\dir-path.csv'
$EmptyDir = "C:\empty"
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$DirPathCount = $DirPaths.Count - 1 #If you do not have a header on your csv file, remove the " - 1" from this line.
Write-Host "Total Imported Paths: $DirPathCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }
# ---- Data Import End ----

# ---- Action ----
foreach ( $DirPath in $DirPaths ) {
    robocopy $EmptyDir $DirPath /MIR
}