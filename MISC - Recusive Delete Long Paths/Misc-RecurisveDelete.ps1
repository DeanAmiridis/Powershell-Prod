# ------- Variables & CSV Import ------- 
$DirPaths = Import-Csv -Path .\dir-path.csv
$EmptyDir = "C:\Empty"
Write-Host "CSV Imported Successfully" -ForegroundColor "green"

# ------- Action ------- 
foreach ( $Line in $DirPaths ) {
    $Path = $Line.Path
    Write-Host "Deleting $Path" -ForegroundColor Red
    robocopy $EmptyDir $Path /MIR
}