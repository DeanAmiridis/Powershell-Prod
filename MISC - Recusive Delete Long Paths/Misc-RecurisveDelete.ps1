# ------- Variables & CSV Import ------- 
$DirPaths = Import-Csv -Path .\dir-path.csv -Header @("Path")
$EmptyDir = "C:\Empty"
Write-Host "CSV Imported Successfully" -ForegroundColor "green"

# ------- Action ------- 
foreach ( $Line in $DirPaths ) {
    Write-Host "Deleting $Line.Path" -ForegroundColor Red
    robocopy $EmptyDir $Line.Path /MIR
}