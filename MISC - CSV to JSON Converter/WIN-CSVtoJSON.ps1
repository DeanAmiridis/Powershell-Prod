#-----------------------------------------
#             VARIABLES                  |
#-----------------------------------------

# This variable should contain the full path to the source file of the CSV.
$SourceFile = "C:\mycsvfile.csv"
# This variable should contain the full path to where you would like the destination JSON to be placed.
$DestinationFile = "mybrandnewfile.json"

#-----------------------------------------
#              EXECUTION                 |
#-----------------------------------------

$ImportedFile = Get-Content $SourceFile | ConvertFrom-CSV
$ImportedFile | ConvertTo-Json | Out-File $DestinationFile
Write-Host "CSV converted to JSON successfully." -ForegroundColor "Green"


