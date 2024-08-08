#-----------------------------------------
#             VARIABLES                  |
#-----------------------------------------
[CmdletBinding()]
Param(
  [string]$SourceFile,
  [string]$DestinationFile
)

#-----------------------------------------
#              EXECUTION                 |
#-----------------------------------------

$ImportedFile = Get-Content $SourceFile | ConvertFrom-CSV
$ImportedFile | ConvertTo-Json | Out-File $DestinationFile
Write-Host "CSV converted to JSON successfully." -ForegroundColor "Green"


