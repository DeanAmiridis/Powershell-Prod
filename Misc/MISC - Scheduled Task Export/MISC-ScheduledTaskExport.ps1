Write-host "Obtained Scheduled Tasks..." -ForegroundColor Yellow -BackgroundColor Black
New-Item -ItemType Directory -Path .\ScheduledTaskExports
Write-Host "Created Temporary Directory..." -ForegroundColor Yellow -BackgroundColor Black
Set-Location .\ScheduledTaskExports
Write-Host "Changed directory to temporary directory..." -ForegroundColor Yellow -BackgroundColor Black
$TaskListExports = Get-ScheduledTask | Where-Object { $_.State -match "Ready" } | Select-Object TaskName, TaskPath # To export all tasks, remove the "where-object" statement on this line.
$TaskListExports | Export-CSV -Delimiter '|' -Path ".\TaskList.csv" -NoTypeInformation
Write-Host "Exported scheduled tasks to CSV..." -ForegroundColor Yellow -BackgroundColor Black
$TaskListImports = Import-Csv -Path '.\TaskList.csv' -Delimiter '|' -Header "TaskName", "TaskPath"
Write-Host "Scheduled tasks imported successfully..." -ForegroundColor Yellow -BackgroundColor Black

$Results = foreach ( $TaskListImport in $TaskListImports ) {
    $TaskXML = Export-ScheduledTask "$($TaskListImport.TaskName)" -TaskPath "$($TaskListImport.TaskPath)"
    $TaskXML | Out-File "$($TaskListImport.TaskName).xml"
    $FileCheck = Test-Path -Path .\$($TaskListImport.TaskName).xml
    If ($FileCheck -eq $True) {
        Write-Host "Exported $TaskListImport.TaskName task successfully..." -ForegroundColor Green -BackgroundColor Black
        Write-Output "Exported $TaskListImport.TaskName task successfully..." # Used for logging
    }
    else {
        Write-Host "Something went wrong exporting $TaskListImport.TaskName to XML. Skipping..." -ForegroundColor Red -BackgroundColor Black
        Write-Output "Something went wrong exporting $TaskListImport.TaskName to XML. Skipping..." # Used for logging
    }
}
$Results | Out-File .\ScriptLogging.txt
Write-Host "See .\ScheduledTaskExports\ScriptLogging.txt for log file" -ForegroundColor Yellow -BackgroundColor "Black"
