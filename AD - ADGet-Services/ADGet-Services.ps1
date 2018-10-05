#Start type can be Manual, Automatic
#Filter by Status  Where-Object {$_.Status -eq "Stopped"} or Running
Get-Service | Where-Object {($_.StartType -eq "Automatic" -and $_.Status -eq "Stopped")} | Select-Object Name, Starttype, Status | Export-Csv "Services.csv" -NoTypeInformation