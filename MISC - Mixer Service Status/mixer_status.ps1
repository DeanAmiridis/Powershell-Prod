# Gets current status of mixer and reports if there are any known outages
# To have the status page pull up when script is ran, change ie.visible to TRUE

$targetUrl  = 'https://status.mixer.com/'
$ie = New-Object -com InternetExplorer.Application 
$ie.visible=$false
$ie.navigate($targetUrl)

while($ie.Busy) {
     Start-Sleep -m 2000
}

$output = $ie.Document.body.innerHTML

if($output -eq 'Partial Outage' -or $output -eq 'Major Outage' -or $output -eq 'Degraded Performance' )
{Write-Host "Yes, There are outages reported on mixer." -ForegroundColor "Red"}
else
{Write-Host "No, There are no outages reported on mixer." -ForegroundColor "Green"}
