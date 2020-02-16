$targetUrl  = 'https://status.mixer.com/'
$ie = New-Object -com InternetExplorer.Application 
$ie.visible=$false
$ie.navigate($targetUrl)

while($ie.Busy) {
     Start-Sleep -m 2000
}

$output = $ie.Document.body.innerHTML

if($output -Like '*Outage*')
{Write-Host "Yes, There are outages reported on mixer." -ForegroundColor "Red"}
else
{Write-Host "No, There are no outages reported on mixer." -ForegroundColor "Green"}