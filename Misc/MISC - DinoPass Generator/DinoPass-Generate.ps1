# Actions
$PassType = Read-Host -Prompt 'Please enter Simple or Strong for password type'
if ($PassType -like "Simple") {
    $SimplePass = "http://www.dinopass.com/password/simple"
    $WebResponseSimple = Invoke-WebRequest $SimplePass
    Write-Host "Your simple password: $WebResponseSimple" -BackgroundColor Green -ForegroundColor Black
}
else {
    $StrongPass = "https://www.dinopass.com/password/strong"
    $WebResponseStrong = Invoke-WebRequest $StrongPass
    Write-Host "Your strong password: $WebResponseStrong" -BackgroundColor Green -ForegroundColor Black
}


