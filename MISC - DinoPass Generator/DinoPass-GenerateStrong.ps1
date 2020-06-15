# For simple passwords, paste the URL below in the StrongPass Variable
# Simple Password URL: http://www.dinopass.com/password/simple
# Strong Password URL: https://www.dinopass.com/password/strong

# Variables
$StrongPass = "https://www.dinopass.com/password/strong"
$WebResponse = Invoke-WebRequest $StrongPass

# Actions
Write-Host "Your password: $WebResponse" -BackgroundColor Green -ForegroundColor Black
