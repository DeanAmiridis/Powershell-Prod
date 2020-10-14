# Variables
$LogPath = "C:\temp\psautoupdater_log.txt" # Change this directory to your preferred log file destination.

# Install required module
Write-Host "Installing PSWindowsUpdate module (required)..." -ForegroundColor Yellow
Install-Module -Name PSWindowsUpdate -AllowClobber -Confirm:$False -Force
Write-Host "Installed/Confirmed PSWindowsUpdate module (required)..." -ForegroundColor Green

# Check for windows updates & install
Write-Host "Checking/Installing updates..." -ForegroundColor Yellow
Get-WindowsUpdate -install -AcceptAll >> Out-File $LogPath
Write-Host "Updates checked/installed..." -ForegroundColor Green

