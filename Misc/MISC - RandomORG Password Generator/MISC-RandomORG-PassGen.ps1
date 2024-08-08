# Example: .\MISC-RandomORG-PassGen.ps1 -PassQTY 5 -PassLen 15
# The above line will generate 5 passwords, with a length of 15 per password.
#
#
# Actions
[CmdletBinding()]
Param(
    [string]$PassQTY,
    [string]$PassLen
)
$PassGenerate = Invoke-WebRequest "https://www.random.org/passwords/?num=$PassQTY&len=$PassLen&format=plain&rnd=new"
Write-Host $PassGenerate.Content
$OutFileRequest = Read-Host -Prompt 'Would you like to save the passwords to a text file? (y/n)'
if ($OutFileRequest -eq 'y') {
    $PassGenerate.Content | Out-File .\PasswordList.txt
    Write-Host "File was saved in the same path as this script." -ForegroundColor Green
}
else {
    Write-Host "File was not saved as requested." -ForegroundColor Red
}