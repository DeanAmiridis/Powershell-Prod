# Actions
$PassQTY = Read-Host -Prompt 'How many passwords do you need? (ex: 20)'
$PassLen = Read-Host -Prompt 'How long do you need the passwords to be? (ex: 12)'
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