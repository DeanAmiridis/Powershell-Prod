import-module activedirectory

# Data Import
$Users = Import-Csv -Path '.\user-import.csv' -Delimiter '|' -Header @("Employee", "TelephoneNumber", "Division")
Write-Host "CSV Imported Successfully..." -ForegroundColor Green

# Action loop
Foreach ( $User in $Users) {
    Get-ADUser $user.Employee -Properties DisplayName, officePhone, telephoneNumber | Set-ADUser -OfficePhone $User.TelephoneNumber
    Write-Host "Updated $User.Employee successfully..." -ForegroundColor Yellow
}