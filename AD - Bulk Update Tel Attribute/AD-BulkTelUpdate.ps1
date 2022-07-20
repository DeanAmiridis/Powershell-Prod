import-module activedirectory

# Data Import
$Users = Import-Csv -Path '.\user-import.csv'
Write-Host "CSV Imported Successfully..." -ForegroundColor Green

# Action loop
Foreach ( $User in $Users) {
    $Employee = $User.Employee
    $TelephoneNumber = $User.TelephoneNumber
    $Division = $User.Division
    Get-ADUser $Employee -Properties DisplayName, officePhone, telephoneNumber | Set-ADUser -OfficePhone $TelephoneNumber
    Write-Host "Updated $Employee successfully..." -ForegroundColor Yellow
}