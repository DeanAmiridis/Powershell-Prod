# ---- Notes ----
# On line 5, set usage location as needed.
# On line 7, Set the license SKU you would like to apply to the accounts within the CSV file.
# To obtain your tenants SKU's, simply run Connect-MsolService and authenticate. Once complete run "Get-MsolAccountSku"
# The csv file should be called user-import.csv and live in the same directory as the .ps1 file. Only 1 column needed that contains the UPN's for all the accounts you are targetting.

# ---- Variables ----
$O365Users = Import-Csv -Path '.\user-import.csv'
$365UsageLocation = "US"
$licenseSku = "reseller-account:ENTERPRISEPACK"

# ---- Action ----
foreach ( $O365User in $O365Users ) {
    $UPN = $O365User.UPN
    get-msoluser -userprincipalname $UPN | Set-Msoluser -UsageLocation $365UsageLocation
    Write-Host "Set UsageLocation for $UPN to $365UsageLocation" -ForegroundColor Green
    get-msoluser -userprincipalname $UPN | Set-Msoluserlicense -AddLicenses "$licenseSku"
    Write-Host "License successfully added to $UPN" -ForegroundColor Yellow
}