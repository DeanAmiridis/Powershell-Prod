# ---- Error Handling ----
# $ErrorActionPreference = "SilentlyContinue" #This is for ErrorHandling, Uncomment to ignore errors.

# ---- Data Import ----
$Mailboxes = Import-Csv -Path '.\mailbox-import.csv' -Delimiter ','  -Header @("Name", "UPN")
Write-Host "CSV Imported Successfully..." -ForegroundColor "green"

# ---- Action ----
$data = foreach ( $Mailbox in $Mailboxes ) { 
    Get-MailboxPermission -Identity $Mailbox.UPN | Select-Object AccessRights,User,Identity | Format-Table
    Write-Host "Exporting permissions for $Mailbox.Name..." -ForegroundColor Yellow
} 
$data | Out-File '.\Exchange-Data-Export.csv'
