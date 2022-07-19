# ---- Error Handling ----
# $ErrorActionPreference = "SilentlyContinue" #This is for ErrorHandling, Uncomment to ignore errors.

# ---- Data Import ----
$Mailboxes = Import-Csv -Path '.\mailbox-import.csv'
Write-Host "CSV Imported Successfully..." -ForegroundColor "green"

# ---- Action ----
$data = foreach ( $Mailbox in $Mailboxes ) {
    $Name = $Mailbox.Name
    $UPN = $Mailbox.UPN
    Get-MailboxPermission -Identity $UPN | Select-Object AccessRights,User,Identity | Format-Table
    Write-Host "Exporting permissions for $Name..." -ForegroundColor Yellow
} 
$data | Out-File '.\Exchange-Data-Export.csv'
