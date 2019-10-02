# ---- Error Handling ----
# $ErrorActionPreference = "SilentlyContinue" #This is for ErrorHandling, Uncomment to ignore errors.

# ---- Data Import ----
$Mailboxes = Import-Csv -Path '.\DL-import.csv' -Delimiter '|'  -Header @("Name", "UPN")
Write-Host "CSV Imported Successfully" -ForegroundColor "green"

# ---- Action ----
$data = foreach ( $Mailbox in $Mailboxes ) { 
    Get-MailboxPermission -Identity $Mailboxes.UPN | Format-List
} 
$data | Export-CSV '.\Exchange-Data-Export.csv'
