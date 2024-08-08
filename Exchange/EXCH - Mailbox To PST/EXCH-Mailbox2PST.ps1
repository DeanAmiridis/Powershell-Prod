# ---- Error Handling ----
# $ErrorActionPreference = "SilentlyContinue" #This is for ErrorHandling, Uncomment to ignore errors.

# ---- Variables ----
$ExportPath = "C:\pst_exports\"
$Export_FileType = ".pst"

# ---- Data Import ----
$Mailboxes = Import-Csv -Path '.\mailbox-import.csv'
Write-Host "CSV Imported Successfully" -ForegroundColor "green"

# ---- Action ----
$data = foreach ( $Mailbox in $Mailboxes ) {
    $MailboxID = $Mailbox.mailboxID
    New-MailboxExportRequest -Mailbox $mailboxID -Name $mailboxID -FilePath ${ExportPath}${$MailboxID}${Export_FileType}
    Write-Host "Exported $MailboxID Successfully"
}
$data | Out-File '.\Exchange-Data-Export.csv'
