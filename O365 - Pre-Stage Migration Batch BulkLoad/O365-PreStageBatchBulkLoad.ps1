# Instructions:
# 1) Create CSV file with the name "mailbox-import.csv" and store it in the same location as this script.
# 2) The CSV file should have lines that are in Name|Email format. Example: 
#   Super Man|superman@domain.com
#   Bat Man|batman@domain.com
# 3) Fill out variables below based on your tenant/environment
# 4) Connect to Office365 in powershell running as ADMINISTRATOR.
# 5) Excecute this powershell script.

# ---- Variables ----
$HybridURL = ""
$TargetDeliveryDomain = ""

# ---- Data Import Start  ----
$Mailboxes = Import-Csv -Path '.\mailbox-import.csv' -Delimiter '|' -Header @("Name", "Email")
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
$MailboxesCount = $Mailboxes.Count
Write-Host "Total Imported Accounts: $MailboxesCount" -ForegroundColor "yellow"
write-host -nonewline "Do you want to continue? (Y/N) " -ForegroundColor "red"
$response = read-host
if ( $response -ne "Y" ) { exit }

# ---- Data Import End ----

# ---- Actions ----
foreach ( $Mailbox in $Mailboxes ) {
    New-MoveRequest -Identity $Mailboxes.Email -remote -RemoteHostName ($HybridURL) -TargetDeliveryDomain $TargetDeliveryDomain -RemoteCredential $UserCredential -AcceptLargeDataLoss -BadItemLimit 50 -LargeItemLimit 50 -BatchName $Mailboxes.Name
    Write-Host "Batch created for $Mailboxes.Name" -ForegroundColor "Green"
}
