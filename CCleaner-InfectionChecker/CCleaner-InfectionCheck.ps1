$ErrorActionPreference = 'silentlycontinue'
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
Clear-Host
$Hostname = Hostname
$KeyValue = Test-Path 'HKLM:\SOFTWARE\Piriform\Agomo'
if ($KeyValue -eq $False) {
    Write-Host "*** Checked Key - No infection found on $Hostname! ***" -ForegroundColor "Green"
    $oReturn = [System.Windows.Forms.Messagebox]::Show("*** Checked Key - No infection found on $Hostname! ***")
}
Else {
    Write-Host "*** Checked Key - INFECTION FOUND on $Hostname! ***" -ForegroundColor "Red"
    $oReturn = [System.Windows.Forms.Messagebox]::Show("*** Checked Key - INFECTION FOUND on $Hostname! ***")
}
