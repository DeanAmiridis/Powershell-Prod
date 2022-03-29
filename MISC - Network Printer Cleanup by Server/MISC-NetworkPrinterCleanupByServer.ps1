$PrintServer = "\\SERVERNAME"
$Printers = Get-WmiObject -Class Win32_Printer
ForEach ($Printer in $Printers) {
    If ($Printer.SystemName -like "$PrintServer") {
        (New-Object -ComObject WScript.Network).RemovePrinterConnection($($Printer.Name))
        Write-Host "Printer: $Printer.Name has been removed." -ForegroundColor Red
    }
    else {
        Write-host "Printer $Printer.Name does not meet criteria (Ignored)"
    }