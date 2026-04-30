# Temp directory check
$folder = "C:\Temp"
if (!(Test-Path $folder)) {
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$logFile = "$folder\$timestamp-DNSReset.txt"

"==== DNS Reset Snapshot ====" | Out-File $logFile
"Timestamp: $(Get-Date)" | Out-File $logFile -Append
"" | Out-File $logFile -Append

$adapters = Get-NetAdapter | Where-Object {
    $_.Status -eq "Up" -and
    $_.InterfaceDescription -notmatch "Virtual|VPN|Loopback|Hyper-V|VMware|TAP|Tunnel|Bluetooth|WAN Miniport"
}

foreach ($adapter in $adapters) {

    $ifIndex = $adapter.ifIndex
    $name = $adapter.Name

    "---- Adapter: $name ----" | Out-File $logFile -Append
    "Interface Description: $($adapter.InterfaceDescription)" | Out-File $logFile -Append

    try {
        $ipInfo  = Get-NetIPConfiguration -InterfaceIndex $ifIndex -ErrorAction Stop
        $dnsInfo = Get-DnsClientServerAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction Stop
        $dhcp    = Get-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction Stop

        "IPv4 Address(es): $($ipInfo.IPv4Address.IPAddress -join ', ')" | Out-File $logFile -Append
        "IPv4 Gateway: $($ipInfo.IPv4DefaultGateway.NextHop)" | Out-File $logFile -Append
        "DNS Servers Before: $($dnsInfo.ServerAddresses -join ', ')" | Out-File $logFile -Append
        "DHCP Enabled: $($dhcp.Dhcp)" | Out-File $logFile -Append
        "" | Out-File $logFile -Append

        if ($dnsInfo.ServerAddresses) {
            Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ResetServerAddresses -ErrorAction Stop
            "DNS Reset: SUCCESS" | Out-File $logFile -Append
        }
        else {
            "DNS Reset: Skipped - Already DHCP/Automatic" | Out-File $logFile -Append
        }
    }
    catch {
        "ERROR: $($_.Exception.Message)" | Out-File $logFile -Append
    }

    "" | Out-File $logFile -Append
}

"==== Completed ====" | Out-File $logFile -Append