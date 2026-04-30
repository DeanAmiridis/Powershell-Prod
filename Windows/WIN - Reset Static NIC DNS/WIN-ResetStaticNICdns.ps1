# Temp directory check
$folder = "C:\Temp"
if (!(Test-Path $folder)) {
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$logFile = "$folder\$timestamp-DNSReset.txt"

"==== DNS Reset Snapshot ====" | Out-File $logFile
"Timestamp: $(Get-Date)"       | Out-File $logFile -Append
""                             | Out-File $logFile -Append

# Inclusion-based filter: Ethernet (802.3) and Wi-Fi (Native 802.11) only
$adapters = Get-NetAdapter | Where-Object {
    $_.PhysicalMediaType -in '802.3', 'Native 802.11'
}

if (-not $adapters) {
    "No matching Ethernet or Wi-Fi adapters found." | Out-File $logFile -Append
    "==== Completed ====" | Out-File $logFile -Append
    exit 0
}

foreach ($adapter in $adapters) {

    $ifIndex = $adapter.ifIndex
    $name    = $adapter.Name

    "---- Adapter: $name ----"                                    | Out-File $logFile -Append
    "Interface Description: $($adapter.InterfaceDescription)"     | Out-File $logFile -Append
    "Physical Media Type:   $($adapter.PhysicalMediaType)"        | Out-File $logFile -Append
    "Link State:            $($adapter.Status)"                   | Out-File $logFile -Append

    try {
        $ipInfo  = Get-NetIPConfiguration -InterfaceIndex $ifIndex -ErrorAction Stop
        $dnsInfo = Get-DnsClientServerAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction Stop
        $dhcp    = Get-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction Stop

        # Build IP + Subnet Mask entries (handles multiple IPs per adapter)
        $ipEntries = foreach ($ip in $ipInfo.IPv4Address) {
            $prefix = $ip.PrefixLength
            $mask   = ([IPAddress]([UInt32]::MaxValue -shl (32 - $prefix) -band [UInt32]::MaxValue)).ToString()
            "$($ip.IPAddress)  /  Subnet: $mask  (/$prefix)"
        }

        "IPv4 Address(es):"                                                  | Out-File $logFile -Append
        ($ipEntries | ForEach-Object { "    $_" })                           | Out-File $logFile -Append
        "IPv4 Gateway:         $($ipInfo.IPv4DefaultGateway.NextHop)"        | Out-File $logFile -Append
        "DHCP Enabled:         $($dhcp.Dhcp)"                                | Out-File $logFile -Append
        "DNS Servers (Before): $($dnsInfo.ServerAddresses -join ', ')"       | Out-File $logFile -Append

        if ($dnsInfo.ServerAddresses) {
            Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ResetServerAddresses -ErrorAction Stop

            # Verify the reset actually took effect
            $dnsAfter = Get-DnsClientServerAddress -InterfaceIndex $ifIndex -AddressFamily IPv4
            "DNS Servers (After):  $($dnsAfter.ServerAddresses -join ', ')"  | Out-File $logFile -Append
            "DNS Reset: SUCCESS"                                              | Out-File $logFile -Append
        }
        else {
            "DNS Reset: Skipped - Already set to automatic"                  | Out-File $logFile -Append
        }
    }
    catch {
        "ERROR: $($_.Exception.Message)" | Out-File $logFile -Append
    }

    "" | Out-File $logFile -Append
}

"==== Completed ====" | Out-File $logFile -Append