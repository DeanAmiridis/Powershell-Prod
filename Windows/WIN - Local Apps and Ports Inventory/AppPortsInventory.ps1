<#
AppPortsInventory.ps1
Dual-mode script for Windows PowerShell 5.1 and PowerShell 7+.
- Uses PS5.1-safe syntax everywhere (so it runs on both)
- Includes IIS binding inventory

USAGE:
.\AppPortsInventory.ps1 -OutputPath "C:\Temp\AppPorts" -IncludeUDP -ExcludeSystem:$false
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [switch]$IncludeUDP,
    [switch]$ExcludeSystem = $true,

    [int[]]$PortInclude,
    [int[]]$PortExclude
)

function Run-AppPortsInventory {
    param([string]$OutputPath, [switch]$IncludeUDP, [switch]$ExcludeSystem, [int[]]$PortInclude, [int[]]$PortExclude)

    $ErrorActionPreference = 'Stop'
    if (!(Test-Path -LiteralPath $OutputPath)) {
        New-Item -Type Directory -Path $OutputPath -Force | Out-Null
    }

    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $server = $env:COMPUTERNAME
    $log = Join-Path $OutputPath "Log_${server}_$ts.txt"
    $csvApp = Join-Path $OutputPath "AppInventory_${server}_$ts.csv"
    $csvPort = Join-Path $OutputPath "PortInventory_${server}_$ts.csv"
    $csvIIS = Join-Path $OutputPath "IISBindings_${server}_$ts.csv"
    $csvSug = Join-Path $OutputPath "SuggestedRules_${server}_$ts.csv"

    "[$(Get-Date -Format o)] Start inventory on $server (PS $($PSVersionTable.PSVersion))" | Out-File -FilePath $log -Encoding UTF8

    $CoreProcessExclusions = @(
        'System', 'Idle', 'Registry', 'smss', 'csrss', 'wininit', 'services', 'lsass', 'lsm',
        'svchost', 'winlogon', 'taskhostw', 'dllhost', 'conhost', 'fontdrvhost', 'dwm',
        'spoolsv', 'audiodg', 'ctfmon', 'SearchIndexer', 'MsMpEng', 'WmiPrvSE', 'sihost',
        'ShellExperienceHost', 'SearchUI', 'tiworker', 'TrustedInstaller'
    )

    function Write-Log { param($m) "[{0}] {1}" -f (Get-Date -Format o), $m | Tee-Object -FilePath $log -Append | Out-Null }
    function Coalesce { param($v, $f) if ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) { $v } else { $f } }

    function Get-InstalledApps {
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        )
        $apps = foreach ($p in $paths) {
            if (Test-Path $p) {
                Get-ChildItem $p | ForEach-Object {
                    $itm = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                    if ($itm.DisplayName) {
                        [PSCustomObject]@{
                            DisplayName     = $itm.DisplayName
                            DisplayVersion  = $itm.DisplayVersion
                            Publisher       = $itm.Publisher
                            InstallDate     = $itm.InstallDate
                            InstallLocation = $itm.InstallLocation
                            UninstallString = $itm.UninstallString
                            PSPath          = $_.PSPath
                            Architecture    = if ($p -like '*Wow6432Node*') { 'x86' } else { 'x64' }
                        }
                    }
                }
            }
        }
        $apps | Sort-Object DisplayName, DisplayVersion -Unique
    }

    function Get-ProcessInfoByPid {
        param([int]$procId)
        try {
            $p = Get-Process -Id $procId -ErrorAction Stop
            $exe = $null
            try { $exe = $p.Path } catch { }
            if (-not $exe) {
                $c = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction Stop
                $exe = $c.ExecutablePath
            }
            $fvi = $null
            if ($exe -and (Test-Path $exe)) { try { $fvi = (Get-Item $exe).VersionInfo } catch { } }
            [PSCustomObject]@{
                PID         = $procId
                Name        = $p.ProcessName
                ExePath     = $exe
                ProductName = $fvi.ProductName
                FileDesc    = $fvi.FileDescription
                CompanyName = $fvi.CompanyName
            }
        }
        catch {
            [PSCustomObject]@{ PID = $procId; Name = $null; ExePath = $null; ProductName = $null; FileDesc = $null; CompanyName = $null }
        }
    }

    function Normalize-AddrPort {
        param([string]$Local)
        if ($Local -match '^\[.*\]:') {
            $s = $Local -replace '^\[|\]', ''
            $addr, $prt = $s -split ':\s*', 2
        }
        else {
            $addr, $prt = $Local -split ':', 2
        }
        [PSCustomObject]@{Addr = $addr; Port = [int]$prt }
    }

    function Get-Listeners {
        $tcp = @()
        $udp = @()

        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            $tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Select-Object @{n = 'Local'; e = { "{0}:{1}" -f $_.LocalAddress, $_.LocalPort } }, LocalAddress, LocalPort, OwningProcess, State, @{n = 'Protocol'; e = { 'TCP' } }
        }
        else {
            Write-Log "Get-NetTCPConnection unavailable; using netstat -ano for TCP"
            $tcp = netstat -ano | Select-String -Pattern '^\s*TCP.*LISTENING\s+(\d+)$' | ForEach-Object {
                $parts = ($_ -split '\s+')
                $local = $parts[1]; 
                $procId = [int]$parts[-1]
                $np = Normalize-AddrPort -Local $local
                [PSCustomObject]@{ Local = $local; LocalAddress = $np.Addr; LocalPort = $np.Port; OwningProcess = $procId; State = 'Listen'; Protocol = 'TCP' }
            }
        }

        if ($IncludeUDP) {
            if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
                $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
                Select-Object @{n = 'Local'; e = { "{0}:{1}" -f $_.LocalAddress, $_.LocalPort } }, LocalAddress, LocalPort, OwningProcess, @{n = 'State'; e = { 'Listen' } }, @{n = 'Protocol'; e = { 'UDP' } }
            }
            else {
                Write-Log "Get-NetUDPEndpoint unavailable; using netstat -ano -p udp"
                $udp = netstat -ano -p udp | Select-String -Pattern '^\s*UDP\s+(\S+)\s+\*\:\*\s+(\d+)$' | ForEach-Object {
                    $parts = ($_ -split '\s+')
                    $local = $parts[1]; 
                    $procId = [int]$parts[-1]
                    $np = Normalize-AddrPort -Local $local
                    [PSCustomObject]@{ Local = $local; LocalAddress = $np.Addr; LocalPort = $np.Port; OwningProcess = $procId; State = 'Listen'; Protocol = 'UDP' }
                }
            }
        }

        @($tcp + $udp)
    }

    function Map-ProcessToApp {
        param([Parameter(Mandatory)]$ProcInfo, [Parameter(Mandatory)]$Apps)
        if (-not $ProcInfo) { return $null }
        $exe = $ProcInfo.ExePath
        $match = $null

        if ($exe) {
            $candidates = $Apps | Where-Object { $_.InstallLocation -and (Test-Path $_.InstallLocation) -and $exe.StartsWith($_.InstallLocation, $true, $null) }
            if ($candidates) { $match = $candidates | Select-Object -First 1 }
        }
        if (-not $match -and $ProcInfo.ProductName) {
            $pn = $ProcInfo.ProductName.ToLower()
            $byName = $Apps | Where-Object { $_.DisplayName -and $_.DisplayName.ToLower() -like "*$pn*" }
            if ($byName) { $match = $byName | Select-Object -First 1 }
        }
        if (-not $match -and $ProcInfo.CompanyName) {
            $co = $ProcInfo.CompanyName.ToLower()
            $byCo = $Apps | Where-Object { $_.Publisher -and $_.Publisher.ToLower() -like "*$co*" }
            if ($byCo) { $match = $byCo | Select-Object -First 1 }
        }
        $match
    }

    function Make-RuleKey {
        param($AppDisplayName, $ExePath, $Protocol)
        $app = Coalesce $AppDisplayName 'UnknownApp'
        $exe = Coalesce $ExePath 'UnknownExe'
        "$app|$exe|$Protocol"
    }

    function Test-ExistingFirewallRule {
        param(
            [string]$Program,
            [string]$Protocol,
            [string]$LocalPorts
        )
        
        try {
            # If no ports specified, can't check anything meaningful
            if (-not $LocalPorts -or $LocalPorts -eq 'N/A' -or $LocalPorts -eq 'Multiple') {
                return $false
            }

            # Parse all ports we need to check
            $portNumbers = @($LocalPorts -split ',' | ForEach-Object { $_.Trim() })
            if ($portNumbers.Count -eq 0) {
                return $false
            }

            # Convert to integers and validate
            $requiredPorts = @()
            foreach ($p in $portNumbers) {
                $portInt = 0
                if ([int]::TryParse($p, [ref]$portInt)) {
                    $requiredPorts += $portInt
                }
            }

            if ($requiredPorts.Count -eq 0) {
                return $false
            }

            # Get all inbound allow rules - do this ONCE for efficiency
            $allRules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue)
            if ($allRules.Count -eq 0) {
                return $false
            }

            # Check EACH required port - all must have a matching rule
            foreach ($requiredPort in $requiredPorts) {
                $portFound = $false

                foreach ($rule in $allRules) {
                    # Get port filter for this rule
                    $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                    if (-not $portFilter) {
                        # Rule has no port filter, skip it
                        continue
                    }

                    # Check protocol match FIRST (must match)
                    $protocolMatches = ($portFilter.Protocol -eq $Protocol -or $portFilter.Protocol -eq 'Any')
                    if (-not $protocolMatches) {
                        continue
                    }

                    # Now check port match
                    $portFilterValue = [string]$portFilter.LocalPort
                    
                    if ($portFilterValue -eq 'Any') {
                        # Rule allows any port
                        $portFound = $true
                        break
                    }
                    elseif ($portFilterValue -eq $requiredPort.ToString()) {
                        # Exact port match
                        $portFound = $true
                        break
                    }
                    elseif ($portFilterValue -match '^\d+-\d+$') {
                        # Port range check
                        $range = $portFilterValue -split '-'
                        if ($range.Count -eq 2) {
                            $rangeStart = [int]$range[0]
                            $rangeEnd = [int]$range[1]
                            if ($requiredPort -ge $rangeStart -and $requiredPort -le $rangeEnd) {
                                $portFound = $true
                                break
                            }
                        }
                    }
                }

                # If this required port was NOT found in any rule, return FALSE immediately
                if (-not $portFound) {
                    return $false
                }
            }

            # All required ports found matching rules
            return $true
        }
        catch {
            Write-Log "Error checking firewall rules: $_"
            return $false
        }
    }

    function Test-ApplicationFirewallRule {
        param([string]$Program)
        
        if (-not $Program -or $Program -eq 'N/A') {
            return $false
        }

        try {
            # Get all inbound allow rules and filter by program manually
            $allRules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue)
            
            foreach ($rule in $allRules) {
                if ($rule.Program -eq $Program) {
                    return $true
                }
            }
            
            return $false
        }
        catch {
            Write-Log "Error checking app firewall rules for $Program : $_"
            return $false
        }
    }

    function Test-PortFirewallRule {
        param(
            [string]$Protocol,
            [string]$LocalPorts
        )
        
        if (-not $LocalPorts -or $LocalPorts -eq 'N/A' -or $LocalPorts -eq 'Multiple') {
            return $false
        }

        try {
            # Parse ports
            $portNumbers = @($LocalPorts -split ',' | ForEach-Object { $_.Trim() })
            $requiredPorts = @()
            
            foreach ($p in $portNumbers) {
                $portInt = 0
                if ([int]::TryParse($p, [ref]$portInt)) {
                    $requiredPorts += $portInt
                }
            }

            if ($requiredPorts.Count -eq 0) {
                return $false
            }

            # Get all inbound allow rules - ONLY check rules with port filters
            $allRules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue)
            if ($allRules.Count -eq 0) {
                return $false
            }

            # Check EACH required port individually
            foreach ($requiredPort in $requiredPorts) {
                $portFound = $false

                foreach ($rule in $allRules) {
                    $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                    
                    # Skip rules with no port filter (these are not port-specific)
                    if (-not $portFilter) {
                        continue
                    }

                    # First check: Protocol must match
                    if ($portFilter.Protocol -ne $Protocol -and $portFilter.Protocol -ne 'Any') {
                        continue
                    }

                    # Second check: Port must match
                    $portFilterValue = [string]$portFilter.LocalPort
                    $localPortMatches = $false

                    # Case 1: "Any" port means all ports allowed
                    if ($portFilterValue -eq 'Any') {
                        $localPortMatches = $true
                    }
                    # Case 2: Exact port match
                    elseif ($portFilterValue -eq $requiredPort.ToString()) {
                        $localPortMatches = $true
                    }
                    # Case 3: Port range
                    elseif ($portFilterValue -match '^\d+-\d+$') {
                        $parts = $portFilterValue -split '-'
                        $rangeStart = [int]$parts[0]
                        $rangeEnd = [int]$parts[1]
                        if ($requiredPort -ge $rangeStart -and $requiredPort -le $rangeEnd) {
                            $localPortMatches = $true
                        }
                    }

                    if ($localPortMatches) {
                        $portFound = $true
                        break
                    }
                }

                # If THIS specific port was not found, return FALSE
                if (-not $portFound) {
                    return $false
                }
            }

            # All required ports have matching rules
            return $true
        }
        catch {
            Write-Log "Error checking port firewall rules for ports $LocalPorts protocol $Protocol : $_"
            return $false
        }
    }

    function Get-IISBindings {
        param([string]$IISPath)
        $bindings = @()
        
        # Check if IIS is installed
        $iisInstalled = $false
        try {
            if (Test-Path $IISPath) {
                $iisInstalled = $true
            }
        }
        catch { }

        if (-not $iisInstalled) {
            Write-Log "IIS not detected on this server"
            $bindings += [PSCustomObject]@{
                SiteName        = 'N/A'
                Binding         = 'N/A'
                Protocol        = 'N/A'
                Port            = 'N/A'
                IPAddress       = 'N/A'
                HostHeader      = 'N/A'
                RedirectType    = 'IIS Installation not detected'
                RedirectTarget  = 'N/A'
                ApplicationPool = 'N/A'
            }
            return $bindings
        }

        try {
            Import-Module WebAdministration -ErrorAction Stop
            Write-Log "WebAdministration module loaded"
        }
        catch {
            Write-Log "WebAdministration module not available"
            $bindings += [PSCustomObject]@{
                SiteName        = 'N/A'
                Binding         = 'N/A'
                Protocol        = 'N/A'
                Port            = 'N/A'
                IPAddress       = 'N/A'
                HostHeader      = 'N/A'
                RedirectType    = 'IIS Installation not detected'
                RedirectTarget  = 'N/A'
                ApplicationPool = 'N/A'
            }
            return $bindings
        }

        try {
            $sites = Get-Item IIS:\Sites -ErrorAction SilentlyContinue
            if ($sites) {
                foreach ($site in $sites) {
                    $siteName = $site.Name
                    $appPool = $site.ApplicationPool
                    
                    # Extract bindings
                    if ($site.Bindings.Collection) {
                        foreach ($binding in $site.Bindings.Collection) {
                            $protocol = $binding.Protocol
                            $bindingInfo = $binding.BindingInformation
                            
                            if ($bindingInfo -match '^(.*?):(\d+):(.*)$') {
                                $ip = if ([string]::IsNullOrWhiteSpace($Matches[1]) -or $Matches[1] -eq '*') { '0.0.0.0' } else { $Matches[1] }
                                $port = [int]$Matches[2]
                                $hostHeader = if ([string]::IsNullOrWhiteSpace($Matches[3])) { '(All Unassigned)' } else { $Matches[3] }
                            }
                            else {
                                $ip = '0.0.0.0'
                                $port = if ($protocol -eq 'https') { 443 } else { 80 }
                                $hostHeader = '(Parse Error)'
                            }
                            
                            $bindings += [PSCustomObject]@{
                                SiteName        = $siteName
                                Binding         = $bindingInfo
                                Protocol        = $protocol
                                Port            = $port
                                IPAddress       = $ip
                                HostHeader      = $hostHeader
                                RedirectType    = 'Standard Binding'
                                RedirectTarget  = 'N/A'
                                ApplicationPool = $appPool
                            }
                        }
                    }
                    
                    # Check for URL Rewrite and HTTP Redirect rules
                    try {
                        $vdir = Get-WebVirtualDirectory -Site $siteName -ErrorAction SilentlyContinue
                        if ($vdir) {
                            foreach ($v in $vdir) {
                                $vdirPath = "IIS:\Sites\$siteName\$($v.Name)"
                                $httpRedirect = Get-WebConfigurationProperty -PSPath $vdirPath -Filter 'system.webServer/httpRedirect' -Name '*' -ErrorAction SilentlyContinue
                                
                                if ($httpRedirect -and $httpRedirect.enabled -eq $true) {
                                    $destination = $httpRedirect.destination
                                    if (-not [string]::IsNullOrWhiteSpace($destination)) {
                                        $bindings += [PSCustomObject]@{
                                            SiteName        = $siteName
                                            Binding         = "$($v.Name) (Virtual Directory)"
                                            Protocol        = 'HTTP/HTTPS'
                                            Port            = 'Multiple'
                                            IPAddress       = '0.0.0.0'
                                            HostHeader      = $v.Name
                                            RedirectType    = "HTTP Redirect (Status: $($httpRedirect.exactDestination))"
                                            RedirectTarget  = $destination
                                            ApplicationPool = $appPool
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch {
            Write-Log "Error retrieving IIS bindings: $_"
        }

        if ($bindings.Count -eq 0) {
            $bindings += [PSCustomObject]@{
                SiteName        = 'N/A'
                Binding         = 'N/A'
                Protocol        = 'N/A'
                Port            = 'N/A'
                IPAddress       = 'N/A'
                HostHeader      = 'N/A'
                RedirectType    = 'IIS Installation not detected'
                RedirectTarget  = 'N/A'
                ApplicationPool = 'N/A'
            }
        }

        return $bindings
    }

    $portRows = New-Object System.Collections.Generic.List[object]

    try {
        Write-Log "Collecting installed applications..."
        $apps = Get-InstalledApps
        $apps | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvApp
        Write-Log "App inventory: $csvApp"

        Write-Log "Collecting IIS bindings..."
        $iisBindings = Get-IISBindings -IISPath 'HKLM:\SOFTWARE\Microsoft\InetStp'
        $iisBindings | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvIIS
        Write-Log "IIS inventory: $csvIIS"

        Write-Log "Collecting listeners..."
        $listeners = Get-Listeners

        if ($PortInclude) {
            $listeners = $listeners | Where-Object { $PortInclude -contains $_.LocalPort }
            Write-Log "Filtered to PortInclude: $($PortInclude -join ',')"
        }
        if ($PortExclude) {
            $listeners = $listeners | Where-Object { $PortExclude -notcontains $_.LocalPort }
            Write-Log "Excluded ports: $($PortExclude -join ',')"
        }

        $procMap = @{}
        foreach ($procId in ($listeners | Select-Object -ExpandProperty OwningProcess -Unique)) {
            $procMap[$procId] = Get-ProcessInfoByPid -procId $procId
        }

        foreach ($l in $listeners) {
            $pi = $procMap[$l.OwningProcess]
            if ($ExcludeSystem -and $pi.Name -and ($CoreProcessExclusions -contains $pi.Name)) { continue }

            $svcName = $null
            try {
                $svcs = Get-CimInstance Win32_Service -Filter "ProcessId=$($l.OwningProcess)" -ErrorAction SilentlyContinue
                if ($svcs) { $svcName = ($svcs | Select-Object -ExpandProperty Name) -join ';' }
            }
            catch {}

            $app = Map-ProcessToApp -ProcInfo $pi -Apps $apps

            $portRows.Add([PSCustomObject]@{
                    ComputerName   = $env:COMPUTERNAME
                    Protocol       = $l.Protocol
                    LocalAddress   = $l.LocalAddress
                    LocalPort      = $l.LocalPort
                    PID            = $l.OwningProcess
                    ProcessName    = $pi.Name
                    ExePath        = $pi.ExePath
                    ServiceName    = $svcName
                    AppDisplayName = $app.DisplayName
                    AppVersion     = $app.DisplayVersion
                    Publisher      = $app.Publisher
                    InstallPath    = $app.InstallLocation
                    ProductName    = $pi.ProductName
                    CompanyName    = $pi.CompanyName
                    FileDesc       = $pi.FileDesc
                })
        }

        $portRows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPort
        Write-Log "Port map: $csvPort"

        $ruleMap = @{}
        foreach ($row in $portRows) {
            $key = Make-RuleKey -AppDisplayName $row.AppDisplayName -ExePath $row.ExePath -Protocol $row.Protocol
            if (-not $ruleMap.ContainsKey($key)) {
                $ruleMap[$key] = [PSCustomObject]@{
                    ComputerName   = $row.ComputerName
                    AppDisplayName = $row.AppDisplayName
                    ExePath        = $row.ExePath
                    Protocol       = $row.Protocol
                    Ports          = New-Object System.Collections.Generic.HashSet[int]
                    ServiceName    = $row.ServiceName
                    Publisher      = $row.Publisher
                }
            }
            $null = $ruleMap[$key].Ports.Add([int]$row.LocalPort)
            if (-not $ruleMap[$key].ServiceName -and $row.ServiceName) { $ruleMap[$key].ServiceName = $row.ServiceName }
            if (-not $ruleMap[$key].Publisher -and $row.Publisher) { $ruleMap[$key].Publisher = $row.Publisher }
        }

        $suggested = foreach ($k in $ruleMap.Keys) {
            $r = $ruleMap[$k]
            $appName = Coalesce $r.AppDisplayName 'UnknownApp'
            $ports = ($r.Ports | Sort-Object) -join ','
            $note = if ($r.ExePath) { 'Prefer Program-based rule' } else { 'No EXE path found; use Port-based rule' }
            $appRuleFound = Test-ApplicationFirewallRule -Program $r.ExePath
            $portRuleFound = Test-PortFirewallRule -Protocol $r.Protocol -LocalPorts $ports

            [PSCustomObject]@{
                ComputerName          = $r.ComputerName
                RuleName              = ("Allow - {0} - {1} {2}" -f $appName, $r.Protocol, $ports) -replace '[^\w\s\-\(\)\.,]', ''
                Program               = $r.ExePath
                Protocol              = $r.Protocol
                LocalPorts            = $ports
                Profile               = 'Any'
                Direction             = 'Inbound'
                ServiceName           = $r.ServiceName
                Publisher             = $r.Publisher
                ApplicationRuleExists = $appRuleFound
                PortRuleExists        = $portRuleFound
                Note                  = $note
            }
        }

        # Add IIS bindings to suggested rules
        if ($iisBindings -and $iisBindings.Count -gt 0) {
            $iisRules = foreach ($binding in $iisBindings) {
                if ($binding.RedirectType -eq 'IIS Installation not detected') {
                    [PSCustomObject]@{
                        ComputerName          = $env:COMPUTERNAME
                        RuleName              = 'Allow - IIS - IIS Installation not detected'
                        Program               = 'N/A'
                        Protocol              = 'N/A'
                        LocalPorts            = 'N/A'
                        Profile               = 'N/A'
                        Direction             = 'N/A'
                        ServiceName           = 'N/A'
                        Publisher             = 'N/A'
                        ApplicationRuleExists = $false
                        PortRuleExists        = $false
                        Note                  = 'IIS Installation not detected'
                    }
                }
                else {
                    $portInfo = if ($binding.Port -eq 'Multiple') { 'Multiple' } else { [string]$binding.Port }
                    $redirectNote = if ($binding.RedirectType -ne 'Standard Binding') { " - Redirect: $($binding.RedirectTarget)" } else { '' }
                    $appRuleFound = Test-ApplicationFirewallRule -Program 'C:\Windows\System32\inetsrv\w3wp.exe'
                    $portRuleFound = Test-PortFirewallRule -Protocol $binding.Protocol -LocalPorts $portInfo
                    
                    [PSCustomObject]@{
                        ComputerName          = $env:COMPUTERNAME
                        RuleName              = ("Allow - IIS - {0} - {1} - {2}" -f $binding.SiteName, $binding.Protocol.ToUpper(), $portInfo) -replace '[^\w\s\-\(\)\.,]', ''
                        Program               = 'C:\Windows\System32\inetsrv\w3wp.exe'
                        Protocol              = $binding.Protocol
                        LocalPorts            = $portInfo
                        Profile               = 'Any'
                        Direction             = 'Inbound'
                        ServiceName           = 'W3SVC'
                        Publisher             = 'Microsoft'
                        ApplicationRuleExists = $appRuleFound
                        PortRuleExists        = $portRuleFound
                        Note                  = "Site: $($binding.SiteName), Host: $($binding.HostHeader), Type: $($binding.RedirectType)$redirectNote"
                    }
                }
            }
            $suggested = @($suggested) + @($iisRules)
        }

        $suggested | Sort-Object RuleName | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvSug
        Write-Log "Suggested (data only) rules: $csvSug"

        Write-Log "Done."
        Write-Host "Inventory complete.`n- Apps: $csvApp`n- Ports: $csvPort`n- IIS Bindings: $csvIIS`n- Suggested: $csvSug`n- Log: $log"
    }
    catch {
        Write-Log "ERROR: $($_.Exception.Message)"
        throw
    }
}

# Run same body for both PS7+ and PS5.1
Run-AppPortsInventory -OutputPath $OutputPath -IncludeUDP:$IncludeUDP -ExcludeSystem:$ExcludeSystem -PortInclude $PortInclude -PortExclude $PortExclude
