<# 
AppPortsInventory_Dual_Fixed.ps1
Dual-mode script for Windows PowerShell 5.1 and PowerShell 7+.
- Uses PS5.1-safe syntax everywhere (so it runs on both)
- Fixes collision with $PID automatic variable (renamed param to $procId)
- Fixes inline if-expression by pre-assigning $note variable
USAGE:
  .\AppPortsInventory_Dual_Fixed.ps1 -OutputPath "C:\Temp\AppPorts" -IncludeUDP -ExcludeSystem:$false
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

    $portRows = New-Object System.Collections.Generic.List[object]

    try {
        Write-Log "Collecting installed applications..."
        $apps = Get-InstalledApps
        $apps | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvApp
        Write-Log "App inventory: $csvApp"

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

            [PSCustomObject]@{
                ComputerName = $r.ComputerName
                RuleName     = ("Allow - {0} - {1} {2}" -f $appName, $r.Protocol, $ports) -replace '[^\w\s\-\(\)\.,]', ''
                Program      = $r.ExePath
                Protocol     = $r.Protocol
                LocalPorts   = $ports
                Profile      = 'Any'
                Direction    = 'Inbound'
                ServiceName  = $r.ServiceName
                Publisher    = $r.Publisher
                Note         = $note
            }
        }

        $suggested | Sort-Object RuleName | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvSug
        Write-Log "Suggested (data only) rules: $csvSug"

        Write-Log "Done."
        Write-Host "Inventory complete.`n- Apps: $csvApp`n- Ports: $csvPort`n- Suggested: $csvSug`n- Log: $log"
    }
    catch {
        Write-Log "ERROR: $($_.Exception.Message)"
        throw
    }
}

# Run same body for both PS7+ and PS5.1
Run-AppPortsInventory -OutputPath $OutputPath -IncludeUDP:$IncludeUDP -ExcludeSystem:$ExcludeSystem -PortInclude $PortInclude -PortExclude $PortExclude
