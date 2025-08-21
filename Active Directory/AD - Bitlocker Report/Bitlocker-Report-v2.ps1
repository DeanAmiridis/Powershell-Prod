#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Generate a comprehensive BitLocker recovery information report from Active Directory.

.DESCRIPTION
    This script generates a detailed BitLocker recovery report by querying Active Directory
    for computers with BitLocker recovery information. It provides enhanced output with
    additional computer and BitLocker details.

.PARAMETER OutputPath
    Specify the output directory for the report. Defaults to script directory.

.PARAMETER Verbose
    Enable verbose output for detailed progress information.

.PARAMETER IncludeDisabled
    Include disabled computer accounts in the report.

.EXAMPLE
    .\Bitlocker-Report-Improved.ps1
    
.EXAMPLE
    .\Bitlocker-Report-Improved.ps1 -OutputPath "C:\Reports" -Verbose

.NOTES
    - Script should be run on a domain controller with BitLocker Management roles installed
    - Requires Active Directory PowerShell module
    - Output includes enhanced BitLocker and computer information
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$OutputPath = $PSScriptRoot,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled
)

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
    Write-Verbose $Message
}

# Function to get enhanced computer information
function Get-EnhancedComputerInfo {
    param(
        [Microsoft.ActiveDirectory.Management.ADComputer]$Computer
    )
    
    try {
        $ComputerDetails = Get-ADComputer -Identity $Computer.DistinguishedName -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate, Enabled -ErrorAction Stop
        return $ComputerDetails
    }
    catch {
        Write-Warning "Could not retrieve enhanced details for $($Computer.Name): $_"
        return $Computer
    }
}

# Main script execution
try {
    # Initialize variables
    $StartTime = Get-Date
    $CurrentDate = $StartTime.ToString("yyyy_MM_dd-HH_mm")
    $DC = $env:COMPUTERNAME
    $OutputFile = Join-Path $OutputPath "$DC-Bitlocker-Report_$CurrentDate.csv"
    $ErrorLogFile = Join-Path $OutputPath "$DC-Bitlocker-Errors_$CurrentDate.log"
    
    Write-ColorOutput "=== BitLocker Recovery Information Report ===" "Cyan"
    Write-ColorOutput "Script started at: $StartTime" "Yellow"
    Write-ColorOutput "Domain Controller: $DC" "Yellow"
    Write-ColorOutput "Output file: $OutputFile" "Yellow"
    
    # Import required module
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-ColorOutput "Active Directory module imported successfully" "Green"
    
    # Build filter based on parameters
    $ComputerFilter = if ($IncludeDisabled) {
        { msFVE-RecoveryInformation -like '*' }
    }
    else {
        { msFVE-RecoveryInformation -like '*' -and Enabled -eq $true }
    }
    
    # Get computers with BitLocker recovery information
    Write-ColorOutput "Querying Active Directory for computers with BitLocker recovery information..." "Yellow"
    $Computers = Get-ADComputer -Filter $ComputerFilter -Properties Enabled, OperatingSystem, OperatingSystemVersion, LastLogonDate
    
    if ($Computers.Count -eq 0) {
        Write-ColorOutput "No computers found with BitLocker recovery information." "Red"
        exit 1
    }
    
    Write-ColorOutput "Found $($Computers.Count) computers with BitLocker recovery information" "Green"
    
    # Initialize collections for data and errors
    $BitLockerData = [System.Collections.ArrayList]::new()
    $ErrorLog = [System.Collections.ArrayList]::new()
    $Counter = 0
    
    # Process each computer
    ForEach ($Computer in $Computers) {
        $Counter++
        $PercentComplete = [math]::Round(($Counter / $Computers.Count) * 100, 1)
        
        Write-Progress -Activity 'Scanning BitLocker recovery data...' -CurrentOperation $Computer.Name -PercentComplete $PercentComplete -Status "$Counter of $($Computers.Count) computers processed"
        Write-Verbose "Processing computer: $($Computer.Name) ($Counter/$($Computers.Count))"
        
        try {
            # Get BitLocker recovery information
            $RecoveryInfo = Get-ADObject -SearchBase $Computer.DistinguishedName -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -Properties msFVE-RecoveryPassword, msFVE-KeyPackage, WhenCreated, Name -ErrorAction Stop
            
            if ($RecoveryInfo) {
                foreach ($Recovery in $RecoveryInfo) {
                    # Extract recovery key ID from the Name property (format: {GUID}{Date})
                    $RecoveryKeyId = if ($Recovery.Name -match '\{([^}]+)\}') { $matches[1] } else { "Unknown" }
                    
                    # Create custom object with enhanced information
                    $BitLockerEntry = [PSCustomObject]@{
                        'Computer Name'      = $Computer.Name
                        'Recovery Key ID'    = $RecoveryKeyId
                        'Recovery Password'  = $Recovery.'msFVE-RecoveryPassword'
                        'Key Created Date'   = $Recovery.WhenCreated
                        'Operating System'   = $Computer.OperatingSystem
                        'OS Version'         = $Computer.OperatingSystemVersion
                        'Computer Enabled'   = $Computer.Enabled
                        'Last Logon Date'    = $Computer.LastLogonDate
                        'Distinguished Name' = $Computer.DistinguishedName
                        'Has Key Package'    = if ($Recovery.'msFVE-KeyPackage') { "Yes" } else { "No" }
                        'Report Generated'   = $StartTime
                    }
                    
                    [void]$BitLockerData.Add($BitLockerEntry)
                }
            }
            else {
                Write-Warning "No recovery information found for $($Computer.Name) despite initial filter match"
                [void]$ErrorLog.Add("$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - WARNING: No recovery info for $($Computer.Name)")
            }
        }
        catch {
            $ErrorMessage = "Error processing $($Computer.Name): $($_.Exception.Message)"
            Write-ColorOutput $ErrorMessage "Red"
            [void]$ErrorLog.Add("$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: $ErrorMessage")
        }
    }
    
    # Clear progress bar
    Write-Progress -Activity 'Scanning BitLocker recovery data...' -Completed
    
    # Export results
    if ($BitLockerData.Count -gt 0) {
        Write-ColorOutput "Exporting $($BitLockerData.Count) BitLocker entries to CSV..." "Yellow"
        $BitLockerData | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        Write-ColorOutput "BitLocker report exported successfully to: $OutputFile" "Green"
        
        # Display summary statistics
        Write-ColorOutput "`n=== Report Summary ===" "Cyan"
        Write-ColorOutput "Total computers with BitLocker: $($Computers.Count)" "White"
        Write-ColorOutput "Total recovery keys exported: $($BitLockerData.Count)" "White"
        Write-ColorOutput "Computers with multiple keys: $(($BitLockerData | Group-Object 'Computer Name' | Where-Object Count -gt 1).Count)" "White"
        Write-ColorOutput "Enabled computers: $(($BitLockerData | Where-Object 'Computer Enabled' -eq $true | Group-Object 'Computer Name').Count)" "White"
        Write-ColorOutput "Disabled computers: $(($BitLockerData | Where-Object 'Computer Enabled' -eq $false | Group-Object 'Computer Name').Count)" "White"
    }
    else {
        Write-ColorOutput "No BitLocker data was collected." "Red"
    }
    
    # Export error log if there were any errors
    if ($ErrorLog.Count -gt 0) {
        $ErrorLog | Out-File -FilePath $ErrorLogFile -Encoding UTF8
        Write-ColorOutput "Errors encountered: $($ErrorLog.Count) - See error log: $ErrorLogFile" "Yellow"
    }
    
    # Calculate execution time
    $EndTime = Get-Date
    $ExecutionTime = $EndTime - $StartTime
    Write-ColorOutput "`nScript completed at: $EndTime" "Yellow"
    Write-ColorOutput "Total execution time: $($ExecutionTime.ToString('mm\:ss'))" "Yellow"
    
}
catch {
    Write-ColorOutput "Critical error occurred: $($_.Exception.Message)" "Red"
    Write-ColorOutput "Stack trace: $($_.ScriptStackTrace)" "Red"
    exit 1
}
