#Requires -Modules GroupPolicy
<#
.SYNOPSIS
    Export comprehensive GPO link information with enhanced performance and details.

.DESCRIPTION
    This script exports detailed information about all enabled and linked Group Policy Objects (GPOs)
    in the domain, including performance optimizations and comprehensive reporting.

.PARAMETER OutputPath
    Path where the CSV report will be saved. If not specified, uses script directory.

.PARAMETER IncludeDisabledGPOs
    Include information about disabled GPOs in the report (but only show their links if enabled).

.PARAMETER Domain
    Target domain to query. Uses current domain if not specified.

.PARAMETER Verbose
    Enable verbose output for detailed progress information.

.EXAMPLE
    .\ADGPOExportAllEnabled-Improved.ps1 -OutputPath "C:\Reports\GPO_Report.csv"

.EXAMPLE
    .\ADGPOExportAllEnabled-Improved.ps1 -IncludeDisabledGPOs -Verbose

.NOTES
    - Requires GroupPolicy module
    - Must be run with appropriate domain permissions
    - Optimized for large environments with progress tracking
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) { return $true }
            $parentDir = Split-Path $_ -Parent
            if (-not (Test-Path $parentDir -PathType Container)) {
                throw "Parent directory does not exist: $parentDir"
            }
            return $true
        })]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabledGPOs,

    [Parameter(Mandatory = $false)]
    [string]$Domain = $env:USERDNSDOMAIN
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

# Function to get enhanced GPO information
function Get-EnhancedGPOInfo {
    param([Microsoft.GroupPolicy.Gpo]$GPO)

    try {
        # Get additional GPO properties
        $GPOInfo = Get-GPO -Guid $GPO.Id -Domain $Domain -ErrorAction Stop

        return [PSCustomObject]@{
            DisplayName      = $GPOInfo.DisplayName
            Id               = $GPOInfo.Id
            DomainName       = $GPOInfo.DomainName
            Owner            = $GPOInfo.Owner
            CreationTime     = $GPOInfo.CreationTime
            ModificationTime = $GPOInfo.ModificationTime
            GpoStatus        = $GPOInfo.GpoStatus
            Description      = $GPOInfo.Description
            WmiFilter        = $GPOInfo.WmiFilter
        }
    }
    catch {
        Write-Warning "Could not retrieve enhanced info for GPO '$($GPO.DisplayName)': $_"
        return $GPO
    }
}

# Main script execution
try {
    $StartTime = Get-Date
    Write-ColorOutput "=== GPO Link Report Generation ===" "Cyan"
    Write-ColorOutput "Started at: $StartTime" "Yellow"
    Write-ColorOutput "Target Domain: $Domain" "Yellow"

    # Set default output path if not provided
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path $PSScriptRoot "GPO_Link_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    }

    Write-ColorOutput "Output file: $OutputPath" "Yellow"

    # Import required module
    Import-Module GroupPolicy -ErrorAction Stop
    Write-ColorOutput "GroupPolicy module imported successfully" "Green"

    # Get all GPOs with enhanced filtering
    Write-ColorOutput "Retrieving GPOs from domain..." "Yellow"
    $AllGPOs = if ($IncludeDisabledGPOs) {
        Get-GPO -All -Domain $Domain
    }
    else {
        Get-GPO -All -Domain $Domain | Where-Object { $_.GpoStatus -ne 'AllSettingsDisabled' }
    }

    $TotalGPOs = $AllGPOs.Count
    Write-ColorOutput "Found $TotalGPOs GPOs to process" "Green"

    if ($TotalGPOs -eq 0) {
        Write-ColorOutput "No GPOs found in domain $Domain" "Red"
        exit 1
    }

    # Initialize collections
    $Results = [System.Collections.ArrayList]::new()
    $ErrorLog = [System.Collections.ArrayList]::new()
    $ProcessedCount = 0
    $LinkedGPOs = 0
    $TotalLinks = 0

    # Process each GPO
    foreach ($GPO in $AllGPOs) {
        $ProcessedCount++
        $PercentComplete = [math]::Round(($ProcessedCount / $TotalGPOs) * 100, 1)

        Write-Progress -Activity 'Processing GPOs...' -CurrentOperation $GPO.DisplayName -PercentComplete $PercentComplete -Status "$ProcessedCount of $TotalGPOs GPOs processed"
        Write-Verbose "Processing GPO: $($GPO.DisplayName) ($ProcessedCount/$TotalGPOs)"

        try {
            # Get enhanced GPO information
            $EnhancedGPO = Get-EnhancedGPOInfo -GPO $GPO

            # Generate XML report for link information
            [xml]$Report = Get-GPOReport -Guid $GPO.Id -ReportType Xml -Domain $Domain -ErrorAction Stop

            # Check if GPO has links
            if ($Report.GPO.LinksTo) {
                $LinkedGPOs++
                $LinksForThisGPO = 0

                # Process each link
                foreach ($Link in $Report.GPO.LinksTo) {
                    $LinksForThisGPO++

                    # Create comprehensive result object
                    $Result = [PSCustomObject]@{
                        # GPO Information
                        'GPO_Name'          = $EnhancedGPO.DisplayName
                        'GPO_GUID'          = $EnhancedGPO.Id
                        'GPO_Domain'        = $EnhancedGPO.DomainName
                        'GPO_Owner'         = $EnhancedGPO.Owner
                        'GPO_Created'       = $EnhancedGPO.CreationTime
                        'GPO_Modified'      = $EnhancedGPO.ModificationTime
                        'GPO_Status'        = $EnhancedGPO.GpoStatus
                        'GPO_Description'   = $EnhancedGPO.Description
                        'GPO_WMI_Filter'    = $EnhancedGPO.WmiFilter

                        # Link Information
                        'Link_Location'     = $Link.SOMPath
                        'Link_Enabled'      = $Link.Enabled
                        'Link_Enforced'     = $Link.NoOverride
                        'Link_Order'        = $Link.SOMOrder

                        # Additional Details
                        'Report_Generated'  = $StartTime
                        'Domain_Controller' = $env:COMPUTERNAME
                    }

                    [void]$Results.Add($Result)
                }

                $TotalLinks += $LinksForThisGPO
                Write-Verbose "GPO '$($GPO.DisplayName)' has $LinksForThisGPO links"
            }
            else {
                Write-Verbose "GPO '$($GPO.DisplayName)' has no links"
            }
        }
        catch {
            $ErrorMessage = "Error processing GPO '$($GPO.DisplayName)': $($_.Exception.Message)"
            Write-ColorOutput $ErrorMessage "Red"
            [void]$ErrorLog.Add("$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: $ErrorMessage")
        }
    }

    # Clear progress bar
    Write-Progress -Activity 'Processing GPOs...' -Completed

    # Export results
    if ($Results.Count -gt 0) {
        Write-ColorOutput "Exporting $($Results.Count) GPO link entries to CSV..." "Yellow"
        $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Force
        Write-ColorOutput "GPO link report exported successfully to: $OutputPath" "Green"

        # Display summary statistics
        Write-ColorOutput "`n=== Report Summary ===" "Cyan"
        Write-ColorOutput "Total GPOs processed: $TotalGPOs" "White"
        Write-ColorOutput "GPOs with links: $LinkedGPOs" "White"
        Write-ColorOutput "Total links found: $TotalLinks" "White"
        Write-ColorOutput "Unique linked locations: $(($Results | Select-Object -ExpandProperty Link_Location -Unique).Count)" "White"
        Write-ColorOutput "Enforced links: $(($Results | Where-Object { $_.Link_Enforced -eq 'true' }).Count)" "White"
        Write-ColorOutput "Disabled links: $(($Results | Where-Object { $_.Link_Enabled -eq 'false' }).Count)" "White"
    }
    else {
        Write-ColorOutput "No GPO link data was collected." "Red"
    }

    # Export error log if there were errors
    if ($ErrorLog.Count -gt 0) {
        $ErrorLogPath = [System.IO.Path]::ChangeExtension($OutputPath, 'log')
        $ErrorLog | Out-File -FilePath $ErrorLogPath -Encoding UTF8
        Write-ColorOutput "Errors encountered: $($ErrorLog.Count) - See error log: $ErrorLogPath" "Yellow"
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