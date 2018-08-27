import-module ActiveDirectory
$Workstations = Get-Content "import_workstation_list.csv" 
$Output = foreach ( $Workstation in $Workstations ) { 
    Get-ADComputer -Identity $Workstation -Properties * | Select-Object Name, OperatingSystem, OperatingSystemVersion
}
$Output | Export-CSV "output_workstation_list.csv" -NoTypeInformation