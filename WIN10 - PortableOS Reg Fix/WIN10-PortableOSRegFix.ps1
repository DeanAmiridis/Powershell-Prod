# Machine must be rebooted after any registry changes are made!
#
#
# -- Test if value exists --
$RegValueCheck = Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Value 'PortableOperatingSystem'
if ($RegValueCheck -eq $True) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "PortableOperatingSystem" -Value 0
    Write-EventLog -LogName Application -Source "PortableOS_Fix" -EntryType Warning -EventID 1 -Message "Registry key detected; value set to 0"
}
else {
    Write-Host 'Portable Operating System is not installed'
    Write-EventLog -LogName Application -Source "PortableOS_Fix" -EntryType Warning -EventID 2 -Message "Registry key NOT detected. No changes made"
}