#Action
Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "TargetReleaseVersion"
Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "TargetReleaseVersionInfo"

#Warning
Write-Warning "You must reboot the changes to take place. Please process ASAP!"