[CmdletBinding()]
Param(
  [string]$TargetVersion
)
#Action
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "TargetReleaseVersion" -Value 1 -PropertyType DWORD
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "TargetReleaseVersionInfo" -Value $TargetVersion -PropertyType String

#Warning
Write-Warning "You must reboot the changes to take place. Please process ASAP!"