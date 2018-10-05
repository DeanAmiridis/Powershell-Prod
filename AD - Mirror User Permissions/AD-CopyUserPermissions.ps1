#./AD-CopyUserPermissions.ps1 -copyfrom empid -copyto empid
[CmdletBinding()]
Param(
    [string]$copyfrom,
    [string]$copyto
)
#Imports active directory module
import-Module ActiveDirectory

#Gets DN Based off of emp ID specified by user
$CopyFromConvert = Get-ADUser -filter {employeeid -eq $copyfrom}
$CopyToConvert = Get-ADUser -filter {employeeid -eq $copyto}

#Deletes all group memberships except for "Domain Users" to the CopyTo account
$MembershipCleanup = Get-ADPrincipalGroupMembership -Identity $CopyToConvert | where {$_.Name -ne "Domain Users"}
Remove-ADPrincipalGroupMembership -Identity "$CopyToConvert" -MemberOf $MembershipCleanup -Confirm:$false

#Copies group memberships from CopyFrom to CopyTo account
get-ADuser -identity $CopyFromConvert -properties memberof | select-object memberof -expandproperty memberof | Add-AdGroupMember -Members $CopyToConvert