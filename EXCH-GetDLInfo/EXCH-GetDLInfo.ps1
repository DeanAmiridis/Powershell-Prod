$Groups = Import-Csv -Path '.\DL-import.csv'
Import-Module activedirectory
$Groups | ForEach-Object {
    $group = $_
    Get-DistributionGroupMember -Identity $group.Name | ForEach-Object {
        New-Object -TypeName PSObject -Property @{
            Group  = $Group.Name
            Member = $_.Name
        }}} |
    Export-CSV "DL_membership_info.csv" -NoTypeInformation
#--------------break--------------#
$Groups | ForEach-Object {
    $group = $_
    Get-DistributionGroup -Identity $group.Name | ForEach-Object {
        New-Object -TypeName PSObject -Property @{
            Group                  = $_.Alias
            DisplayName            = $_.DisplayName
            PrimaryEmail           = $_.PrimarySmtpAddress
            GALHidden              = $_.HiddenFromAddressListsEnabled
            LegacyExchDN_X500      = $_.LegacyExchangeDN
            AcceptMessagesOnlyFrom = $_.AcceptMessagesOnlyFrom
            ManagedBy              = $_.ManagedBy
            OU                     = $_.OrganizationalUnit
            EmailAddresses         = $_.EmailAddresses
        }
    }} |
    Export-CSV "DL_attribute_info.csv" -NoTypeInformation
#--------------break--------------#
$Groups | ForEach-Object {
    $group = $_
    Get-ADGroup -Identity $group.Name -Properties * | Select-Object $Group.Name, ProxyAddresses | Format-List
} |
    Out-File "DL_email-addresses_info.txt"