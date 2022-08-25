# Connect to Office 365 via Azure
#$UserCredential = Get-Credential
#$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
#Import-PSSession $Session
$Groups = Get-UnifiedGroup -ResultSize Unlimited
$Groups | ForEach-Object {
    $group = $_
    Get-UnifiedGroupLinks -Identity $group.Name -LinkType Members | ForEach-Object {
        New-Object -TypeName PSObject -Property @{
            Group         = $group.DisplayName
            Member        = $_.Name
            EmailAddress  = $_.PrimarySMTPAddress
            RecipientType = $_.RecipientType
        } } } |
Export-CSV ".\O365-Groups.csv" -NoTypeInformation