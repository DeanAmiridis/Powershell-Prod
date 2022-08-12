# Import Active Directory module for running AD cmdlets

Import-Module activedirectory

#Store the data from your file in the $ADUsers variable

$ADUsers = Import-csv .\filename.csv

#Loop through each row containing user details in the CSV file

foreach ($User in $ADUsers)
{
#Read user data from each field in each row and assign the data to a variable as below
$Username = $User.username
$Password = $User.password
$Firstname = $User.firstname
$Lastname = $User.lastname
$OU = $User.ou
$email = $User.email
$Domain = "@domain.com" # MAKE SURE TO FILL THIS IN!!!!!!!!

#Check to see if the user already exists in the AD

if (Get-ADUser -F {SamAccountName -eq $Username})
{
#If the user does exist, give a warning
Write-Warning "A user account with username $Username already exists in Active Directory."
}
else
{
#User does not exist then proceed to create the new user account
#Account will be created in the OU provided by the $OU variable read from the CSV file
New-ADUser `
-SamAccountName $Username `
-UserPrincipalName "$Username$Domain" `
-Name "$Firstname $Lastname" `
-GivenName $Firstname `
-Surname $Lastname `
-Enabled $True `
-DisplayName "$Firstname $Lastname" `
-Path $OU `
-EmailAddress $email `
-AccountPassword (convertto-securestring $Password -AsPlainText -Force) `
-ChangePasswordAtLogon $False
}
}