# Follow these steps to obtain information needed to compile user-import.csv:
#
# 1. In azure-ad export all users with added column of "ObjectID"; this will be used as the variable for REFOBJECTID
# 2. Connect-AzureAD in powershell as admin
# 3. Run get-azureadgroup to list out all of the security groups with their ObjectID's; this will be used as the variable for OBJECTID
# 4. With some excel trickery, Create a CSV as follows (per line):
# objectID|RefObjectID (Please note there is a PIPE as a delimeter in the CSV)
# example: group object id is 999-aaa-123 and Users ObjectID is 999-bbb-123 your line would be:
# 999-aaa-123|999-bbb-123

# ---- Data Import ----
$Users = Import-Csv -Path '.\user-import.csv'
Write-Host "CSV Imported Successfully" -ForegroundColor "green"
# ---- Data Import End ----

# ---- Action ----
foreach ( $User in $Users ) {
    $objectID = $User.ObjectID
    $RefObjectID = $User.RefObjectID
    Add-AzureADgroupmember -ObjectId $objectId -RefObjectId $RefObjectId
    Write-Host "Successfully added user $RefObjectId to group $objectId" -ForegroundColor "green"
}