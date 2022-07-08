# Azure - Bulk Add Users to Security Group

## user-import.csv Population

1. In azure-ad export all users with added column of "ObjectID"; this will be used as the variable for REFOBJECTID
2. Connect-AzureAD in powershell as admin
3. Run get-azureadgroup to list out all of the security groups with their ObjectID's; this will be used as the variable for OBJECTID
4. With some excel trickery, Create a CSV as follows (per line):
objectID|RefObjectID (Please note there is a PIPE as a delimeter in the CSV)
example: group object id is 999-aaa-123 and Users ObjectID is 999-bbb-123 your line would be:
```sh
999-aaa-123|999-bbb-123
```