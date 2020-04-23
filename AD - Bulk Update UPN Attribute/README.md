# AD - Bulk Update UPN Attribute

> ## CSV File Formatting
* Create csv file in same path as .ps1 file named "user-import.csv"
* Each line should follow the format below:
    * adUsername,NewUPN
    * adUsername2,NewUPN2

> ## Script Usage
After creating your script file, call AD-BulkUpdateUPN.ps1 from Powershell (Running as Administrator!).
