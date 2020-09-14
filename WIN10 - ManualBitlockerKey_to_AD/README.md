> What does this script do?

This script will grab the KeyProtectorID from the current workstation and securely send a push request to your local active directory server. 

> Why do I need this?

There are many scenarios in why you would need to perform this task, some of which are:

 1. Bitlocker was executed on the workstation prior to joining workstation to Domain
 2. Bitlocker did not successfully back-up the recovery keys to Active Directory during the time of encryption


> Why are there 2 scripts?

**WIN10-ManualBitlockerKey_to_AD.ps1** - This script requires user to confirm (Y/N) that they are connected to the corporate network either in-office or by VPN before proceeding.

**WIN10-ManualBitlockerKey_to_AD-SILENT.ps1** - This script does not have any user interaction and will automatically assume the workstation it is executed on, is connected to the corporate network in order to communicate with Active Directory. 
