[CmdletBinding()]
Param(
  [string]$key
)
slmgr.vbs -ipk $key
slmgr.vbs -ato

