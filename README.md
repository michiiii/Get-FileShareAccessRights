# Get-FileShareAccessRights

## Description
This script lists all access rights for each file and folder on the specified network share. It uses a main function called Get-FileShareAccessRights that takes a network share path as a parameter.

## Example
```
$sysvolaccess = Get-FileShareAccessRights -NetworkSharePath "\\dc01.pwnyfarm.local\SYSVOL"
```

## Example analysis
```
$sysvolaccess | Where-Object {
(( -not $_.Username.Contains("Administrator")) -and ( -not $_.Username.Contains("NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS")) -and ( -not $_.Username.Contains("CREATOR OWNER")) -and ( -not $_.Username.Contains("Admins")) -and ($_.Username -ne "NT AUTHORITY\SYSTEM") -and ($_.Username -ne "S-1-5-32-549") -and ($_.Username -ne "pwnyfarm\Group Policy Creator Owners")) -and
(($_.AccessRight -eq "Write"))
}
```
