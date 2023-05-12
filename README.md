# Get-FileShareAccessRights

## Description
This script lists all access rights for each file and folder on the specified network share. It uses a main function called Get-FileShareAccessRights that takes a network share path as a parameter.

```
iex (New-Object Net.Webclient).downloadstring('https://raw.githubusercontent.com/michiiii/Get-FileShareAccessRights/main/Get-FileShareAccessRights.ps1')
```

## Example
```
$sharePermissions = Get-FileShareAccessRights -NetworkSharePath "\\dc01.pwnyfarm.local\SYSVOL"
```

## Example analysis
```
$interestingSharePermissions = $sharepermissions | Where-Object {
(($_.AccessRight -eq "Write"))
}
$interestingSharePermissions | ft
```

Following that I want to create an overview of which users have how many write permissions

```
$interestingSharePermissionsOverview = $interestingSharePermissions | Group-Object -Property Username | Select-Object Name, Count
$interestingSharePermissionsOverview
```

Finally, you can filter for intersting user/groups:
```
$sharepermissions | Where-Object {
 ( $_.Username.Contains("lmueller")) -and
 (($_.AccessRight -eq "Write"))
}
```


## Todo
- Make the queries language independent by using well known SIDs
