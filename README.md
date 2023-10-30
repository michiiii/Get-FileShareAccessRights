# PowerShell Network Share Tools

This repository provides a collection of PowerShell functions that assist administrators in managing and evaluating network share permissions, Discretionary Access Control Lists (DACLs), and ownership details.

## Functions

1. `Get-FileShareCriticalPermissions`: Recursively retrieves the access rights for a specified network share path, listing the users/groups and their associated rights.
2. `Get-FileDACL`: Fetches the DACL of a specified file, returning each Access Control Entry (ACE) as an individual object.
3. `Get-FileShareOwnershipAndCreator`: Recursively fetches the owner and creator (if available) of files and folders from a given network share path.

## Usage

### Get-FileShareCriticalPermissions

Download and import
```powershell
iex (New-Object Net.Webclient).downloadstring('https://raw.githubusercontent.com/michiiii/Get-FileShareAccessRights/main/Get-FileShareAccessRights.ps1')
```

Retrieve the access rights for a specified network share path.

```powershell
$permissions = Get-FileShareCriticalPermissions -NetworkSharePath "\\pwnyfarm.local\netlogon"
```

Following that I want to create an overview of which users have how many write permissions

```powershell
# See users that have potential critical rights
$permissions | Group-Object -Property Username | Select-Object Name, Count
```

Finally, you can filter for intersting user/groups:
```powershell
$permissions | Where-Object {
 ( $_.Username.Contains("Authenticated Users"))
} | Format-Table Path, Username, AccessRight, IsInherited
```

### Get-FileDACL

Retrieves the DACL for a specified file.

```powershell
Get-FileDACL -FilePath "\\pwnyfarm.local\netlogon\LAPS.msi"
```

### Get-FileShareOwnershipAndCreator
Retrieve the owner and creator information from a network share path.

```powershell
Get-FileShareOwnershipAndCreator -NetworkSharePath "\\pwnyfarm.local\netlogon"
```

## Notes
- These functions were developed and tested in a Windows environment. Ensure you have the necessary permissions and dependencies before executing them.
- Always test scripts and functions in a controlled environment before using them in production.

## Contributions

Feel free to submit pull requests or issues if you identify any bugs or have suggestions for improvements.


## Todo
- Make the queries language independent by using well known SIDs to filter out default build-in groups
- Don´t collect "default" permissions to speed up the process
- Create a flag to remove the inheritance check
