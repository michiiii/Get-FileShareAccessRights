# PowerShell Network Share Tools

This repository provides a collection of PowerShell functions that assist administrators in managing and evaluating network share permissions, Discretionary Access Control Lists (DACLs), and ownership details.

## Functions

1. `Get-FileShareCriticalPermissions`: Recursively retrieves the access rights for a specified network share path, listing the users/groups and their associated rights.
2. `Get-CriticalPermissionOverview`: Get an overview which users have critical permissions on the share
3. `Get-CriticalPermissionsByUser`: Get file and folder objects a user has critical permissions to
4. `Get-FileDACL`: Fetches the DACL of a specified file, returning each Access Control Entry (ACE) as an individual object.
5. `Get-FileShareOwnershipAndCreator`: Recursively fetches the owner and creator (if available) of files and folders from a given network share path.

## Usage

### Get-FileShareCriticalPermissions

Download and import
```powershell
iex (New-Object Net.Webclient).downloadstring('https://raw.githubusercontent.com/michiiii/Get-FileShareAccessRights/main/Get-FileShareAccessRights.ps1')
```

Retrieve the ACE´s for a specified network share path.

```powershell
$permissions = Get-FileShareCriticalPermissions -NetworkSharePath "\\pwnyfarm.local\netlogon"
```

### Get-CriticalPermissionOverview

Following that I want to create an overview of which users have how many write permissions

```powershell
# See users that have potential critical rights
Get-CriticalPermissionOverview -SharePermissions $permissions
```
### Get-CriticalPermissionsByUser

Finally, you can filter for intersting user/groups:
```powershell
Get-CriticalPermissionsByUser -SharePermissions $permissions -UserName "Authenticated Users"
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

## Contributions

Feel free to submit pull requests or issues if you identify any bugs or have suggestions for improvements.

