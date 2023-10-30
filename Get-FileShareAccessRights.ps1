<#
.SYNOPSIS
Retrieves the access rights for a specified network share path, filtering by specific rights and excluding certain SIDs.

.DESCRIPTION
This function fetches the access rights of the specified network share path. It recursively evaluates each file and directory, 
listing the users/groups and their associated rights. The results exclude certain rights and SIDs based on criteria.

.PARAMETER NetworkSharePath
The path of the network share to evaluate.

.EXAMPLE
Get-FileShareCriticalPermissions -NetworkSharePath "\\example.local\netlogon"

.NOTES
The function evaluates both files and directories within the specified network share path.
#>

function Get-FileShareCriticalPermissions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, HelpMessage="The network share path to evaluate.")]
        [string]$NetworkSharePath
    )

    # Converts the FileSystemRights flags to an array of string rights
    function Convert-AccessRightsToArray {
        param (
            [System.Security.AccessControl.FileSystemRights]$Rights
        )

        $RightsValue = $Rights.value__
        return [System.Enum]::GetNames([System.Security.AccessControl.FileSystemRights]) |
               Where-Object { $RightsValue -band [int][System.Security.AccessControl.FileSystemRights]::$_ }
    }

    # Recursively gathers access rights from files and directories
    function Get-AccessRightsRecursively {
        param (
            [string]$NetworkSharePath
        )

        function Gather-AccessRights {
            param (
                [string]$ItemPath
            )
            $Acl = Get-Acl -Path $ItemPath
            foreach ($AccessRule in $Acl.Access) {
                $Username = $AccessRule.IdentityReference.Value
                $UserSID = $AccessRule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value

                # Exclude well known SIDs
                # Well known SIDs
                # $UserSID -eq "S-1-5-18"-> Local System
                # $UserSID -like "*S-1-3-0"-> Creator Owner
                # $UserSID -like '*S-1-5-32-544' -> Build-In Administratoren
                # $UserSID -match '-520$' -> Group Policy Creator Owners
                # $UserSID -match '-512$' -> Domain Admins
                # $UserSID -match '-512$' -> Enterprise admins
                if (
                    ($UserSID -eq "S-1-5-18") -or
                    ($UserSID -eq "S-1-3-0") -or
                    ($UserSID -like "*S-1-5-32-544") -or 
                    ($UserSID -match '-520$') -or
                    ($UserSID -match '-512$') -or
                    ($UserSID -match '-519$')                    
                     ) {
                    continue
                }

                $AccessRights = Convert-AccessRightsToArray -Rights $AccessRule.FileSystemRights

                foreach ($Right in $AccessRights) {
                    # Filter results by specific rights
                    if ($Right -in @("ChangePermissions", "TakeOwnership", "Write", "AppendData", "CreateFiles", "Delete", "WriteData", "WriteAttributes", "WriteExtendedAttributes")) {
                        [PSCustomObject]@{
                            Path         = $ItemPath
                            Username     = $Username
                            SID          = $UserSID
                            AccessRight  = $Right
                            IsInherited  = $AccessRule.IsInherited
                        }
                    }
                }
            }
            # Recurse into directories
            if (Test-Path -Path $ItemPath -PathType Container) {
                Get-ChildItem -Path $ItemPath | ForEach-Object { Gather-AccessRights -ItemPath $_.FullName }
            }
        }
        return Gather-AccessRights -ItemPath $NetworkSharePath
    }
    return Get-AccessRightsRecursively -NetworkSharePath $NetworkSharePath
}


<#
.SYNOPSIS
Provides an overview of critical permissions based on the input of SharePermissions.

.DESCRIPTION
This function processes an array of SharePermissions and returns an overview table grouped by Username.

.PARAMETER SharePermissions
An array of PowerShell objects representing SharePermissions, where each object must have a 'Username' property.

.EXAMPLE
$permissions = @(
    [PSCustomObject]@{Username='User1'; AccessRight='Write'},
    [PSCustomObject]@{Username='User2'; AccessRight='Read'},
    [PSCustomObject]@{Username='User1'; AccessRight='Delete'}
)
Get-CriticalPermissionOverview -SharePermissions $permissions

Output:
Name  Count
----  -----
User1 2
User2 1
#>

function Get-CriticalPermissionOverview {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [PSObject[]]$SharePermissions
    )

    # Group by Username and return the overview
    return $SharePermissions | Group-Object -Property Username | Select-Object Name, Count
}


<#
.SYNOPSIS
Provides detailed critical permissions for a specified user based on the input of SharePermissions.

.DESCRIPTION
This function processes an array of SharePermissions and returns a detailed table of permissions for a specific user.

.PARAMETER SharePermissions
An array of PowerShell objects representing SharePermissions. Each object should contain properties like 'Path', 'Username', 'AccessRight', and 'IsInherited'.

.PARAMETER UserName
The name of the user for whom the critical permissions should be fetched.

.EXAMPLE
$permissions = @(
    [PSCustomObject]@{Path="\\path1"; Username='User1'; AccessRight='Write'; IsInherited=$false},
    [PSCustomObject]@{Path="\\path2"; Username='User2'; AccessRight='Read'; IsInherited=$true},
    [PSCustomObject]@{Path="\\path3"; Username='User1'; AccessRight='Delete'; IsInherited=$false}
)
Get-CriticalPermissionByUser -SharePermissions $permissions -UserName "User1"

Output:
Path     Username AccessRight IsInherited
----     -------- ----------- -----------
\\path1  User1    Write       False      
\\path3  User1    Delete      False      
#>

function Get-CriticalPermissionsByUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [PSObject[]]$SharePermissions,

        [Parameter(Mandatory=$true)]
        [string]$UserName
    )

    # Filter by UserName and return the detailed table
    return $SharePermissions | Where-Object { $_.Username.Contains($UserName) } | Format-Table Path, Username, AccessRight, IsInherited -AutoSize
}


<#
.SYNOPSIS
Retrieves the Discretionary Access Control List (DACL) for a specified file.

.DESCRIPTION
The function fetches the DACL of the specified file and returns each 
Access Control Entry (ACE) as an individual object within an array.

.PARAMETER FilePath
Specifies the path of the file to evaluate.

.EXAMPLE
Get-FileDACL -FilePath "C:\path\to\file.txt"

.NOTES
Warnings will be emitted if:
1. The specified file doesn't exist.
2. There's an error retrieving the ACL.
#>
function Get-FileDACL {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
        Write-Warning "File does not exist: $FilePath"
        return
    }

    $acl = $null
    try {
        $acl = Get-Acl -Path $FilePath
    } catch {
        Write-Warning "Failed to obtain ACL for: $FilePath"
        Write-Warning $_.Exception.Message
        return
    }

    return $acl.Access | ForEach-Object {
        [PSCustomObject]@{
            FilePath           = $FilePath
            IdentityReference  = $_.IdentityReference
            AccessControlType  = $_.AccessControlType
            FileSystemRights   = $_.FileSystemRights
            IsInherited        = $_.IsInherited
            InheritanceFlags   = $_.InheritanceFlags
            PropagationFlags   = $_.PropagationFlags
        }
    }
}

<#
.SYNOPSIS
Retrieve the owner and creator information from a network share path.

.DESCRIPTION
This function recursively fetches the owner and creator (if available) 
of files and folders from a given network share path.

.PARAMETER NetworkSharePath
The network share path to evaluate.

.EXAMPLE
Get-FileShareOwnershipAndCreator -NetworkSharePath "\\myserver\myshare"

.NOTES
The 'Creator' is derived from the 'Author' metadata property. 
It might be empty for some files or might not accurately represent 
the actual file creator for every file type.
#>
function Get-FileShareOwnershipAndCreator {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, HelpMessage="The network share path to evaluate.")]
        [string]$NetworkSharePath
    )

    function Get-Creator {
        param (
            [string]$Path
        )

        $creator = $null
        try {
            $shell = New-Object -ComObject Shell.Application
            $folder = $shell.Namespace((Get-Item $Path).DirectoryName)
            $file = $folder.ParseName((Get-Item $Path).Name)
            $creator = $folder.GetDetailsOf($file, 10)
        } catch {
            # Silently ignore errors
        }
        return $creator
    }

    function Gather-OwnershipAndCreator {
        param (
            [string]$Path
        )

        $Acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue
        $Owner = if ($Acl) { $Acl.Owner } else { $null }
        $Creator = Get-Creator -Path $Path

        [PSCustomObject]@{
            Path     = $Path
            Owner    = $Owner
            Creator  = $Creator
        }

        if (Test-Path -Path $Path -PathType Container -ErrorAction SilentlyContinue) {
            Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | 
                ForEach-Object { Gather-OwnershipAndCreator -Path $_.FullName }
        }
    }

    return Gather-OwnershipAndCreator -Path $NetworkSharePath
}

