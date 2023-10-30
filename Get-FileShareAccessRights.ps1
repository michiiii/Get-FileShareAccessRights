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
            [string]$Path
        )

        function Gather-AccessRights {
            param (
                [string]$ItemPath
            )
            Write-Host $ItemPath
            $Acl = Get-Acl -Path $ItemPath
            foreach ($AccessRule in $Acl.Access) {
                $Username = $AccessRule.IdentityReference.Value
                $UserSID = $AccessRule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value

                # Exclude built-in Administrators and Local System SIDs
                if ($UserSID -like "*S-1-5-32-544" -or $UserSID -eq "S-1-5-18") {
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
            Write-Host $ItemPath
            # Recurse into directories
            if (Test-Path -Path $ItemPath -PathType Container) {
                Get-ChildItem -Path $ItemPath | ForEach-Object { Gather-AccessRights -Path $_.FullName }
            }
        }

        return Gather-AccessRights -Path $Path
    }
    Write-Host $NetworkSharePath
    return Get-AccessRightsRecursively -Path $NetworkSharePath
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

<#
.SYNOPSIS
Retrieves an overview of potentially exploitable share permissions for provided users.

.DESCRIPTION
The function evaluates the provided SharePermissions object array to identify potentially 
exploitable permissions such as "ChangePermissions", "TakeOwnership", and various write-related permissions.
It then groups these permissions by username and provides an overview of how many potentially 
exploitable permissions each user possesses.

.PARAMETER SharePermissions
An array of objects representing share permissions. Each object should have properties for 
AccessRight and Username.

.EXAMPLE
$permissions = @(
    [PSCustomObject]@{Username="UserA"; AccessRight="Write"},
    [PSCustomObject]@{Username="UserA"; AccessRight="Read"},
    [PSCustomObject]@{Username="UserB"; AccessRight="ChangePermissions"},
    [PSCustomObject]@{Username="UserC"; AccessRight="TakeOwnership"}
)

Get-ExploitableSharePermissionsOverview -SharePermissions $permissions

.NOTES
The function is designed to provide an overview and should be used in conjunction with 
further investigation for security assessments.
#>

function Get-ExploitableSharePermissionsOverview {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage="Array of objects representing share permissions.")]
        [array]$SharePermissions
    )

    # Filter permissions to identify potentially exploitable ones
    $interestingSharePermissions = $SharePermissions | Where-Object {
        ($_.AccessRight -eq "ChangePermissions") -or
        ($_.AccessRight -eq "TakeOwnership") -or
        ($_.AccessRight -eq "Write") -or
        ($_.AccessRight -eq "AppendData") -or
        ($_.AccessRight -eq "CreateFiles") -or
        ($_.AccessRight -eq "Delete") -or
        ($_.AccessRight -eq "WriteData") -or
        ($_.AccessRight -eq "WriteAttributes") -or
        ($_.AccessRight -eq "WriteExtendedAttributes")
    }

    # Generate an overview grouped by username
    $interestingSharePermissionsOverview = $interestingSharePermissions | Group-Object -Property Username | Select-Object Name, Count

    return $interestingSharePermissionsOverview
}

