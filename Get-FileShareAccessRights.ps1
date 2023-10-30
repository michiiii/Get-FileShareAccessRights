<#
.SYNOPSIS
Retrieves the access rights for a specified network share path.

.DESCRIPTION
The function fetches the access rights of the specified network share path. 
It recursively evaluates each file and directory, listing the users/groups and their associated rights.

.PARAMETER NetworkSharePath
Specifies the path of the network share to evaluate.

.EXAMPLE
Get-FileShareAccessRights -NetworkSharePath "\\pwnyfarm.local\netlogon"

.NOTES
The function evaluates both files and directories within the specified network share path.
#>
function Get-FileShareAccessRights {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, HelpMessage="The network share path to evaluate.")]
        [string]$NetworkSharePath
    )

    # Converts enumerated access rights to a human-readable array.
    function Convert-AccessRightsToArray {
        param (
            [System.Security.AccessControl.FileSystemRights]$Rights
        )

        $RightsValue = $Rights.value__
        return [System.Enum]::GetNames([System.Security.AccessControl.FileSystemRights]) |
               Where-Object { $RightsValue -band [int][System.Security.AccessControl.FileSystemRights]::$_ }
    }

    # Recursively retrieves access rights for files and directories.
    function Get-AccessRightsRecursively {
        param (
            [string]$Path
        )

        # Gathers access rights for the specified path.
        function Gather-AccessRights {
            param (
                [string]$Path
            )

            $Acl = Get-Acl -Path $Path

            foreach ($AccessRule in $Acl.Access) {
                $Username = $AccessRule.IdentityReference.Value
                $AccessRights = Convert-AccessRightsToArray -Rights $AccessRule.FileSystemRights

                foreach ($Right in $AccessRights) {
                    [PSCustomObject]@{
                        Path         = $Path
                        Username     = $Username
                        AccessRight  = $Right
                        IsInherited  = $AccessRule.IsInherited
                    }
                }
            }

            # If the current path is a directory, evaluate its children.
            if (Test-Path -Path $Path -PathType Container) {
                Get-ChildItem -Path $Path | ForEach-Object { Gather-AccessRights -Path $_.FullName }
            }
        }

        return Gather-AccessRights -Path $Path
    }

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
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    # Validates the existence of the file.
    if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
        Write-Warning "File does not exist: $FilePath"
        return
    }

    # Attempts to retrieve the DACL for the specified file.
    $acl = $null
    try {
        $acl = Get-Acl -Path $FilePath
    }
    catch {
        Write-Warning "Failed to obtain ACL for: $FilePath"
        Write-Warning $_.Exception.Message
        return
    }

    # Iterates through each ACE, creating a custom object for each and adding to the results array.
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
        [Parameter(
            Mandatory=$true, 
            Position=0, 
            HelpMessage="The network share path to evaluate."
        )]
        [string]$NetworkSharePath
    )

    # Helper function to retrieve the 'Creator' of the file.
    function Get-Creator {
        param (
            [string]$Path
        )

        $creator = $null
        try {
            $shell = New-Object -ComObject Shell.Application
            $folder = $shell.Namespace((Get-Item $Path -ErrorAction SilentlyContinue).DirectoryName)
            $file = $folder.ParseName((Get-Item $Path -ErrorAction SilentlyContinue).Name)
            
            # 10 corresponds to the 'Author' property for many file types in the shell.
            $creator = $folder.GetDetailsOf($file, 10)
        } catch {
            # Silently ignore errors, $creator remains $null
        }
        return $creator
    }

    # Helper function to recursively gather ownership and creator details.
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

        # If the current path is a directory, iterate over its children.
        if (Test-Path -Path $Path -PathType Container -ErrorAction SilentlyContinue) {
            Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | 
                ForEach-Object { Gather-OwnershipAndCreator -Path $_.FullName }
        }
    }

    # Start the recursion from the provided network share path.
    return Gather-OwnershipAndCreator -Path $NetworkSharePath
}

