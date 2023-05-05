<#
.SYNOPSIS
    Retrieves access rights for a network share path, including all files and folders.

.DESCRIPTION
    This script lists all access rights for each file and folder on the specified network share. It uses
    a main function called Get-FileShareAccessRights that takes a network share path as a parameter.

.PARAMETER NetworkSharePath
    The network share path to evaluate.

.EXAMPLE
    Get-FileShareAccessRights -NetworkSharePath "\\dc01.pwnyfarm.local\SYSVOL"

.NOTES
    [TBD]
#>
function Get-FileShareAccessRights {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, HelpMessage="The network share path to evaluate.")]
        [string]$NetworkSharePath
    )

    # This function converts FileSystemRights to an array of strings
    function Convert-AccessRightsToArray {
        param (
            [System.Security.AccessControl.FileSystemRights]$Rights
        )

        $RightsValue = $Rights.value__
        $AccessRights = [System.Enum]::GetNames([System.Security.AccessControl.FileSystemRights]) | Where-Object { $RightsValue -band [int][System.Security.AccessControl.FileSystemRights]::$_ }
        return $AccessRights
    }

    # This function recursively gathers access rights for the provided path
    function Get-AccessRightsRecursively {
        param (
            [string]$Path
        )

        # Recursive function to gather access rights
        function Gather-AccessRights {
            param (
                [string]$Path
            )

            # Get the ACL (Access Control List) of the current path
            $Acl = Get-Acl -Path $Path

            # Loop through each access rule in the ACL
            foreach ($AccessRule in $Acl.Access) {
                $Username = $AccessRule.IdentityReference.Value
                $AccessRights = Convert-AccessRightsToArray -Rights $AccessRule.FileSystemRights
                $IsInherited = $AccessRule.IsInherited

                # Loop through each access right and output it separately
                foreach ($Right in $AccessRights) {
                    # Output the user's access right for the current path
                    [PSCustomObject]@{
                        Path        = $Path
                        Username    = $Username
                        AccessRight = $Right
                        IsInherited = $IsInherited
                    }
                }
            }

            # If the current path is a directory, recursively call this function for all its children
            if (Test-Path -Path $Path -PathType Container) {
                Get-ChildItem -Path $Path | ForEach-Object { Gather-AccessRights -Path $_.FullName }
            }
        }

        # Gather access rights and return them through the pipeline
        Gather-AccessRights -Path $Path
    }

    $accessRights = Get-AccessRightsRecursively -Path $NetworkSharePath
    return $accessRights
}
