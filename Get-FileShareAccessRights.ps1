function Get-FileShareAccessRights {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, HelpMessage="The network share path to evaluate.")]
        [string]$NetworkSharePath
    )

    function Convert-AccessRightsToArray {
        param (
            [System.Security.AccessControl.FileSystemRights]$Rights
        )

        $RightsValue = $Rights.value__
        $AccessRights = [System.Enum]::GetNames([System.Security.AccessControl.FileSystemRights]) | Where-Object { $RightsValue -band [int][System.Security.AccessControl.FileSystemRights]::$_ }
        return $AccessRights
    }

    function Get-InheritanceSource {
        param (
            [string]$Path,
            [string]$Username
        )

        while ($Path -ne (Split-Path -Path $Path -Parent)) {
            $Path = Split-Path -Path $Path -Parent
            if ($null -ne $Path -and (Test-Path -Path $Path -PathType Container)) {
                $Acl = Get-Acl -Path $Path
                foreach ($AccessRule in $Acl.Access) {
                    if ($AccessRule.IdentityReference.Value -eq $Username -and !$AccessRule.IsInherited) {
                        return $Path
                    }
                }
            }
        }
        return $null
    }

    function Get-AccessRightsRecursively {
        param (
            [string]$Path
        )

        function Gather-AccessRights {
            param (
                [string]$Path
            )

            $Acl = Get-Acl -Path $Path

            foreach ($AccessRule in $Acl.Access) {
                $Username = $AccessRule.IdentityReference.Value
                $AccessRights = Convert-AccessRightsToArray -Rights $AccessRule.FileSystemRights
                $IsInherited = $AccessRule.IsInherited

                $InheritanceSource = if ($IsInherited) { Get-InheritanceSource -Path $Path -Username $Username } else { $null }

                foreach ($Right in $AccessRights) {
                    [PSCustomObject]@{
                        Path                = $Path
                        InheritanceSource   = $InheritanceSource
                        Username            = $Username
                        AccessRight         = $Right
                        IsInherited         = $IsInherited
                    }
                }
            }

            if (Test-Path -Path $Path -PathType Container) {
                Get-ChildItem -Path $Path | ForEach-Object { Gather-AccessRights -Path $_.FullName }
            }
        }

        Gather-AccessRights -Path $Path
    }

    $accessRights = Get-AccessRightsRecursively -Path $NetworkSharePath
    return $accessRights
}
