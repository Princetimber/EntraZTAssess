#Requires -Version 7.0

# Recursively removes denylisted properties from an object graph before it
# is persisted as a raw evidence snapshot. The denylist is defined in
# settings.psd1 (RedactionDenylist) and matched case-insensitively against
# property names at any depth. Returns a deep, cleansed copy; the input
# object is never modified.
function Protect-ZTAssessData {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter()]
        [string[]]$Denylist
    )

    begin {
        if (-not $PSBoundParameters.ContainsKey('Denylist')) {
            $Denylist = @((Get-ZTAssessConfiguration -Name Settings).RedactionDenylist)
        }

        # Pre-compute simple property names (entries such as
        # 'keyCredentials.key' contribute their leaf name 'key').
        $denyNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $Denylist) {
            $leaf = ($entry -split '\.')[-1]
            $null = $denyNames.Add($leaf)
        }

        function Convert-Branch {
            param(
                [AllowNull()]
                [object]$Node,

                [System.Collections.Generic.HashSet[string]]$DenySet
            )

            if ($null -eq $Node) {
                return $null
            }

            # Primitive and value types pass through untouched.
            if ($Node -is [string] -or $Node -is [bool] -or $Node.GetType().IsValueType) {
                return $Node
            }

            # Dictionaries / hashtables
            if ($Node -is [System.Collections.IDictionary]) {
                $cleanTable = [ordered]@{}
                foreach ($dictionaryKey in $Node.Keys) {
                    if ($DenySet.Contains([string]$dictionaryKey)) {
                        $cleanTable[$dictionaryKey] = '***REDACTED***'
                    }
                    else {
                        $cleanTable[$dictionaryKey] = Convert-Branch -Node $Node[$dictionaryKey] -DenySet $DenySet
                    }
                }
                return $cleanTable
            }

            # Arrays and other enumerables (but not strings, handled above)
            if ($Node -is [System.Collections.IEnumerable]) {
                $cleanList = [System.Collections.Generic.List[object]]::new()
                foreach ($element in $Node) {
                    $cleanList.Add((Convert-Branch -Node $element -DenySet $DenySet))
                }
                return , $cleanList.ToArray()
            }

            # PSObjects and other reference types: walk note properties.
            $cleanObject = [ordered]@{}
            foreach ($property in $Node.PSObject.Properties) {
                if ($DenySet.Contains($property.Name)) {
                    $cleanObject[$property.Name] = '***REDACTED***'
                }
                else {
                    $cleanObject[$property.Name] = Convert-Branch -Node $property.Value -DenySet $DenySet
                }
            }
            return [pscustomobject]$cleanObject
        }
    }

    process {
        return Convert-Branch -Node $InputObject -DenySet $denyNames
    }
}
