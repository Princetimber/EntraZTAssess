#Requires -Version 7.0

# Recursively converts the structure produced by ConvertFrom-Json -AsHashTable
# back into the PSCustomObject/array shape callers already expect from
# ConvertFrom-Json's default mode, resolving any case-insensitive sibling key
# collision (e.g. 'value' and 'Value' at the same object level) along the
# way - that collision is exactly what -AsHashTable was used to survive in
# the first place, since Hashtable can hold both distinctly but PSCustomObject
# cannot. Ordered dictionaries/hashtables are case-insensitive for .Contains()
# by default, which is what lets this detect the collision.
function ConvertTo-ZTAssessNormalizedJsonObject {
    [CmdletBinding()]
    [OutputType([object], [object[]])]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        $InputObject
    )

    process {
        if ($null -eq $InputObject) {
            return $null
        }

        if ($InputObject -is [System.Collections.IDictionary]) {
            $ordered = [ordered]@{}
            foreach ($key in $InputObject.Keys) {
                $value = ConvertTo-ZTAssessNormalizedJsonObject -InputObject $InputObject[$key]
                if ($ordered.Contains($key)) {
                    # Case-insensitive collision with an already-seen sibling
                    # key - keep whichever value is non-null/non-empty rather
                    # than throwing, since both keys are legal JSON on their
                    # own; only their case-insensitive coexistence is the
                    # problem.
                    if ($null -ne $value -and $value -ne '') {
                        $ordered[$key] = $value
                    }
                } else {
                    $ordered[$key] = $value
                }
            }
            return [pscustomobject]$ordered
        }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            return @($InputObject | ForEach-Object { ConvertTo-ZTAssessNormalizedJsonObject -InputObject $_ })
        }

        return $InputObject
    }
}
