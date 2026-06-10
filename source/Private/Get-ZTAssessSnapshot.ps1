#Requires -Version 7.0

# Reads a persisted raw snapshot from a run folder. Returns the parsed
# objects, or $null when the snapshot does not exist - assessors treat a
# missing snapshot as NotAssessed rather than an error, preserving graceful
# degradation when a collector was skipped or failed.
function Get-ZTAssessSnapshot {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RunPath,

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9\-_]+$')]
        [string]$Name
    )

    $snapshotPath = Join-Path -Path $RunPath -ChildPath (Join-Path 'Raw' "$Name.json")

    if (-not (Test-Path -LiteralPath $snapshotPath)) {
        return $null
    }

    try {
        $content = Get-Content -LiteralPath $snapshotPath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($content) -or $content.Trim() -eq 'null') {
            return $null
        }
        # -NoEnumerate plus the comma wrapper preserve empty arrays: an empty
        # snapshot ([]) must reach assessors as an empty collection, not $null,
        # because "no policies exist" and "snapshot unavailable" are different
        # findings.
        $parsed = ConvertFrom-Json -InputObject $content -Depth 50 -NoEnumerate
        return , $parsed
    }
    catch {
        throw "Failed to read snapshot '$Name' from '$snapshotPath': $($_.Exception.Message)"
    }
}
