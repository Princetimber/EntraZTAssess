#Requires -Version 7.0

# Persists the run manifest as manifest.json in the run folder. The manifest
# must never contain tokens, secrets, or raw payloads; it records identity,
# scope, timing, and count metadata only.
function Save-ZTAssessRunManifest {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ZTAssessRunManifest]$Manifest,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RunPath
    )

    $problems = $Manifest.Validate()
    if ($problems.Count -gt 0) {
        throw "Run manifest is invalid: $($problems -join ' ')"
    }

    if (-not (Test-Path -LiteralPath $RunPath)) {
        throw "Run path does not exist: $RunPath"
    }

    $manifestPath = Join-Path -Path $RunPath -ChildPath 'manifest.json'

    if ($PSCmdlet.ShouldProcess($manifestPath, 'Write run manifest')) {
        try {
            $Manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM -ErrorAction Stop
            Write-ToLog -Message "Run manifest written to $manifestPath" -Level DEBUG -NoConsole
        }
        catch {
            throw "Failed to write run manifest to '$manifestPath': $($_.Exception.Message)"
        }
    }

    return $manifestPath
}
