#Requires -Version 7.0

# Persists a raw data snapshot collected from Microsoft Graph to the Raw
# folder of the current run, applying the redaction denylist first so no
# secret material is ever written to disk. Returns the path written.
function Save-ZTAssessSnapshot {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Data,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RunPath,

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9\-_]+$')]
        [string]$Name
    )

    if (-not (Test-Path -LiteralPath $RunPath)) {
        throw "Run path does not exist: $RunPath"
    }

    $rawFolder = Join-Path -Path $RunPath -ChildPath 'Raw'
    if (-not (Test-Path -LiteralPath $rawFolder)) {
        $null = New-Item -Path $rawFolder -ItemType Directory -Force -ErrorAction Stop
    }

    $snapshotPath = Join-Path -Path $rawFolder -ChildPath "$Name.json"

    if ($PSCmdlet.ShouldProcess($snapshotPath, 'Write redacted raw snapshot')) {
        try {
            $cleansed = Protect-ZTAssessData -InputObject $Data
            $cleansed | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $snapshotPath -Encoding utf8NoBOM -ErrorAction Stop
            Write-ToLog -Message "Snapshot '$Name' written to $snapshotPath" -Level DEBUG -NoConsole
        }
        catch {
            throw "Failed to write snapshot '$Name' to '$snapshotPath': $($_.Exception.Message)"
        }
    }

    return $snapshotPath
}
