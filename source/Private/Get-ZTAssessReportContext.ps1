#Requires -Version 7.0

# Loads everything the report renderers need from a persisted run folder:
# findings, scores, the run manifest, optional platform profiles and device
# classification, and the engagement settings (branding, classification
# marking) resolved from the engagement folder two levels above the run.
# Pure read operation; throws actionable errors for missing core artefacts.
function Get-ZTAssessReportContext {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RunPath
    )

    $findingsPath = Join-Path $RunPath 'Findings/findings.json'
    $scoresPath = Join-Path $RunPath 'Scores/scores.json'
    $manifestPath = Join-Path $RunPath 'manifest.json'

    foreach ($required in @($findingsPath, $scoresPath)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Required run artefact not found: $required. Run Invoke-ZTAssessment first."
        }
    }

    $findings = Get-Content -LiteralPath $findingsPath -Raw | ConvertFrom-Json -Depth 20
    $scores = Get-Content -LiteralPath $scoresPath -Raw | ConvertFrom-Json -Depth 20

    $manifest = $null
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 10
    }

    $platformProfiles = $null
    $profilesPath = Join-Path $RunPath 'Findings/platformProfiles.json'
    if (Test-Path -LiteralPath $profilesPath -PathType Leaf) {
        $platformProfiles = Get-Content -LiteralPath $profilesPath -Raw | ConvertFrom-Json -Depth 20
    }

    $deviceClassification = $null
    $classificationPath = Join-Path $RunPath 'Findings/deviceClassification.json'
    if (Test-Path -LiteralPath $classificationPath -PathType Leaf) {
        $deviceClassification = Get-Content -LiteralPath $classificationPath -Raw | ConvertFrom-Json -Depth 20
    }

    # Engagement settings live two levels up (<Engagement>/Runs/<Run>).
    $engagement = @{
        CustomerName   = 'Customer'
        Reference      = ''
        Classification = 'Confidential'
        Branding       = @{}
    }
    $engagementPath = Split-Path -Parent (Split-Path -Parent $RunPath)
    $engagementFile = Join-Path $engagementPath 'engagement.psd1'
    if (Test-Path -LiteralPath $engagementFile -PathType Leaf) {
        try {
            $loaded = Import-PowerShellDataFile -LiteralPath $engagementFile
            foreach ($key in $loaded.Keys) { $engagement[$key] = $loaded[$key] }
        }
        catch {
            Write-Warning "Failed to parse engagement settings at '$engagementFile'; using defaults. $($_.Exception.Message)"
        }
    }

    return [pscustomobject]@{
        PSTypeName           = 'ZTAssess.ReportContext'
        RunPath              = $RunPath
        Findings             = @($findings)
        Scores               = $scores
        Manifest             = $manifest
        PlatformProfiles     = if ($platformProfiles) { @($platformProfiles) } else { $null }
        DeviceClassification = if ($deviceClassification) { @($deviceClassification) } else { $null }
        Engagement           = $engagement
        GeneratedUtc         = [datetime]::UtcNow
    }
}
