#Requires -Version 7.0

function Get-ZTAssessScore {
    <#
    .SYNOPSIS
    Retrieves the maturity and risk scores from a completed assessment run.

    .DESCRIPTION
    Reads the persisted scores.json from a run folder produced by
    Invoke-ZTAssessment and returns the score summary: per-domain maturity
    scores and levels, Zero Trust pillar scores, the overall maturity
    percentage and level, and the risk posture with severity counts.
    Maturity and risk are deliberately reported side by side, never
    blended: any Critical finding caps the risk posture at "At Risk"
    regardless of the maturity percentage.

    .PARAMETER RunPath
    The run folder produced by Invoke-ZTAssessment (the folder containing
    the Scores subfolder).

    .EXAMPLE
    Get-ZTAssessScore -RunPath 'D:\Assessments\Contoso-ENG-2026-042\Runs\20260610-0930'

    Returns the full score summary for the run.

    .EXAMPLE
    (Get-ZTAssessScore -RunPath $run.RunPath).Domains | Format-Table Domain, ScorePercent, Level

    Tabulates the per-domain maturity scores.

    .OUTPUTS
    PSCustomObject
    A score summary with OverallScorePercent, OverallLevel, RiskPosture,
    RiskCounts, Domains, and Pillars properties.

    .NOTES
    Performs no network calls; operates entirely on the persisted run.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath (Join-Path $_ 'Scores/scores.json') -PathType Leaf })]
        [string]$RunPath
    )

    $scoresPath = Join-Path $RunPath 'Scores/scores.json'

    try {
        return Get-Content -LiteralPath $scoresPath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 20
    }
    catch {
        Write-Error -Message "Failed to read scores from '$scoresPath': $($_.Exception.Message)" -Category ReadError -ErrorAction Stop
    }
}
