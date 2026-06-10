#Requires -Version 7.0

# Scoring engine. Computes per-domain maturity scores, Zero Trust pillar
# scores, the overall maturity percentage and level, and the risk posture
# summary from a set of findings, per the toolkit scoring specification:
#
#   DomainScore% = 100 x sum(weight x statusValue) / sum(weight of assessed)
#   statusValue: Pass = 1.0, Partial = 0.5, Fail = 0.0
#   NotAssessed and Informational findings are excluded from the denominator.
#   A domain with more than the configured share of weight NotAssessed is
#   labelled InsufficientData rather than scored.
#
# Deterministic: identical findings always produce identical scores.
function Measure-ZTAssessScore {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Findings,

        [Parameter()]
        [hashtable]$Settings
    )

    if (-not $Settings) {
        $Settings = Get-ZTAssessConfiguration -Name Settings
    }

    $statusValues = @{ Pass = 1.0; Partial = 0.5; Fail = 0.0 }
    $insufficientDataPercent = [double]$Settings.Thresholds.DomainInsufficientDataPercent

    $resolveLevel = {
        param([double]$score)
        foreach ($band in $Settings.MaturityBands) {
            if ($score -ge $band.Minimum -and $score -le $band.Maximum) {
                return $band.Level
            }
        }
        return 'Initial'
    }

    $scoreGroup = {
        param([object[]]$groupFindings)

        $assessed = @($groupFindings | Where-Object { $_.Status -in @('Pass', 'Partial', 'Fail') })
        $notAssessed = @($groupFindings | Where-Object { $_.Status -eq 'NotAssessed' })

        $assessedWeight = ($assessed | Measure-Object -Property MaturityWeight -Sum).Sum
        $notAssessedWeight = ($notAssessed | Measure-Object -Property MaturityWeight -Sum).Sum
        if (-not $assessedWeight) { $assessedWeight = 0.0 }
        if (-not $notAssessedWeight) { $notAssessedWeight = 0.0 }
        $totalWeight = $assessedWeight + $notAssessedWeight

        $insufficient = ($totalWeight -eq 0) -or
            ($totalWeight -gt 0 -and (100 * $notAssessedWeight / $totalWeight) -gt $insufficientDataPercent)

        $score = $null
        if (-not $insufficient -and $assessedWeight -gt 0) {
            $weightedSum = 0.0
            foreach ($finding in $assessed) {
                $weightedSum += [double]$finding.MaturityWeight * $statusValues[$finding.Status]
            }
            $score = [math]::Round(100 * $weightedSum / $assessedWeight, 1)
        }

        [pscustomobject]@{
            ScorePercent      = $score
            Level             = if ($null -ne $score) { & $resolveLevel $score } else { 'InsufficientData' }
            AssessedCount     = $assessed.Count
            NotAssessedCount  = $notAssessed.Count
            AssessedWeight    = $assessedWeight
            NotAssessedWeight = $notAssessedWeight
        }
    }

    # --- Domain scores ------------------------------------------------------
    $domainScores = @()
    foreach ($domainGroup in ($Findings | Group-Object -Property Domain | Sort-Object -Property Name)) {
        $result = & $scoreGroup @($domainGroup.Group)
        $domainScores += [pscustomobject]@{
            PSTypeName        = 'ZTAssess.DomainScore'
            Domain            = $domainGroup.Name
            ScorePercent      = $result.ScorePercent
            Level             = $result.Level
            AssessedCount     = $result.AssessedCount
            NotAssessedCount  = $result.NotAssessedCount
        }
    }

    # --- Pillar scores ------------------------------------------------------
    $pillarScores = @()
    foreach ($pillar in @('VerifyExplicitly', 'LeastPrivilege', 'AssumeBreach')) {
        $pillarFindings = @($Findings | Where-Object { @($_.ZeroTrustPillars) -contains $pillar })
        $result = & $scoreGroup $pillarFindings
        $pillarScores += [pscustomobject]@{
            PSTypeName       = 'ZTAssess.PillarScore'
            Pillar           = $pillar
            ScorePercent     = $result.ScorePercent
            Level            = $result.Level
            AssessedCount    = $result.AssessedCount
            NotAssessedCount = $result.NotAssessedCount
        }
    }

    # --- Overall maturity ---------------------------------------------------
    $weights = $Settings.DomainWeights
    $weightedTotal = 0.0
    $weightSum = 0.0
    foreach ($domainScore in $domainScores) {
        if ($null -eq $domainScore.ScorePercent) { continue }
        $domainWeight = if ($weights.ContainsKey($domainScore.Domain)) { [double]$weights[$domainScore.Domain] } else { 1.0 }
        if ($domainWeight -le 0) { continue }
        $weightedTotal += $domainScore.ScorePercent * $domainWeight
        $weightSum += $domainWeight
    }

    $overallScore = if ($weightSum -gt 0) { [math]::Round($weightedTotal / $weightSum, 1) } else { $null }
    $overallLevel = if ($null -ne $overallScore) { & $resolveLevel $overallScore } else { 'InsufficientData' }

    # --- Risk posture -------------------------------------------------------
    $riskCounts = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    foreach ($finding in ($Findings | Where-Object { $_.Status -in @('Fail', 'Partial') })) {
        if ($riskCounts.Contains($finding.Severity)) {
            $riskCounts[$finding.Severity] = [int]$riskCounts[$finding.Severity] + 1
        }
    }

    $posture = if ($riskCounts['Critical'] -gt 0) { 'At Risk' }
    elseif ($riskCounts['High'] -gt 0) { 'Needs Attention' }
    else { 'Managed Risk' }

    return [pscustomobject]@{
        PSTypeName          = 'ZTAssess.ScoreSummary'
        OverallScorePercent = $overallScore
        OverallLevel        = $overallLevel
        RiskPosture         = $posture
        RiskCounts          = [pscustomobject]$riskCounts
        Domains             = $domainScores
        Pillars             = $pillarScores
    }
}
