#Requires -Version 7.0

# Renders the executive report: overall maturity and risk posture, domain
# and Zero Trust pillar summaries, the top risks in business language, and
# remediation priorities. Print-ready (browser print to PDF) and free of
# raw technical dumps.
function ConvertTo-ZTAssessExecutiveHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $encode = { param($value) [System.Net.WebUtility]::HtmlEncode([string]$value) }
    $body = [System.Text.StringBuilder]::new()
    $scores = $Context.Scores

    $severityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; None = 4 }

    # --- Headline -------------------------------------------------------------
    $overall = if ($null -ne $scores.OverallScorePercent) { "$($scores.OverallScorePercent)%" } else { 'N/A' }
    $null = $body.AppendLine('<div class="kpi-row">')
    $null = $body.AppendLine("<div class='kpi'><div class='value'>$overall</div><div class='label'>Overall maturity</div></div>")
    $null = $body.AppendLine("<div class='kpi'><div class='value'>$(& $encode $scores.OverallLevel)</div><div class='label'>Maturity level</div></div>")
    $null = $body.AppendLine("<div class='kpi'><div class='value'>$(& $encode $scores.RiskPosture)</div><div class='label'>Risk posture</div></div>")
    $null = $body.AppendLine("<div class='kpi'><div class='value'>$($scores.RiskCounts.Critical)/$($scores.RiskCounts.High)</div><div class='label'>Critical / High risks</div></div>")
    $null = $body.AppendLine('</div>')

    $null = $body.AppendLine("<p>This assessment evaluated the Microsoft Entra ID and endpoint estate of $(& $encode $Context.Engagement.CustomerName) against the toolkit's Zero Trust check library using read-only collection. Maturity and risk are reported side by side and are deliberately not blended: the maturity percentage describes how much of recommended practice is in place, while the risk posture is capped at &ldquo;At Risk&rdquo; whenever any Critical exposure exists, regardless of the overall score.</p>")

    # --- Domain maturity --------------------------------------------------------
    $null = $body.AppendLine('<h2>Maturity by domain</h2><table><tr><th>Domain</th><th>Score</th><th>Level</th><th></th></tr>')
    foreach ($domain in (@($scores.Domains) | Sort-Object Domain)) {
        $pct = if ($null -ne $domain.ScorePercent) { [double]$domain.ScorePercent } else { $null }
        $barWidth = if ($null -ne $pct) { [int]$pct * 2.2 } else { 0 }
        $scoreText = if ($null -ne $pct) { "$pct%" } else { '&mdash;' }
        $null = $body.AppendLine("<tr><td>$(& $encode $domain.Domain)</td><td>$scoreText</td><td>$(& $encode $domain.Level)</td><td><span class='bar-track'><span class='bar-fill' style='width:$([math]::Min($barWidth,220))px'></span></span></td></tr>")
    }
    $null = $body.AppendLine('</table>')

    # --- Zero Trust pillars -------------------------------------------------------
    $null = $body.AppendLine('<h2>Zero Trust pillar alignment</h2><table><tr><th>Pillar</th><th>Score</th><th>Level</th></tr>')
    $pillarNames = @{ VerifyExplicitly = 'Verify explicitly'; LeastPrivilege = 'Use least privilege'; AssumeBreach = 'Assume breach' }
    foreach ($pillar in @($scores.Pillars)) {
        $displayName = $pillarNames[[string]$pillar.Pillar] ?? $pillar.Pillar
        $scoreText = if ($null -ne $pillar.ScorePercent) { "$($pillar.ScorePercent)%" } else { '&mdash;' }
        $null = $body.AppendLine("<tr><td>$(& $encode $displayName)</td><td>$scoreText</td><td>$(& $encode $pillar.Level)</td></tr>")
    }
    $null = $body.AppendLine('</table>')

    # --- Top risks ------------------------------------------------------------------
    $topRisks = @($Context.Findings |
            Where-Object { $_.Status -in @('Fail', 'Partial') -and $_.Severity -in @('Critical', 'High') } |
            Sort-Object { $severityRank[[string]$_.Severity] }, CheckId |
            Select-Object -First 10)

    $null = $body.AppendLine('<h2>Top risks requiring attention</h2>')
    if ($topRisks.Count -eq 0) {
        $null = $body.AppendLine('<p>No Critical or High severity exposures were identified. Remaining findings are improvement opportunities managed through the remediation roadmap.</p>')
    }
    else {
        $null = $body.AppendLine('<table><tr><th>Ref</th><th>Severity</th><th>Risk</th><th>Business impact</th></tr>')
        foreach ($risk in $topRisks) {
            $null = $body.AppendLine("<tr><td>$(& $encode $risk.CheckId)</td><td><span class='badge $(& $encode $risk.Severity)'>$(& $encode $risk.Severity)</span></td><td>$(& $encode $risk.Title)</td><td>$(& $encode $risk.Rationale)</td></tr>")
        }
        $null = $body.AppendLine('</table>')
    }

    # --- Remediation outlook -----------------------------------------------------------
    $remediable = @($Context.Findings | Where-Object { $_.Status -in @('Fail', 'Partial') })
    $waves = Get-ZTAssessRemediationRoadmap -Context $Context
    $waveCounts = $waves | Group-Object Wave | Sort-Object Name
    $null = $body.AppendLine('<h2>Remediation outlook</h2>')
    $null = $body.AppendLine("<p>$($remediable.Count) finding(s) require remediation, sequenced into delivery waves by severity and effort. Wave timings run from engagement acceptance and assume customer change processes operate normally.</p>")
    $null = $body.AppendLine('<table><tr><th>Wave</th><th>Window</th><th>Items</th></tr>')
    $waveWindows = @{ 'Wave 1' = '0&ndash;30 days'; 'Wave 2' = '30&ndash;90 days'; 'Wave 3' = '90&ndash;180 days'; 'Strategic' = '180+ days' }
    foreach ($wave in $waveCounts) {
        $null = $body.AppendLine("<tr><td>$(& $encode $wave.Name)</td><td>$($waveWindows[[string]$wave.Name])</td><td>$($wave.Count)</td></tr>")
    }
    $null = $body.AppendLine('</table>')

    $null = $body.AppendLine("<p class='evidence'>Full technical detail, evidence, and per-finding remediation guidance are provided in the accompanying technical findings report, risk register, and remediation roadmap.</p>")

    return ConvertTo-ZTAssessHtmlDocument -Title 'Executive Assessment Report' -BodyHtml $body.ToString() -Context $Context
}
