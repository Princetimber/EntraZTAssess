#Requires -Version 7.0

# Renders the technical findings report: every finding grouped by domain
# with status, severity, evidence, rationale, remediation, and references,
# plus a closing appendix of NotAssessed items with reasons.
function ConvertTo-ZTAssessTechnicalHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $encode = { param($value) [System.Net.WebUtility]::HtmlEncode([string]$value) }
    $body = [System.Text.StringBuilder]::new()

    $statusCounts = $Context.Findings | Group-Object Status | Sort-Object Name
    $null = $body.AppendLine('<div class="kpi-row">')
    foreach ($group in $statusCounts) {
        $null = $body.AppendLine("<div class='kpi'><div class='value'>$($group.Count)</div><div class='label'>$(& $encode $group.Name)</div></div>")
    }
    $null = $body.AppendLine('</div>')

    foreach ($domainGroup in ($Context.Findings | Group-Object Domain | Sort-Object Name)) {
        $domainScore = @($Context.Scores.Domains) | Where-Object Domain -eq $domainGroup.Name | Select-Object -First 1
        $scoreText = if ($null -ne $domainScore.ScorePercent) { "$($domainScore.ScorePercent)% &mdash; $(& $encode $domainScore.Level)" } else { 'Insufficient data' }
        $null = $body.AppendLine("<h2>$(& $encode $domainGroup.Name) <span class='evidence'>($scoreText)</span></h2>")

        foreach ($finding in ($domainGroup.Group | Sort-Object CheckId)) {
            $null = $body.AppendLine("<h3>$(& $encode $finding.CheckId) &mdash; $(& $encode $finding.Title) <span class='badge $(& $encode $finding.Status)'>$(& $encode $finding.Status)</span>$(if ($finding.Severity -and $finding.Severity -ne 'None') { " <span class='badge $(& $encode $finding.Severity)'>$(& $encode $finding.Severity)</span>" })</h3>")

            if ($finding.Status -eq 'NotAssessed') {
                $null = $body.AppendLine("<p class='evidence'><strong>Not assessed:</strong> $(& $encode $finding.NotAssessedReason)</p>")
            }
            else {
                if ($finding.Evidence) {
                    $null = $body.AppendLine("<p><strong>Evidence:</strong> $(& $encode $finding.Evidence)</p>")
                }
                if ($finding.Rationale) {
                    $null = $body.AppendLine("<p class='evidence'><strong>Why it matters:</strong> $(& $encode $finding.Rationale)</p>")
                }
                if ($finding.Status -in @('Fail', 'Partial') -and $finding.Remediation) {
                    $null = $body.AppendLine("<p><strong>Recommended remediation:</strong> $(& $encode $finding.Remediation)$(if ($finding.RemediationEffort) { " <span class='evidence'>(effort: $(& $encode $finding.RemediationEffort))</span>" })</p>")
                }
            }

            $references = @($finding.References) | Where-Object { $_ }
            if ($references.Count -gt 0) {
                $links = ($references | ForEach-Object { "<a href='$(& $encode $_)'>$(& $encode $_)</a>" }) -join '<br>'
                $null = $body.AppendLine("<p class='evidence'><strong>References:</strong><br>$links</p>")
            }
        }
    }

    $notAssessed = @($Context.Findings | Where-Object Status -eq 'NotAssessed' | Sort-Object CheckId)
    if ($notAssessed.Count -gt 0) {
        $null = $body.AppendLine('<h2>Appendix: items not assessed</h2>')
        $null = $body.AppendLine('<table><tr><th>Check</th><th>Title</th><th>Reason</th></tr>')
        foreach ($finding in $notAssessed) {
            $null = $body.AppendLine("<tr><td>$(& $encode $finding.CheckId)</td><td>$(& $encode $finding.Title)</td><td>$(& $encode $finding.NotAssessedReason)</td></tr>")
        }
        $null = $body.AppendLine('</table>')
    }

    return ConvertTo-ZTAssessHtmlDocument -Title 'Technical Findings Report' -BodyHtml $body.ToString() -Context $Context
}
