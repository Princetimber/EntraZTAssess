#Requires -Version 7.0

function Export-ZTAssessReport {
    <#
    .SYNOPSIS
    Exports local HTML, risk-register, and remediation-roadmap reports for a completed assessment run.

    .DESCRIPTION
    Reads a completed run folder produced by Invoke-ZTAssessment and writes the
    delivery-ready report artifacts beneath the run's Reports folder:
    ExecutiveReport.html, TechnicalReport.html, RiskRegister.json,
    RiskRegister.csv, and RemediationRoadmap.json. The command is intentionally
    disk-only: it performs no Microsoft Graph calls, does not require an active
    Graph connection, and does not mutate tenant configuration. Risk-register
    and roadmap rows include only findings with Fail or Partial status; Pass,
    Informational, and NotAssessed findings remain visible in the technical HTML
    report but are not treated as remediation backlog rows.

    .PARAMETER RunPath
    The completed run folder produced by Invoke-ZTAssessment. The folder must
    contain Findings/findings.json and Scores/scores.json. The command also
    consumes optional manifest.json, Findings/platformProfiles.json, and
    Findings/deviceClassification.json when present.

    .PARAMETER RedactUserIdentifiers
    Redacts user-identifying values from the generated report artifacts. This
    option affects only the exported reports and does not modify source run
    artifacts such as Findings/findings.json.

    .EXAMPLE
    Export-ZTAssessReport -RunPath 'D:\Assessments\Contoso-ENG-2026-042\Runs\20260610-0930'

    Writes the Phase 4 MVP report artifacts to the run's Reports folder and
    returns the artifact paths.

    .EXAMPLE
    $export = Export-ZTAssessReport -RunPath $run.RunPath -WhatIf

    Shows the local report write operation without creating the Reports folder
    or any artifacts. The returned object still contains the deterministic paths
    that would be used.

    .EXAMPLE
    Export-ZTAssessReport -RunPath $run.RunPath -RedactUserIdentifiers

    Writes report artifacts with user-identifying values replaced by a stable
    redaction marker for client handoff.

    .OUTPUTS
    PSCustomObject
    Returns a ZTAssess.ReportExportResult object with RunPath, ReportsPath,
    GeneratedUtc, and one path property per generated artifact.

    .NOTES
    This command is a local filesystem export only. It does not generate PDF,
    Excel workbook, or dashboard artifacts; print the HTML
    files from a browser if a PDF handoff is required.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RunPath,

        [Parameter()]
        [switch]$RedactUserIdentifiers
    )

    $resolvedRunPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($RunPath)
    $context = Get-ZTAssessReportContext -RunPath $resolvedRunPath
    $exportContext = $context
    if ($RedactUserIdentifiers.IsPresent) {
        $exportContext = Protect-ZTAssessReportUserIdentifier -Context $context
    }
    $reportsPath = Join-Path -Path $resolvedRunPath -ChildPath 'Reports'

    $executiveReportPath = Join-Path -Path $reportsPath -ChildPath 'ExecutiveReport.html'
    $technicalReportPath = Join-Path -Path $reportsPath -ChildPath 'TechnicalReport.html'
    $riskRegisterJsonPath = Join-Path -Path $reportsPath -ChildPath 'RiskRegister.json'
    $riskRegisterCsvPath = Join-Path -Path $reportsPath -ChildPath 'RiskRegister.csv'
    $roadmapJsonPath = Join-Path -Path $reportsPath -ChildPath 'RemediationRoadmap.json'

    if ($PSCmdlet.ShouldProcess($reportsPath, 'Write report artifacts')) {
        try {
            $null = New-Item -Path $reportsPath -ItemType Directory -Force -ErrorAction Stop

            $executiveHtml = ConvertTo-ZTAssessExecutiveHtml -Context $exportContext
            $technicalHtml = ConvertTo-ZTAssessTechnicalHtml -Context $exportContext
            $riskRegister = @(Get-ZTAssessRiskRegister -Context $exportContext)
            $roadmap = @(Get-ZTAssessRemediationRoadmap -Context $exportContext)

            Set-Content -LiteralPath $executiveReportPath -Value $executiveHtml -Encoding utf8NoBOM -ErrorAction Stop
            Set-Content -LiteralPath $technicalReportPath -Value $technicalHtml -Encoding utf8NoBOM -ErrorAction Stop
            ConvertTo-Json -InputObject $riskRegister -Depth 20 | Set-Content -LiteralPath $riskRegisterJsonPath -Encoding utf8NoBOM -ErrorAction Stop

            $csvRows = @($riskRegister | ConvertTo-ZTAssessRiskRegisterCsvRow)
            if ($csvRows.Count -gt 0) {
                $csvRows | ConvertTo-Csv -NoTypeInformation | Set-Content -LiteralPath $riskRegisterCsvPath -Encoding utf8NoBOM -ErrorAction Stop
            }
            else {
                '"CheckId","Domain","Title","Status","Severity","SlaDays","Evidence","Rationale","Remediation","RemediationEffort","ZeroTrustPillars","References"' |
                    Set-Content -LiteralPath $riskRegisterCsvPath -Encoding utf8NoBOM -ErrorAction Stop
            }

            ConvertTo-Json -InputObject $roadmap -Depth 20 | Set-Content -LiteralPath $roadmapJsonPath -Encoding utf8NoBOM -ErrorAction Stop
        }
        catch {
            Write-Error -Message "Failed to export reports for run '$resolvedRunPath': $($_.Exception.Message)" -Category WriteError -ErrorAction Stop
        }
    }

    return [pscustomobject]@{
        PSTypeName                  = 'ZTAssess.ReportExportResult'
        RunPath                     = $resolvedRunPath
        ReportsPath                 = $reportsPath
        GeneratedUtc                = $exportContext.GeneratedUtc
        ExecutiveReportPath         = $executiveReportPath
        TechnicalReportPath         = $technicalReportPath
        RiskRegisterJsonPath        = $riskRegisterJsonPath
        RiskRegisterCsvPath         = $riskRegisterCsvPath
        RemediationRoadmapJsonPath  = $roadmapJsonPath
    }
}
