#Requires -Version 7.0

# Factory that merges a declarative check definition with an assessment
# outcome to produce a validated ZTAssessFinding. Severity defaults to the
# check's DefaultSeverity for Fail/Partial outcomes and None for Pass;
# assessors may escalate or downgrade via -SeverityOverride where the check
# definition documents conditional escalation.
function New-ZTAssessFinding {
    [CmdletBinding()]
    [OutputType([ZTAssessFinding])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Factory function creating an in-memory object only; no external state is changed.')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CheckId,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Partial', 'NotAssessed', 'Informational')]
        [string]$Status,

        [Parameter()]
        [string]$Evidence = '',

        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'None')]
        [string]$SeverityOverride,

        [Parameter()]
        [string]$NotAssessedReason,

        [Parameter()]
        [string]$RawEvidenceRef = ''
    )

    $definition = Get-ZTAssessCheckDefinition -CheckId $CheckId

    $finding = [ZTAssessFinding]::new()
    $finding.CheckId = $definition.CheckId
    $finding.Domain = $definition.Domain
    $finding.Title = $definition.Title
    $finding.Status = $Status
    $finding.MaturityWeight = [double]$definition.MaturityWeight
    $finding.Evidence = $Evidence
    $finding.RawEvidenceRef = $RawEvidenceRef
    $finding.Rationale = [string]$definition.Rationale
    $finding.Remediation = [string]$definition.Remediation
    $finding.RemediationEffort = [string]$definition.RemediationEffort
    $finding.ZeroTrustPillars = @($definition.ZeroTrustPillars)
    $finding.References = @($definition.References)
    $finding.NotAssessedReason = $NotAssessedReason

    if ($SeverityOverride) {
        $finding.Severity = $SeverityOverride
    }
    elseif ($Status -in @('Fail', 'Partial')) {
        $finding.Severity = $definition.DefaultSeverity
    }
    else {
        $finding.Severity = 'None'
    }

    $problems = $finding.Validate()
    if ($problems.Count -gt 0) {
        throw "Finding for check '$CheckId' failed validation: $($problems -join ' ')"
    }

    return $finding
}
