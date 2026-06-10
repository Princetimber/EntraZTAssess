#Requires -Version 7.0

# Builds the consultant risk register from persisted findings. Only Fail and
# Partial findings become risk rows; Pass, Informational, and NotAssessed items
# stay in the technical report context rather than the remediation register.
function Get-ZTAssessRiskRegister {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $settings = Get-ZTAssessConfiguration -Name Settings
    $slaDays = $settings.RemediationSlaDays
    $severityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; None = 4 }

    $riskFindings = @($Context.Findings |
            Where-Object { $_.Status -in @('Fail', 'Partial') } |
            Sort-Object @{ Expression = { $severityRank[[string]$_.Severity] ?? 99 } }, Domain, CheckId)

    foreach ($finding in $riskFindings) {
        $severity = [string]$finding.Severity
        $days = if ($slaDays.ContainsKey($severity)) { [int]$slaDays[$severity] } else { $null }

        [pscustomobject][ordered]@{
            CheckId           = [string]$finding.CheckId
            Domain            = [string]$finding.Domain
            Title             = [string]$finding.Title
            Status            = [string]$finding.Status
            Severity          = $severity
            SlaDays           = $days
            Evidence          = [string]$finding.Evidence
            Rationale         = [string]$finding.Rationale
            Remediation       = [string]$finding.Remediation
            RemediationEffort = [string]$finding.RemediationEffort
            ZeroTrustPillars  = @($finding.ZeroTrustPillars | Where-Object { $_ } | Sort-Object)
            References        = @($finding.References | Where-Object { $_ } | Sort-Object)
        }
    }
}

# Converts risk rows to CSV-safe rows while keeping array flattening stable and
# deterministic. JSON exports retain arrays; only CSV receives semicolon joins.
function ConvertTo-ZTAssessRiskRegisterCsvRow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [pscustomobject]$InputObject
    )

    process {
        [pscustomobject][ordered]@{
            CheckId           = [string]$InputObject.CheckId
            Domain            = [string]$InputObject.Domain
            Title             = [string]$InputObject.Title
            Status            = [string]$InputObject.Status
            Severity          = [string]$InputObject.Severity
            SlaDays           = [string]$InputObject.SlaDays
            Evidence          = [string]$InputObject.Evidence
            Rationale         = [string]$InputObject.Rationale
            Remediation       = [string]$InputObject.Remediation
            RemediationEffort = [string]$InputObject.RemediationEffort
            ZeroTrustPillars  = (@($InputObject.ZeroTrustPillars | Where-Object { $_ } | Sort-Object) -join '; ')
            References        = (@($InputObject.References | Where-Object { $_ } | Sort-Object) -join '; ')
        }
    }
}
