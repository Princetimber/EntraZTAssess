#Requires -Version 7.0

# Converts risk-register rows into a practical remediation roadmap. Sequencing
# is severity-led and deterministic: Critical/High in Wave 1, Medium in Wave 2,
# Low in Wave 3, with unknown severities treated as strategic follow-up.
function Get-ZTAssessRemediationRoadmap {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context
    )

    $waveBySeverity = @{
        Critical = 'Wave 1'
        High     = 'Wave 1'
        Medium   = 'Wave 2'
        Low      = 'Wave 3'
    }
    $windowByWave = @{
        'Wave 1'   = '0-30 days'
        'Wave 2'   = '30-90 days'
        'Wave 3'   = '90-180 days'
        Strategic  = '180+ days'
    }
    $waveRank = @{ 'Wave 1' = 0; 'Wave 2' = 1; 'Wave 3' = 2; Strategic = 3 }

    $riskRows = @(Get-ZTAssessRiskRegister -Context $Context)

    foreach ($risk in ($riskRows | Sort-Object @{ Expression = { $waveRank[$waveBySeverity[[string]$_.Severity] ?? 'Strategic'] } }, CheckId)) {
        $wave = $waveBySeverity[[string]$risk.Severity] ?? 'Strategic'

        [pscustomobject][ordered]@{
            Wave              = $wave
            Window            = $windowByWave[$wave]
            CheckId           = $risk.CheckId
            Domain            = $risk.Domain
            Title             = $risk.Title
            Severity          = $risk.Severity
            Status            = $risk.Status
            SlaDays           = $risk.SlaDays
            Remediation       = $risk.Remediation
            RemediationEffort = $risk.RemediationEffort
            ZeroTrustPillars  = @($risk.ZeroTrustPillars)
            References        = @($risk.References)
        }
    }
}
