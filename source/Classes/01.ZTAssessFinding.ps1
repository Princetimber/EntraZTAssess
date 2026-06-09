#Requires -Version 7.0

<#
    ZTAssessFinding

    Standard finding object emitted by every assessor in the EntraZTAssess
    assessment engine. One instance represents the outcome of a single check
    against the tenant. Findings are persisted as JSON and consumed by the
    scoring and reporting layers.

    Status values  : Pass | Fail | Partial | NotAssessed | Informational
    Severity values: Critical | High | Medium | Low | None
#>
class ZTAssessFinding {
    [string] $CheckId
    [string] $Domain
    [string] $Title
    [string] $Status
    [string] $Severity
    [double] $MaturityWeight
    [string] $Evidence
    [string] $RawEvidenceRef
    [string] $Rationale
    [string] $Remediation
    [string] $RemediationEffort
    [string[]] $ZeroTrustPillars
    [string[]] $References
    [string] $NotAssessedReason

    static [string[]] $ValidStatuses = @('Pass', 'Fail', 'Partial', 'NotAssessed', 'Informational')
    static [string[]] $ValidSeverities = @('Critical', 'High', 'Medium', 'Low', 'None')
    static [string[]] $ValidEfforts = @('Low', 'Medium', 'High', '')
    static [string[]] $ValidPillars = @('VerifyExplicitly', 'LeastPrivilege', 'AssumeBreach')

    ZTAssessFinding() {
        $this.MaturityWeight = 3
        $this.ZeroTrustPillars = @()
        $this.References = @()
    }

    # Returns a list of validation problems; empty list means the finding is valid.
    [string[]] Validate() {
        $problems = [System.Collections.Generic.List[string]]::new()

        if ([string]::IsNullOrWhiteSpace($this.CheckId)) {
            $problems.Add('CheckId is required.')
        }

        if ([string]::IsNullOrWhiteSpace($this.Domain)) {
            $problems.Add('Domain is required.')
        }

        if ($this.Status -notin [ZTAssessFinding]::ValidStatuses) {
            $problems.Add("Status '$($this.Status)' is not one of: $([ZTAssessFinding]::ValidStatuses -join ', ').")
        }

        if ($this.Severity -notin [ZTAssessFinding]::ValidSeverities) {
            $problems.Add("Severity '$($this.Severity)' is not one of: $([ZTAssessFinding]::ValidSeverities -join ', ').")
        }

        if ($this.MaturityWeight -lt 0 -or $this.MaturityWeight -gt 5) {
            $problems.Add('MaturityWeight must be between 0 and 5.')
        }

        foreach ($pillar in $this.ZeroTrustPillars) {
            if ($pillar -notin [ZTAssessFinding]::ValidPillars) {
                $problems.Add("ZeroTrustPillar '$pillar' is not one of: $([ZTAssessFinding]::ValidPillars -join ', ').")
            }
        }

        if ($this.Status -eq 'NotAssessed' -and [string]::IsNullOrWhiteSpace($this.NotAssessedReason)) {
            $problems.Add('NotAssessedReason is required when Status is NotAssessed.')
        }

        return $problems.ToArray()
    }

    [string] ToString() {
        return ('[{0}] {1} - {2} ({3})' -f $this.CheckId, $this.Title, $this.Status, $this.Severity)
    }
}
