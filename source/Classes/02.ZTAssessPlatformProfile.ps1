#Requires -Version 7.0

<#
    ZTAssessPlatformProfile

    Per-platform device assessment profile produced by the device platform
    assessment logic. One instance is produced for each platform in scope
    (Android, iOS/iPadOS, macOS, Windows) and consumed by the device
    enrolment assessment report and the BYOD versus corporate-owned
    comparison report.

    Coverage percentages are expressed 0-100. A value of -1 means the
    coverage could not be calculated (NotAssessed).
#>
class ZTAssessPlatformProfile {
    [string] $Platform
    [string[]] $EnrolmentMethodsInUse
    [hashtable] $EnrolmentRestrictions
    [hashtable] $OwnershipSplit
    [double] $CompliancePolicyCoveragePercent
    [double] $ConfigProfileCoveragePercent
    [double] $BaselineCoveragePercent
    [double] $AppProtectionCoveragePercent
    [hashtable] $CADependency
    [string[]] $Gaps
    [string] $RiskRating
    [string[]] $Remediations

    static [string[]] $ValidPlatforms = @('Android', 'iOS', 'macOS', 'Windows')
    static [string[]] $ValidRiskRatings = @('Critical', 'High', 'Medium', 'Low', 'None', 'NotAssessed')
    static [string[]] $OwnershipClasses = @('Corporate', 'BYOD', 'Shared', 'Kiosk', 'PAW', 'Unknown')

    ZTAssessPlatformProfile() {
        $this.EnrolmentMethodsInUse = @()
        $this.EnrolmentRestrictions = @{}
        $this.OwnershipSplit = @{}
        $this.CADependency = @{}
        $this.Gaps = @()
        $this.Remediations = @()
        $this.CompliancePolicyCoveragePercent = -1
        $this.ConfigProfileCoveragePercent = -1
        $this.BaselineCoveragePercent = -1
        $this.AppProtectionCoveragePercent = -1
        $this.RiskRating = 'NotAssessed'
    }

    # Returns a list of validation problems; empty list means the profile is valid.
    [string[]] Validate() {
        $problems = [System.Collections.Generic.List[string]]::new()

        if ($this.Platform -notin [ZTAssessPlatformProfile]::ValidPlatforms) {
            $problems.Add("Platform '$($this.Platform)' is not one of: $([ZTAssessPlatformProfile]::ValidPlatforms -join ', ').")
        }

        if ($this.RiskRating -notin [ZTAssessPlatformProfile]::ValidRiskRatings) {
            $problems.Add("RiskRating '$($this.RiskRating)' is not one of: $([ZTAssessPlatformProfile]::ValidRiskRatings -join ', ').")
        }

        foreach ($percentProperty in @(
                'CompliancePolicyCoveragePercent',
                'ConfigProfileCoveragePercent',
                'BaselineCoveragePercent',
                'AppProtectionCoveragePercent'
            )) {
            $value = $this.$percentProperty
            if ($value -ne -1 -and ($value -lt 0 -or $value -gt 100)) {
                $problems.Add("$percentProperty must be between 0 and 100, or -1 for NotAssessed.")
            }
        }

        foreach ($ownershipKey in $this.OwnershipSplit.Keys) {
            if ($ownershipKey -notin [ZTAssessPlatformProfile]::OwnershipClasses) {
                $problems.Add("OwnershipSplit key '$ownershipKey' is not one of: $([ZTAssessPlatformProfile]::OwnershipClasses -join ', ').")
            }
        }

        return $problems.ToArray()
    }

    [string] ToString() {
        return ('{0}: risk {1}, {2} gap(s)' -f $this.Platform, $this.RiskRating, $this.Gaps.Count)
    }
}
