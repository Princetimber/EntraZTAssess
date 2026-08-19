#Requires -Version 7.0

# DataProtection assessor. Implements checks DP-001 to DP-004 against
# persisted snapshots. Pure function over data on disk: no network calls.
# A missing snapshot means the Exchange Online / IPPS connection was
# unavailable, was skipped (delegated sign-in), or the collector failed -
# every substantive check below degrades to NotAssessed in that case.
function Test-ZTAssessDataProtection {
    [CmdletBinding()]
    [OutputType([ZTAssessFinding[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RunPath,

        [Parameter()]
        [hashtable]$Settings
    )

    if (-not $Settings) {
        $Settings = Get-ZTAssessConfiguration -Name Settings
    }

    $findings = [System.Collections.Generic.List[object]]::new()

    $dlpPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'dlpCompliancePolicies'
    $dlpRules = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'dlpComplianceRules'
    $sensitivityLabels = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'sensitivityLabels'
    $labelPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'labelPolicies'

    # --- DP-001: DLP policies enforce protection across core workloads ---------
    if ($null -eq $dlpPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'DP-001' -Status NotAssessed -NotAssessedReason 'dlpCompliancePolicies snapshot unavailable (requires the Exchange Online / IPPS connection).'))
    } else {
        $policies = @($dlpPolicies)
        $enforcing = @($policies | Where-Object {
                $_.Mode -eq 'Enable' -and
                @($_.ExchangeLocation).Count -gt 0 -and (@($_.SharePointLocation).Count -gt 0 -or @($_.OneDriveLocation).Count -gt 0)
            })

        if ($enforcing.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DP-001' -Status Pass -Evidence "$($enforcing.Count) DLP policy(ies) are enforcing across Exchange and SharePoint/OneDrive."))
        } elseif ($policies.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DP-001' -Status Partial -Evidence "$($policies.Count) DLP policy(ies) exist, but none are both enforcing (Enable mode) and covering Exchange with SharePoint/OneDrive."))
        } else {
            $findings.Add((New-ZTAssessFinding -CheckId 'DP-001' -Status Fail -Evidence 'No DLP policies were found.'))
        }
    }

    # --- DP-002: DLP rules block sensitive-information matches -----------------
    if ($null -eq $dlpRules) {
        $findings.Add((New-ZTAssessFinding -CheckId 'DP-002' -Status NotAssessed -NotAssessedReason 'dlpComplianceRules snapshot unavailable (requires the Exchange Online / IPPS connection).'))
    } else {
        $rules = @($dlpRules)
        $blocking = @($rules | Where-Object { [bool]$_.BlockAccess })

        if ($blocking.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DP-002' -Status Pass -Evidence "$($blocking.Count) of $($rules.Count) DLP rule(s) block access on a sensitive-information match."))
        } elseif ($rules.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DP-002' -Status Fail -Evidence "$($rules.Count) DLP rule(s) exist, but none block access; matches are only logged or notified."))
        } else {
            $findings.Add((New-ZTAssessFinding -CheckId 'DP-002' -Status Fail -Evidence 'No DLP rules were found.'))
        }
    }

    # --- DP-003: sensitivity labels are published for classification -----------
    if ($null -eq $sensitivityLabels) {
        $findings.Add((New-ZTAssessFinding -CheckId 'DP-003' -Status NotAssessed -NotAssessedReason 'sensitivityLabels snapshot unavailable (requires the Exchange Online / IPPS connection).'))
    } else {
        $labels = @($sensitivityLabels)
        if ($labels.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'DP-003' -Status Fail -Evidence 'No sensitivity labels were found.'))
        } else {
            $publishedLabelCount = 0
            if ($labelPolicies) {
                $publishedLabelCount = @(@($labelPolicies) | ForEach-Object { @($_.Labels) } | Where-Object { $_ } | Select-Object -Unique).Count
            }

            if ($publishedLabelCount -gt 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'DP-003' -Status Pass -Evidence "$($labels.Count) sensitivity label(s) exist and at least one label policy publishes them."))
            } else {
                $findings.Add((New-ZTAssessFinding -CheckId 'DP-003' -Status Partial -Evidence "$($labels.Count) sensitivity label(s) exist, but no label policy publishes them; they are unavailable to users."))
            }
        }
    }

    # --- DP-004: data protection inventory (informational) ---------------------
    $dlpPolicyCount = if ($dlpPolicies) { @($dlpPolicies).Count } else { 0 }
    $dlpRuleCount = if ($dlpRules) { @($dlpRules).Count } else { 0 }
    $labelCount = if ($sensitivityLabels) { @($sensitivityLabels).Count } else { 0 }
    $labelPolicyCount = if ($labelPolicies) { @($labelPolicies).Count } else { 0 }
    $findings.Add((New-ZTAssessFinding -CheckId 'DP-004' -Status Informational -Evidence "Inventory: $dlpPolicyCount DLP policy(ies), $dlpRuleCount DLP rule(s), $labelCount sensitivity label(s), $labelPolicyCount label policy(ies)." -SeverityOverride None))

    return $findings.ToArray()
}
