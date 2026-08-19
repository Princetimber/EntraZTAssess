#Requires -Version 7.0

# SecurityCompliance assessor. Implements checks SC-001 to SC-004 against
# persisted snapshots. Pure function over data on disk: no network calls.
# A missing snapshot means the Exchange Online / IPPS connection was
# unavailable, was skipped (delegated sign-in), or the collector failed -
# every substantive check below degrades to NotAssessed in that case.
function Test-ZTAssessSecurityCompliance {
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
    $thresholds = $Settings.Thresholds

    $findings = [System.Collections.Generic.List[object]]::new()

    $retentionPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'retentionCompliancePolicies'
    $retentionRules = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'retentionComplianceRules'
    $complianceTags = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'complianceTags'

    # --- SC-001: retention policies cover core workloads ------------------------
    if ($null -eq $retentionPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'SC-001' -Status NotAssessed -NotAssessedReason 'retentionCompliancePolicies snapshot unavailable (requires the Exchange Online / IPPS connection).'))
    } else {
        $policies = @($retentionPolicies | Where-Object { [bool]$_.Enabled })
        $coveringCore = @($policies | Where-Object {
                @($_.ExchangeLocation).Count -gt 0 -and (@($_.SharePointLocation).Count -gt 0 -or @($_.OneDriveLocation).Count -gt 0)
            })

        if ($coveringCore.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'SC-001' -Status Pass -Evidence "$($coveringCore.Count) enabled retention policy(ies) cover Exchange together with SharePoint or OneDrive."))
        } elseif ($policies.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'SC-001' -Status Partial -Evidence "$($policies.Count) enabled retention policy(ies) exist, but none cover Exchange together with SharePoint or OneDrive."))
        } else {
            $findings.Add((New-ZTAssessFinding -CheckId 'SC-001' -Status Fail -Evidence 'No enabled retention policies were found.'))
        }
    }

    # --- SC-002: retention rules enforce a minimum duration ---------------------
    if ($null -eq $retentionRules) {
        $findings.Add((New-ZTAssessFinding -CheckId 'SC-002' -Status NotAssessed -NotAssessedReason 'retentionComplianceRules snapshot unavailable (requires the Exchange Online / IPPS connection).'))
    } else {
        $rules = @($retentionRules)
        if ($rules.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'SC-002' -Status Fail -Evidence 'No retention rules were found.'))
        } else {
            $sufficient = @($rules | Where-Object {
                    $_.RetentionDuration -eq 'Unlimited' -or ([int]::TryParse([string]$_.RetentionDuration, [ref]0) -and [int]$_.RetentionDuration -ge [int]$thresholds.RetentionRuleMinimumDurationDays)
                })
            if ($sufficient.Count -eq $rules.Count) {
                $findings.Add((New-ZTAssessFinding -CheckId 'SC-002' -Status Pass -Evidence "All $($rules.Count) retention rule(s) retain content for at least $($thresholds.RetentionRuleMinimumDurationDays) days or indefinitely."))
            } elseif ($sufficient.Count -gt 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'SC-002' -Status Partial -Evidence "$($sufficient.Count) of $($rules.Count) retention rule(s) meet the $($thresholds.RetentionRuleMinimumDurationDays)-day minimum; the rest expire sooner."))
            } else {
                $findings.Add((New-ZTAssessFinding -CheckId 'SC-002' -Status Fail -Evidence "None of the $($rules.Count) retention rule(s) meet the $($thresholds.RetentionRuleMinimumDurationDays)-day minimum retention duration."))
            }
        }
    }

    # --- SC-003: records-declaring compliance tags are published ----------------
    if ($null -eq $complianceTags) {
        $findings.Add((New-ZTAssessFinding -CheckId 'SC-003' -Status NotAssessed -NotAssessedReason 'complianceTags snapshot unavailable (requires the Exchange Online / IPPS connection).'))
    } else {
        $tags = @($complianceTags)
        $recordTags = @($tags | Where-Object { [bool]$_.IsRecordLabel })

        if ($recordTags.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'SC-003' -Status Pass -Evidence "$($recordTags.Count) compliance tag(s) are configured as record labels."))
        } elseif ($tags.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'SC-003' -Status Partial -Evidence "$($tags.Count) compliance tag(s) exist, but none are configured as record labels."))
        } else {
            $findings.Add((New-ZTAssessFinding -CheckId 'SC-003' -Status Fail -Evidence 'No compliance tags were found.'))
        }
    }

    # --- SC-004: retention/records inventory (informational) -------------------
    $policyCount = if ($retentionPolicies) { @($retentionPolicies).Count } else { 0 }
    $ruleCount = if ($retentionRules) { @($retentionRules).Count } else { 0 }
    $tagCount = if ($complianceTags) { @($complianceTags).Count } else { 0 }
    $findings.Add((New-ZTAssessFinding -CheckId 'SC-004' -Status Informational -Evidence "Inventory: $policyCount retention policy(ies), $ruleCount retention rule(s), $tagCount compliance tag(s)." -SeverityOverride None))

    return $findings.ToArray()
}
