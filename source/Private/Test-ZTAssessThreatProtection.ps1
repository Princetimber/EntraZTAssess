#Requires -Version 7.0

# ThreatProtection assessor. Implements checks TP-001 to TP-004 against
# persisted snapshots. Pure function over data on disk: no network calls.
# A missing snapshot means the Exchange Online / IPPS connection was
# unavailable, was skipped (delegated sign-in), or the collector failed -
# every check below degrades to NotAssessed in that case, never Fail.
function Test-ZTAssessThreatProtection {
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

    $safeLinksPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'safeLinksPolicies'
    $safeAttachmentPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'safeAttachmentPolicies'
    $antiPhishPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'antiPhishPolicies'
    $malwareFilterPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'malwareFilterPolicies'

    # --- TP-001: Safe Links protection is hardened ------------------------------
    if ($null -eq $safeLinksPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'TP-001' -Status NotAssessed -NotAssessedReason 'safeLinksPolicies snapshot unavailable (requires the Exchange Online / IPPS connection and a Defender for Office 365 licence).'))
    } else {
        $policies = @($safeLinksPolicies)
        if ($policies.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'TP-001' -Status Fail -Evidence 'No Safe Links policies were found; URL protection is not configured.'))
        } else {
            $hardened = @($policies | Where-Object {
                    [bool]$_.ScanUrls -and -not [bool]$_.AllowClickThrough -and
                    ([bool]$_.EnableSafeLinksForEmail -or [bool]$_.EnableSafeLinksForTeams -or [bool]$_.EnableSafeLinksForOffice)
                })
            if ($hardened.Count -eq $policies.Count) {
                $findings.Add((New-ZTAssessFinding -CheckId 'TP-001' -Status Pass -Evidence "All $($policies.Count) Safe Links policy(ies) scan URLs and block click-through."))
            } elseif ($hardened.Count -gt 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'TP-001' -Status Partial -Evidence "$($hardened.Count) of $($policies.Count) Safe Links policy(ies) are fully hardened; the rest allow click-through or do not scan URLs."))
            } else {
                $findings.Add((New-ZTAssessFinding -CheckId 'TP-001' -Status Fail -Evidence "None of the $($policies.Count) Safe Links policy(ies) both scan URLs and block click-through."))
            }
        }
    }

    # --- TP-002: Safe Attachments blocks malicious attachments ------------------
    if ($null -eq $safeAttachmentPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'TP-002' -Status NotAssessed -NotAssessedReason 'safeAttachmentPolicies snapshot unavailable (requires the Exchange Online / IPPS connection and a Defender for Office 365 licence).'))
    } else {
        $policies = @($safeAttachmentPolicies)
        if ($policies.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'TP-002' -Status Fail -Evidence 'No Safe Attachments policies were found; attachment sandboxing is not configured.'))
        } else {
            $blocking = @($policies | Where-Object { [bool]$_.Enable -and $_.Action -in @('Block', 'DynamicDelivery', 'Replace') })
            if ($blocking.Count -eq $policies.Count) {
                $findings.Add((New-ZTAssessFinding -CheckId 'TP-002' -Status Pass -Evidence "All $($policies.Count) Safe Attachments policy(ies) are enabled with a blocking action."))
            } elseif ($blocking.Count -gt 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'TP-002' -Status Partial -Evidence "$($blocking.Count) of $($policies.Count) Safe Attachments policy(ies) block malicious attachments; the rest are disabled or monitor-only."))
            } else {
                $findings.Add((New-ZTAssessFinding -CheckId 'TP-002' -Status Fail -Evidence "None of the $($policies.Count) Safe Attachments policy(ies) are enabled with a blocking action."))
            }
        }
    }

    # --- TP-003: Anti-phishing impersonation protection is enabled --------------
    if ($null -eq $antiPhishPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'TP-003' -Status NotAssessed -NotAssessedReason 'antiPhishPolicies snapshot unavailable (requires the Exchange Online / IPPS connection).'))
    } else {
        $policies = @($antiPhishPolicies)
        if ($policies.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'TP-003' -Status Fail -Evidence 'No anti-phishing policies were found.'))
        } else {
            $hardened = @($policies | Where-Object {
                    [bool]$_.Enabled -and [bool]$_.EnableMailboxIntelligence -and [bool]$_.EnableSpoofIntelligence -and
                    [int]$_.PhishThresholdLevel -ge [int]$thresholds.PhishThresholdMinimumLevel
                })
            if ($hardened.Count -eq $policies.Count) {
                $findings.Add((New-ZTAssessFinding -CheckId 'TP-003' -Status Pass -Evidence "All $($policies.Count) anti-phishing policy(ies) enable mailbox and spoof intelligence at or above threshold level $($thresholds.PhishThresholdMinimumLevel)."))
            } elseif ($hardened.Count -gt 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'TP-003' -Status Partial -Evidence "$($hardened.Count) of $($policies.Count) anti-phishing policy(ies) are fully hardened; review the rest for mailbox/spoof intelligence and threshold level."))
            } else {
                $findings.Add((New-ZTAssessFinding -CheckId 'TP-003' -Status Fail -Evidence "None of the $($policies.Count) anti-phishing policy(ies) meet the mailbox intelligence, spoof intelligence, and threshold-level bar."))
            }
        }
    }

    # --- TP-004: Malware filtering blocks malicious attachments -----------------
    if ($null -eq $malwareFilterPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'TP-004' -Status NotAssessed -NotAssessedReason 'malwareFilterPolicies snapshot unavailable (requires the Exchange Online / IPPS connection).'))
    } else {
        $policies = @($malwareFilterPolicies)
        if ($policies.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'TP-004' -Status Fail -Evidence 'No malware filter policies were found.'))
        } else {
            $blocking = @($policies | Where-Object { [bool]$_.EnableFileFilter -and $_.Action -in @('DeleteMessage', 'DeleteAttachmentAndUseDefaultAlert', 'Reject') })
            if ($blocking.Count -eq $policies.Count) {
                $findings.Add((New-ZTAssessFinding -CheckId 'TP-004' -Status Pass -Evidence "All $($policies.Count) malware filter policy(ies) filter common attachment types and take a blocking action."))
            } elseif ($blocking.Count -gt 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'TP-004' -Status Partial -Evidence "$($blocking.Count) of $($policies.Count) malware filter policy(ies) are fully hardened; review the rest for the file filter and blocking action."))
            } else {
                $findings.Add((New-ZTAssessFinding -CheckId 'TP-004' -Status Fail -Evidence "None of the $($policies.Count) malware filter policy(ies) enable the file filter with a blocking action."))
            }
        }
    }

    return $findings.ToArray()
}
