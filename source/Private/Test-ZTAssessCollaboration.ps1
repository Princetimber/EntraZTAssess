#Requires -Version 7.0

# Collaboration assessor. Implements checks CO-001 to CO-004 against
# persisted snapshots. Pure function over data on disk: no network calls.
# A missing snapshot means the Exchange Online / IPPS connection was
# unavailable, was skipped (delegated sign-in), or the collector failed -
# every substantive check below degrades to NotAssessed in that case.
function Test-ZTAssessCollaboration {
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

    $sharingPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'sharingPolicies'
    $transportRules = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'transportRules'

    # Splits each policy's 'Domains' entries (e.g. 'Anonymous:CalendarSharingFreeBusyDetail')
    # into Domain/Permission pairs for evaluation.
    $splitDomainEntries = {
        param($policy)
        @($policy.Domains) | Where-Object { $_ } | ForEach-Object {
            $parts = ([string]$_).Split(':', 2)
            [pscustomobject]@{ Domain = $parts[0]; Permission = if ($parts.Count -gt 1) { $parts[1] } else { '' } }
        }
    }

    # --- CO-001: anonymous calendar sharing is not detailed ---------------------
    if ($null -eq $sharingPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CO-001' -Status NotAssessed -NotAssessedReason 'sharingPolicies snapshot unavailable (requires the Exchange Online / IPPS connection).'))
    } else {
        $enabledPolicies = @($sharingPolicies | Where-Object { [bool]$_.Enabled })
        $riskyAnonymous = @($enabledPolicies | ForEach-Object { & $splitDomainEntries $_ } |
                Where-Object { $_.Domain -eq 'Anonymous' -and $_.Permission -in @('CalendarSharingFreeBusyDetail', 'CalendarSharingFullDetails') })

        if ($riskyAnonymous.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'CO-001' -Status Pass -Evidence 'No enabled sharing policy grants anonymous users calendar detail or full details.'))
        } else {
            $findings.Add((New-ZTAssessFinding -CheckId 'CO-001' -Status Fail -Evidence "$($riskyAnonymous.Count) enabled sharing policy domain entry(ies) grant anonymous users calendar detail or full details."))
        }
    }

    # --- CO-002: no silent redirect/blind-copy transport rule ------------------
    if ($null -eq $transportRules) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CO-002' -Status NotAssessed -NotAssessedReason 'transportRules snapshot unavailable (requires the Exchange Online / IPPS connection).'))
    } else {
        $riskyRules = @($transportRules | Where-Object { $_.State -eq 'Enabled' -and (@($_.RedirectMessageTo).Count -gt 0 -or @($_.BlindCopyTo).Count -gt 0) })

        if ($riskyRules.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'CO-002' -Status Pass -Evidence 'No enabled transport rule redirects or blind-copies messages.'))
        } else {
            $findings.Add((New-ZTAssessFinding -CheckId 'CO-002' -Status Fail -Evidence "$($riskyRules.Count) enabled transport rule(s) redirect or blind-copy messages: $(@($riskyRules | ForEach-Object { $_.Name }) -join ', ')."))
        }
    }

    # --- CO-003: no wildcard full-details external calendar sharing ------------
    if ($null -eq $sharingPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CO-003' -Status NotAssessed -NotAssessedReason 'sharingPolicies snapshot unavailable (requires the Exchange Online / IPPS connection).'))
    } else {
        $enabledPolicies = @($sharingPolicies | Where-Object { [bool]$_.Enabled })
        $riskyWildcard = @($enabledPolicies | ForEach-Object { & $splitDomainEntries $_ } |
                Where-Object { $_.Domain -eq '*' -and $_.Permission -eq 'CalendarSharingFullDetails' })

        if ($riskyWildcard.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'CO-003' -Status Pass -Evidence 'No enabled sharing policy grants full calendar details to all external domains.'))
        } else {
            $findings.Add((New-ZTAssessFinding -CheckId 'CO-003' -Status Fail -Evidence "$($riskyWildcard.Count) enabled sharing policy domain entry(ies) grant full calendar details to all external domains."))
        }
    }

    # --- CO-004: external collaboration inventory (informational) -------------
    $sharingPolicyCount = if ($sharingPolicies) { @($sharingPolicies).Count } else { 0 }
    $redirectRuleCount = if ($transportRules) { @($transportRules | Where-Object { @($_.RedirectMessageTo).Count -gt 0 -or @($_.BlindCopyTo).Count -gt 0 }).Count } else { 0 }
    $findings.Add((New-ZTAssessFinding -CheckId 'CO-004' -Status Informational -Evidence "Inventory: $sharingPolicyCount sharing policy(ies), $redirectRuleCount redirect/blind-copy transport rule(s)." -SeverityOverride None))

    return $findings.ToArray()
}
