#Requires -Version 7.0

# Monitoring and detection assessor. Implements checks MD-001 to MD-006
# against persisted snapshots. Pure function over data on disk: no network
# calls.
function Test-ZTAssessMonitoring {
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

    $caPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'conditionalAccessPolicies'
    $skus = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'subscribedSkus'
    $riskyUsers = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'riskyUsers'
    $riskSummary = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'riskDetectionsSummary'
    $auditProbe = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'directoryAuditProbe'
    $mdiSensors = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'mdiSensors'
    $sentinelConnectors = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'sentinelConnectors'
    $organization = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'organization'
    $legacyAuth = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'legacyAuthSignIns'

    $hasP2 = $null
    if ($skus) {
        $planNames = @($skus | ForEach-Object { @($_.servicePlans) } | ForEach-Object { $_.servicePlanName })
        $hasP2 = @($planNames | Where-Object { $_ -in @($Settings.LicenceDetection.EntraP2ServicePlanNames) }).Count -gt 0
    }

    # --- MD-001: risk-based policies enforced ---------------------------------
    if ($hasP2 -eq $false) {
        $findings.Add((New-ZTAssessFinding -CheckId 'MD-001' -Status NotAssessed -NotAssessedReason 'Entra ID P2 was not detected; Identity Protection risk policies are unavailable.'))
    }
    elseif ($null -eq $caPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'MD-001' -Status NotAssessed -NotAssessedReason 'conditionalAccessPolicies snapshot unavailable.'))
    }
    else {
        $enabled = @($caPolicies | Where-Object { $_.state -eq 'enabled' })
        $signInRisk = @($enabled | Where-Object { @($_.conditions.signInRiskLevels).Count -gt 0 })
        $userRisk = @($enabled | Where-Object { @($_.conditions.userRiskLevels).Count -gt 0 })

        if ($signInRisk.Count -gt 0 -and $userRisk.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'MD-001' -Status Pass -Evidence 'Sign-in risk and user risk are both enforced through Conditional Access.'))
        }
        elseif ($signInRisk.Count -gt 0 -or $userRisk.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'MD-001' -Status Partial -Evidence "Only one risk signal is enforced (sign-in risk policies: $($signInRisk.Count), user risk policies: $($userRisk.Count))."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'MD-001' -Status Fail -Evidence 'No enabled Conditional Access policy enforces Identity Protection risk signals.'))
        }
    }

    # --- MD-002: risky users remediated promptly --------------------------------
    if ($null -eq $riskyUsers) {
        $findings.Add((New-ZTAssessFinding -CheckId 'MD-002' -Status NotAssessed -NotAssessedReason 'riskyUsers snapshot unavailable (requires IdentityRiskyUser.Read.All and Entra ID P2).'))
    }
    else {
        $cutoff = [datetime]::UtcNow.AddDays(-[int]$thresholds.RiskyUserUnremediatedMaxDays)
        $open = @($riskyUsers | Where-Object { $_.riskState -eq 'atRisk' })
        $overdue = @($open | Where-Object { $_.riskLastUpdatedDateTime -and [datetime]$_.riskLastUpdatedDateTime -lt $cutoff })
        $highOverdue = @($overdue | Where-Object { $_.riskLevel -eq 'high' })

        if ($open.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'MD-002' -Status Pass -Evidence 'No users are currently in the at-risk state.'))
        }
        elseif ($overdue.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'MD-002' -Status Pass -Evidence "$($open.Count) at-risk user(s), all within the $($thresholds.RiskyUserUnremediatedMaxDays)-day remediation window."))
        }
        else {
            $severity = if ($highOverdue.Count -gt 0) { 'High' } else { 'Medium' }
            $findings.Add((New-ZTAssessFinding -CheckId 'MD-002' -Status Fail -Evidence "$($overdue.Count) at-risk user(s) unremediated beyond $($thresholds.RiskyUserUnremediatedMaxDays) days ($($highOverdue.Count) high risk)." -SeverityOverride $severity))
        }
    }

    # --- MD-003: audit availability and retention --------------------------------
    if ($null -eq $auditProbe) {
        $findings.Add((New-ZTAssessFinding -CheckId 'MD-003' -Status NotAssessed -NotAssessedReason 'directoryAuditProbe snapshot unavailable (requires AuditLog.Read.All).'))
    }
    elseif ([bool]$auditProbe.available) {
        $findings.Add((New-ZTAssessFinding -CheckId 'MD-003' -Status Partial -Evidence 'Directory audit logs are available, but retention beyond the licence default (30 days) is not verifiable via Graph. Confirm diagnostic settings export audit and sign-in logs to long-term storage or a SIEM.'))
    }
    else {
        $findings.Add((New-ZTAssessFinding -CheckId 'MD-003' -Status Fail -Evidence 'No directory audit records were returned; audit logging availability could not be demonstrated.'))
    }

    # --- MD-004: Defender for Identity sensor health -------------------------------
    $org = @($organization) | Select-Object -First 1
    $isHybrid = [bool]$org.onPremisesSyncEnabled
    if (-not $isHybrid) {
        $findings.Add((New-ZTAssessFinding -CheckId 'MD-004' -Status NotAssessed -NotAssessedReason 'Cloud-only tenant: there are no domain controllers to monitor.'))
    }
    elseif ($null -eq $mdiSensors) {
        $findings.Add((New-ZTAssessFinding -CheckId 'MD-004' -Status NotAssessed -NotAssessedReason 'mdiSensors snapshot unavailable (beta endpoint; requires a Defender for Identity licence and SecurityIdentitiesSensors.Read.All).'))
    }
    else {
        $sensors = @($mdiSensors)
        $unhealthy = @($sensors | Where-Object { $_.healthStatus -ne 'healthy' })
        if ($sensors.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'MD-004' -Status Fail -Evidence 'Hybrid tenant with no Defender for Identity sensors deployed; on-premises AD attacks are undetected.'))
        }
        elseif ($unhealthy.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'MD-004' -Status Pass -Evidence "$($sensors.Count) Defender for Identity sensor(s), all healthy."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'MD-004' -Status Partial -Evidence "$($unhealthy.Count) of $($sensors.Count) Defender for Identity sensor(s) are unhealthy: $(@($unhealthy | ForEach-Object { $_.displayName }) -join ', ')."))
        }
    }

    # --- MD-005: SIEM integration ----------------------------------------------------
    if ($null -eq $sentinelConnectors) {
        $findings.Add((New-ZTAssessFinding -CheckId 'MD-005' -Status NotAssessed -NotAssessedReason 'Sentinel connector data was not collected (optional module requiring Azure Reader via Az modules); verify identity log connectors in the SIEM manually.'))
    }
    else {
        $identityConnectors = @($sentinelConnectors | Where-Object { $_.kind -match 'AzureActiveDirectory|MicrosoftDefender' })
        if ($identityConnectors.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'MD-005' -Status Pass -Evidence "Identity-relevant Sentinel connector(s) enabled: $($identityConnectors.Count)."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'MD-005' -Status Fail -Evidence 'No identity-relevant Sentinel data connectors were found.'))
        }
    }

    # --- MD-006: telemetry summary (informational) -------------------------------------
    $legacyText = if ($legacyAuth) { "$([int]$legacyAuth.totalLegacyCount) legacy sign-in(s) in $([int]$legacyAuth.lookbackDays) day(s)" } else { 'legacy sign-in data unavailable' }
    $riskText = if ($riskSummary) { "$([int]$riskSummary.totalDetections) risk detection(s) on record" } else { 'risk detection data unavailable' }
    $findings.Add((New-ZTAssessFinding -CheckId 'MD-006' -Status Informational -Evidence "Telemetry summary: $legacyText; $riskText." -SeverityOverride None))

    return $findings.ToArray()
}
