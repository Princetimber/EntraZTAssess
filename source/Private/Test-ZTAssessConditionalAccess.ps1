#Requires -Version 7.0

# Conditional Access assessor. Implements checks CA-001 to CA-013 against
# persisted snapshots. Pure function over data on disk: no network calls.
function Test-ZTAssessConditionalAccess {
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
    $namedLocations = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'namedLocations'
    $skus = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'subscribedSkus'

    if ($null -eq $caPolicies) {
        foreach ($checkId in 1..13 | ForEach-Object { 'CA-{0:d3}' -f $_ }) {
            $findings.Add((New-ZTAssessFinding -CheckId $checkId -Status NotAssessed -NotAssessedReason 'conditionalAccessPolicies snapshot unavailable (requires Policy.Read.All and Entra ID P1).'))
        }
        return $findings.ToArray()
    }

    $enabled = @($caPolicies | Where-Object { $_.state -eq 'enabled' })
    $reportOnly = @($caPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })
    $disabled = @($caPolicies | Where-Object { $_.state -eq 'disabled' })

    # Helper predicates ------------------------------------------------------
    $hasMfaGrant = {
        param($policy)
        (@($policy.grantControls.builtInControls) -contains 'mfa') -or
        ($null -ne $policy.grantControls.authenticationStrength -and $policy.grantControls.authenticationStrength.id)
    }
    $hasPhishingResistantStrength = {
        param($policy)
        $strength = $policy.grantControls.authenticationStrength
        $null -ne $strength -and ($strength.displayName -match 'Phishing-resistant' -or $strength.id -eq '00000000-0000-0000-0000-000000000004')
    }
    $targetsAllUsers = { param($policy) @($policy.conditions.users.includeUsers) -contains 'All' }
    $targetsAllApps = { param($policy) @($policy.conditions.applications.includeApplications) -contains 'All' }
    $targetsAdminRoles = { param($policy) @($policy.conditions.users.includeRoles).Count -gt 0 }

    # --- CA-001: MFA for all users -----------------------------------------
    $allUserMfa = @($enabled | Where-Object { (& $targetsAllUsers $_) -and (& $targetsAllApps $_) -and (& $hasMfaGrant $_) })
    $allUserMfaReportOnly = @($reportOnly | Where-Object { (& $targetsAllUsers $_) -and (& $targetsAllApps $_) -and (& $hasMfaGrant $_) })

    if ($allUserMfa.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-001' -Status Pass -Evidence "Enforced all-users, all-apps MFA policy: '$($allUserMfa[0].displayName)'."))
    }
    elseif ($allUserMfaReportOnly.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-001' -Status Partial -Evidence "An all-users MFA policy exists but only in report-only mode: '$($allUserMfaReportOnly[0].displayName)'. Report-only enforces nothing." -SeverityOverride High))
    }
    else {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-001' -Status Fail -Evidence 'No enabled policy requires MFA for all users across all cloud apps.'))
    }

    # --- CA-002: phishing-resistant MFA for administrators ------------------
    $adminMfa = @($enabled | Where-Object { ((& $targetsAdminRoles $_) -or (& $targetsAllUsers $_)) -and (& $hasMfaGrant $_) })
    $adminPhishingResistant = @($adminMfa | Where-Object { (& $targetsAdminRoles $_) -and (& $hasPhishingResistantStrength $_) })

    if ($adminPhishingResistant.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-002' -Status Pass -Evidence "Phishing-resistant authentication strength enforced for directory roles: '$($adminPhishingResistant[0].displayName)'."))
    }
    elseif (@($adminMfa | Where-Object { & $targetsAdminRoles $_ }).Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-002' -Status Partial -Evidence 'Administrators are required to use MFA, but not a phishing-resistant authentication strength.' -SeverityOverride Medium))
    }
    elseif ($adminMfa.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-002' -Status Partial -Evidence 'Administrators are covered only by the general all-users MFA policy; no dedicated administrator policy with stronger requirements exists.'))
    }
    else {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-002' -Status Fail -Evidence 'No enabled policy enforces MFA for administrator roles.'))
    }

    # --- CA-003: legacy authentication block --------------------------------
    $legacyBlock = @($enabled | Where-Object {
            $clientApps = @($_.conditions.clientAppTypes)
            ($clientApps -contains 'exchangeActiveSync' -or $clientApps -contains 'other') -and
            (@($_.grantControls.builtInControls) -contains 'block')
        })
    $legacyBlockAllUsers = @($legacyBlock | Where-Object { & $targetsAllUsers $_ })

    if ($legacyBlockAllUsers.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-003' -Status Pass -Evidence "Legacy authentication blocked for all users by '$($legacyBlockAllUsers[0].displayName)'."))
    }
    elseif ($legacyBlock.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-003' -Status Partial -Evidence "A legacy authentication block exists ('$($legacyBlock[0].displayName)') but does not target all users."))
    }
    else {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-003' -Status Fail -Evidence 'No enabled policy blocks legacy authentication clients.'))
    }

    # --- CA-004: risk-based policies ----------------------------------------
    $hasP2 = $null
    if ($skus) {
        $planNames = @($skus | ForEach-Object { @($_.servicePlans) } | ForEach-Object { $_.servicePlanName })
        $hasP2 = @($planNames | Where-Object { $_ -in @($Settings.LicenceDetection.EntraP2ServicePlanNames) }).Count -gt 0
    }

    if ($hasP2 -eq $false) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-004' -Status NotAssessed -NotAssessedReason 'Entra ID P2 was not detected in the tenant licence inventory; risk-based Conditional Access is unavailable.'))
    }
    else {
        $signInRisk = @($enabled | Where-Object { @($_.conditions.signInRiskLevels).Count -gt 0 })
        $userRisk = @($enabled | Where-Object { @($_.conditions.userRiskLevels).Count -gt 0 })

        if ($signInRisk.Count -gt 0 -and $userRisk.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'CA-004' -Status Pass -Evidence "Sign-in risk policy ('$($signInRisk[0].displayName)') and user risk policy ('$($userRisk[0].displayName)') are enforced."))
        }
        elseif ($signInRisk.Count -gt 0 -or $userRisk.Count -gt 0) {
            $present = if ($signInRisk.Count -gt 0) { 'sign-in risk' } else { 'user risk' }
            $missing = if ($signInRisk.Count -gt 0) { 'user risk' } else { 'sign-in risk' }
            $findings.Add((New-ZTAssessFinding -CheckId 'CA-004' -Status Partial -Evidence "A $present policy is enforced but no $missing policy exists."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'CA-004' -Status Fail -Evidence 'No enabled risk-based Conditional Access policies were found despite Entra ID P2 licensing.'))
        }
    }

    # --- CA-005: device-based controls --------------------------------------
    $deviceGrant = @($enabled | Where-Object {
            $controls = @($_.grantControls.builtInControls)
            ($controls -contains 'compliantDevice' -or $controls -contains 'domainJoinedDevice')
        })
    $deviceGrantBroad = @($deviceGrant | Where-Object { (& $targetsAllUsers $_) })

    if ($deviceGrantBroad.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-005' -Status Pass -Evidence "Compliant or hybrid-joined device required for broad access by '$($deviceGrantBroad[0].displayName)'."))
    }
    elseif ($deviceGrant.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-005' -Status Partial -Evidence "Device-based controls exist ('$($deviceGrant[0].displayName)') but are not applied to the broad user population."))
    }
    else {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-005' -Status Fail -Evidence 'No enabled policy requires a compliant or hybrid-joined device; unmanaged endpoints access corporate resources unchecked.'))
    }

    # --- CA-006: session controls -------------------------------------------
    $signInFrequency = @($enabled | Where-Object { $_.sessionControls.signInFrequency.isEnabled })
    $persistentBrowser = @($enabled | Where-Object { $_.sessionControls.persistentBrowser.isEnabled })

    if ($signInFrequency.Count -gt 0 -and $persistentBrowser.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-006' -Status Pass -Evidence "Sign-in frequency ($($signInFrequency.Count) policy/policies) and persistent browser controls ($($persistentBrowser.Count)) are deployed."))
    }
    elseif ($signInFrequency.Count -gt 0 -or $persistentBrowser.Count -gt 0) {
        $present = if ($signInFrequency.Count -gt 0) { 'sign-in frequency' } else { 'persistent browser' }
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-006' -Status Partial -Evidence "Only $present session controls are deployed."))
    }
    else {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-006' -Status Fail -Evidence 'No session controls (sign-in frequency, persistent browser restrictions) are deployed.'))
    }

    # --- CA-007: trusted-location MFA bypass --------------------------------
    $locationBypass = @($enabled | Where-Object {
            $excludedLocations = @($_.conditions.locations.excludeLocations | Where-Object { $_ })
            (& $hasMfaGrant $_) -and $excludedLocations.Count -gt 0
        })
    $locationEvidence = "Named locations defined: $(@($namedLocations).Count)."

    if ($locationBypass.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-007' -Status Pass -Evidence "No MFA policy is bypassed by network location. $locationEvidence"))
    }
    else {
        $names = ($locationBypass | ForEach-Object { $_.displayName }) -join ', '
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-007' -Status Fail -Evidence "MFA policies excluding trusted locations (location-based bypass): $names. $locationEvidence"))
    }

    # --- CA-008: exclusion hygiene ------------------------------------------
    $excludedUsers = [System.Collections.Generic.HashSet[string]]::new()
    $excludedGroups = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($policy in $enabled) {
        foreach ($userId in @($policy.conditions.users.excludeUsers)) {
            if ($userId) { $null = $excludedUsers.Add($userId) }
        }
        foreach ($groupId in @($policy.conditions.users.excludeGroups)) {
            if ($groupId) { $null = $excludedGroups.Add($groupId) }
        }
    }

    if ($excludedGroups.Count -eq 0 -and $excludedUsers.Count -le 2) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-008' -Status Pass -Evidence "Exclusions are minimal: $($excludedUsers.Count) excluded user(s) (consistent with break-glass), no excluded groups."))
    }
    elseif ($excludedGroups.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-008' -Status Fail -Evidence "$($excludedGroups.Count) group(s) and $($excludedUsers.Count) user(s) are excluded from enabled policies. Group exclusions are silent bypass paths; review membership and governance of each." -SeverityOverride High))
    }
    else {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-008' -Status Partial -Evidence "$($excludedUsers.Count) user(s) are excluded from enabled policies - more than the expected break-glass pair. Review and document each exclusion."))
    }

    # --- CA-009: stalled report-only policies -------------------------------
    $staleCutoff = [datetime]::UtcNow.AddDays(-[int]$thresholds.ReportOnlyMaxAgeDays)
    $stalled = @($reportOnly | Where-Object {
            $reference = if ($_.modifiedDateTime) { [datetime]$_.modifiedDateTime } elseif ($_.createdDateTime) { [datetime]$_.createdDateTime } else { $null }
            $null -ne $reference -and $reference -lt $staleCutoff
        })

    if ($reportOnly.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-009' -Status Pass -Evidence 'No policies are in report-only mode.'))
    }
    elseif ($stalled.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-009' -Status Pass -Evidence "$($reportOnly.Count) report-only policy/policies exist, all within the $($thresholds.ReportOnlyMaxAgeDays)-day rollout window."))
    }
    else {
        $names = ($stalled | ForEach-Object { $_.displayName }) -join ', '
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-009' -Status Fail -Evidence "Report-only policies older than $($thresholds.ReportOnlyMaxAgeDays) days: $names."))
    }

    # --- CA-010: disabled policies that would close gaps --------------------
    $usefulDisabled = @($disabled | Where-Object {
            $controls = @($_.grantControls.builtInControls)
            ($controls -contains 'mfa' -or $controls -contains 'block' -or $controls -contains 'compliantDevice')
        })

    if ($usefulDisabled.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-010' -Status Pass -Evidence 'No disabled policies with meaningful controls were found.'))
    }
    else {
        $names = ($usefulDisabled | ForEach-Object { $_.displayName }) -join ', '
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-010' -Status Informational -Evidence "Disabled policies containing meaningful controls (candidates for re-enablement): $names." -SeverityOverride None))
    }

    # --- CA-011: critical applications protected ----------------------------
    $azureManagementId = $Settings.WellKnownApplications.AzureManagement
    $azureMgmtProtected = @($enabled | Where-Object {
            (& $hasMfaGrant $_) -and (
                (& $targetsAllApps $_) -or
                @($_.conditions.applications.includeApplications) -contains $azureManagementId
            ) -and ((& $targetsAllUsers $_) -or (& $targetsAdminRoles $_))
        })

    if ($azureMgmtProtected.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-011' -Status Pass -Evidence "Azure management access requires MFA via '$($azureMgmtProtected[0].displayName)'."))
    }
    else {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-011' -Status Fail -Evidence 'No enabled policy explicitly requires MFA for Microsoft Azure Management.'))
    }

    # --- CA-012: high-risk authentication flows -----------------------------
    $deviceCodeBlock = @($enabled | Where-Object {
            @($_.conditions.authenticationFlows.transferMethods) -match 'deviceCodeFlow' -and
            @($_.grantControls.builtInControls) -contains 'block'
        })

    if ($deviceCodeBlock.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-012' -Status Pass -Evidence "Device code flow is blocked by '$($deviceCodeBlock[0].displayName)'."))
    }
    else {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-012' -Status Fail -Evidence 'Device code flow is not restricted; it remains available for token phishing.'))
    }

    # --- CA-013: guest MFA ---------------------------------------------------
    $guestMfa = @($enabled | Where-Object {
            $users = $_.conditions.users
            ((& $hasMfaGrant $_)) -and (
                (& $targetsAllUsers $_) -or
                ($null -ne $users.includeGuestsOrExternalUsers -and $users.includeGuestsOrExternalUsers.guestOrExternalUserTypes) -or
                (@($users.includeUsers) -contains 'GuestsOrExternalUsers')
            )
        })
    $guestSpecific = @($guestMfa | Where-Object {
            ($null -ne $_.conditions.users.includeGuestsOrExternalUsers -and $_.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes) -or
            (@($_.conditions.users.includeUsers) -contains 'GuestsOrExternalUsers')
        })

    if ($guestSpecific.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-013' -Status Pass -Evidence "Guest access requires MFA via '$($guestSpecific[0].displayName)'."))
    }
    elseif ($guestMfa.Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-013' -Status Pass -Evidence 'Guests are covered by the all-users MFA policy.'))
    }
    else {
        $findings.Add((New-ZTAssessFinding -CheckId 'CA-013' -Status Fail -Evidence 'No enabled policy requires MFA for guest or external users.'))
    }

    return $findings.ToArray()
}
