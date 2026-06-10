#Requires -Version 7.0

# Application security assessor. Implements checks AS-001 to AS-007 against
# persisted snapshots. Pure function over data on disk: no network calls.
function Test-ZTAssessApplicationSecurity {
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
    $appConfig = $Settings.ApplicationSecurity

    $findings = [System.Collections.Generic.List[object]]::new()

    $applications = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'applications'
    $oauthGrants = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'oauth2PermissionGrants'
    $graphSp = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'graphServicePrincipal'
    $graphAssignments = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'graphAppRoleAssignments'
    $spSignIns = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'spSignInActivities'
    $servicePrincipals = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'servicePrincipals'
    $authorizationPolicy = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'authorizationPolicy'
    $adminConsentPolicy = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'adminConsentRequestPolicy'

    # By-id lookups skip malformed records with null or blank IDs.
    $spById = @{}
    foreach ($sp in @($servicePrincipals)) {
        if ($null -eq $sp -or [string]::IsNullOrWhiteSpace([string]$sp.id)) { continue }
        $spById[$sp.id] = $sp
    }

    # Resolve Graph app role IDs to permission names.
    $roleNameById = @{}
    foreach ($role in @($graphSp.appRoles)) {
        if ($null -eq $role -or [string]::IsNullOrWhiteSpace([string]$role.id)) { continue }
        $roleNameById[[string]$role.id] = $role.value
    }

    # Dangerous application permission assignments (excluding Microsoft first-party).
    $dangerousAssignments = @()
    if ($graphAssignments -and $roleNameById.Count -gt 0) {
        foreach ($assignment in @($graphAssignments)) {
            $roleName = $roleNameById[[string]$assignment.appRoleId]
            if (-not $roleName) { continue }
            $tier = if ($roleName -in @($appConfig.Tier0AppRoleValues)) { 'Tier0' }
            elseif ($roleName -in @($appConfig.HighRiskAppRoleValues)) { 'High' }
            else { $null }
            if (-not $tier) { continue }

            $principal = $spById[[string]$assignment.principalId]
            $ownerTenant = [string]$principal.appOwnerOrganizationId
            if ($ownerTenant -and $ownerTenant -in @($appConfig.MicrosoftAppOwnerTenantIds)) { continue }

            $dangerousAssignments += [pscustomobject]@{
                PrincipalId   = $assignment.principalId
                PrincipalName = $assignment.principalDisplayName ?? $principal.displayName ?? $assignment.principalId
                Permission    = $roleName
                Tier          = $tier
            }
        }
    }

    # --- AS-001: user consent restricted -------------------------------------
    if ($null -eq $authorizationPolicy) {
        $findings.Add((New-ZTAssessFinding -CheckId 'AS-001' -Status NotAssessed -NotAssessedReason 'authorizationPolicy snapshot unavailable.'))
    }
    else {
        $consentPolicies = @($authorizationPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
        $workflowEnabled = [bool]$adminConsentPolicy.isEnabled
        $workflowText = "Admin consent workflow enabled: $workflowEnabled."

        if (@($consentPolicies | Where-Object { $_ -match 'user-default-legacy' }).Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-001' -Status Fail -Evidence "Users may consent to any application requesting any permission (legacy default). $workflowText"))
        }
        elseif ($consentPolicies.Count -eq 0) {
            $status = if ($workflowEnabled) { 'Pass' } else { 'Partial' }
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-001' -Status $status -Evidence "User consent is disabled; admin consent is required for all applications. $workflowText$(if (-not $workflowEnabled) { ' Enable the workflow so users have a governed request path.' })"))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-001' -Status Pass -Evidence "User consent restricted to policy: $($consentPolicies -join ', '). $workflowText"))
        }
    }

    # --- AS-002: high-privilege application permissions -----------------------
    if ($null -eq $graphAssignments -or $roleNameById.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'AS-002' -Status NotAssessed -NotAssessedReason 'Graph application role assignment snapshots unavailable.'))
    }
    else {
        $tier0 = @($dangerousAssignments | Where-Object Tier -eq 'Tier0')
        $high = @($dangerousAssignments | Where-Object Tier -eq 'High')

        if ($dangerousAssignments.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-002' -Status Pass -Evidence 'No non-Microsoft workload identity holds Tier-0 or high-risk Microsoft Graph application permissions.'))
        }
        elseif ($tier0.Count -gt 0) {
            $detail = ($tier0 | ForEach-Object { "$($_.PrincipalName): $($_.Permission)" } | Select-Object -Unique) -join '; '
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-002' -Status Fail -Evidence "Tier-0 application permissions held by workload identities: $detail. High-risk grants: $($high.Count)."))
        }
        else {
            $detail = ($high | ForEach-Object { "$($_.PrincipalName): $($_.Permission)" } | Select-Object -Unique) -join '; '
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-002' -Status Partial -Evidence "High-risk (broad data) application permissions held: $detail." -SeverityOverride High))
        }
    }

    # --- AS-003: application credential hygiene --------------------------------
    if ($null -eq $applications) {
        $findings.Add((New-ZTAssessFinding -CheckId 'AS-003' -Status NotAssessed -NotAssessedReason 'applications snapshot unavailable.'))
    }
    else {
        $now = [datetime]::UtcNow
        $maxValidityYears = [double]$thresholds.AppCredentialMaxValidityYears
        $privilegedAppIds = @($dangerousAssignments | ForEach-Object {
                $spById[[string]$_.PrincipalId].appId
            } | Where-Object { $_ })

        $longLived = [System.Collections.Generic.List[string]]::new()
        $expiredLeftovers = 0
        $secretsOnPrivileged = [System.Collections.Generic.List[string]]::new()

        foreach ($app in @($applications)) {
            $allCredentials = @($app.passwordCredentials) + @($app.keyCredentials)
            foreach ($credential in $allCredentials) {
                if ($null -eq $credential) { continue }
                if ($credential.endDateTime -and [datetime]$credential.endDateTime -lt $now) {
                    $expiredLeftovers++
                    continue
                }
                if ($credential.startDateTime -and $credential.endDateTime) {
                    $validityYears = ([datetime]$credential.endDateTime - [datetime]$credential.startDateTime).TotalDays / 365.25
                    if ($validityYears -gt $maxValidityYears) {
                        $longLived.Add("$($app.displayName) ($([math]::Round($validityYears,1))y)")
                    }
                }
            }

            if (@($app.passwordCredentials | Where-Object { $_ -and (-not $_.endDateTime -or [datetime]$_.endDateTime -ge $now) }).Count -gt 0 -and $app.appId -in $privilegedAppIds) {
                $secretsOnPrivileged.Add($app.displayName)
            }
        }

        $evidence = "Long-validity credentials (> $maxValidityYears y): $($longLived.Count)$(if ($longLived.Count -gt 0) { " ($(@($longLived | Select-Object -First 5) -join ', '))" }). Client secrets on privileged apps: $($secretsOnPrivileged.Count)$(if ($secretsOnPrivileged.Count -gt 0) { " ($($secretsOnPrivileged -join ', '))" }). Expired leftover credentials: $expiredLeftovers."

        if ($secretsOnPrivileged.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-003' -Status Fail -Evidence $evidence))
        }
        elseif ($longLived.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-003' -Status Partial -Evidence $evidence))
        }
        elseif ($expiredLeftovers -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-003' -Status Partial -Evidence $evidence -SeverityOverride Low))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-003' -Status Pass -Evidence $evidence))
        }
    }

    # --- AS-004: unused service principals with access -------------------------
    if ($null -eq $spSignIns) {
        $findings.Add((New-ZTAssessFinding -CheckId 'AS-004' -Status NotAssessed -NotAssessedReason 'servicePrincipalSignInActivities unavailable (beta endpoint; requires workload identity reporting).'))
    }
    else {
        $staleCutoff = [datetime]::UtcNow.AddDays(-[int]$thresholds.StaleSignInDays)
        $signInByAppId = @{}
        foreach ($activity in @($spSignIns)) {
            if ($null -eq $activity -or [string]::IsNullOrWhiteSpace([string]$activity.appId)) { continue }
            $signInByAppId[[string]$activity.appId] = $activity
        }

        $permissionedSpAppIds = @($dangerousAssignments | ForEach-Object { $spById[[string]$_.PrincipalId].appId }) +
            @($oauthGrants | ForEach-Object { $spById[[string]$_.clientId].appId }) | Where-Object { $_ } | Select-Object -Unique

        $dormant = [System.Collections.Generic.List[string]]::new()
        foreach ($appId in $permissionedSpAppIds) {
            $activity = $signInByAppId[[string]$appId]
            $lastSignIn = $activity.lastSignInActivity.lastSignInDateTime ?? $activity.lastSignInDateTime
            if (-not $lastSignIn -or [datetime]$lastSignIn -lt $staleCutoff) {
                $name = @($servicePrincipals | Where-Object appId -eq $appId | Select-Object -First 1).displayName ?? $appId
                $dormant.Add($name)
            }
        }

        if ($permissionedSpAppIds.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-004' -Status Pass -Evidence 'No service principals hold permission grants to evaluate for dormancy.'))
        }
        elseif ($dormant.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-004' -Status Pass -Evidence "All $($permissionedSpAppIds.Count) permissioned service principal(s) show sign-in activity within $($thresholds.StaleSignInDays) days."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-004' -Status Fail -Evidence "Dormant permissioned service principal(s) (no sign-in within $($thresholds.StaleSignInDays) days): $($dormant -join ', ')."))
        }
    }

    # --- AS-005: redirect URI hygiene -------------------------------------------
    if ($null -eq $applications) {
        $findings.Add((New-ZTAssessFinding -CheckId 'AS-005' -Status NotAssessed -NotAssessedReason 'applications snapshot unavailable.'))
    }
    else {
        $offenders = [System.Collections.Generic.List[string]]::new()
        foreach ($app in @($applications)) {
            $uris = @($app.web.redirectUris) + @($app.spa.redirectUris) + @($app.publicClient.redirectUris) | Where-Object { $_ }
            foreach ($uri in $uris) {
                $isHttpNonLocal = $uri -match '^http://' -and $uri -notmatch '^http://(localhost|127\.0\.0\.1)'
                $hasWildcard = $uri -match '\*'
                if ($isHttpNonLocal -or $hasWildcard) {
                    $offenders.Add("$($app.displayName): $uri")
                }
            }
        }

        if ($offenders.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-005' -Status Pass -Evidence 'No wildcard or non-localhost HTTP redirect URIs found.'))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-005' -Status Fail -Evidence "Risky redirect URIs: $(@($offenders | Select-Object -First 10) -join '; ')."))
        }
    }

    # --- AS-006: unverified publisher applications -------------------------------
    if ($null -eq $servicePrincipals -or $null -eq $oauthGrants) {
        $findings.Add((New-ZTAssessFinding -CheckId 'AS-006' -Status NotAssessed -NotAssessedReason 'Service principal or OAuth grant snapshots unavailable.'))
    }
    else {
        $consentedClientIds = @($oauthGrants | ForEach-Object { [string]$_.clientId } | Select-Object -Unique)
        $unverified = [System.Collections.Generic.List[string]]::new()
        foreach ($clientId in $consentedClientIds) {
            $sp = $spById[$clientId]
            if ($null -eq $sp) { continue }
            $ownerTenant = [string]$sp.appOwnerOrganizationId
            if ($ownerTenant -and $ownerTenant -in @($appConfig.MicrosoftAppOwnerTenantIds)) { continue }
            $publisher = $sp.verifiedPublisher.displayName
            if ([string]::IsNullOrWhiteSpace([string]$publisher)) {
                $unverified.Add([string]$sp.displayName)
            }
        }

        if ($unverified.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-006' -Status Pass -Evidence 'No consented third-party application has an unverified publisher.'))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-006' -Status Fail -Evidence "Consented applications with unverified publishers: $(@($unverified | Select-Object -First 10) -join ', ')."))
        }
    }

    # --- AS-007: ownerless app registrations --------------------------------------
    if ($null -eq $applications) {
        $findings.Add((New-ZTAssessFinding -CheckId 'AS-007' -Status NotAssessed -NotAssessedReason 'applications snapshot unavailable.'))
    }
    else {
        $now = [datetime]::UtcNow
        $ownerless = @($applications | Where-Object {
                @($_.owners).Count -eq 0 -and (
                    @($_.passwordCredentials | Where-Object { $_ -and (-not $_.endDateTime -or [datetime]$_.endDateTime -ge $now) }).Count -gt 0 -or
                    @($_.keyCredentials).Count -gt 0
                )
            })

        if ($ownerless.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-007' -Status Pass -Evidence 'Every app registration holding credentials has at least one owner.'))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'AS-007' -Status Fail -Evidence "Ownerless app registrations holding credentials: $(@($ownerless | ForEach-Object { $_.displayName } | Select-Object -First 10) -join ', ')."))
        }
    }

    return $findings.ToArray()
}
