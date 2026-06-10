#Requires -Version 7.0

# Identity security assessor. Implements checks ID-001 to ID-012 against
# persisted snapshots. Pure function over data on disk: no network calls.
# Missing snapshots produce NotAssessed findings, never errors.
function Test-ZTAssessIdentitySecurity {
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

    $users = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'users'
    $regDetails = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'userRegistrationDetails'
    $authPolicy = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'authenticationMethodsPolicy'
    $secDefaults = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'securityDefaultsPolicy'
    $legacyAuth = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'legacyAuthSignIns'
    $caPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'conditionalAccessPolicies'
    $roleAssignments = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'roleAssignments'
    $roleDefinitions = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'roleDefinitions'
    $domains = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'domains'
    $enrollmentConfigs = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'enrollmentConfigurations'

    $enabledCaPolicies = @($caPolicies | Where-Object { $_.state -eq 'enabled' })

    $enabledMembers = @($users | Where-Object { $_.accountEnabled -and $_.userType -ne 'Guest' })

    # Resolve privileged user IDs where role data is available (cross-module).
    $privilegedUserIds = $null
    if ($roleAssignments -and $roleDefinitions) {
        $templateByDefinition = @{}
        foreach ($definition in $roleDefinitions) {
            $templateByDefinition[$definition.id] = $definition.templateId
        }
        $privilegedTemplates = @($Settings.PrivilegedRoles.PrivilegedTemplateIds)
        $privilegedUserIds = @(
            $roleAssignments |
                Where-Object { $templateByDefinition[$_.roleDefinitionId] -in $privilegedTemplates } |
                Select-Object -ExpandProperty principalId -Unique
        )
    }

    # --- ID-001: MFA registration coverage --------------------------------
    if ($null -eq $regDetails) {
        $findings.Add((New-ZTAssessFinding -CheckId 'ID-001' -Status NotAssessed -NotAssessedReason 'userRegistrationDetails snapshot unavailable (requires Reports.Read.All and Entra ID P1).'))
    }
    else {
        $memberRegistrations = @($regDetails | Where-Object { $_.userType -ne 'guest' })
        $total = $memberRegistrations.Count
        if ($total -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-001' -Status NotAssessed -NotAssessedReason 'No member registration records returned.'))
        }
        else {
            $registered = @($memberRegistrations | Where-Object { $_.isMfaRegistered }).Count
            $coverage = [math]::Round(100 * $registered / $total, 1)
            $evidence = "$registered of $total member users registered for MFA ($coverage%). Threshold: $($thresholds.MfaRegistrationCoveragePercent)%."

            if ($coverage -ge $thresholds.MfaRegistrationCoveragePercent) {
                $findings.Add((New-ZTAssessFinding -CheckId 'ID-001' -Status Pass -Evidence $evidence))
            }
            elseif ($coverage -ge $thresholds.MfaRegistrationCoverageFailPercent) {
                $findings.Add((New-ZTAssessFinding -CheckId 'ID-001' -Status Partial -Evidence $evidence))
            }
            else {
                $findings.Add((New-ZTAssessFinding -CheckId 'ID-001' -Status Fail -Evidence $evidence -SeverityOverride High))
            }
        }
    }

    # --- ID-002: privileged accounts MFA capable --------------------------
    if ($null -eq $regDetails -or $null -eq $privilegedUserIds) {
        $findings.Add((New-ZTAssessFinding -CheckId 'ID-002' -Status NotAssessed -NotAssessedReason 'Requires both userRegistrationDetails and role assignment snapshots (run the PrivilegedAccess module alongside Identity).'))
    }
    else {
        $registrationById = @{}
        foreach ($record in $regDetails) {
            $registrationById[$record.id] = $record
        }

        $privilegedUsersInScope = @($privilegedUserIds | Where-Object { $registrationById.ContainsKey($_) })
        $notCapable = @($privilegedUsersInScope | Where-Object { -not $registrationById[$_].isMfaCapable })

        if ($privilegedUsersInScope.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-002' -Status NotAssessed -NotAssessedReason 'No privileged principals matched user registration records (roles may be held by groups or service principals only).'))
        }
        elseif ($notCapable.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-002' -Status Pass -Evidence "All $($privilegedUsersInScope.Count) privileged user(s) are MFA capable."))
        }
        else {
            $sample = ($notCapable | Select-Object -First 5 | ForEach-Object { $registrationById[$_].userPrincipalName }) -join ', '
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-002' -Status Fail -Evidence "$($notCapable.Count) of $($privilegedUsersInScope.Count) privileged user(s) are not MFA capable. Sample: $sample"))
        }
    }

    # --- ID-003: legacy authentication blocked ----------------------------
    $legacyBlockPolicies = @($enabledCaPolicies | Where-Object {
            $clientApps = @($_.conditions.clientAppTypes)
            $controls = @($_.grantControls.builtInControls)
            ($clientApps -contains 'exchangeActiveSync' -or $clientApps -contains 'other') -and ($controls -contains 'block')
        })

    if ($null -eq $caPolicies -and $null -eq $legacyAuth) {
        $findings.Add((New-ZTAssessFinding -CheckId 'ID-003' -Status NotAssessed -NotAssessedReason 'Neither Conditional Access policies nor sign-in data are available.'))
    }
    else {
        $observedCount = if ($legacyAuth) { [int]$legacyAuth.totalLegacyCount } else { -1 }
        $observedText = if ($observedCount -ge 0) { "$observedCount legacy sign-in(s) observed in the last $($legacyAuth.lookbackDays) day(s)." } else { 'Sign-in data unavailable; observation not assessed.' }

        if ($legacyBlockPolicies.Count -eq 0) {
            $severity = if ($observedCount -gt 0) { 'Critical' } else { 'High' }
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-003' -Status Fail -Evidence "No enabled Conditional Access policy blocks legacy authentication. $observedText" -SeverityOverride $severity))
        }
        elseif ($observedCount -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-003' -Status Partial -Evidence "Legacy authentication block policy exists ('$($legacyBlockPolicies[0].displayName)') but legacy sign-ins are still occurring. $observedText Review policy scope and exclusions."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-003' -Status Pass -Evidence "Legacy authentication blocked by '$($legacyBlockPolicies[0].displayName)'. $observedText"))
        }
    }

    # --- ID-004: baseline protection in force -----------------------------
    if ($null -eq $secDefaults -and $null -eq $caPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'ID-004' -Status NotAssessed -NotAssessedReason 'Security defaults and Conditional Access snapshots unavailable.'))
    }
    else {
        $defaultsOn = [bool]$secDefaults.isEnabled
        $caInForce = $enabledCaPolicies.Count -gt 0

        if ($defaultsOn -and $caInForce) {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-004' -Status Partial -Evidence 'Both security defaults and Conditional Access policies are enabled; this combination is unsupported and produces unpredictable enforcement. Disable security defaults in favour of the Conditional Access baseline.' -SeverityOverride Low))
        }
        elseif ($defaultsOn -or $caInForce) {
            $mode = if ($caInForce) { "Conditional Access ($($enabledCaPolicies.Count) enabled policies)" } else { 'security defaults' }
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-004' -Status Pass -Evidence "Baseline identity protection in force via $mode."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-004' -Status Fail -Evidence 'Neither security defaults nor any enabled Conditional Access policy protects this tenant.'))
        }
    }

    # --- ID-005 / ID-006 / ID-008: authentication methods policy ----------
    if ($null -eq $authPolicy) {
        foreach ($checkId in @('ID-005', 'ID-006', 'ID-008')) {
            $findings.Add((New-ZTAssessFinding -CheckId $checkId -Status NotAssessed -NotAssessedReason 'authenticationMethodsPolicy snapshot unavailable.'))
        }
    }
    else {
        $methodConfigs = @($authPolicy.authenticationMethodConfigurations)
        $getMethod = { param($id) $methodConfigs | Where-Object { $_.id -eq $id } | Select-Object -First 1 }

        # ID-005: SMS / voice restricted
        $weakMethods = @('Sms', 'Voice') | ForEach-Object { & $getMethod $_ } | Where-Object { $_ -and $_.state -eq 'enabled' }
        if ($weakMethods.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-005' -Status Pass -Evidence 'SMS and voice call authentication methods are disabled.'))
        }
        else {
            $allUsersTargeted = @($weakMethods | Where-Object { @($_.includeTargets) | Where-Object { $_.id -eq 'all_users' } })
            if ($allUsersTargeted.Count -gt 0) {
                $findings.Add((New-ZTAssessFinding -CheckId 'ID-005' -Status Fail -Evidence ("Telephony methods enabled for all users: " + (($allUsersTargeted | ForEach-Object { $_.id }) -join ', ') + '.')))
            }
            else {
                $findings.Add((New-ZTAssessFinding -CheckId 'ID-005' -Status Partial -Evidence 'Telephony methods are enabled but scoped to targeted groups. Confirm privileged users are not in scope.'))
            }
        }

        # ID-006: FIDO2 / passkeys enabled
        $fido2 = & $getMethod 'Fido2'
        if ($fido2 -and $fido2.state -eq 'enabled') {
            $adoptionEvidence = ''
            if ($regDetails) {
                $passkeyUsers = @($regDetails | Where-Object { @($_.methodsRegistered) -match 'passKey|fido2' }).Count
                $adoptionEvidence = " $passkeyUsers user(s) have registered a passkey or FIDO2 credential."
            }
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-006' -Status Pass -Evidence ('FIDO2/passkey method is enabled.' + $adoptionEvidence)))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-006' -Status Fail -Evidence 'FIDO2/passkey authentication method is not enabled; phishing-resistant credentials are unavailable to users.'))
        }

        # ID-008: Temporary Access Pass enabled
        $tap = & $getMethod 'TemporaryAccessPass'
        if ($tap -and $tap.state -eq 'enabled') {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-008' -Status Pass -Evidence 'Temporary Access Pass is enabled, supporting passwordless onboarding.'))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-008' -Status Fail -Evidence 'Temporary Access Pass is not enabled; passwordless onboarding requires a password-based first factor.'))
        }
    }

    # --- ID-007: Windows Hello for Business -------------------------------
    if ($null -eq $enrollmentConfigs) {
        $findings.Add((New-ZTAssessFinding -CheckId 'ID-007' -Status NotAssessed -NotAssessedReason 'Enrolment configuration snapshot unavailable; run the Devices module to assess Windows Hello for Business.'))
    }
    else {
        $whfbConfigs = @($enrollmentConfigs | Where-Object {
                $_.'@odata.type' -match 'windowsHelloForBusiness' -and $_.state -eq 'enabled'
            })
        if ($whfbConfigs.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-007' -Status Pass -Evidence "Windows Hello for Business enrolment configuration is enabled ($($whfbConfigs.Count) configuration(s))."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-007' -Status Fail -Evidence 'No enabled Windows Hello for Business enrolment configuration was found.'))
        }
    }

    # --- ID-009: break-glass accounts -------------------------------------
    if ($null -eq $users -or $null -eq $privilegedUserIds -or $null -eq $caPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'ID-009' -Status NotAssessed -NotAssessedReason 'Requires users, role assignment, and Conditional Access snapshots (run Identity, ConditionalAccess, and PrivilegedAccess together).'))
    }
    else {
        $usersById = @{}
        foreach ($user in $users) {
            $usersById[$user.id] = $user
        }

        $gaTemplate = $Settings.PrivilegedRoles.GlobalAdministratorTemplateId
        $templateByDefinition = @{}
        foreach ($definition in $roleDefinitions) {
            $templateByDefinition[$definition.id] = $definition.templateId
        }
        $gaUserIds = @($roleAssignments |
                Where-Object { $templateByDefinition[$_.roleDefinitionId] -eq $gaTemplate } |
                Select-Object -ExpandProperty principalId -Unique)

        $excludedEverywhere = @()
        $excludedSyncedAccounts = @()
        foreach ($gaId in $gaUserIds) {
            $user = $usersById[$gaId]
            if (-not $user -or -not $user.accountEnabled) { continue }

            $excludedFromAll = $true
            foreach ($policy in $enabledCaPolicies) {
                if (@($policy.conditions.users.excludeUsers) -notcontains $gaId) {
                    $excludedFromAll = $false
                    break
                }
            }

            if ($excludedFromAll -and $enabledCaPolicies.Count -gt 0) {
                if ($user.onPremisesSyncEnabled) {
                    $excludedSyncedAccounts += $user.userPrincipalName
                }
                else {
                    $excludedEverywhere += $user.userPrincipalName
                }
            }
        }

        if ($excludedEverywhere.Count -ge 2) {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-009' -Status Pass -Evidence "Identified $($excludedEverywhere.Count) cloud-only break-glass candidate(s) excluded from all enabled Conditional Access policies: $($excludedEverywhere -join ', '). Confirm phishing-resistant credentials and sign-in alerting."))
        }
        elseif ($excludedEverywhere.Count -eq 1) {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-009' -Status Partial -Evidence "Only one break-glass candidate identified ($($excludedEverywhere[0])); a minimum of two is recommended for availability."))
        }
        else {
            $syncedNote = if ($excludedSyncedAccounts.Count -gt 0) { " Synchronised accounts excluded from CA were found ($($excludedSyncedAccounts -join ', ')); synchronised break-glass accounts are unsafe." } else { '' }
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-009' -Status Fail -Evidence ('No cloud-only break-glass account excluded from all enabled Conditional Access policies was identified.' + $syncedNote)))
        }
    }

    # --- ID-010: per-user MFA not in use -----------------------------------
    $findings.Add((New-ZTAssessFinding -CheckId 'ID-010' -Status NotAssessed -NotAssessedReason 'Per-user MFA state is only exposed via the beta users endpoint; verify manually in the Entra admin centre (Users > Per-user MFA) or enable beta collection in a later toolkit version.'))

    # --- ID-011: password expiry policy ------------------------------------
    if ($null -eq $domains) {
        $findings.Add((New-ZTAssessFinding -CheckId 'ID-011' -Status NotAssessed -NotAssessedReason 'domains snapshot unavailable.'))
    }
    else {
        $verifiedDomains = @($domains | Where-Object { $_.isVerified })
        $expiringDomains = @($verifiedDomains | Where-Object {
                $_.passwordValidityPeriodInDays -and $_.passwordValidityPeriodInDays -lt 2147483647
            })
        if ($expiringDomains.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-011' -Status Pass -Evidence 'No verified domain enforces periodic password expiry, in line with current guidance.'))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-011' -Status Fail -Evidence ("Periodic password expiry is enforced on: " + (($expiringDomains | ForEach-Object { "$($_.id) ($($_.passwordValidityPeriodInDays) days)" }) -join ', ') + '.')))
        }
    }

    # --- ID-012: SSPR enabled ----------------------------------------------
    if ($null -eq $regDetails) {
        $findings.Add((New-ZTAssessFinding -CheckId 'ID-012' -Status NotAssessed -NotAssessedReason 'userRegistrationDetails snapshot unavailable.'))
    }
    else {
        $memberRegistrations = @($regDetails | Where-Object { $_.userType -ne 'guest' })
        $ssprEnabled = @($memberRegistrations | Where-Object { $_.isSsprEnabled })
        if ($ssprEnabled.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'ID-012' -Status Fail -Evidence 'No users are enabled for self-service password reset.'))
        }
        else {
            $ssprRegistered = @($ssprEnabled | Where-Object { $_.isSsprRegistered }).Count
            $registrationRate = [math]::Round(100 * $ssprRegistered / $ssprEnabled.Count, 1)
            if ($registrationRate -ge 50) {
                $findings.Add((New-ZTAssessFinding -CheckId 'ID-012' -Status Pass -Evidence "SSPR enabled for $($ssprEnabled.Count) user(s); $registrationRate% have registered."))
            }
            else {
                $findings.Add((New-ZTAssessFinding -CheckId 'ID-012' -Status Partial -Evidence "SSPR enabled for $($ssprEnabled.Count) user(s) but only $registrationRate% have registered; drive registration to make the capability effective."))
            }
        }
    }

    # Suppress unused-variable analyser note for $enabledMembers (reserved
    # for coverage normalisation in later checks).
    $null = $enabledMembers

    return $findings.ToArray()
}
