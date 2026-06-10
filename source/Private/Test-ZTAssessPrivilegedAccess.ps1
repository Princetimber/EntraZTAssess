#Requires -Version 7.0

# Privileged access assessor. Implements checks PA-001 to PA-010 against
# persisted snapshots. Pure function over data on disk: no network calls.
function Test-ZTAssessPrivilegedAccess {
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
    $roleConfig = $Settings.PrivilegedRoles

    $findings = [System.Collections.Generic.List[object]]::new()

    $roleDefinitions = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'roleDefinitions'
    $roleAssignments = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'roleAssignments'
    $eligibilitySchedules = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'roleEligibilitySchedules'
    $assignmentSchedules = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'roleAssignmentSchedules'
    $rolePolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'roleManagementPolicies'
    $rolePolicyAssignments = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'roleManagementPolicyAssignments'
    $users = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'users'
    $groups = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'groups'
    $servicePrincipals = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'servicePrincipals'
    $caPolicies = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'conditionalAccessPolicies'

    if ($null -eq $roleDefinitions -or $null -eq $roleAssignments) {
        foreach ($checkId in 1..10 | ForEach-Object { 'PA-{0:d3}' -f $_ }) {
            $findings.Add((New-ZTAssessFinding -CheckId $checkId -Status NotAssessed -NotAssessedReason 'Role definition or role assignment snapshots unavailable (requires RoleManagement.Read.Directory).'))
        }
        return $findings.ToArray()
    }

    # Lookup tables ----------------------------------------------------------
    $templateByDefinition = @{}
    $roleNameByDefinition = @{}
    foreach ($definition in $roleDefinitions) {
        $templateByDefinition[$definition.id] = $definition.templateId
        $roleNameByDefinition[$definition.id] = $definition.displayName
    }

    $usersById = @{}
    foreach ($user in @($users)) {
        if ($null -eq $user -or [string]::IsNullOrWhiteSpace([string]$user.id)) {
            continue
        }
        $usersById[$user.id] = $user
    }
    $groupsById = @{}
    foreach ($group in @($groups)) {
        if ($null -eq $group -or [string]::IsNullOrWhiteSpace([string]$group.id)) {
            continue
        }
        $groupsById[$group.id] = $group
    }
    $spById = @{}
    foreach ($sp in @($servicePrincipals)) {
        if ($null -eq $sp -or [string]::IsNullOrWhiteSpace([string]$sp.id)) {
            continue
        }
        $spById[$sp.id] = $sp
    }

    $gaTemplate = $roleConfig.GlobalAdministratorTemplateId
    $privilegedTemplates = @($roleConfig.PrivilegedTemplateIds)
    $tier0Templates = @($roleConfig.Tier0TemplateIds)

    $privilegedAssignments = @($roleAssignments | Where-Object { $templateByDefinition[$_.roleDefinitionId] -in $privilegedTemplates })
    $gaAssignments = @($roleAssignments | Where-Object { $templateByDefinition[$_.roleDefinitionId] -eq $gaTemplate })

    $describePrincipal = {
        param($principalId)
        if ($usersById.ContainsKey($principalId)) { return $usersById[$principalId].userPrincipalName }
        if ($groupsById.ContainsKey($principalId)) { return "group:$($groupsById[$principalId].displayName)" }
        if ($spById.ContainsKey($principalId)) { return "sp:$($spById[$principalId].displayName)" }
        return $principalId
    }

    # --- PA-001: Global Administrator count ---------------------------------
    $gaEligibleIds = @()
    if ($eligibilitySchedules) {
        $gaEligibleIds = @($eligibilitySchedules |
                Where-Object { $templateByDefinition[$_.roleDefinitionId] -eq $gaTemplate } |
                Select-Object -ExpandProperty principalId -Unique)
    }
    $gaPrincipalIds = @(@($gaAssignments | Select-Object -ExpandProperty principalId) + $gaEligibleIds | Select-Object -Unique)
    $gaCount = $gaPrincipalIds.Count
    $gaNames = ($gaPrincipalIds | ForEach-Object { & $describePrincipal $_ }) -join ', '

    if ($gaCount -ge $thresholds.GlobalAdminMinimum -and $gaCount -le $thresholds.GlobalAdminMaximum) {
        $findings.Add((New-ZTAssessFinding -CheckId 'PA-001' -Status Pass -Evidence "$gaCount Global Administrator principal(s) (active or eligible): $gaNames."))
    }
    elseif ($gaCount -lt $thresholds.GlobalAdminMinimum) {
        $findings.Add((New-ZTAssessFinding -CheckId 'PA-001' -Status Fail -Evidence "Only $gaCount Global Administrator principal(s) exist; fewer than $($thresholds.GlobalAdminMinimum) risks tenant lockout. $gaNames"))
    }
    else {
        $findings.Add((New-ZTAssessFinding -CheckId 'PA-001' -Status Fail -Evidence "$gaCount Global Administrator principals exceed the recommended maximum of $($thresholds.GlobalAdminMaximum): $gaNames."))
    }

    # --- PA-002: PIM eligibility versus permanent assignment ----------------
    if ($null -eq $assignmentSchedules -and $null -eq $eligibilitySchedules) {
        $findings.Add((New-ZTAssessFinding -CheckId 'PA-002' -Status NotAssessed -NotAssessedReason 'PIM schedule snapshots unavailable (requires Entra ID P2).'))
    }
    else {
        $permanentPrivileged = @(@($assignmentSchedules) | Where-Object {
                $templateByDefinition[$_.roleDefinitionId] -in $privilegedTemplates -and
                $_.scheduleInfo.expiration.type -eq 'noExpiration' -and
                $_.assignmentType -ne 'Activated'
            })
        $eligiblePrivileged = @(@($eligibilitySchedules) | Where-Object { $templateByDefinition[$_.roleDefinitionId] -in $privilegedTemplates })
        $permanentGa = @($permanentPrivileged | Where-Object { $templateByDefinition[$_.roleDefinitionId] -eq $gaTemplate })

        $evidence = "Permanent privileged assignments: $($permanentPrivileged.Count); PIM-eligible: $($eligiblePrivileged.Count); permanent Global Administrators: $($permanentGa.Count)."

        if ($permanentGa.Count -gt 2) {
            $names = ($permanentGa | ForEach-Object { & $describePrincipal $_.principalId }) -join ', '
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-002' -Status Fail -Evidence "$evidence Permanent GAs beyond the break-glass pair: $names."))
        }
        elseif ($eligiblePrivileged.Count -eq 0 -and $permanentPrivileged.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-002' -Status Fail -Evidence "$evidence PIM is licensed but not in use; all privileged access is standing."))
        }
        elseif ($permanentPrivileged.Count -gt $eligiblePrivileged.Count) {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-002' -Status Partial -Evidence "$evidence The majority of privileged access remains permanent; continue converting to eligibility."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-002' -Status Pass -Evidence $evidence))
        }
    }

    # --- PA-003: PIM activation requirements for Tier-0 ---------------------
    if ($null -eq $rolePolicies -or $null -eq $rolePolicyAssignments) {
        $findings.Add((New-ZTAssessFinding -CheckId 'PA-003' -Status NotAssessed -NotAssessedReason 'Role management policy snapshots unavailable (requires Entra ID P2).'))
    }
    else {
        $policyById = @{}
        foreach ($policy in $rolePolicies) { $policyById[$policy.id] = $policy }

        # roleDefinitionId on directory-scope policy assignments is the role template ID.
        $tier0PolicyAssignments = @($rolePolicyAssignments | Where-Object { $_.roleDefinitionId -in $tier0Templates })

        $weakRoles = [System.Collections.Generic.List[string]]::new()
        $assessedRoles = 0
        foreach ($policyAssignment in $tier0PolicyAssignments) {
            $policy = $policyById[$policyAssignment.policyId]
            if (-not $policy) { continue }
            $assessedRoles++

            $enablementRule = @($policy.rules) | Where-Object {
                $_.id -eq 'Enablement_EndUser_Assignment'
            } | Select-Object -First 1

            $enabledRules = @($enablementRule.enabledRules)
            if ($enabledRules -notcontains 'MultiFactorAuthentication' -or $enabledRules -notcontains 'Justification') {
                $weakRoles.Add([string]$policyAssignment.roleDefinitionId)
            }
        }

        if ($assessedRoles -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-003' -Status NotAssessed -NotAssessedReason 'No role management policy assignments matched Tier-0 role templates.'))
        }
        elseif ($weakRoles.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-003' -Status Pass -Evidence "All $assessedRoles assessed Tier-0 role(s) require MFA and justification on PIM activation."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-003' -Status Fail -Evidence "$($weakRoles.Count) of $assessedRoles Tier-0 role(s) lack MFA and/or justification on activation (template IDs: $($weakRoles -join ', '))."))
        }
    }

    # --- PA-004: privileged accounts cloud-only -----------------------------
    if ($null -eq $users) {
        $findings.Add((New-ZTAssessFinding -CheckId 'PA-004' -Status NotAssessed -NotAssessedReason 'users snapshot unavailable.'))
    }
    else {
        $syncedPrivileged = @($privilegedAssignments | Where-Object {
                $usersById.ContainsKey($_.principalId) -and $usersById[$_.principalId].onPremisesSyncEnabled
            })
        if ($syncedPrivileged.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-004' -Status Pass -Evidence 'All privileged user accounts are cloud-only.'))
        }
        else {
            $syncedGa = @($syncedPrivileged | Where-Object { $templateByDefinition[$_.roleDefinitionId] -eq $gaTemplate })
            $severity = if ($syncedGa.Count -gt 0) { 'Critical' } else { 'High' }
            $detail = ($syncedPrivileged | ForEach-Object { "$(& $describePrincipal $_.principalId) ($($roleNameByDefinition[$_.roleDefinitionId]))" } | Select-Object -Unique) -join ', '
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-004' -Status Fail -Evidence "Synchronised accounts hold privileged roles: $detail. On-premises compromise escalates directly to the cloud." -SeverityOverride $severity))
        }
    }

    # --- PA-005: daily-driver privileged accounts (heuristic) ---------------
    if ($null -eq $users) {
        $findings.Add((New-ZTAssessFinding -CheckId 'PA-005' -Status NotAssessed -NotAssessedReason 'users snapshot unavailable.'))
    }
    else {
        $licensedPrivileged = @($privilegedAssignments | ForEach-Object { $_.principalId } | Select-Object -Unique | Where-Object {
                $usersById.ContainsKey($_) -and @($usersById[$_].assignedLicenses).Count -gt 0
            })
        if ($licensedPrivileged.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-005' -Status Pass -Evidence 'No privileged account carries productivity licences; admin/daily-driver separation appears in place.'))
        }
        else {
            $names = ($licensedPrivileged | ForEach-Object { & $describePrincipal $_ }) -join ', '
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-005' -Status Partial -Evidence "Privileged accounts carrying licences (possible daily-driver use - consultant to confirm): $names."))
        }
    }

    # --- PA-006: stale privileged assignments -------------------------------
    $privilegedUserRecords = @($privilegedAssignments | ForEach-Object { $_.principalId } | Select-Object -Unique |
            Where-Object { $usersById.ContainsKey($_) } | ForEach-Object { $usersById[$_] })
    $haveSignInActivity = @($privilegedUserRecords | Where-Object { $_.PSObject.Properties['signInActivity'] -and $_.signInActivity })

    if ($privilegedUserRecords.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'PA-006' -Status NotAssessed -NotAssessedReason 'No privileged user records available for staleness analysis.'))
    }
    elseif ($haveSignInActivity.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'PA-006' -Status NotAssessed -NotAssessedReason 'signInActivity unavailable on the user snapshot (requires Entra ID P1 and AuditLog.Read.All).'))
    }
    else {
        $staleCutoff = [datetime]::UtcNow.AddDays(-[int]$thresholds.StaleSignInDays)
        $stale = @($haveSignInActivity | Where-Object {
                $lastSignIn = $_.signInActivity.lastSignInDateTime
                -not $lastSignIn -or [datetime]$lastSignIn -lt $staleCutoff
            })
        if ($stale.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-006' -Status Pass -Evidence "All $($haveSignInActivity.Count) privileged user(s) have signed in within $($thresholds.StaleSignInDays) days."))
        }
        else {
            $names = ($stale | ForEach-Object { $_.userPrincipalName }) -join ', '
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-006' -Status Fail -Evidence "Privileged accounts with no sign-in for over $($thresholds.StaleSignInDays) days: $names."))
        }
    }

    # --- PA-007: role-assignable group hygiene ------------------------------
    $groupAssignments = @($privilegedAssignments | Where-Object { $groupsById.ContainsKey($_.principalId) })
    if ($groupAssignments.Count -eq 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'PA-007' -Status Pass -Evidence 'No privileged roles are granted to groups.'))
    }
    else {
        $nonRoleAssignable = @($groupAssignments | Where-Object { -not $groupsById[$_.principalId].isAssignableToRole })
        if ($nonRoleAssignable.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-007' -Status Pass -Evidence "$($groupAssignments.Count) privileged group grant(s), all to role-assignable groups."))
        }
        else {
            $names = ($nonRoleAssignable | ForEach-Object { "$($groupsById[$_.principalId].displayName) ($($roleNameByDefinition[$_.roleDefinitionId]))" } | Select-Object -Unique) -join ', '
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-007' -Status Fail -Evidence "Privileged roles granted to standard (non-role-assignable) groups: $names. Group owners can mint administrators."))
        }
    }

    # --- PA-008: no guests in privileged roles ------------------------------
    if ($null -eq $users) {
        $findings.Add((New-ZTAssessFinding -CheckId 'PA-008' -Status NotAssessed -NotAssessedReason 'users snapshot unavailable.'))
    }
    else {
        $guestPrivileged = @($privilegedAssignments | Where-Object {
                $usersById.ContainsKey($_.principalId) -and $usersById[$_.principalId].userType -eq 'Guest'
            })
        if ($guestPrivileged.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-008' -Status Pass -Evidence 'No guest accounts hold privileged roles.'))
        }
        else {
            $names = ($guestPrivileged | ForEach-Object { "$(& $describePrincipal $_.principalId) ($($roleNameByDefinition[$_.roleDefinitionId]))" } | Select-Object -Unique) -join ', '
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-008' -Status Fail -Evidence "Guest accounts holding privileged roles: $names."))
        }
    }

    # --- PA-009: service principals with privileged roles -------------------
    if ($null -eq $servicePrincipals) {
        $findings.Add((New-ZTAssessFinding -CheckId 'PA-009' -Status NotAssessed -NotAssessedReason 'servicePrincipals snapshot unavailable.'))
    }
    else {
        $spPrivileged = @($privilegedAssignments | Where-Object { $spById.ContainsKey($_.principalId) })
        if ($spPrivileged.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-009' -Status Pass -Evidence 'No service principals hold privileged directory roles. GA-equivalent application permissions are assessed by the Applications module.'))
        }
        else {
            $names = ($spPrivileged | ForEach-Object { "$($spById[$_.principalId].displayName) ($($roleNameByDefinition[$_.roleDefinitionId]))" } | Select-Object -Unique) -join ', '
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-009' -Status Fail -Evidence "Service principals holding privileged directory roles: $names. Workload identities have no MFA and require strict credential governance."))
        }
    }

    # --- PA-010: privileged access bound to secured workstations ------------
    if ($null -eq $caPolicies) {
        $findings.Add((New-ZTAssessFinding -CheckId 'PA-010' -Status NotAssessed -NotAssessedReason 'conditionalAccessPolicies snapshot unavailable (run the ConditionalAccess module alongside PrivilegedAccess).'))
    }
    else {
        $pawPolicies = @($caPolicies | Where-Object {
                $_.state -eq 'enabled' -and
                @($_.conditions.users.includeRoles).Count -gt 0 -and
                (@($_.grantControls.builtInControls) -contains 'compliantDevice' -or @($_.grantControls.builtInControls) -contains 'domainJoinedDevice')
            })
        if ($pawPolicies.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-010' -Status Pass -Evidence "Privileged role usage requires a managed device via '$($pawPolicies[0].displayName)'. Confirm device filters narrow this to PAWs where required."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'PA-010' -Status Fail -Evidence 'No enabled policy binds privileged role usage to compliant or designated admin workstations.'))
        }
    }

    return $findings.ToArray()
}
