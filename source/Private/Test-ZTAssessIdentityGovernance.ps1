#Requires -Version 7.0

# Identity governance assessor. Implements checks IG-001 to IG-006 against
# persisted snapshots. Pure function over data on disk: no network calls.
function Test-ZTAssessIdentityGovernance {
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

    $reviewDefinitions = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'accessReviewDefinitions'
    $accessPackages = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'accessPackages'
    $lifecycleWorkflows = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'lifecycleWorkflows'
    $authorizationPolicy = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'authorizationPolicy'
    $crossTenantDefault = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'crossTenantAccessPolicyDefault'
    $users = Get-ZTAssessSnapshot -RunPath $RunPath -Name 'users'

    $guests = @($users | Where-Object { $_.userType -eq 'Guest' -and $_.accountEnabled })

    # --- IG-001: access reviews for privileged roles -------------------------
    if ($null -eq $reviewDefinitions) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IG-001' -Status NotAssessed -NotAssessedReason 'accessReviewDefinitions snapshot unavailable (requires AccessReview.Read.All and Entra ID P2/Governance).'))
    }
    else {
        $roleReviews = @($reviewDefinitions | Where-Object {
                $_.scope.query -match 'roleAssignment|roleManagement' -or
                $_.displayName -match 'role|admin|privileg'
            })
        if ($roleReviews.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'IG-001' -Status Pass -Evidence "Privileged role access review(s) defined: $(@($roleReviews | ForEach-Object { $_.displayName }) -join ', ')."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'IG-001' -Status Fail -Evidence "No access review covers privileged role assignments ($(@($reviewDefinitions).Count) review definition(s) exist)."))
        }
    }

    # --- IG-002: access reviews for guests ------------------------------------
    if ($null -eq $reviewDefinitions -or $null -eq $users) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IG-002' -Status NotAssessed -NotAssessedReason 'Access review or user snapshots unavailable.'))
    }
    elseif ($guests.Count -lt [int]$thresholds.GuestCountReviewThreshold) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IG-002' -Status Pass -Evidence "Guest population ($($guests.Count)) is below the review threshold ($($thresholds.GuestCountReviewThreshold))."))
    }
    else {
        $guestReviews = @($reviewDefinitions | Where-Object {
                $_.scope.query -match "userType eq 'Guest'|guest" -or $_.displayName -match 'guest'
            })
        if ($guestReviews.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'IG-002' -Status Pass -Evidence "$($guests.Count) guest(s); guest access review(s) defined: $(@($guestReviews | ForEach-Object { $_.displayName }) -join ', ')."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'IG-002' -Status Fail -Evidence "$($guests.Count) enabled guest account(s) with no guest access review defined."))
        }
    }

    # --- IG-003: entitlement management adoption -------------------------------
    if ($null -eq $accessPackages) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IG-003' -Status NotAssessed -NotAssessedReason 'accessPackages snapshot unavailable (requires EntitlementManagement.Read.All and Entra ID P2/Governance).'))
    }
    elseif (@($accessPackages).Count -gt 0) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IG-003' -Status Pass -Evidence "$(@($accessPackages).Count) entitlement management access package(s) in use."))
    }
    else {
        $findings.Add((New-ZTAssessFinding -CheckId 'IG-003' -Status Fail -Evidence 'No entitlement management access packages exist; access provisioning is ungoverned by packages.'))
    }

    # --- IG-004: lifecycle workflows and guest hygiene -------------------------
    if ($null -eq $lifecycleWorkflows -and $null -eq $users) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IG-004' -Status NotAssessed -NotAssessedReason 'Lifecycle workflow and user snapshots unavailable.'))
    }
    else {
        $enabledWorkflows = @($lifecycleWorkflows | Where-Object { $_.isEnabled })

        $staleGuestText = 'Guest staleness not assessed (signInActivity unavailable).'
        $staleGuestPct = $null
        $guestsWithActivity = @($guests | Where-Object { $_.PSObject.Properties['signInActivity'] -and $_.signInActivity })
        if ($guestsWithActivity.Count -gt 0) {
            $staleCutoff = [datetime]::UtcNow.AddDays(-[int]$thresholds.StaleGuestDays)
            $staleGuests = @($guestsWithActivity | Where-Object {
                    -not $_.signInActivity.lastSignInDateTime -or [datetime]$_.signInActivity.lastSignInDateTime -lt $staleCutoff
                })
            $staleGuestPct = [math]::Round(100 * $staleGuests.Count / $guestsWithActivity.Count, 1)
            $staleGuestText = "$($staleGuests.Count) of $($guestsWithActivity.Count) guest(s) ($staleGuestPct%) inactive beyond $($thresholds.StaleGuestDays) days."
        }
        elseif ($guests.Count -eq 0) {
            $staleGuestPct = 0
            $staleGuestText = 'No enabled guests.'
        }

        if ($enabledWorkflows.Count -gt 0 -and ($null -ne $staleGuestPct -and $staleGuestPct -le 10)) {
            $findings.Add((New-ZTAssessFinding -CheckId 'IG-004' -Status Pass -Evidence "$($enabledWorkflows.Count) enabled lifecycle workflow(s). $staleGuestText"))
        }
        elseif ($enabledWorkflows.Count -gt 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'IG-004' -Status Partial -Evidence "$($enabledWorkflows.Count) enabled lifecycle workflow(s), but guest hygiene needs attention. $staleGuestText"))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'IG-004' -Status Fail -Evidence "No enabled lifecycle workflows; joiner/leaver processing is manual. $staleGuestText"))
        }
    }

    # --- IG-005: guest invitation and permission settings ----------------------
    if ($null -eq $authorizationPolicy) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IG-005' -Status NotAssessed -NotAssessedReason 'authorizationPolicy snapshot unavailable.'))
    }
    else {
        $restrictedGuestRole = '2af84b1e-32c8-42b7-82bc-daa82404023b'
        $memberEquivalentRole = 'a0b1b346-4d3e-4e8b-98f8-753987be4970'

        $inviteSetting = [string]$authorizationPolicy.allowInvitesFrom
        $guestRole = [string]$authorizationPolicy.guestUserRoleId

        $problems = @()
        if ($inviteSetting -in @('everyone')) {
            $problems += "guest invitations are open to everyone (allowInvitesFrom=$inviteSetting)"
        }
        if ($guestRole -eq $memberEquivalentRole) {
            $problems += 'guests receive member-equivalent directory permissions'
        }

        if ($problems.Count -eq 0 -and $guestRole -eq $restrictedGuestRole) {
            $findings.Add((New-ZTAssessFinding -CheckId 'IG-005' -Status Pass -Evidence "Guest invitations restricted (allowInvitesFrom=$inviteSetting) and guests hold the restricted permission level."))
        }
        elseif ($problems.Count -eq 0) {
            $findings.Add((New-ZTAssessFinding -CheckId 'IG-005' -Status Partial -Evidence "Guest invitations restricted (allowInvitesFrom=$inviteSetting), but guests hold the default rather than restricted permission level."))
        }
        else {
            $findings.Add((New-ZTAssessFinding -CheckId 'IG-005' -Status Fail -Evidence ("Guest governance gaps: " + ($problems -join '; ') + '.')))
        }
    }

    # --- IG-006: cross-tenant access posture -----------------------------------
    if ($null -eq $crossTenantDefault) {
        $findings.Add((New-ZTAssessFinding -CheckId 'IG-006' -Status NotAssessed -NotAssessedReason 'crossTenantAccessPolicyDefault snapshot unavailable.'))
    }
    else {
        $trust = $crossTenantDefault.inboundTrust
        $trustText = "Inbound trust: MFA=$([bool]$trust.isMfaAccepted), compliant device=$([bool]$trust.isCompliantDeviceAccepted), hybrid joined=$([bool]$trust.isHybridAzureADJoinedDeviceAccepted)."
        $findings.Add((New-ZTAssessFinding -CheckId 'IG-006' -Status Informational -Evidence "Default cross-tenant access settings reviewed. $trustText Confirm this trust posture is deliberate for every partner relationship." -SeverityOverride None))
    }

    return $findings.ToArray()
}
