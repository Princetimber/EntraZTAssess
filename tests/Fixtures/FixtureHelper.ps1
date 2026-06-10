#Requires -Version 7.0

<#
    Test fixture helper. Builds a "well-configured tenant" snapshot set in a
    run folder so assessor tests can start from an all-Pass baseline and
    selectively degrade it. Dot-source this file in test BeforeAll blocks.
#>

function New-ZTAssessTestRun {
    [CmdletBinding()]
    [OutputType([string])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Test fixture helper writing to Pester TestDrive only.')]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [string[]]$ExcludeSnapshots = @(),

        [Parameter()]
        [hashtable]$Overrides = @{}
    )

    $gaTemplate = '62e90394-69f5-4237-9190-012177145e10'
    $breakGlassIds = @('bg-1', 'bg-2')
    $excludeBg = $breakGlassIds

    $recentSignIn = [datetime]::UtcNow.AddDays(-5).ToString('yyyy-MM-ddTHH:mm:ssZ')

    $snapshots = @{
        organization = @(
            @{ id = 'tenant-1'; displayName = 'Contoso Ltd' }
        )

        subscribedSkus = @(
            @{ skuPartNumber = 'EMSPREMIUM'; servicePlans = @(
                    @{ servicePlanName = 'AAD_PREMIUM' }
                    @{ servicePlanName = 'AAD_PREMIUM_P2' }
                )
            }
        )

        domains = @(
            @{ id = 'contoso.com'; isVerified = $true; passwordValidityPeriodInDays = 2147483647 }
        )

        users = @(
            @{ id = 'bg-1'; userPrincipalName = 'breakglass1@contoso.com'; accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $false; assignedLicenses = @(); signInActivity = @{ lastSignInDateTime = $recentSignIn } }
            @{ id = 'bg-2'; userPrincipalName = 'breakglass2@contoso.com'; accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $false; assignedLicenses = @(); signInActivity = @{ lastSignInDateTime = $recentSignIn } }
            @{ id = 'u-1'; userPrincipalName = 'alice@contoso.com'; accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $false; assignedLicenses = @(@{ skuId = 'sku-1' }); signInActivity = @{ lastSignInDateTime = $recentSignIn } }
            @{ id = 'u-2'; userPrincipalName = 'bob@contoso.com'; accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $true; assignedLicenses = @(@{ skuId = 'sku-1' }); signInActivity = @{ lastSignInDateTime = $recentSignIn } }
        )

        groups = @(
            @{ id = 'g-1'; displayName = 'Role Group'; isAssignableToRole = $true; securityEnabled = $true }
        )

        servicePrincipals = @(
            @{ id = 'sp-1'; appId = 'app-1'; displayName = 'Workload App'; servicePrincipalType = 'Application'; accountEnabled = $true }
        )

        userRegistrationDetails = @(
            @{ id = 'bg-1'; userPrincipalName = 'breakglass1@contoso.com'; userType = 'member'; isMfaRegistered = $true; isMfaCapable = $true; isSsprEnabled = $true; isSsprRegistered = $true; methodsRegistered = @('passKeyDeviceBound') }
            @{ id = 'bg-2'; userPrincipalName = 'breakglass2@contoso.com'; userType = 'member'; isMfaRegistered = $true; isMfaCapable = $true; isSsprEnabled = $true; isSsprRegistered = $true; methodsRegistered = @('passKeyDeviceBound') }
            @{ id = 'u-1'; userPrincipalName = 'alice@contoso.com'; userType = 'member'; isMfaRegistered = $true; isMfaCapable = $true; isSsprEnabled = $true; isSsprRegistered = $true; methodsRegistered = @('microsoftAuthenticatorPush') }
            @{ id = 'u-2'; userPrincipalName = 'bob@contoso.com'; userType = 'member'; isMfaRegistered = $true; isMfaCapable = $true; isSsprEnabled = $true; isSsprRegistered = $true; methodsRegistered = @('microsoftAuthenticatorPush') }
        )

        authenticationMethodsPolicy = @{
            authenticationMethodConfigurations = @(
                @{ id = 'Fido2'; state = 'enabled' }
                @{ id = 'TemporaryAccessPass'; state = 'enabled' }
                @{ id = 'MicrosoftAuthenticator'; state = 'enabled' }
                @{ id = 'Sms'; state = 'disabled' }
                @{ id = 'Voice'; state = 'disabled' }
            )
        }

        securityDefaultsPolicy = @{ isEnabled = $false }

        legacyAuthSignIns = @{
            lookbackDays      = 30
            totalLegacyCount  = 0
            countsByClientApp = @()
        }

        enrollmentConfigurations = @(
            @{ '@odata.type' = '#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration'; state = 'enabled' }
        )

        namedLocations = @(
            @{ displayName = 'Head Office'; '@odata.type' = '#microsoft.graph.ipNamedLocation' }
        )

        authenticationStrengthPolicies = @(
            @{ id = '00000000-0000-0000-0000-000000000004'; displayName = 'Phishing-resistant MFA' }
        )

        conditionalAccessPolicies = @(
            @{ id = 'ca-1'; displayName = 'All users MFA'; state = 'enabled'
                conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = $excludeBg; excludeGroups = @() }
                    applications = @{ includeApplications = @('All') }; clientAppTypes = @('all') }
                grantControls = @{ builtInControls = @('mfa') } }
            @{ id = 'ca-2'; displayName = 'Admins phishing-resistant MFA'; state = 'enabled'
                conditions = @{ users = @{ includeUsers = @(); includeRoles = @($gaTemplate); excludeUsers = $excludeBg; excludeGroups = @() }
                    applications = @{ includeApplications = @('All') }; clientAppTypes = @('all') }
                grantControls = @{ builtInControls = @(); authenticationStrength = @{ id = '00000000-0000-0000-0000-000000000004'; displayName = 'Phishing-resistant MFA' } }
                sessionControls = @{ signInFrequency = @{ isEnabled = $true; value = 4; type = 'hours' } } }
            @{ id = 'ca-3'; displayName = 'Block legacy authentication'; state = 'enabled'
                conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = $excludeBg; excludeGroups = @() }
                    applications = @{ includeApplications = @('All') }; clientAppTypes = @('exchangeActiveSync', 'other') }
                grantControls = @{ builtInControls = @('block') } }
            @{ id = 'ca-4'; displayName = 'Require compliant device'; state = 'enabled'
                conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = $excludeBg; excludeGroups = @() }
                    applications = @{ includeApplications = @('All') }; clientAppTypes = @('all') }
                grantControls = @{ builtInControls = @('compliantDevice') }
                sessionControls = @{ persistentBrowser = @{ isEnabled = $true; mode = 'never' } } }
            @{ id = 'ca-5'; displayName = 'Sign-in risk MFA'; state = 'enabled'
                conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = $excludeBg; excludeGroups = @() }
                    applications = @{ includeApplications = @('All') }; signInRiskLevels = @('medium', 'high'); clientAppTypes = @('all') }
                grantControls = @{ builtInControls = @('mfa') } }
            @{ id = 'ca-6'; displayName = 'User risk password change'; state = 'enabled'
                conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = $excludeBg; excludeGroups = @() }
                    applications = @{ includeApplications = @('All') }; userRiskLevels = @('high'); clientAppTypes = @('all') }
                grantControls = @{ builtInControls = @('passwordChange', 'mfa') } }
            @{ id = 'ca-7'; displayName = 'Block device code flow'; state = 'enabled'
                conditions = @{ users = @{ includeUsers = @('All'); excludeUsers = $excludeBg; excludeGroups = @() }
                    applications = @{ includeApplications = @('All') }
                    authenticationFlows = @{ transferMethods = 'deviceCodeFlow' }; clientAppTypes = @('all') }
                grantControls = @{ builtInControls = @('block') } }
            @{ id = 'ca-8'; displayName = 'Guest MFA'; state = 'enabled'
                conditions = @{ users = @{ includeUsers = @(); excludeUsers = $excludeBg; excludeGroups = @()
                        includeGuestsOrExternalUsers = @{ guestOrExternalUserTypes = 'b2bCollaborationGuest,b2bCollaborationMember' } }
                    applications = @{ includeApplications = @('All') }; clientAppTypes = @('all') }
                grantControls = @{ builtInControls = @('mfa') } }
            @{ id = 'ca-9'; displayName = 'Admins require managed device'; state = 'enabled'
                conditions = @{ users = @{ includeUsers = @(); includeRoles = @($gaTemplate); excludeUsers = $excludeBg; excludeGroups = @() }
                    applications = @{ includeApplications = @('All') }; clientAppTypes = @('all') }
                grantControls = @{ builtInControls = @('compliantDevice') } }
        )

        roleDefinitions = @(
            @{ id = 'rd-ga'; templateId = $gaTemplate; displayName = 'Global Administrator'; isBuiltIn = $true }
            @{ id = 'rd-user'; templateId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; displayName = 'User Administrator'; isBuiltIn = $true }
        )

        roleAssignments = @(
            @{ id = 'ra-1'; principalId = 'bg-1'; roleDefinitionId = 'rd-ga'; directoryScopeId = '/' }
            @{ id = 'ra-2'; principalId = 'bg-2'; roleDefinitionId = 'rd-ga'; directoryScopeId = '/' }
        )

        roleEligibilitySchedules = @(
            @{ id = 're-1'; principalId = 'u-1'; roleDefinitionId = 'rd-ga'; scheduleInfo = @{ expiration = @{ type = 'afterDateTime' } } }
            @{ id = 're-2'; principalId = 'u-2'; roleDefinitionId = 'rd-user'; scheduleInfo = @{ expiration = @{ type = 'afterDateTime' } } }
        )

        roleAssignmentSchedules = @(
            @{ id = 'ras-1'; principalId = 'bg-1'; roleDefinitionId = 'rd-ga'; assignmentType = 'Assigned'; scheduleInfo = @{ expiration = @{ type = 'noExpiration' } } }
            @{ id = 'ras-2'; principalId = 'bg-2'; roleDefinitionId = 'rd-ga'; assignmentType = 'Assigned'; scheduleInfo = @{ expiration = @{ type = 'noExpiration' } } }
        )

        roleManagementPolicies = @(
            @{ id = 'pol-ga'; rules = @(
                    @{ id = 'Enablement_EndUser_Assignment'; enabledRules = @('MultiFactorAuthentication', 'Justification') }
                )
            }
        )

        roleManagementPolicyAssignments = @(
            @{ id = 'pa-ga'; policyId = 'pol-ga'; roleDefinitionId = $gaTemplate }
        )
    }

    foreach ($key in $Overrides.Keys) {
        $snapshots[$key] = $Overrides[$key]
    }

    $rawFolder = Join-Path $Path 'Raw'
    $null = New-Item -Path $rawFolder -ItemType Directory -Force

    foreach ($name in $snapshots.Keys) {
        if ($name -in $ExcludeSnapshots) { continue }
        # -InputObject so empty arrays serialise as [] rather than an empty file.
        ConvertTo-Json -InputObject $snapshots[$name] -Depth 20 |
            Set-Content -LiteralPath (Join-Path $rawFolder "$name.json") -Encoding utf8NoBOM
    }

    return $Path
}
