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
            @{ id = 'tenant-1'; displayName = 'Contoso Ltd'; onPremisesSyncEnabled = $true; onPremisesLastSyncDateTime = [datetime]::UtcNow.AddMinutes(-30).ToString('yyyy-MM-ddTHH:mm:ssZ') }
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
            @{ '@odata.type' = '#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration'; platformType = 'windows'; platformRestriction = @{ personalDeviceEnrollmentBlocked = $true } }
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

        # ----- Device / endpoint snapshots (well-configured estate) -----

        managedDevices = @(
            @{ id = 'md-1'; deviceName = 'WIN-CORP-01'; operatingSystem = 'Windows'; osVersion = '10.0.26100'; managedDeviceOwnerType = 'company'; deviceEnrollmentType = 'windowsAutoEnrollment'; complianceState = 'compliant'; isEncrypted = $true; isSupervised = $false; lastSyncDateTime = $recentSignIn; managementAgent = 'mdm'; userPrincipalName = 'alice@contoso.com'; azureADDeviceId = 'aad-1'; serialNumber = 'SER-WIN-1' }
            @{ id = 'md-2'; deviceName = 'WIN-CORP-02'; operatingSystem = 'Windows'; osVersion = '10.0.26100'; managedDeviceOwnerType = 'company'; deviceEnrollmentType = 'windowsAutoEnrollment'; complianceState = 'compliant'; isEncrypted = $true; isSupervised = $false; lastSyncDateTime = $recentSignIn; managementAgent = 'configurationManagerClientMdm'; userPrincipalName = 'bob@contoso.com'; azureADDeviceId = 'aad-2'; serialNumber = 'SER-WIN-2' }
            @{ id = 'md-3'; deviceName = 'IPHONE-CORP-01'; operatingSystem = 'iOS'; osVersion = '18.1'; managedDeviceOwnerType = 'company'; deviceEnrollmentType = 'appleBulkWithUser'; complianceState = 'compliant'; isEncrypted = $true; isSupervised = $true; lastSyncDateTime = $recentSignIn; managementAgent = 'mdm'; userPrincipalName = 'alice@contoso.com'; azureADDeviceId = 'aad-3'; serialNumber = 'SER-IOS-1' }
            @{ id = 'md-4'; deviceName = 'IPHONE-BYOD-01'; operatingSystem = 'iOS'; osVersion = '18.1'; managedDeviceOwnerType = 'personal'; deviceEnrollmentType = 'userEnrollment'; complianceState = 'compliant'; isEncrypted = $true; isSupervised = $false; lastSyncDateTime = $recentSignIn; managementAgent = 'mdm'; userPrincipalName = 'bob@contoso.com'; azureADDeviceId = 'aad-4'; serialNumber = 'SER-IOS-2' }
            @{ id = 'md-5'; deviceName = 'MAC-CORP-01'; operatingSystem = 'macOS'; osVersion = '15.1'; managedDeviceOwnerType = 'company'; deviceEnrollmentType = 'appleBulkWithUser'; complianceState = 'compliant'; isEncrypted = $true; isSupervised = $true; lastSyncDateTime = $recentSignIn; managementAgent = 'mdm'; userPrincipalName = 'alice@contoso.com'; azureADDeviceId = 'aad-5'; serialNumber = 'SER-MAC-1' }
            @{ id = 'md-6'; deviceName = 'AND-BYOD-01'; operatingSystem = 'Android'; osVersion = '15'; managedDeviceOwnerType = 'personal'; deviceEnrollmentType = 'androidEnterpriseWorkProfile'; complianceState = 'compliant'; isEncrypted = $true; isSupervised = $false; lastSyncDateTime = $recentSignIn; managementAgent = 'mdm'; userPrincipalName = 'bob@contoso.com'; azureADDeviceId = 'aad-6'; serialNumber = 'SER-AND-1' }
            @{ id = 'md-7'; deviceName = 'AND-CORP-01'; operatingSystem = 'Android'; osVersion = '15'; managedDeviceOwnerType = 'company'; deviceEnrollmentType = 'androidEnterpriseFullyManaged'; complianceState = 'compliant'; isEncrypted = $true; isSupervised = $false; lastSyncDateTime = $recentSignIn; managementAgent = 'mdm'; userPrincipalName = 'alice@contoso.com'; azureADDeviceId = 'aad-7'; serialNumber = 'SER-AND-2' }
        )

        entraDevices = @(
            @{ id = 'ed-1'; deviceId = 'aad-1'; displayName = 'WIN-CORP-01'; operatingSystem = 'Windows'; trustType = 'AzureAd'; profileType = 'RegisteredDevice'; isManaged = $true; isCompliant = $true; accountEnabled = $true; approximateLastSignInDateTime = $recentSignIn }
            @{ id = 'ed-2'; deviceId = 'aad-2'; displayName = 'WIN-CORP-02'; operatingSystem = 'Windows'; trustType = 'AzureAd'; profileType = 'RegisteredDevice'; isManaged = $true; isCompliant = $true; accountEnabled = $true; approximateLastSignInDateTime = $recentSignIn }
            @{ id = 'ed-3'; deviceId = 'aad-3'; displayName = 'IPHONE-CORP-01'; operatingSystem = 'iOS'; trustType = 'Workplace'; profileType = 'RegisteredDevice'; isManaged = $true; isCompliant = $true; accountEnabled = $true; approximateLastSignInDateTime = $recentSignIn }
            @{ id = 'ed-4'; deviceId = 'aad-4'; displayName = 'IPHONE-BYOD-01'; operatingSystem = 'iOS'; trustType = 'Workplace'; profileType = 'RegisteredDevice'; isManaged = $true; isCompliant = $true; accountEnabled = $true; approximateLastSignInDateTime = $recentSignIn }
            @{ id = 'ed-5'; deviceId = 'aad-5'; displayName = 'MAC-CORP-01'; operatingSystem = 'MacMDM'; trustType = 'Workplace'; profileType = 'RegisteredDevice'; isManaged = $true; isCompliant = $true; accountEnabled = $true; approximateLastSignInDateTime = $recentSignIn }
            @{ id = 'ed-6'; deviceId = 'aad-6'; displayName = 'AND-BYOD-01'; operatingSystem = 'Android'; trustType = 'Workplace'; profileType = 'RegisteredDevice'; isManaged = $true; isCompliant = $true; accountEnabled = $true; approximateLastSignInDateTime = $recentSignIn }
            @{ id = 'ed-7'; deviceId = 'aad-7'; displayName = 'AND-CORP-01'; operatingSystem = 'Android'; trustType = 'Workplace'; profileType = 'RegisteredDevice'; isManaged = $true; isCompliant = $true; accountEnabled = $true; approximateLastSignInDateTime = $recentSignIn }
        )

        compliancePolicies = @(
            @{ id = 'cp-win'; '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; displayName = 'Windows compliance'; osMinimumVersion = '10.0.22631'; bitLockerEnabled = $true; passwordRequired = $true; defenderEnabled = $true }
            @{ id = 'cp-ios'; '@odata.type' = '#microsoft.graph.iosCompliancePolicy'; displayName = 'iOS compliance'; osMinimumVersion = '17.0'; securityBlockJailbrokenDevices = $true; passwordRequired = $true; storageRequireEncryption = $true }
            @{ id = 'cp-mac'; '@odata.type' = '#microsoft.graph.macOSCompliancePolicy'; displayName = 'macOS compliance'; osMinimumVersion = '14.0'; storageRequireEncryption = $true; firewallEnabled = $true; passwordRequired = $true }
            @{ id = 'cp-and'; '@odata.type' = '#microsoft.graph.androidDeviceOwnerCompliancePolicy'; displayName = 'Android compliance'; osMinimumVersion = '13'; securityBlockJailbrokenDevices = $true; storageRequireEncryption = $true; passwordRequired = $true }
        )

        deviceConfigurations = @(
            @{ id = 'dc-win'; '@odata.type' = '#microsoft.graph.windows10GeneralConfiguration'; displayName = 'Windows hardening' }
            @{ id = 'dc-ios'; '@odata.type' = '#microsoft.graph.iosGeneralDeviceConfiguration'; displayName = 'iOS restrictions' }
            @{ id = 'dc-mac'; '@odata.type' = '#microsoft.graph.macOSGeneralDeviceConfiguration'; displayName = 'macOS Gatekeeper and security' }
            @{ id = 'dc-and'; '@odata.type' = '#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration'; displayName = 'Android restrictions' }
        )

        configurationPolicies = @(
            @{ id = 'sc-1'; name = 'Defender Antivirus policy'; platforms = 'windows10'; templateReference = @{ templateFamily = 'endpointSecurityAntivirus' } }
            @{ id = 'sc-2'; name = 'Firewall policy'; platforms = 'windows10'; templateReference = @{ templateFamily = 'endpointSecurityFirewall' } }
            @{ id = 'sc-3'; name = 'Attack Surface Reduction rules'; platforms = 'windows10'; templateReference = @{ templateFamily = 'endpointSecurityAttackSurfaceReduction' } }
            @{ id = 'sc-4'; name = 'EDR onboarding'; platforms = 'windows10'; templateReference = @{ templateFamily = 'endpointSecurityEndpointDetectionAndResponse' } }
        )

        intents = @(
            @{ id = 'in-1'; displayName = 'Windows security baseline'; templateId = 'tmpl-baseline'; isAssigned = $true }
            @{ id = 'in-2'; displayName = 'BitLocker disk encryption'; templateId = 'tmpl-encrypt'; isAssigned = $true }
        )

        appProtectionPolicies = @(
            @{ id = 'mam-ios'; '@odata.type' = '#microsoft.graph.iosManagedAppProtection'; displayName = 'iOS app protection' }
            @{ id = 'mam-and'; '@odata.type' = '#microsoft.graph.androidManagedAppProtection'; displayName = 'Android app protection' }
            @{ id = 'mam-win'; '@odata.type' = '#microsoft.graph.windowsManagedAppProtection'; displayName = 'Windows app protection' }
        )

        autopilotDevices = @(
            @{ id = 'ap-1'; serialNumber = 'SER-WIN-1'; model = 'Surface Laptop'; manufacturer = 'Microsoft' }
            @{ id = 'ap-2'; serialNumber = 'SER-WIN-2'; model = 'Surface Laptop'; manufacturer = 'Microsoft' }
        )

        autopilotProfiles = @(
            @{ id = 'app-1'; displayName = 'Corporate Autopilot profile' }
        )

        applePushCertificate = @{ id = 'apns-1'; expirationDateTime = [datetime]::UtcNow.AddDays(200).ToString('yyyy-MM-ddTHH:mm:ssZ') }

        depOnboardingSettings = @(
            @{ id = 'dep-1'; tokenName = 'Contoso ABM'; tokenExpirationDateTime = [datetime]::UtcNow.AddDays(200).ToString('yyyy-MM-ddTHH:mm:ssZ'); appleIdentifier = 'abm@contoso.com' }
        )

        androidEnterpriseSettings = @{ id = 'ae-1'; bindStatus = 'boundAndValidated'; ownerUserPrincipalName = 'admin@contoso.com' }

        mtdConnectors = @(
            @{ id = 'mtd-1'; partnerState = 'enabled' }
        )

        deviceManagementSettings = @{ secureByDefault = $true; deviceComplianceCheckinThresholdDays = 30 }

        # ----- Governance / applications / hybrid / monitoring snapshots -----

        accessReviewDefinitions = @(
            @{ id = 'rev-1'; displayName = 'Privileged role assignments review'; scope = @{ query = '/roleManagement/directory/roleAssignments' } }
            @{ id = 'rev-2'; displayName = 'Guest access review'; scope = @{ query = "/users?`$filter=userType eq 'Guest'" } }
        )

        accessPackages = @(
            @{ id = 'pkg-1'; displayName = 'Contractor onboarding'; isHidden = $false }
        )

        lifecycleWorkflows = @(
            @{ id = 'wf-1'; displayName = 'Leaver - disable and remove access'; category = 'leaver'; isEnabled = $true }
        )

        authorizationPolicy = @{
            id                         = 'authorizationPolicy'
            allowInvitesFrom           = 'adminsAndGuestInviters'
            guestUserRoleId            = '2af84b1e-32c8-42b7-82bc-daa82404023b'
            defaultUserRolePermissions = @{
                permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low')
            }
        }

        crossTenantAccessPolicyDefault = @{
            id           = 'default'
            inboundTrust = @{ isMfaAccepted = $false; isCompliantDeviceAccepted = $false; isHybridAzureADJoinedDeviceAccepted = $false }
        }

        adminConsentRequestPolicy = @{ isEnabled = $true }

        applications = @(
            @{ id = 'app-obj-1'; appId = 'app-1'; displayName = 'Line of Business API'
                signInAudience = 'AzureADMyOrg'
                web = @{ redirectUris = @('https://lob.contoso.com/auth') }
                spa = @{ redirectUris = @() }
                publicClient = @{ redirectUris = @() }
                keyCredentials = @(@{ keyId = 'kc-1'; startDateTime = [datetime]::UtcNow.AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ'); endDateTime = [datetime]::UtcNow.AddDays(335).ToString('yyyy-MM-ddTHH:mm:ssZ') })
                passwordCredentials = @()
                verifiedPublisher = @{ displayName = 'Contoso Ltd' }
                owners = @(@{ id = 'u-1' })
            }
        )

        oauth2PermissionGrants = @()

        graphServicePrincipal = @{
            id = 'graph-sp'; appId = '00000003-0000-0000-c000-000000000000'; displayName = 'Microsoft Graph'
            appRoles = @(
                @{ id = 'role-dir-rw'; value = 'Directory.ReadWrite.All' }
                @{ id = 'role-role-rw'; value = 'RoleManagement.ReadWrite.Directory' }
                @{ id = 'role-mail-rw'; value = 'Mail.ReadWrite' }
                @{ id = 'role-user-read'; value = 'User.Read.All' }
            )
        }

        graphAppRoleAssignments = @(
            @{ id = 'ara-1'; principalId = 'sp-1'; principalDisplayName = 'Workload App'; appRoleId = 'role-user-read'; resourceId = 'graph-sp' }
        )

        spSignInActivities = @(
            @{ id = 'act-1'; appId = 'app-1'; lastSignInActivity = @{ lastSignInDateTime = [datetime]::UtcNow.AddDays(-3).ToString('yyyy-MM-ddTHH:mm:ssZ') } }
        )

        onPremisesSynchronization = @(
            @{ id = 'sync-1'; features = @{ passwordSyncEnabled = $true; deviceWritebackEnabled = $false; groupWriteBackEnabled = $false } }
        )

        provisioningErrorsSummary = @{ syncedUserCount = 1; usersWithErrors = 0; errorsByCategory = @() }

        riskyUsers = @()

        riskDetectionsSummary = @{ totalDetections = 0; countsByType = @(); countsByLevel = @() }

        directoryAuditProbe = @{ available = $true; sampledActivity = 'Update user' }

        mdiSensors = @(
            @{ id = 'sensor-1'; displayName = 'DC01'; healthStatus = 'healthy'; sensorType = 'domainControllerIntegrated' }
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
