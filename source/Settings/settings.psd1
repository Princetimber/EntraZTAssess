@{
    # ==========================================================================
    # EntraZTAssess default engagement settings.
    # All thresholds are consultancy defaults and may be overridden per
    # engagement via an engagement-level settings file.
    # ==========================================================================

    # Numeric thresholds used by assessment checks.
    Thresholds = @{
        MfaRegistrationCoveragePercent      = 95    # ID-001 pass threshold
        MfaRegistrationCoverageFailPercent  = 80    # ID-001 High severity below this
        StaleDeviceDays                     = 90    # EM-007 device check-in staleness
        StaleSignInDays                     = 90    # PA-006 / IG-004 account staleness
        StaleGuestDays                      = 90    # IG-004 guest staleness
        GlobalAdminMinimum                  = 2     # PA-001 lower bound
        GlobalAdminMaximum                  = 5     # PA-001 upper bound
        SignInLookbackDays                  = 30    # default sign-in log window
        ReportOnlyMaxAgeDays                = 90    # CA-009 stalled report-only policies
        UnmanagedDeviceMaxPercent           = 20    # DT-001 unknown/unmanaged ceiling
        StaleManagedDeviceMaxPercent        = 15    # EM-007 stale estate ceiling
        EncryptionCoverageMinimumPercent    = 90    # EM-002 BitLocker / FileVault estate coverage
        BaselineCoverageMinimumPercent      = 90    # EM-001 security baseline coverage
        SupervisedCorporateIosMinimumPercent = 80   # IOS supervised corporate estate
        CertificateExpiryWarningDays        = 30    # IOS/MAC push certificate and ADE token warning
        AppCredentialMaxValidityYears       = 2     # AS-003 credential validity ceiling
        RiskyUserUnremediatedMaxDays        = 7     # MD-002 open risky user age
        DomainInsufficientDataPercent       = 40    # NotAssessed weight above which a domain is not scored
    }

    # Microsoft Graph request behaviour.
    Graph = @{
        MaxRetryCount        = 5
        RetryBaseDelaySeconds = 2     # exponential backoff base (2, 4, 8, ...)
        DefaultPageSize      = 999
        DefaultApiVersion    = 'v1.0'
    }

    # Property names removed from raw snapshots before they are persisted.
    # Matched case-insensitively against property names at any depth.
    RedactionDenylist = @(
        'secretText'
        'password'
        'passwordProfile'
        'key'
        'keyCredentials.key'
        'symmetricKey'
        'token'
        'refreshToken'
        'accessToken'
        'clientSecret'
        'privateKey'
    )

    # Group name patterns used by the device classification engine to flag
    # privileged admin workstation (PAW) candidates. Wildcards supported.
    PawGroupPatterns = @(
        '*PAW*'
        '*Privileged*Workstation*'
        '*SecureAdmin*'
    )

    # Maturity level bands (inclusive lower bound, exclusive upper bound
    # except Optimised which includes 100).
    MaturityBands = @(
        @{ Level = 'Initial'; Minimum = 0; Maximum = 16 }
        @{ Level = 'Basic'; Minimum = 17; Maximum = 33 }
        @{ Level = 'Developing'; Minimum = 34; Maximum = 50 }
        @{ Level = 'Managed'; Minimum = 51; Maximum = 67 }
        @{ Level = 'Advanced'; Minimum = 68; Maximum = 84 }
        @{ Level = 'Optimised'; Minimum = 85; Maximum = 100 }
    )

    # Domain weights for the overall maturity percentage. A weight of 0
    # excludes the domain (applied automatically for HybridIdentity on
    # cloud-only tenants).
    DomainWeights = @{
        IdentitySecurity          = 1.5
        ConditionalAccess         = 1.5
        PrivilegedAccess          = 1.5
        EndpointManagement        = 1.0
        DeviceTrust               = 1.0
        MonitoringDetection       = 1.0
        ApplicationSecurity       = 1.0
        ByodGovernance            = 0.75
        CorporateDeviceGovernance = 0.75
        IdentityGovernance        = 0.75
        HybridIdentity            = 0.5
    }

    # Remediation SLA in days, by severity, used by the risk register.
    RemediationSlaDays = @{
        Critical = 7
        High     = 30
        Medium   = 90
        Low      = 180
    }

    # Privileged directory role template IDs used by the privileged access
    # assessment. Template IDs are stable across all tenants.
    PrivilegedRoles = @{
        GlobalAdministratorTemplateId = '62e90394-69f5-4237-9190-012177145e10'

        # Tier-0: roles that can take over the tenant directly or indirectly.
        Tier0TemplateIds = @(
            '62e90394-69f5-4237-9190-012177145e10' # Global Administrator
            'e8611ab8-c189-46e8-94e1-60213ab1f814' # Privileged Role Administrator
            '194ae4cb-b126-40b2-bd5b-6091b380977d' # Security Administrator
            'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' # Conditional Access Administrator
            '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' # Application Administrator
            '158c047a-c907-4556-b7ef-446551a6b5f7' # Cloud Application Administrator
            '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' # Privileged Authentication Administrator
            '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' # Hybrid Identity Administrator
        )

        # Broader privileged set assessed for hygiene checks.
        PrivilegedTemplateIds = @(
            '62e90394-69f5-4237-9190-012177145e10' # Global Administrator
            'e8611ab8-c189-46e8-94e1-60213ab1f814' # Privileged Role Administrator
            '194ae4cb-b126-40b2-bd5b-6091b380977d' # Security Administrator
            'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' # Conditional Access Administrator
            '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' # Application Administrator
            '158c047a-c907-4556-b7ef-446551a6b5f7' # Cloud Application Administrator
            '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' # Privileged Authentication Administrator
            '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' # Hybrid Identity Administrator
            'fe930be7-5e62-47db-91af-98c3a49a38b1' # User Administrator
            '29232cdf-9323-42fd-ade2-1d097af3e4de' # Exchange Administrator
            'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' # SharePoint Administrator
            '3a2c62db-5318-420d-8d74-23affee5d9d5' # Intune Administrator
            '729827e3-9c14-49f7-bb1b-9608f156bbb8' # Helpdesk Administrator
            'c4e39bd9-1100-46d3-8c65-fb160da0071f' # Authentication Administrator
        )
    }

    # Well-known application IDs referenced by Conditional Access checks.
    WellKnownApplications = @{
        AzureManagement = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
    }

    # Licence service plan name fragments used for capability detection.
    LicenceDetection = @{
        EntraP2ServicePlanNames = @('AAD_PREMIUM_P2')
        EntraP1ServicePlanNames = @('AAD_PREMIUM', 'AAD_PREMIUM_P2')
    }
}
