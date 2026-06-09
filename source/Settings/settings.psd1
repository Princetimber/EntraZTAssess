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
}
