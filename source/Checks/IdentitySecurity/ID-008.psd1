@{
    CheckId = 'ID-008'
    Domain = 'IdentitySecurity'
    Title = 'Temporary Access Pass enabled'
    Description = 'Checks whether Temporary Access Pass is enabled to support passwordless onboarding and credential recovery.'
    Rationale = 'TAP enables first-run registration of passwordless credentials without a password ever existing, and a secure recovery path.'
    DefaultSeverity = 'Low'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'authenticationMethodsPolicy'
    )
    Remediation = 'Enable Temporary Access Pass scoped to appropriate groups with conservative lifetime settings.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass'
    )
}
