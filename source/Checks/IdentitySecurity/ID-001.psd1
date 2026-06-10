@{
    CheckId = 'ID-001'
    Domain = 'IdentitySecurity'
    Title = 'MFA registration coverage'
    Description = 'Measures the percentage of enabled users registered for multifactor authentication against the engagement threshold (default 95 per cent).'
    Rationale = 'Accounts without MFA are the primary target of password spray and phishing attacks; Microsoft telemetry shows MFA blocks the overwhelming majority of identity attacks.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Entra ID P1 for the registration report'
    PermissionDependency = @(
        'Reports.Read.All'
    )
    DataSources = @(
        'userRegistrationDetails'
        'users'
    )
    Remediation = 'Drive MFA registration campaigns and enforce registration via Conditional Access or Identity Protection registration policy until coverage exceeds the threshold.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/authentication/howto-authentication-methods-activity'
    )
}
