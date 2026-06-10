@{
    CheckId = 'AS-006'
    Domain = 'ApplicationSecurity'
    Title = 'Unverified publisher applications'
    Description = 'Flags third-party applications with consented permissions whose publisher is unverified.'
    Rationale = 'Publisher verification ties an app to a vetted organisation; unverified third-party apps with data access are unaccountable.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Application.Read.All'
    )
    DataSources = @(
        'servicePrincipals'
        'oauth2PermissionGrants'
    )
    Remediation = 'Review consented unverified third-party applications, remove unneeded ones, and prefer verified publishers in consent policy.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity-platform/publisher-verification-overview'
    )
}
