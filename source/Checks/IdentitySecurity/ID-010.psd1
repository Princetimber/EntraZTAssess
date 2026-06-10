@{
    CheckId = 'ID-010'
    Domain = 'IdentitySecurity'
    Title = 'Legacy per-user MFA not in use'
    Description = 'Detects users still configured with legacy per-user MFA alongside Conditional Access.'
    Rationale = 'Mixed per-user MFA and Conditional Access produces unpredictable prompts and blocks migration to modern authentication strengths.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'None'
    PermissionDependency = @(
        'Reports.Read.All'
    )
    DataSources = @(
        'userRegistrationDetails'
    )
    Remediation = 'Migrate per-user MFA users to Conditional Access enforcement and disable per-user MFA settings.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/authentication/howto-mfa-userstates'
    )
}
