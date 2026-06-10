@{
    CheckId = 'CA-001'
    Domain = 'ConditionalAccess'
    Title = 'MFA required for all users'
    Description = 'Verifies an enabled policy requires MFA or an authentication strength for all users across all cloud apps.'
    Rationale = 'Universal MFA enforcement is the single most effective identity control; report-only policies do not protect anyone.'
    DefaultSeverity = 'Critical'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'VerifyExplicitly'
    )
    LicenceDependency = 'Entra ID P1'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'conditionalAccessPolicies'
    )
    Remediation = 'Deploy an all-users, all-apps MFA policy with documented break-glass exclusions, moving from report-only to enabled after impact review.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa'
    )
}
