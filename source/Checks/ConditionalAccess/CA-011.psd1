@{
    CheckId = 'CA-011'
    Domain = 'ConditionalAccess'
    Title = 'Critical applications protected'
    Description = 'Verifies MFA policy coverage explicitly includes critical applications, in particular Azure management endpoints.'
    Rationale = 'Azure management access grants control over infrastructure; per-app targeting frequently misses it when policies are not all-apps.'
    DefaultSeverity = 'High'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'VerifyExplicitly'
        'LeastPrivilege'
    )
    LicenceDependency = 'Entra ID P1'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'conditionalAccessPolicies'
    )
    Remediation = 'Ensure an enabled policy requires MFA for Microsoft Azure Management, or adopt all-apps targeting.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-azure-management'
    )
}
