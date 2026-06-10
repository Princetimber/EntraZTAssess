@{
    CheckId = 'ID-003'
    Domain = 'IdentitySecurity'
    Title = 'Legacy authentication blocked'
    Description = 'Confirms legacy authentication protocols are blocked by policy and that no legacy sign-ins were observed in the lookback window.'
    Rationale = 'Legacy protocols cannot enforce MFA and are the most common vector for password spray; observed legacy sign-ins with no block escalate this check to Critical.'
    DefaultSeverity = 'High'
    MaturityWeight = 5
    ZeroTrustPillars = @(
        'VerifyExplicitly'
        'AssumeBreach'
    )
    LicenceDependency = 'Entra ID P1 for sign-in logs'
    PermissionDependency = @(
        'Policy.Read.All'
        'AuditLog.Read.All'
    )
    DataSources = @(
        'conditionalAccessPolicies'
        'legacyAuthSignIns'
    )
    Remediation = 'Create a Conditional Access policy blocking legacy authentication clients for all users, after confirming remaining legacy usage owners and migration paths.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-block-legacy'
    )
}
