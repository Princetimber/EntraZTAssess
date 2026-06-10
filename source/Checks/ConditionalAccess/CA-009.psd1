@{
    CheckId = 'CA-009'
    Domain = 'ConditionalAccess'
    Title = 'Stalled report-only policies'
    Description = 'Flags policies left in report-only mode beyond the engagement threshold (default 90 days).'
    Rationale = 'Report-only policies enforce nothing; a stalled rollout signals an unprotected gap the organisation believes is closed.'
    DefaultSeverity = 'Low'
    MaturityWeight = 2
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
    Remediation = 'Review report-only policy impact data and either enable or retire each stalled policy.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-report-only'
    )
}
