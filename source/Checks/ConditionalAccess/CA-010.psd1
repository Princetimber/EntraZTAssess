@{
    CheckId = 'CA-010'
    Domain = 'ConditionalAccess'
    Title = 'Disabled policies closing current gaps'
    Description = 'Identifies disabled policies whose conditions would close gaps found elsewhere in this assessment.'
    Rationale = 'Disabled policies often represent abandoned good intentions; re-enabling them is frequently the fastest remediation available.'
    DefaultSeverity = 'Low'
    MaturityWeight = 1
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
    Remediation = 'Review disabled policies against the gap analysis and re-enable, update, or delete each one.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access'
    )
}
