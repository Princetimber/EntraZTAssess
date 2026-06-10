@{
    CheckId = 'CA-008'
    Domain = 'ConditionalAccess'
    Title = 'Policy exclusion hygiene'
    Description = 'Enumerates every user and group excluded from Conditional Access policies and flags exclusions beyond documented break-glass accounts.'
    Rationale = 'Exclusions are the most common silent bypass of Conditional Access; each one is an unguarded gate that attackers actively hunt for.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'LeastPrivilege'
        'VerifyExplicitly'
    )
    LicenceDependency = 'Entra ID P1'
    PermissionDependency = @(
        'Policy.Read.All'
        'Directory.Read.All'
    )
    DataSources = @(
        'conditionalAccessPolicies'
        'users'
    )
    Remediation = 'Review every exclusion, remove those without documented justification, and protect remaining exclusion groups with access reviews.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access'
    )
}
