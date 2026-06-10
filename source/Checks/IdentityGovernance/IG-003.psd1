@{
    CheckId = 'IG-003'
    Domain = 'IdentityGovernance'
    Title = 'Entitlement management adoption'
    Description = 'Checks whether entitlement management access packages govern internal and guest access provisioning.'
    Rationale = 'Access packages replace ad hoc, permanent grants with time-bound, approved, reviewable bundles - the governed path for access.'
    DefaultSeverity = 'Low'
    MaturityWeight = 2
    ZeroTrustPillars = @(
        'LeastPrivilege'
    )
    LicenceDependency = 'Entra ID P2 / Governance'
    PermissionDependency = @(
        'EntitlementManagement.Read.All'
    )
    DataSources = @(
        'accessPackages'
    )
    Remediation = 'Adopt entitlement management for recurring access patterns, starting with guest onboarding and high-turnover teams.'
    RemediationEffort = 'Medium'
    References = @(
        'https://learn.microsoft.com/entra/id-governance/entitlement-management-overview'
    )
}
