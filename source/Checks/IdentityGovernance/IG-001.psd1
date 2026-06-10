@{
    CheckId = 'IG-001'
    Domain = 'IdentityGovernance'
    Title = 'Access reviews for privileged roles'
    Description = 'Verifies recurring access reviews exist for privileged directory role assignments.'
    Rationale = 'Privilege accumulates silently; periodic recertification is the only scalable way to remove access that is no longer justified.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'LeastPrivilege'
    )
    LicenceDependency = 'Entra ID P2 / Governance'
    PermissionDependency = @(
        'AccessReview.Read.All'
    )
    DataSources = @(
        'accessReviewDefinitions'
    )
    Remediation = 'Create recurring access reviews for all privileged directory roles with auto-removal on non-response.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/id-governance/access-reviews-overview'
    )
}
