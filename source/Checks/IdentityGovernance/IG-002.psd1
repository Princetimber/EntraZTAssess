@{
    CheckId = 'IG-002'
    Domain = 'IdentityGovernance'
    Title = 'Access reviews for guest accounts'
    Description = 'Verifies guest access is periodically reviewed where the guest population exceeds the engagement threshold.'
    Rationale = 'Guests outlive the projects that justified them; unreviewed guest access is a slow leak of corporate data to external identities.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 3
    ZeroTrustPillars = @(
        'LeastPrivilege'
    )
    LicenceDependency = 'Entra ID P2 / Governance'
    PermissionDependency = @(
        'AccessReview.Read.All'
        'Directory.Read.All'
    )
    DataSources = @(
        'accessReviewDefinitions'
        'users'
    )
    Remediation = 'Create recurring guest access reviews on Teams and Microsoft 365 Groups with removal on denial or non-response.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/id-governance/manage-guest-access-with-access-reviews'
    )
}
