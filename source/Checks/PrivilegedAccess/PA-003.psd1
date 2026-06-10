@{
    CheckId = 'PA-003'
    Domain = 'PrivilegedAccess'
    Title = 'PIM activation requirements for Tier-0 roles'
    Description = 'Verifies PIM role settings require MFA and justification on activation for Tier-0 roles, with approval for Global Administrator as a maturity signal.'
    Rationale = 'Activation gates ensure even a compromised eligible account cannot silently assume privilege.'
    DefaultSeverity = 'Medium'
    MaturityWeight = 4
    ZeroTrustPillars = @(
        'LeastPrivilege'
        'VerifyExplicitly'
    )
    LicenceDependency = 'Entra ID P2'
    PermissionDependency = @(
        'Policy.Read.All'
    )
    DataSources = @(
        'roleManagementPolicies'
    )
    Remediation = 'Configure PIM role settings for Tier-0 roles to require MFA and justification, and add approval for Global Administrator activation.'
    RemediationEffort = 'Low'
    References = @(
        'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'
    )
}
